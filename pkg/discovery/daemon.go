package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
)

const (
	hostsBlockStart = "# === SYSBRIDGE MANAGED (DO NOT EDIT) ==="
	hostsBlockEnd   = "# === END SYSBRIDGE MANAGED ==="
	defaultHosts    = "/etc/hosts"
)

var hostsMu sync.Mutex

type Daemon struct {
	cfg       *config.Config
	key       []byte
	store     *StateStore
	conn      *net.UDPConn
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
	hostsPath string
	onPeer    func(st *PeerState)
}

func NewDaemon(cfg *config.Config, store *StateStore) (*Daemon, error) {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}

	key, err := LoadOrCreateKey(cfg.Mesh.SecretKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load mesh secret key: %w", err)
	}

	if store == nil {
		store = NewStateStore(cfg.Mesh.StatePath)
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Daemon{
		cfg:       cfg,
		key:       key,
		store:     store,
		ctx:       ctx,
		cancel:    cancel,
		hostsPath: defaultHosts,
	}, nil
}

func (d *Daemon) StateStore() *StateStore {
	return d.store
}

func (d *Daemon) SetOnPeerCallback(fn func(st *PeerState)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.onPeer = fn
}

func (d *Daemon) StartAsync(ctx context.Context) error {
	if ctx != nil {
		go func() {
			select {
			case <-ctx.Done():
				d.Stop()
			case <-d.ctx.Done():
			}
		}()
	}

	port := d.cfg.Mesh.UDPPort
	if port <= 0 {
		port = DefaultPort
	}

	addr := net.UDPAddr{
		Port: port,
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp4", &addr)
	if err != nil {
		return fmt.Errorf("listen udp4 :%d: %w", port, err)
	}

	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()

	go d.listenLoop()
	go d.beaconLoop()
	go d.healthCheckLoop()

	if d.cfg.Mesh.NetlinkBurst {
		StartNetlinkWatcher(d.ctx, func() {
			d.SendBeaconsBurst(3)
		})
	}

	return nil
}

func (d *Daemon) Start(ctx context.Context) error {
	if err := d.StartAsync(ctx); err != nil {
		return err
	}
	<-d.ctx.Done()
	return nil
}

func (d *Daemon) Stop() {
	d.cancel()
	d.mu.Lock()
	if d.conn != nil {
		_ = d.conn.Close()
		d.conn = nil
	}
	d.mu.Unlock()
}

func (d *Daemon) LocalAddr() net.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.conn == nil {
		return nil
	}
	return d.conn.LocalAddr()
}

func (d *Daemon) listenLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-d.ctx.Done():
			return
		default:
		}

		d.mu.RLock()
		conn := d.conn
		d.mu.RUnlock()
		if conn == nil {
			return
		}

		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			continue
		}

		pkt, err := DecodeAndVerify(buf[:n], d.key)
		if err != nil {
			continue
		}

		if pkt.Sender == d.cfg.Mesh.Role && pkt.Hostname == d.cfg.Mesh.NodeName {
			continue
		}

		d.handlePacket(pkt, remoteAddr)
	}
}

func (d *Daemon) handlePacket(pkt *Packet, remoteAddr *net.UDPAddr) {
	remoteIP := ""
	if remoteAddr != nil && remoteAddr.IP != nil {
		remoteIP = remoteAddr.IP.String()
	}
	if pkt.IP != "" && isValidIPv4(pkt.IP) {
		remoteIP = pkt.IP
	}
	if remoteIP == "" {
		return
	}

	now := time.Now().Unix()
	var rttMs float64
	if pkt.Type == TypeAck && pkt.Nonce != "" {
		if sentNano, err := strconv.ParseInt(pkt.Nonce, 10, 64); err == nil && sentNano > 0 {
			diff := time.Now().UnixNano() - sentNano
			if diff > 0 {
				rttMs = float64(diff) / 1e6
			}
		}
	}

	peerKey := pkt.Sender
	if peerKey == "" {
		peerKey = pkt.Hostname
	}
	if peerKey == "" {
		peerKey = remoteIP
	}

	st := &PeerState{
		Status:          "online",
		PeerRole:        pkt.Sender,
		PeerName:        pkt.Hostname,
		PeerIP:          remoteIP,
		SSHPort:         pkt.SSHPort,
		MoshPort:        pkt.MoshPort,
		LastSeenSecAgo:  0,
		LastSeenEpoch:   now,
		RTTMs:           rttMs,
		DiscoveryMethod: "udp_mesh",
		Metrics:         pkt.Metrics,
	}

	_ = d.store.Upsert(peerKey, st)

	cacheFile := filepath.Join(config.UserCacheDir(), "ip_"+peerKey)
	if err := os.MkdirAll(filepath.Dir(cacheFile), 0700); err == nil {
		_ = os.WriteFile(cacheFile, []byte(remoteIP+"\n"), 0600)
	}

	if d.cfg.Mesh.ManageEtcHosts {
		var domains []string
		if p, err := d.cfg.ResolvePeer(peerKey); err == nil && p != nil {
			domains = p.Domains
		}
		_ = UpdateEtcHostsFile(d.hostsPath, pkt.Sender, remoteIP, domains)
	}

	d.mu.RLock()
	cb := d.onPeer
	conn := d.conn
	d.mu.RUnlock()

	if cb != nil {
		cb(st)
	}

	if pkt.Type == TypeBeacon && conn != nil && remoteAddr != nil {
		sshPort, moshPort := d.localAdvertisedPorts()
		ack := &Packet{
			Type:      TypeAck,
			Sender:    d.cfg.Mesh.Role,
			Hostname:  d.cfg.Mesh.NodeName,
			SSHPort:   sshPort,
			MoshPort:  moshPort,
			Timestamp: now,
			Nonce:     pkt.Nonce,
			Metrics:   collectLocalMetrics(),
		}
		if encoded, err := ack.Encode(d.key); err == nil {
			_, _ = conn.WriteToUDP(encoded, remoteAddr)
		}
	}
}

func (d *Daemon) beaconLoop() {
	interval := d.cfg.Mesh.BeaconIntervalSec
	if interval <= 0 {
		interval = 10
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	d.SendBeacons()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			d.SendBeacons()
		}
	}
}

func (d *Daemon) SendBeacons() {
	d.mu.RLock()
	conn := d.conn
	d.mu.RUnlock()
	if conn == nil {
		return
	}

	targets := DiscoverBroadcastTargets()
	if len(targets) == 0 {
		return
	}

	sshPort, moshPort := d.localAdvertisedPorts()
	pkt := &Packet{
		Type:      TypeBeacon,
		Sender:    d.cfg.Mesh.Role,
		Hostname:  d.cfg.Mesh.NodeName,
		SSHPort:   sshPort,
		MoshPort:  moshPort,
		Timestamp: time.Now().Unix(),
		Nonce:     strconv.FormatInt(time.Now().UnixNano(), 10),
		Metrics:   collectLocalMetrics(),
	}

	data, err := pkt.Encode(d.key)
	if err != nil {
		return
	}

	port := d.cfg.Mesh.UDPPort
	if port <= 0 {
		port = DefaultPort
	}

	for _, targetIP := range targets {
		ip := net.ParseIP(targetIP)
		if ip == nil {
			continue
		}
		dst := &net.UDPAddr{
			IP:   ip,
			Port: port,
		}
		_, _ = conn.WriteToUDP(data, dst)
	}
}

func (d *Daemon) SendBeaconsBurst(count int) {
	if count <= 0 {
		count = 3
	}
	for i := 0; i < count; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.SendBeacons()
			if i+1 < count {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (d *Daemon) healthCheckLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			peers, err := d.store.Load()
			if err == nil && len(peers) > 0 {
				_ = d.store.Save(peers)
			}
		}
	}
}

func (d *Daemon) localAdvertisedPorts() (int, int) {
	sshPort := 22
	moshPort := 60000
	if strings.EqualFold(d.cfg.Mesh.Role, "phone") {
		sshPort = 8022
	}
	if p, ok := d.cfg.Peers[d.cfg.Mesh.Role]; ok && p != nil {
		if p.SSHPort > 0 {
			sshPort = p.SSHPort
		}
		if p.MoshPort > 0 {
			moshPort = p.MoshPort
		}
	}
	return sshPort, moshPort
}

func DiscoverBroadcastTargets() []string {
	var targets []string
	seen := make(map[string]bool)

	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] {
			seen[ip] = true
			targets = append(targets, ip)
		}
	}

	if gw := defaultGatewayIP(); gw != "" {
		add(gw)
	}

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok || ipnet.IP == nil {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil || len(ipnet.Mask) != 4 {
					continue
				}
				bcast := net.IP(make([]byte, 4))
				for i := 0; i < 4; i++ {
					bcast[i] = ip4[i] | ^ipnet.Mask[i]
				}
				add(bcast.String())
			}
		}
	}

	add("255.255.255.255")
	return targets
}

func defaultGatewayIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	return extractFieldAfter(fields, "via")
}

func collectLocalMetrics() *Metrics {
	m := &Metrics{}
	hasData := false

	if loadBytes, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(loadBytes))
		if len(fields) >= 3 {
			m.LoadAvg = strings.Join(fields[:3], " ")
			hasData = true
		}
	}

	if matches, err := filepath.Glob("/sys/class/power_supply/BAT*"); err == nil && len(matches) > 0 {
		if capBytes, err := os.ReadFile(filepath.Join(matches[0], "capacity")); err == nil {
			if pct, convErr := strconv.Atoi(strings.TrimSpace(string(capBytes))); convErr == nil {
				m.BatteryPct = pct
				hasData = true
			}
		}
		if statusBytes, err := os.ReadFile(filepath.Join(matches[0], "status")); err == nil {
			st := strings.ToLower(strings.TrimSpace(string(statusBytes)))
			m.IsCharging = st == "charging" || st == "full"
		}
	}

	if !hasData {
		return nil
	}
	return m
}

func UpdateEtcHostsFile(hostsPath string, peerRole string, peerIP string, domains []string) error {
	hostsMu.Lock()
	defer hostsMu.Unlock()

	if peerIP == "" {
		return nil
	}
	if hostsPath == "" {
		hostsPath = defaultHosts
	}

	if !isFileWritable(hostsPath) {
		return nil
	}

	if len(domains) == 0 {
		if strings.EqualFold(peerRole, "laptop") {
			domains = []string{"laptop.local", "daemon.local"}
		} else {
			domains = []string{"phone.local", "termux.local"}
		}
	}

	peerDomains := strings.Join(domains, " ")
	entry := fmt.Sprintf("%s\n%s\t%s\n%s\n", hostsBlockStart, peerIP, peerDomains, hostsBlockEnd)

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil
	}

	content := string(data)
	startIdx := strings.Index(content, hostsBlockStart)
	endIdx := strings.Index(content, hostsBlockEnd)

	var newContent string
	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		existingBlock := content[startIdx : endIdx+len(hostsBlockEnd)]
		if strings.Contains(existingBlock, peerIP) && strings.Contains(existingBlock, peerDomains) {
			return nil
		}
		newContent = content[:startIdx] + strings.TrimSpace(entry) + content[endIdx+len(hostsBlockEnd):]
	} else {
		newContent = strings.TrimSpace(content) + "\n\n" + entry
	}

	formatted := []byte(strings.TrimSpace(newContent) + "\n")
	if err := os.WriteFile(hostsPath, formatted, 0644); err == nil {
		return nil
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", hostsPath, os.Getpid())
	if err := os.WriteFile(tmpFile, formatted, 0644); err != nil {
		return nil
	}
	if err := os.Rename(tmpFile, hostsPath); err != nil {
		_ = os.Remove(tmpFile)
	}
	return nil
}

func isFileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
