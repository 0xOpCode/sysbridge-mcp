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
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
)

type Resolver struct {
	cfg          *config.Config
	store        *StateStore
	hostsFile    string
	cacheDir     string
	probeTimeout time.Duration
	cmdRunner    func(name string, args ...string) (string, error)
	tcpProber    func(host string, port int, timeout time.Duration) bool
}

func NewResolver(cfg *config.Config, store *StateStore) *Resolver {
	statePath := ""
	if cfg != nil {
		statePath = cfg.Mesh.StatePath
	}
	if store == nil {
		store = NewStateStore(statePath)
	}
	return &Resolver{
		cfg:          cfg,
		store:        store,
		hostsFile:    "/etc/hosts",
		cacheDir:     config.UserCacheDir(),
		probeTimeout: 400 * time.Millisecond,
		cmdRunner:    defaultCmdRunner,
		tcpProber:    defaultTCPProber,
	}
}

func (r *Resolver) StateStore() *StateStore {
	return r.store
}

func (r *Resolver) CacheFilePath(peerName string) string {
	dir := r.cacheDir
	if dir == "" {
		dir = config.UserCacheDir()
	}
	return filepath.Join(dir, "ip_"+peerName)
}

func (r *Resolver) saveCachedIP(peerName, ip string) {
	if peerName == "" || ip == "" {
		return
	}
	cachePath := r.CacheFilePath(peerName)
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return
	}
	_ = os.WriteFile(cachePath, []byte(strings.TrimSpace(ip)+"\n"), 0600)
}

func (r *Resolver) ResolvePeerHost(peer *config.PeerConfig) (string, int, string, error) {
	if peer == nil {
		return "", 0, "", fmt.Errorf("peer config is nil")
	}

	port := peer.SSHPort
	if port <= 0 {
		port = 22
	}

	hostTrimmed := strings.TrimSpace(peer.Host)
	if hostTrimmed != "" && !strings.EqualFold(hostTrimmed, "auto") {
		r.saveCachedIP(peer.Name, hostTrimmed)
		return hostTrimmed, port, "explicit_host", nil
	}

	if ip, stPort, ok := r.resolveFromStateStore(peer); ok {
		if stPort > 0 {
			port = stPort
		}
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "mesh_state", nil
	}

	if ip, ok := r.resolveFromEtcHosts(peer, port); ok {
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "etc_hosts", nil
	}

	if ip, ok := r.resolveFromCacheFile(peer, port); ok {
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "ip_cache", nil
	}

	if ip, ok := r.resolveFromUSBTethering(peer, port); ok {
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "usb_tether", nil
	}

	if ip, ok := r.resolveFromHotspotAndADB(peer, port); ok {
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "hotspot_adb", nil
	}

	if ip, ok := r.resolveFromSubnetNeighbors(peer, port); ok {
		r.saveCachedIP(peer.Name, ip)
		return ip, port, "subnet_neigh", nil
	}

	return "", 0, "", fmt.Errorf("failed to resolve IP for peer %q across 7 discovery stages", peer.Name)
}

func (r *Resolver) resolveFromStateStore(peer *config.PeerConfig) (string, int, bool) {
	if r.store == nil {
		return "", 0, false
	}

	candidates := []string{peer.Name}
	candidates = append(candidates, peer.Domains...)
	for _, key := range candidates {
		if key == "" {
			continue
		}
		st, ok := r.store.Get(key)
		if !ok || st == nil {
			continue
		}
		if st.Status != "offline" && strings.TrimSpace(st.PeerIP) != "" {
			return strings.TrimSpace(st.PeerIP), st.SSHPort, true
		}
	}
	return "", 0, false
}

func (r *Resolver) resolveFromEtcHosts(peer *config.PeerConfig, port int) (string, bool) {
	hostsPath := r.hostsFile
	if hostsPath == "" {
		hostsPath = "/etc/hosts"
	}
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return "", false
	}

	domains := peer.Domains
	if len(domains) == 0 {
		switch strings.ToLower(peer.Name) {
		case "laptop":
			domains = []string{"laptop.local", "daemon.local"}
		case "phone":
			domains = []string{"phone.local", "termux.local"}
		}
	}
	if len(domains) == 0 {
		return "", false
	}

	domainSet := make(map[string]bool, len(domains))
	for _, d := range domains {
		domainSet[strings.ToLower(strings.TrimSpace(d))] = true
	}

	for _, line := range strings.Split(string(data), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := fields[0]
		if ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" {
			continue
		}
		for _, hostField := range fields[1:] {
			if domainSet[strings.ToLower(hostField)] {
				if r.probeTCP(ip, port) {
					return ip, true
				}
			}
		}
	}
	return "", false
}

func (r *Resolver) resolveFromCacheFile(peer *config.PeerConfig, port int) (string, bool) {
	paths := []string{r.CacheFilePath(peer.Name)}
	if strings.EqualFold(peer.Name, "laptop") {
		paths = append(paths, "/root/.cache/ssh-laptop-ip")
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(data))
		if ip == "" {
			continue
		}
		if r.probeTCP(ip, port) {
			return ip, true
		}
	}
	return "", false
}

func (r *Resolver) resolveFromUSBTethering(peer *config.PeerConfig, port int) (string, bool) {
	var candidates []string
	seen := make(map[string]bool)
	addCandidate := func(ip string) {
		ip = strings.TrimSpace(ip)
		if isValidIPv4(ip) && !seen[ip] {
			seen[ip] = true
			candidates = append(candidates, ip)
		}
	}

	usbIfaces := make(map[string]bool)
	if linkOut, err := r.runCmd("ip", "-br", "link"); err == nil {
		for _, line := range strings.Split(linkOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			ifName := strings.Split(fields[0], "@")[0]
			if isUSBInterfaceName(ifName) {
				usbIfaces[ifName] = true
			}
		}
	}

	usbMAC := strings.ToLower(strings.TrimSpace(peer.Discovery.USBMAC))
	if neighOut, err := r.runCmd("ip", "-4", "neigh"); err == nil {
		for _, line := range strings.Split(neighOut, "\n") {
			if isFailedNeighLine(line) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			ip := fields[0]
			dev := extractFieldAfter(fields, "dev")
			lladdr := strings.ToLower(extractFieldAfter(fields, "lladdr"))
			if (usbMAC != "" && lladdr == usbMAC) || isUSBInterfaceName(dev) || usbIfaces[dev] {
				addCandidate(ip)
			}
		}
	}

	if routeOut, err := r.runCmd("ip", "-4", "route"); err == nil {
		for _, line := range strings.Split(routeOut, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			dev := extractFieldAfter(fields, "dev")
			if !isUSBInterfaceName(dev) && !usbIfaces[dev] {
				continue
			}
			via := extractFieldAfter(fields, "via")
			if via != "" {
				addCandidate(via)
			}
		}
	}

	for _, ip := range candidates {
		if r.probeTCP(ip, port) {
			return ip, true
		}
	}
	return "", false
}

func (r *Resolver) resolveFromHotspotAndADB(peer *config.PeerConfig, port int) (string, bool) {
	var candidates []string
	seen := make(map[string]bool)
	addCandidate := func(ip string) {
		ip = strings.TrimSpace(ip)
		if isValidIPv4(ip) && !seen[ip] {
			seen[ip] = true
			candidates = append(candidates, ip)
		}
	}

	wifiMAC := strings.ToLower(strings.TrimSpace(peer.Discovery.WiFiMAC))
	usbMAC := strings.ToLower(strings.TrimSpace(peer.Discovery.USBMAC))

	if peer.Discovery.ADBNeighborLookup || wifiMAC != "" || usbMAC != "" {
		if adbOut, err := r.runCmd("adb", "shell", "ip", "neighbor"); err == nil && strings.TrimSpace(adbOut) != "" {
			lines := strings.Split(adbOut, "\n")
			for _, line := range lines {
				if isFailedNeighLine(line) {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				ip := fields[0]
				dev := extractFieldAfter(fields, "dev")
				lladdr := strings.ToLower(extractFieldAfter(fields, "lladdr"))
				if isUSBInterfaceName(dev) || (usbMAC != "" && lladdr == usbMAC) || (wifiMAC != "" && lladdr == wifiMAC) {
					addCandidate(ip)
				}
			}
		}
	}

	if routeOut, err := r.runCmd("ip", "-4", "route", "show", "default"); err == nil {
		for _, line := range strings.Split(routeOut, "\n") {
			fields := strings.Fields(line)
			if via := extractFieldAfter(fields, "via"); via != "" {
				addCandidate(via)
			}
		}
	}

	for _, ip := range candidates {
		if r.probeTCP(ip, port) {
			return ip, true
		}
	}
	return "", false
}

func (r *Resolver) resolveFromSubnetNeighbors(peer *config.PeerConfig, port int) (string, bool) {
	neighOut, err := r.runCmd("ip", "-4", "neigh")
	if err != nil {
		return "", false
	}

	wifiMAC := strings.ToLower(strings.TrimSpace(peer.Discovery.WiFiMAC))
	var prioritized []string
	var others []string
	seen := make(map[string]bool)

	for _, line := range strings.Split(neighOut, "\n") {
		if isFailedNeighLine(line) {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := fields[0]
		if !isValidIPv4(ip) || seen[ip] {
			continue
		}
		seen[ip] = true
		lladdr := strings.ToLower(extractFieldAfter(fields, "lladdr"))
		if wifiMAC != "" && lladdr == wifiMAC {
			prioritized = append(prioritized, ip)
		} else {
			others = append(others, ip)
		}
	}

	all := append(prioritized, others...)
	for _, ip := range all {
		if r.probeTCP(ip, port) {
			return ip, true
		}
	}
	return "", false
}

func (r *Resolver) probeTCP(host string, port int) bool {
	timeout := r.probeTimeout
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	if r.tcpProber != nil {
		return r.tcpProber(host, port, timeout)
	}
	return defaultTCPProber(host, port, timeout)
}

func (r *Resolver) runCmd(name string, args ...string) (string, error) {
	if r.cmdRunner != nil {
		return r.cmdRunner(name, args...)
	}
	return defaultCmdRunner(name, args...)
}

func defaultTCPProber(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func defaultCmdRunner(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func isUSBInterfaceName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.HasPrefix(n, "usb") || strings.HasPrefix(n, "rndis") || strings.HasPrefix(n, "ncm") || strings.HasPrefix(n, "enx") {
		return true
	}
	if strings.HasPrefix(n, "enp") && strings.Contains(n, "u") {
		return true
	}
	return false
}

func extractFieldAfter(fields []string, key string) string {
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == key {
			return fields[i+1]
		}
	}
	return ""
}

func isFailedNeighLine(line string) bool {
	upper := strings.ToUpper(line)
	return strings.Contains(upper, "FAILED") || strings.Contains(upper, "INCOMPLETE")
}

func isValidIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified()
}
