package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

func TestCryptoGenerateLoadSignVerify(t *testing.T) {
	hexKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if len(hexKey) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(hexKey))
	}

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "nested", "secret.key")

	keyBytes, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey create failed: %v", err)
	}
	if len(keyBytes) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(keyBytes))
	}

	loadedBytes, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey reload failed: %v", err)
	}
	if string(keyBytes) != string(loadedBytes) {
		t.Fatal("reloaded key bytes did not match created key")
	}

	payload := []byte("sysbridge-discovery-payload")
	sig := Sign(payload, keyBytes)
	if !Verify(payload, sig, keyBytes) {
		t.Fatal("Verify rejected valid HMAC-SHA256 signature")
	}
	if Verify([]byte("tampered-payload"), sig, keyBytes) {
		t.Fatal("Verify accepted tampered payload")
	}
	if Verify(payload, "deadbeef", keyBytes) {
		t.Fatal("Verify accepted invalid signature")
	}
}

func TestPacketEncodeDecodeVerify(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	pkt := &Packet{
		Type:     TypeBeacon,
		Sender:   "laptop",
		Hostname: "daemon",
		IP:       "192.168.42.10",
		SSHPort:  22,
		MoshPort: 60000,
		Nonce:    "123456789",
		Metrics: &Metrics{
			BatteryPct: 88,
			IsCharging: true,
			ActiveWS:   "1",
			LoadAvg:    "0.42 0.31 0.25",
		},
	}

	raw, err := pkt.Encode(key)
	if err != nil {
		t.Fatalf("Packet.Encode failed: %v", err)
	}

	decoded, err := DecodeAndVerify(raw, key)
	if err != nil {
		t.Fatalf("DecodeAndVerify failed: %v", err)
	}
	if decoded.Sender != "laptop" || decoded.Hostname != "daemon" || decoded.IP != "192.168.42.10" {
		t.Fatalf("unexpected decoded packet fields: %+v", decoded)
	}
	if decoded.Metrics == nil || decoded.Metrics.BatteryPct != 88 || !decoded.Metrics.IsCharging {
		t.Fatalf("unexpected decoded metrics: %+v", decoded.Metrics)
	}

	wrongKey := []byte("fedcba9876543210fedcba9876543210")
	if _, err := DecodeAndVerify(raw, wrongKey); err == nil {
		t.Fatal("expected DecodeAndVerify to fail with wrong key")
	}

	tampered := strings.Replace(string(raw), "192.168.42.10", "192.168.42.99", 1)
	if _, err := DecodeAndVerify([]byte(tampered), key); err == nil {
		t.Fatal("expected DecodeAndVerify to fail on tampered JSON")
	}
}

func TestStateStoreAtomicAndLegacyCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "peers.json")
	legacyPath := filepath.Join(tmpDir, "buddy-peer.json")

	store := NewStateStore(statePath)
	store.SetLegacyPaths(legacyPath)

	now := time.Now().Unix()
	err := store.Upsert("laptop", &PeerState{
		Status:          "online",
		PeerRole:        "laptop",
		PeerName:        "daemon",
		PeerIP:          "10.42.0.10",
		SSHPort:         22,
		MoshPort:        60000,
		LastSeenEpoch:   now,
		DiscoveryMethod: "udp_mesh",
	})
	if err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}

	legacySingle := PeerState{
		Status:        "online",
		PeerRole:      "phone",
		PeerName:      "termux",
		PeerIP:        "10.42.0.99",
		SSHPort:       8022,
		MoshPort:      60000,
		LastSeenEpoch: now,
	}
	legBytes, _ := json.Marshal(&legacySingle)
	if err := os.WriteFile(legacyPath, legBytes, 0600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	store2 := NewStateStore(statePath)
	store2.SetLegacyPaths(legacyPath)

	stLaptop, ok := store2.Get("daemon")
	if !ok || stLaptop.PeerIP != "10.42.0.10" {
		t.Fatalf("expected laptop state from multi-peer store, got %+v (ok=%v)", stLaptop, ok)
	}

	stPhone, ok := store2.Get("phone")
	if !ok || stPhone.PeerIP != "10.42.0.99" || stPhone.SSHPort != 8022 {
		t.Fatalf("expected phone state from legacy file, got %+v (ok=%v)", stPhone, ok)
	}

	_ = store2.Upsert("stale_node", &PeerState{
		Status:        "online",
		PeerRole:      "stale_node",
		PeerName:      "oldbox",
		PeerIP:        "10.0.0.50",
		SSHPort:       22,
		LastSeenEpoch: now - 45,
	})
	if stStale, ok := store2.Get("stale_node"); !ok || stStale.Status != "stale" {
		t.Fatalf("expected status 'stale', got %+v", stStale)
	}

	_ = store2.Upsert("dead_node", &PeerState{
		Status:        "online",
		PeerRole:      "dead_node",
		PeerName:      "deadbox",
		PeerIP:        "10.0.0.51",
		SSHPort:       22,
		LastSeenEpoch: now - 90,
	})
	if stDead, ok := store2.Get("dead_node"); !ok || stDead.Status != "offline" {
		t.Fatalf("expected status 'offline', got %+v", stDead)
	}
}

func TestResolverSevenStageCascade(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "peers.json")
	hostsPath := filepath.Join(tmpDir, "hosts")
	cacheDir := filepath.Join(tmpDir, "cache")

	store := NewStateStore(statePath)
	store.SetLegacyPaths()

	cfg := config.DefaultConfig()
	cfg.Mesh.StatePath = statePath

	res := NewResolver(cfg, store)
	res.hostsFile = hostsPath
	res.cacheDir = cacheDir

	var _ transport.HostResolver = res.ResolvePeerHost

	reachableIPs := map[string]bool{}
	res.tcpProber = func(host string, port int, timeout time.Duration) bool {
		return reachableIPs[fmt.Sprintf("%s:%d", host, port)]
	}

	mockOutputs := map[string]string{}
	res.cmdRunner = func(name string, args ...string) (string, error) {
		key := name + " " + strings.Join(args, " ")
		if out, ok := mockOutputs[key]; ok {
			return out, nil
		}
		return "", fmt.Errorf("no mock output for %s", key)
	}

	peer := &config.PeerConfig{
		Name:    "laptop",
		Host:    "192.0.2.10",
		Domains: []string{"laptop.local", "daemon.local"},
		SSHPort: 22,
		Discovery: config.DiscoveryHints{
			WiFiMAC:           "00:e0:29:2d:04:f8",
			USBMAC:            "1a:9a:3a:63:52:a0",
			ADBNeighborLookup: true,
		},
	}

	// Stage 1: Explicit Host
	host, port, method, err := res.ResolvePeerHost(peer)
	if err != nil || host != "192.0.2.10" || port != 22 || method != "explicit_host" {
		t.Fatalf("Stage 1 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	cachedData, err := os.ReadFile(res.CacheFilePath("laptop"))
	if err != nil || strings.TrimSpace(string(cachedData)) != "192.0.2.10" {
		t.Fatalf("Stage 1 did not persist IP cache file: %v", err)
	}
	_ = os.Remove(res.CacheFilePath("laptop"))

	// Switch to auto for Stages 2..7
	peer.Host = "auto"

	// Stage 2: Live StateStore
	_ = store.Upsert("laptop", &PeerState{
		Status:        "online",
		PeerRole:      "laptop",
		PeerName:      "daemon",
		PeerIP:        "10.10.10.2",
		SSHPort:       2222,
		LastSeenEpoch: time.Now().Unix(),
	})
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "10.10.10.2" || port != 2222 || method != "mesh_state" {
		t.Fatalf("Stage 2 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	_ = store.Save(map[string]*PeerState{})
	_ = os.Remove(res.CacheFilePath("laptop"))

	// Stage 3: /etc/hosts lookup with TCP probe
	_ = os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n10.10.10.3 laptop.local daemon.local\n"), 0644)
	reachableIPs["10.10.10.3:22"] = true
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "10.10.10.3" || port != 22 || method != "etc_hosts" {
		t.Fatalf("Stage 3 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	delete(reachableIPs, "10.10.10.3:22")

	// Stage 4: Cached IP file in ~/.cache/sysbridge/ip_<peer.Name>
	_ = os.WriteFile(res.CacheFilePath("laptop"), []byte("10.10.10.4\n"), 0600)
	reachableIPs["10.10.10.4:22"] = true
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "10.10.10.4" || method != "ip_cache" {
		t.Fatalf("Stage 4 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	delete(reachableIPs, "10.10.10.4:22")
	_ = os.Remove(res.CacheFilePath("laptop"))

	// Stage 5: USB Tethering interface inspection
	mockOutputs["ip -br link"] = "lo UNKNOWN 00:00:00:00:00:00\nrndis0 UP 1a:9a:3a:63:52:a0\n"
	mockOutputs["ip -4 neigh"] = "10.42.0.55 dev rndis0 lladdr 1a:9a:3a:63:52:a0 REACHABLE\n"
	reachableIPs["10.42.0.55:22"] = true
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "10.42.0.55" || method != "usb_tether" {
		t.Fatalf("Stage 5 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	delete(reachableIPs, "10.42.0.55:22")
	delete(mockOutputs, "ip -br link")
	delete(mockOutputs, "ip -4 neigh")
	_ = os.Remove(res.CacheFilePath("laptop"))

	// Stage 6: Wi-Fi Hotspot gateway + ADB neighbor MAC lookup
	mockOutputs["adb shell ip neighbor"] = "192.168.43.105 dev wlan0 lladdr 00:e0:29:2d:04:f8 REACHABLE\n"
	reachableIPs["192.168.43.105:22"] = true
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "192.168.43.105" || method != "hotspot_adb" {
		t.Fatalf("Stage 6 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
	delete(reachableIPs, "192.168.43.105:22")
	delete(mockOutputs, "adb shell ip neighbor")
	_ = os.Remove(res.CacheFilePath("laptop"))

	// Stage 7: Local Wi-Fi subnet neighbor table probe
	mockOutputs["ip -4 neigh"] = "192.168.1.50 dev wlan0 lladdr aa:bb:cc:dd:ee:ff STALE\n192.168.1.77 dev wlan0 lladdr 00:e0:29:2d:04:f8 REACHABLE\n"
	reachableIPs["192.168.1.77:22"] = true
	host, port, method, err = res.ResolvePeerHost(peer)
	if err != nil || host != "192.168.1.77" || method != "subnet_neigh" {
		t.Fatalf("Stage 7 failed: host=%s port=%d method=%s err=%v", host, port, method, err)
	}
}

func TestDaemonUDPBeaconAndAck(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "secret.key")
	statePath := filepath.Join(tmpDir, "peers.json")
	hostsPath := filepath.Join(tmpDir, "hosts")
	_ = os.WriteFile(hostsPath, []byte("127.0.0.1 localhost\n"), 0644)

	cfg := config.DefaultConfig()
	cfg.Mesh.SecretKeyPath = keyPath
	cfg.Mesh.StatePath = statePath
	cfg.Mesh.Role = "phone"
	cfg.Mesh.NodeName = "termux"
	cfg.Mesh.ManageEtcHosts = true
	cfg.Mesh.NetlinkBurst = false

	probeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ephemeral udp listen failed: %v", err)
	}
	port := probeConn.LocalAddr().(*net.UDPAddr).Port
	_ = probeConn.Close()

	cfg.Mesh.UDPPort = port

	store := NewStateStore(statePath)
	store.SetLegacyPaths()

	daemon, err := NewDaemon(cfg, store)
	if err != nil {
		t.Fatalf("NewDaemon failed: %v", err)
	}
	daemon.hostsPath = hostsPath

	peerSeen := make(chan *PeerState, 1)
	daemon.SetOnPeerCallback(func(st *PeerState) {
		select {
		case peerSeen <- st:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := daemon.StartAsync(ctx); err != nil {
		t.Fatalf("Daemon.StartAsync failed: %v", err)
	}
	defer daemon.Stop()

	keyBytes, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey failed: %v", err)
	}

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client udp listen failed: %v", err)
	}
	defer clientConn.Close()

	beacon := &Packet{
		Type:     TypeBeacon,
		Sender:   "laptop",
		Hostname: "daemon",
		IP:       "192.168.43.200",
		SSHPort:  22,
		MoshPort: 60000,
		Nonce:    "987654321",
	}
	encoded, err := beacon.Encode(keyBytes)
	if err != nil {
		t.Fatalf("beacon encode failed: %v", err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	if _, err := clientConn.WriteToUDP(encoded, dst); err != nil {
		t.Fatalf("send beacon failed: %v", err)
	}

	select {
	case st := <-peerSeen:
		if st.PeerIP != "192.168.43.200" || st.PeerRole != "laptop" || st.PeerName != "daemon" {
			t.Fatalf("unexpected peer state received: %+v", st)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for daemon to process UDP beacon")
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	ackBuf := make([]byte, 4096)
	n, _, err := clientConn.ReadFromUDP(ackBuf)
	if err != nil {
		t.Fatalf("expected UDP ACK from daemon: %v", err)
	}
	ackPkt, err := DecodeAndVerify(ackBuf[:n], keyBytes)
	if err != nil {
		t.Fatalf("ACK DecodeAndVerify failed: %v", err)
	}
	if ackPkt.Type != TypeAck || ackPkt.Nonce != "987654321" {
		t.Fatalf("unexpected ACK packet: %+v", ackPkt)
	}

	hostsContent, _ := os.ReadFile(hostsPath)
	if !strings.Contains(string(hostsContent), "192.168.43.200") || !strings.Contains(string(hostsContent), "laptop.local") {
		t.Fatalf("expected hosts file to be updated, got:\n%s", string(hostsContent))
	}
}
