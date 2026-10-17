package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
)

const (
	ProtocolVersion = 1
	DefaultPort     = 42424
	TypeBeacon      = "BEACON"
	TypeAck         = "ACK"
	TypeHeartbeat   = "HEARTBEAT"
)

type Metrics struct {
	BatteryPct int    `json:"battery_pct,omitempty"`
	IsCharging bool   `json:"is_charging,omitempty"`
	ActiveWS   string `json:"active_workspace,omitempty"`
	LoadAvg    string `json:"load_avg,omitempty"`
}

type Packet struct {
	Version   int      `json:"v"`
	Type      string   `json:"t"`
	Sender    string   `json:"sender"`
	Hostname  string   `json:"hostname"`
	IP        string   `json:"ip"`
	SSHPort   int      `json:"ssh_port"`
	MoshPort  int      `json:"mosh_port"`
	Timestamp int64    `json:"ts"`
	Nonce     string   `json:"nonce"`
	Metrics   *Metrics `json:"metrics,omitempty"`
	Signature string   `json:"sig,omitempty"`
}

func (p *Packet) Encode(key []byte) ([]byte, error) {
	cp := *p
	cp.Version = ProtocolVersion
	if cp.Timestamp == 0 {
		cp.Timestamp = time.Now().Unix()
	}
	cp.Signature = ""

	raw, err := json.Marshal(&cp)
	if err != nil {
		return nil, err
	}

	cp.Signature = Sign(raw, key)
	p.Version = cp.Version
	p.Timestamp = cp.Timestamp
	p.Signature = cp.Signature
	return json.Marshal(&cp)
}

func DecodeAndVerify(data []byte, key []byte) (*Packet, error) {
	var p Packet
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid packet json: %w", err)
	}

	receivedSig := p.Signature
	if receivedSig == "" {
		return nil, fmt.Errorf("missing packet signature")
	}

	p.Signature = ""
	raw, err := json.Marshal(&p)
	if err != nil {
		return nil, fmt.Errorf("canonicalize packet: %w", err)
	}

	if !Verify(raw, receivedSig, key) {
		return nil, fmt.Errorf("signature verification failed")
	}

	p.Signature = receivedSig
	return &p, nil
}

type PeerState struct {
	Status          string   `json:"status"`
	PeerRole        string   `json:"peer_role"`
	PeerName        string   `json:"peer_name"`
	PeerIP          string   `json:"peer_ip"`
	SSHPort         int      `json:"ssh_port"`
	MoshPort        int      `json:"mosh_port"`
	LastSeenSecAgo  int64    `json:"last_seen_sec_ago"`
	LastSeenEpoch   int64    `json:"last_seen_epoch"`
	RTTMs           float64  `json:"rtt_ms,omitempty"`
	DiscoveryMethod string   `json:"discovery_method,omitempty"`
	Metrics         *Metrics `json:"metrics,omitempty"`
}

func FormatHumanDuration(sec int64) string {
	if sec < 5 {
		return "Just now"
	}
	if sec < 60 {
		return fmt.Sprintf("%ds ago", sec)
	}
	minutes := sec / 60
	remSec := sec % 60
	if minutes < 60 {
		if remSec == 0 {
			return fmt.Sprintf("%dm ago", minutes)
		}
		return fmt.Sprintf("%dm %ds ago", minutes, remSec)
	}
	hours := minutes / 60
	remMin := minutes % 60
	return fmt.Sprintf("%dh %dm ago", hours, remMin)
}

type StateStore struct {
	mu          sync.RWMutex
	path        string
	legacyPaths []string
	peers       map[string]*PeerState
}

func NewStateStore(path string) *StateStore {
	expanded := config.ExpandPath(path)
	if expanded == "" {
		expanded = filepath.Join(config.UserCacheDir(), "peers.json")
	}
	return &StateStore{
		path:        expanded,
		legacyPaths: []string{"/run/buddy-peer.json", "/tmp/buddy-peer.json"},
		peers:       make(map[string]*PeerState),
	}
}

func (s *StateStore) Path() string {
	return s.path
}

func (s *StateStore) SetLegacyPaths(paths ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.legacyPaths = append([]string(nil), paths...)
}

func (s *StateStore) Upsert(key string, st *PeerState) error {
	if st == nil {
		return fmt.Errorf("nil peer state")
	}
	s.mu.Lock()
	if s.peers == nil {
		s.peers = make(map[string]*PeerState)
	}
	if key == "" {
		if st.PeerRole != "" {
			key = st.PeerRole
		} else {
			key = st.PeerName
		}
	}
	cp := *st
	refreshPeerLiveness(&cp, time.Now().Unix())
	s.peers[key] = &cp
	snapshot := copyPeerMap(s.peers)
	s.mu.Unlock()

	return s.writeAtomic(snapshot)
}

func (s *StateStore) Save(peers map[string]*PeerState) error {
	now := time.Now().Unix()
	s.mu.Lock()
	s.peers = make(map[string]*PeerState, len(peers))
	for k, v := range peers {
		if v == nil {
			continue
		}
		cp := *v
		refreshPeerLiveness(&cp, now)
		s.peers[k] = &cp
	}
	snapshot := copyPeerMap(s.peers)
	s.mu.Unlock()

	return s.writeAtomic(snapshot)
}

func (s *StateStore) writeAtomic(peers map[string]*PeerState) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state dir %s: %w", dir, err)
	}

	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}

	tmpFile := fmt.Sprintf("%s.tmp.%d", s.path, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	if err := os.Rename(tmpFile, s.path); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	return nil
}

func (s *StateStore) Load() (map[string]*PeerState, error) {
	now := time.Now().Unix()

	s.mu.RLock()
	primaryPath := s.path
	legacyPaths := append([]string(nil), s.legacyPaths...)
	memPeers := copyPeerMap(s.peers)
	s.mu.RUnlock()

	merged := make(map[string]*PeerState)
	for k, v := range memPeers {
		refreshPeerLiveness(v, now)
		merged[k] = v
	}

	if diskPeers, err := parseStateFile(primaryPath, now); err == nil {
		for k, v := range diskPeers {
			mergePeerEntry(merged, k, v)
		}
	}

	for _, lp := range legacyPaths {
		if lp == "" {
			continue
		}
		if legPeers, err := parseStateFile(lp, now); err == nil {
			for k, v := range legPeers {
				mergePeerEntry(merged, k, v)
			}
		}
	}

	s.mu.Lock()
	s.peers = copyPeerMap(merged)
	s.mu.Unlock()

	return merged, nil
}

func (s *StateStore) Get(nameOrRole string) (*PeerState, bool) {
	target := strings.TrimSpace(nameOrRole)
	if target == "" {
		return nil, false
	}

	peers, _ := s.Load()
	if st, ok := peers[target]; ok && st != nil {
		return st, true
	}

	for k, st := range peers {
		if st == nil {
			continue
		}
		if strings.EqualFold(k, target) || strings.EqualFold(st.PeerName, target) || strings.EqualFold(st.PeerRole, target) {
			return st, true
		}
	}
	return nil, false
}

func parseStateFile(path string, now int64) (map[string]*PeerState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	out := make(map[string]*PeerState)

	var multi map[string]*PeerState
	if err := json.Unmarshal(data, &multi); err == nil && len(multi) > 0 {
		validMulti := false
		for k, v := range multi {
			if v != nil && (v.PeerIP != "" || v.PeerName != "" || v.PeerRole != "" || v.Status != "") {
				validMulti = true
				cp := *v
				refreshPeerLiveness(&cp, now)
				out[k] = &cp
			}
		}
		if validMulti {
			return out, nil
		}
	}

	var single PeerState
	if err := json.Unmarshal(data, &single); err != nil {
		return nil, err
	}
	if single.PeerIP == "" && single.PeerName == "" && single.PeerRole == "" {
		return nil, fmt.Errorf("empty peer state in %s", path)
	}

	refreshPeerLiveness(&single, now)
	key := single.PeerRole
	if key == "" {
		key = single.PeerName
	}
	if key == "" {
		key = "peer"
	}
	out[key] = &single
	return out, nil
}

func mergePeerEntry(dst map[string]*PeerState, key string, candidate *PeerState) {
	if candidate == nil {
		return
	}
	existing, ok := dst[key]
	if !ok || existing == nil || candidate.LastSeenEpoch >= existing.LastSeenEpoch {
		cp := *candidate
		dst[key] = &cp
	}
}

func refreshPeerLiveness(st *PeerState, now int64) {
	if st == nil {
		return
	}
	if st.LastSeenEpoch > 0 {
		secAgo := now - st.LastSeenEpoch
		if secAgo < 0 {
			secAgo = 0
		}
		st.LastSeenSecAgo = secAgo
		switch {
		case secAgo > 60:
			st.Status = "offline"
		case secAgo > 30:
			st.Status = "stale"
		default:
			if st.Status == "" {
				st.Status = "online"
			}
		}
	}
}

func copyPeerMap(in map[string]*PeerState) map[string]*PeerState {
	out := make(map[string]*PeerState, len(in))
	for k, v := range in {
		if v != nil {
			cp := *v
			if v.Metrics != nil {
				m := *v.Metrics
				cp.Metrics = &m
			}
			out[k] = &cp
		}
	}
	return out
}
