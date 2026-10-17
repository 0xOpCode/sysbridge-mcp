package tunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

type Rule struct {
	Name       string `json:"name"`
	Peer       string `json:"peer"`
	LocalPort  int    `json:"local_port"`
	RemotePort int    `json:"remote_port"`
	TargetHost string `json:"target_host"`
	Type       string `json:"type"`
	Temporary  bool   `json:"temporary"`
	Enabled    bool   `json:"enabled"`
	Status     string `json:"status"`
}

type activeTunnel struct {
	rule     *Rule
	listener net.Listener
	cancel   context.CancelFunc
}

type Supervisor struct {
	mu      sync.Mutex
	pool    *transport.Pool
	tunnels map[string]*activeTunnel
}

func NewSupervisor(pool *transport.Pool) *Supervisor {
	s := &Supervisor{
		pool:    pool,
		tunnels: make(map[string]*activeTunnel),
	}
	_ = os.MkdirAll(s.persistentDir(), 0700)
	_ = os.MkdirAll(s.ramDir(), 0700)
	s.loadRulesFromDisk()
	return s
}

func (s *Supervisor) persistentDir() string {
	return filepath.Join(config.UserConfigDir(), "tunnels.d")
}

func (s *Supervisor) ramDir() string {
	return filepath.Join(config.UserRuntimeDir(), "tunnels.ram")
}

func (s *Supervisor) ruleFilePath(name string, temporary bool) string {
	safe := sanitizeRuleName(name)
	if temporary {
		return filepath.Join(s.ramDir(), safe+".json")
	}
	return filepath.Join(s.persistentDir(), safe+".json")
}

func (s *Supervisor) AddRule(ctx context.Context, rule *Rule) (*Rule, error) {
	if rule == nil {
		return nil, errors.New("tunnel rule cannot be nil")
	}

	normalized, err := s.normalizeRule(rule)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if existing, ok := s.tunnels[normalized.Name]; ok {
		s.stopTunnelLocked(existing)
		delete(s.tunnels, normalized.Name)
	}
	s.mu.Unlock()

	tun, startErr := s.startTunnel(ctx, normalized)
	if startErr != nil {
		return nil, startErr
	}

	if err := s.saveRuleFile(normalized); err != nil {
		s.mu.Lock()
		s.stopTunnelLocked(tun)
		s.mu.Unlock()
		return nil, err
	}

	s.mu.Lock()
	s.tunnels[normalized.Name] = tun
	cp := *normalized
	s.mu.Unlock()

	return &cp, nil
}

func (s *Supervisor) RemoveRule(name string) error {
	clean := strings.TrimSpace(name)
	if clean == "" {
		return errors.New("rule name is required")
	}

	s.mu.Lock()
	tun, ok := s.tunnels[clean]
	if ok {
		s.stopTunnelLocked(tun)
		delete(s.tunnels, clean)
	}
	s.mu.Unlock()

	pFile := s.ruleFilePath(clean, false)
	rFile := s.ruleFilePath(clean, true)
	errP := os.Remove(pFile)
	errR := os.Remove(rFile)

	if !ok && os.IsNotExist(errP) && os.IsNotExist(errR) {
		return fmt.Errorf("tunnel rule %q not found", clean)
	}
	return nil
}

func (s *Supervisor) ListRules() []*Rule {
	s.mu.Lock()
	defer s.mu.Unlock()

	names := make([]string, 0, len(s.tunnels))
	for name := range s.tunnels {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]*Rule, 0, len(names))
	for _, name := range names {
		cp := *s.tunnels[name].rule
		out = append(out, &cp)
	}
	return out
}

func (s *Supervisor) SyncAll(ctx context.Context) {
	s.loadRulesFromDisk()

	s.mu.Lock()
	var pending []*Rule
	for _, tun := range s.tunnels {
		if tun.rule.Enabled && tun.listener == nil {
			cp := *tun.rule
			pending = append(pending, &cp)
		}
	}
	s.mu.Unlock()

	for _, r := range pending {
		tun, err := s.startTunnel(ctx, r)
		if err != nil {
			s.mu.Lock()
			if existing, ok := s.tunnels[r.Name]; ok {
				existing.rule.Status = "error"
			}
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		if existing, ok := s.tunnels[r.Name]; ok {
			s.stopTunnelLocked(existing)
		}
		s.tunnels[r.Name] = tun
		s.mu.Unlock()
		_ = s.saveRuleFile(r)
	}
}

func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, tun := range s.tunnels {
		s.stopTunnelLocked(tun)
		delete(s.tunnels, name)
	}
}

func (s *Supervisor) normalizeRule(in *Rule) (*Rule, error) {
	r := *in
	r.Name = strings.TrimSpace(r.Name)
	r.Peer = strings.TrimSpace(r.Peer)
	if r.Peer == "" {
		if s.pool != nil && s.pool.Config() != nil && s.pool.Config().DefaultPeer != "" {
			r.Peer = s.pool.Config().DefaultPeer
		} else {
			r.Peer = "local"
		}
	}
	if r.TargetHost == "" {
		r.TargetHost = "127.0.0.1"
	}

	switch strings.ToLower(strings.TrimSpace(r.Type)) {
	case "", "local", "l", "-l":
		r.Type = "local"
	case "reverse", "r", "-r":
		r.Type = "reverse"
	default:
		return nil, fmt.Errorf("invalid tunnel type %q (expected 'local' or 'reverse')", r.Type)
	}

	if r.Type == "local" && r.RemotePort <= 0 {
		return nil, errors.New("remote_port must be positive for local tunnel")
	}
	if r.Type == "reverse" && r.LocalPort <= 0 {
		return nil, errors.New("local_port must be positive for reverse tunnel")
	}

	if r.Name == "" {
		r.Name = fmt.Sprintf("%s_%s_%d_%d", sanitizeRuleName(r.Peer), r.Type, r.LocalPort, r.RemotePort)
	}
	r.Enabled = true
	return &r, nil
}

func (s *Supervisor) startTunnel(ctx context.Context, rule *Rule) (*activeTunnel, error) {
	tunCtx, cancel := context.WithCancel(context.Background())

	if rule.Type == "local" {
		bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.LocalPort))
		ln, err := net.Listen("tcp", bindAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen local %s: %w", bindAddr, err)
		}
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			rule.LocalPort = tcpAddr.Port
		}
		rule.Status = "active"

		tun := &activeTunnel{
			rule:     rule,
			listener: ln,
			cancel:   cancel,
		}
		go s.serveLocalForward(tunCtx, ln, rule)
		return tun, nil
	}

	isLocalPeer := rule.Peer == "local" || rule.Peer == "localhost"
	if !isLocalPeer && s.pool != nil {
		if peerCfg, _, _, _, err := s.pool.ResolveTarget(rule.Peer); err == nil && peerCfg.Name == "local" {
			isLocalPeer = true
		}
	}

	if isLocalPeer {
		bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.RemotePort))
		ln, err := net.Listen("tcp", bindAddr)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("listen reverse local %s: %w", bindAddr, err)
		}
		if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
			rule.RemotePort = tcpAddr.Port
		}
		rule.Status = "active"
		tun := &activeTunnel{
			rule:     rule,
			listener: ln,
			cancel:   cancel,
		}
		go s.serveReverseForward(tunCtx, ln, rule)
		return tun, nil
	}

	if s.pool == nil {
		rule.Status = "pending"
		return &activeTunnel{rule: rule, cancel: cancel}, nil
	}

	sshClient, _, _, err := s.pool.GetSSHClient(ctx, rule.Peer)
	if err != nil {
		rule.Status = "pending"
		return &activeTunnel{rule: rule, cancel: cancel}, nil
	}

	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.RemotePort))
	remoteLn, err := sshClient.Listen("tcp", bindAddr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("remote ssh listen %s on %s: %w", bindAddr, rule.Peer, err)
	}
	if tcpAddr, ok := remoteLn.Addr().(*net.TCPAddr); ok && rule.RemotePort == 0 {
		rule.RemotePort = tcpAddr.Port
	}
	rule.Status = "active"

	tun := &activeTunnel{
		rule:     rule,
		listener: remoteLn,
		cancel:   cancel,
	}
	go s.serveReverseForward(tunCtx, remoteLn, rule)
	return tun, nil
}

func (s *Supervisor) serveLocalForward(ctx context.Context, ln net.Listener, rule *Rule) {
	targetAddr := net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.RemotePort))
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		go func(src net.Conn) {
			defer src.Close()
			dst, dialErr := s.dialRemoteOrLocal(ctx, rule.Peer, targetAddr)
			if dialErr != nil {
				return
			}
			defer dst.Close()
			pipeConns(src, dst)
		}(conn)
	}
}

func (s *Supervisor) serveReverseForward(ctx context.Context, ln net.Listener, rule *Rule) {
	targetAddr := net.JoinHostPort(rule.TargetHost, strconv.Itoa(rule.LocalPort))
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}
		go func(src net.Conn) {
			defer src.Close()
			dialer := net.Dialer{Timeout: 5 * time.Second}
			dst, dialErr := dialer.DialContext(ctx, "tcp", targetAddr)
			if dialErr != nil {
				return
			}
			defer dst.Close()
			pipeConns(src, dst)
		}(conn)
	}
}

func (s *Supervisor) dialRemoteOrLocal(ctx context.Context, peerName, targetAddr string) (net.Conn, error) {
	if peerName == "local" || peerName == "localhost" || s.pool == nil {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, "tcp", targetAddr)
	}
	if peerCfg, _, _, _, err := s.pool.ResolveTarget(peerName); err == nil && peerCfg.Name == "local" {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		return dialer.DialContext(ctx, "tcp", targetAddr)
	}
	sshClient, _, _, err := s.pool.GetSSHClient(ctx, peerName)
	if err != nil {
		return nil, err
	}
	return sshClient.Dial("tcp", targetAddr)
}

func pipeConns(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

func (s *Supervisor) stopTunnelLocked(tun *activeTunnel) {
	if tun == nil {
		return
	}
	if tun.cancel != nil {
		tun.cancel()
	}
	if tun.listener != nil {
		_ = tun.listener.Close()
		tun.listener = nil
	}
	if tun.rule != nil {
		tun.rule.Status = "stopped"
	}
}

func (s *Supervisor) saveRuleFile(rule *Rule) error {
	dir := s.persistentDir()
	otherPath := s.ruleFilePath(rule.Name, true)
	if rule.Temporary {
		dir = s.ramDir()
		otherPath = s.ruleFilePath(rule.Name, false)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	_ = os.Remove(otherPath)

	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.ruleFilePath(rule.Name, rule.Temporary), data, 0600)
}

func (s *Supervisor) loadRulesFromDisk() {
	s.loadDir(s.persistentDir(), false)
	s.loadDir(s.ramDir(), true)
}

func (s *Supervisor) loadDir(dir string, temporary bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var r Rule
		if err := json.Unmarshal(data, &r); err != nil || r.Name == "" {
			continue
		}
		r.Temporary = temporary
		s.mu.Lock()
		if _, exists := s.tunnels[r.Name]; !exists {
			if r.Status == "" {
				r.Status = "stopped"
			}
			s.tunnels[r.Name] = &activeTunnel{rule: &r}
		}
		s.mu.Unlock()
	}
}

func sanitizeRuleName(name string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(name) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	res := strings.Trim(b.String(), "_")
	if res == "" {
		return "rule"
	}
	return res
}
