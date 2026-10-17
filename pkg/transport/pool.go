package transport

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type HostResolver func(peer *config.PeerConfig) (host string, port int, method string, err error)

type ExecOptions struct {
	Cwd     string
	Env     map[string]string
	Sudo    bool
	Stdin   []byte
	Timeout time.Duration
}

type ExecResult struct {
	Stdout        string `json:"stdout"`
	Stderr        string `json:"stderr"`
	ExitCode      int    `json:"exit_code"`
	DurationMs    int64  `json:"duration_ms"`
	TransportUsed string `json:"transport_used"`
	ResolvedHost  string `json:"resolved_host"`
}

type MoshSessionInfo struct {
	PeerName     string `json:"peer_name"`
	Host         string `json:"host"`
	User         string `json:"user"`
	SSHPort      int    `json:"ssh_port"`
	UDPPort      int    `json:"udp_port"`
	Key          string `json:"key"`
	PredictMode  string `json:"predict_mode"`
	UDPReachable bool   `json:"udp_reachable"`
	ConnectCmd   string `json:"connect_cmd"`
}

type pooledConn struct {
	sshClient  *ssh.Client
	sftpClient *sftp.Client
	host       string
	port       int
	createdAt  time.Time
}

type Pool struct {
	mu       sync.Mutex
	cfg      *config.Config
	guard    *safety.Guard
	resolver HostResolver
	conns    map[string]*pooledConn
}

var moshConnectRegex = regexp.MustCompile(`MOSH CONNECT (\d+) ([A-Za-z0-9+/=_-]+)`)

func NewPool(cfg *config.Config, guard *safety.Guard, resolver HostResolver) *Pool {
	return &Pool{
		cfg:      cfg,
		guard:    guard,
		resolver: resolver,
		conns:    make(map[string]*pooledConn),
	}
}

func (p *Pool) SetResolver(r HostResolver) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resolver = r
}

func (p *Pool) Guard() *safety.Guard {
	return p.guard
}

func (p *Pool) Config() *config.Config {
	return p.cfg
}

func (p *Pool) ResolveTarget(peerName string) (*config.PeerConfig, string, int, string, error) {
	peer, err := p.cfg.ResolvePeer(peerName)
	if err != nil {
		return nil, "", 0, "", err
	}
	if peer.Name == "local" {
		return peer, "127.0.0.1", 0, "local", nil
	}

	p.mu.Lock()
	res := p.resolver
	p.mu.Unlock()

	if res != nil {
		host, port, method, err := res(peer)
		if err == nil && host != "" {
			if port == 0 {
				port = peer.SSHPort
			}
			return peer, host, port, method, nil
		}
	}

	if peer.Host != "" && peer.Host != "auto" {
		return peer, peer.Host, peer.SSHPort, "static_config", nil
	}

	return nil, "", 0, "", fmt.Errorf("unable to resolve IP for peer %q (host is set to auto and discovery returned no active target)", peer.Name)
}

func (p *Pool) GetSSHClient(ctx context.Context, peerName string) (*ssh.Client, *config.PeerConfig, string, error) {
	peer, host, port, _, err := p.ResolveTarget(peerName)
	if err != nil {
		return nil, nil, "", err
	}
	if peer.Name == "local" {
		return nil, peer, "127.0.0.1", fmt.Errorf("peer %q uses local execution", peer.Name)
	}

	p.mu.Lock()
	existing, ok := p.conns[peer.Name]
	if ok && existing.sshClient != nil && existing.host == host && existing.port == port {
		p.mu.Unlock()
		_, _, keepaliveErr := existing.sshClient.SendRequest("keepalive@openssh.com", true, nil)
		if keepaliveErr == nil {
			return existing.sshClient, peer, host, nil
		}
		p.invalidatePeer(peer.Name)
	} else {
		p.mu.Unlock()
	}

	clientCfg, err := buildSSHClientConfig(peer)
	if err != nil {
		return nil, peer, host, err
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 5 * time.Second}
	netConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, peer, host, fmt.Errorf("ssh tcp dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, clientCfg)
	if err != nil {
		_ = netConn.Close()
		return nil, peer, host, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	setupClientAgentForwarding(client, peer)

	p.mu.Lock()
	p.conns[peer.Name] = &pooledConn{
		sshClient: client,
		host:      host,
		port:      port,
		createdAt: time.Now(),
	}
	p.mu.Unlock()

	return client, peer, host, nil
}

func (p *Pool) GetSFTPClient(ctx context.Context, peerName string) (*sftp.Client, *config.PeerConfig, error) {
	sshClient, peer, _, err := p.GetSSHClient(ctx, peerName)
	if err != nil {
		return nil, peer, err
	}

	p.mu.Lock()
	entry := p.conns[peer.Name]
	if entry != nil && entry.sftpClient != nil {
		sftpCli := entry.sftpClient
		p.mu.Unlock()
		if _, statErr := sftpCli.Getwd(); statErr == nil {
			return sftpCli, peer, nil
		}
		_ = sftpCli.Close()
	} else {
		p.mu.Unlock()
	}

	sftpCli, err := sftp.NewClient(sshClient, sftp.MaxPacket(32768))
	if err != nil {
		return nil, peer, fmt.Errorf("sftp subsystem init on %s: %w", peer.Name, err)
	}

	p.mu.Lock()
	if entry, ok := p.conns[peer.Name]; ok {
		entry.sftpClient = sftpCli
	}
	p.mu.Unlock()

	return sftpCli, peer, nil
}

func (p *Pool) Exec(ctx context.Context, peerName string, command string, opts ExecOptions) (*ExecResult, error) {
	if err := p.guard.CheckCommand(command); err != nil {
		return nil, err
	}

	peer, host, _, _, err := p.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	if peer.Name == "local" {
		return p.execLocal(ctx, peer, command, opts)
	}

	sshClient, _, resolvedHost, err := p.GetSSHClient(ctx, peer.Name)
	if err != nil {
		return p.execSSHBinaryFallback(ctx, peer, host, command, opts)
	}

	session, err := sshClient.NewSession()
	if err != nil {
		p.invalidatePeer(peer.Name)
		return p.execSSHBinaryFallback(ctx, peer, host, command, opts)
	}
	defer session.Close()

	if opts.Sudo || peer.Sudo.Mode == "agent_forward" {
		if opts.Sudo && peer.Sudo.Mode == "disabled" {
			return nil, fmt.Errorf("sudo execution rejected: sudo.mode is 'disabled' for peer %q", peer.Name)
		}
		_ = agent.RequestAgentForwarding(session)
	}

	wrappedCmd := buildRemoteShellCommand(command, opts)

	var stdoutBuf, stderrBuf bytes.Buffer
	session.Stdout = &stdoutBuf
	session.Stderr = &stderrBuf
	if len(opts.Stdin) > 0 {
		session.Stdin = bytes.NewReader(opts.Stdin)
	}

	start := time.Now()
	runErr := make(chan error, 1)
	go func() {
		runErr <- session.Run(wrappedCmd)
	}()

	var errResult error
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = session.Close()
		return &ExecResult{
			Stdout:        stdoutBuf.String(),
			Stderr:        stderrBuf.String(),
			ExitCode:      124,
			DurationMs:    time.Since(start).Milliseconds(),
			TransportUsed: "ssh-pool",
			ResolvedHost:  resolvedHost,
		}, ctx.Err()
	case errResult = <-runErr:
	}

	exitCode := 0
	if errResult != nil {
		if exitErr, ok := errResult.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			exitCode = 1
		}
	}

	return &ExecResult{
		Stdout:        stdoutBuf.String(),
		Stderr:        stderrBuf.String(),
		ExitCode:      exitCode,
		DurationMs:    time.Since(start).Milliseconds(),
		TransportUsed: "ssh-pool",
		ResolvedHost:  resolvedHost,
	}, nil
}

func (p *Pool) StartMosh(ctx context.Context, peerName string, predictMode string) (*MoshSessionInfo, error) {
	if predictMode == "" {
		predictMode = "never"
	}
	peer, host, port, _, err := p.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	moshPortSpec := strconv.Itoa(peer.MoshPort)
	if peer.MoshPort > 0 {
		moshPortSpec = fmt.Sprintf("%d:%d", peer.MoshPort, peer.MoshPort+50)
	}

	cmd := fmt.Sprintf("mosh-server new -s -c 256 -l LANG=en_US.UTF-8 -p %s", moshPortSpec)
	res, err := p.Exec(ctx, peer.Name, cmd, ExecOptions{Timeout: 10 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("spawn mosh-server on %s: %w", peer.Name, err)
	}

	combined := res.Stdout + "\n" + res.Stderr
	matches := moshConnectRegex.FindStringSubmatch(combined)
	if len(matches) < 3 {
		return nil, fmt.Errorf("mosh-server did not return MOSH CONNECT line (is mosh installed on %s? output: %s)", peer.Name, strings.TrimSpace(combined))
	}

	udpPort, _ := strconv.Atoi(matches[1])
	key := matches[2]

	udpReachable := probeUDP(host, udpPort)
	connectCmd := fmt.Sprintf("MOSH_KEY=%s mosh-client %s %d", key, host, udpPort)

	return &MoshSessionInfo{
		PeerName:     peer.Name,
		Host:         host,
		User:         peer.User,
		SSHPort:      port,
		UDPPort:      udpPort,
		Key:          key,
		PredictMode:  predictMode,
		UDPReachable: udpReachable,
		ConnectCmd:   connectCmd,
	}, nil
}

func (p *Pool) ProbeTCP(host string, port int, timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for name, entry := range p.conns {
		if entry.sftpClient != nil {
			_ = entry.sftpClient.Close()
		}
		if entry.sshClient != nil {
			_ = entry.sshClient.Close()
		}
		delete(p.conns, name)
	}
	return nil
}

func (p *Pool) invalidatePeer(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry, ok := p.conns[name]; ok {
		if entry.sftpClient != nil {
			_ = entry.sftpClient.Close()
		}
		if entry.sshClient != nil {
			_ = entry.sshClient.Close()
		}
		delete(p.conns, name)
	}
}

func (p *Pool) execLocal(ctx context.Context, peer *config.PeerConfig, command string, opts ExecOptions) (*ExecResult, error) {
	wrapped := buildRemoteShellCommand(command, opts)
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", wrapped)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if len(opts.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	}

	start := time.Now()
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return &ExecResult{
		Stdout:        stdoutBuf.String(),
		Stderr:        stderrBuf.String(),
		ExitCode:      exitCode,
		DurationMs:    time.Since(start).Milliseconds(),
		TransportUsed: "local-exec",
		ResolvedHost:  "127.0.0.1",
	}, nil
}

func (p *Pool) execSSHBinaryFallback(ctx context.Context, peer *config.PeerConfig, host string, command string, opts ExecOptions) (*ExecResult, error) {
	if opts.Sudo && peer.Sudo.Mode == "disabled" {
		return nil, fmt.Errorf("sudo execution rejected: sudo.mode is 'disabled' for peer %q", peer.Name)
	}

	args := []string{
		"-p", strconv.Itoa(peer.SSHPort),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=8",
		"-o", "ServerAliveInterval=5",
	}
	if opts.Sudo || peer.Sudo.Mode == "agent_forward" {
		args = append(args, "-A")
	}
	if keyFile := resolveIdentityFile(peer); keyFile != "" {
		args = append(args, "-i", keyFile)
	}
	args = append(args, fmt.Sprintf("%s@%s", peer.User, host), buildRemoteShellCommand(command, opts))

	cmd := exec.CommandContext(ctx, "ssh", args...)
	if sock := resolveAgentSock(peer); sock != "" {
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if len(opts.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(opts.Stdin)
	}

	start := time.Now()
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return nil, fmt.Errorf("ssh fallback to %s@%s failed: %w (%s)", peer.User, host, err, strings.TrimSpace(stderrBuf.String()))
		}
	}

	return &ExecResult{
		Stdout:        stdoutBuf.String(),
		Stderr:        stderrBuf.String(),
		ExitCode:      exitCode,
		DurationMs:    time.Since(start).Milliseconds(),
		TransportUsed: "ssh-cli-fallback",
		ResolvedHost:  host,
	}, nil
}

func buildRemoteShellCommand(command string, opts ExecOptions) string {
	var b strings.Builder
	for k, v := range opts.Env {
		if isValidEnvKey(k) {
			b.WriteString(fmt.Sprintf("export %s=%s; ", k, shellQuote(v)))
		}
	}
	if opts.Cwd != "" {
		b.WriteString(fmt.Sprintf("cd %s && ", shellQuote(opts.Cwd)))
	}
	if opts.Sudo {
		b.WriteString("sudo -n -E /bin/sh -c ")
		b.WriteString(shellQuote(command))
	} else {
		b.WriteString(command)
	}
	return b.String()
}

func setupClientAgentForwarding(client *ssh.Client, peer *config.PeerConfig) {
	if peer == nil || peer.Sudo.Mode == "disabled" {
		return
	}
	keyring := agent.NewKeyring()
	added := 0
	if keyFile := resolveIdentityFile(peer); keyFile != "" {
		if keyData, err := os.ReadFile(keyFile); err == nil {
			if rawKey, pErr := ssh.ParseRawPrivateKey(keyData); pErr == nil {
				if addErr := keyring.Add(agent.AddedKey{PrivateKey: rawKey}); addErr == nil {
					added++
				}
			}
		}
	}
	if added > 0 {
		_ = agent.ForwardToAgent(client, keyring)
		return
	}
	if sockPath := resolveAgentSock(peer); sockPath != "" {
		_ = agent.ForwardToRemote(client, sockPath)
	}
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isValidEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if i == 0 && !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_') {
			return false
		}
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func resolveAgentSock(peer *config.PeerConfig) string {
	if peer.Auth.SSHAgentSock != "" {
		expanded := config.ExpandPath(peer.Auth.SSHAgentSock)
		if info, err := os.Stat(expanded); err == nil && info.Mode()&os.ModeSocket != 0 {
			return expanded
		}
	}
	if envSock := os.Getenv("SSH_AUTH_SOCK"); envSock != "" {
		if info, err := os.Stat(envSock); err == nil && info.Mode()&os.ModeSocket != 0 {
			return envSock
		}
	}
	return ""
}

func resolveIdentityFile(peer *config.PeerConfig) string {
	candidates := []string{}
	if peer.Auth.IdentityFile != "" {
		candidates = append(candidates, config.ExpandPath(peer.Auth.IdentityFile))
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "scalingo_account3"),
			filepath.Join(home, ".ssh", "id_rsa"),
		)
	}
	candidates = append(candidates,
		"/root/.ssh/id_ed25519",
		"/root/.ssh/scalingo_account3",
		"/home/akash/.ssh/scalingo_account3",
		"/home/akash/.ssh/id_ed25519",
	)
	for _, c := range candidates {
		if c != "" {
			if info, err := os.Stat(c); err == nil && !info.IsDir() {
				return c
			}
		}
	}
	return ""
}

func buildSSHClientConfig(peer *config.PeerConfig) (*ssh.ClientConfig, error) {
	var authMethods []ssh.AuthMethod

	if sock := resolveAgentSock(peer); sock != "" {
		if conn, err := net.Dial("unix", sock); err == nil {
			agentClient := agent.NewClient(conn)
			if signers, sErr := agentClient.Signers(); sErr == nil && len(signers) > 0 {
				authMethods = append(authMethods, ssh.PublicKeys(signers...))
			}
		}
	}

	if keyFile := resolveIdentityFile(peer); keyFile != "" {
		if keyData, err := os.ReadFile(keyFile); err == nil {
			if signer, pErr := ssh.ParsePrivateKey(keyData); pErr == nil {
				authMethods = append(authMethods, ssh.PublicKeys(signer))
			}
		}
	}

	if peer.Auth.PasswordEnv != "" {
		if pw := os.Getenv(peer.Auth.PasswordEnv); pw != "" {
			authMethods = append(authMethods, ssh.Password(pw))
		}
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no usable SSH credentials found for peer %q (checked agent socket and identity_file)", peer.Name)
	}

	return &ssh.ClientConfig{
		User:            peer.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         8 * time.Second,
	}, nil
}

func probeUDP(host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, 1*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
