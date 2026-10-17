package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Transport    string `json:"transport" yaml:"transport"`
	Listen       string `json:"listen" yaml:"listen"`
	UnixSocket   string `json:"unix_socket" yaml:"unix_socket"`
	AuthTokenEnv string `json:"auth_token_env" yaml:"auth_token_env"`
	ToolProfile  string `json:"tool_profile" yaml:"tool_profile"`
}

type MeshConfig struct {
	Enabled           bool   `json:"enabled" yaml:"enabled"`
	NodeName          string `json:"node_name" yaml:"node_name"`
	Role              string `json:"role" yaml:"role"`
	UDPPort           int    `json:"udp_port" yaml:"udp_port"`
	BeaconIntervalSec int    `json:"beacon_interval_sec" yaml:"beacon_interval_sec"`
	SecretKeyPath     string `json:"secret_key_path" yaml:"secret_key_path"`
	StatePath         string `json:"state_path" yaml:"state_path"`
	ManageEtcHosts    bool   `json:"manage_etc_hosts" yaml:"manage_etc_hosts"`
	NetlinkBurst      bool   `json:"netlink_burst" yaml:"netlink_burst"`
}

type AuthConfig struct {
	Method       string `json:"method" yaml:"method"`
	IdentityFile string `json:"identity_file" yaml:"identity_file"`
	SSHAgentSock string `json:"ssh_agent_sock" yaml:"ssh_agent_sock"`
	PasswordEnv  string `json:"password_env" yaml:"password_env"`
}

type SudoConfig struct {
	Mode string `json:"mode" yaml:"mode"`
}

type VFSConfig struct {
	Backend       string `json:"backend" yaml:"backend"`
	WorkspaceRoot string `json:"workspace_root" yaml:"workspace_root"`
	DownloadsDir  string `json:"downloads_dir" yaml:"downloads_dir"`
}

type DiscoveryHints struct {
	WiFiMAC           string `json:"wifi_mac" yaml:"wifi_mac"`
	USBMAC            string `json:"usb_mac" yaml:"usb_mac"`
	ADBNeighborLookup bool   `json:"adb_neighbor_lookup" yaml:"adb_neighbor_lookup"`
}

type PeerConfig struct {
	Name      string         `json:"name" yaml:"name"`
	Host      string         `json:"host" yaml:"host"`
	Domains   []string       `json:"domains" yaml:"domains"`
	User      string         `json:"user" yaml:"user"`
	SSHPort   int            `json:"ssh_port" yaml:"ssh_port"`
	MoshPort  int            `json:"mosh_port" yaml:"mosh_port"`
	Auth      AuthConfig     `json:"auth" yaml:"auth"`
	Sudo      SudoConfig     `json:"sudo" yaml:"sudo"`
	VFS       VFSConfig      `json:"vfs" yaml:"vfs"`
	Discovery DiscoveryHints `json:"discovery_hints" yaml:"discovery_hints"`
}

type ExecutionConfig struct {
	AutoDetachMs    int    `json:"auto_detach_ms" yaml:"auto_detach_ms"`
	DetachedBackend string `json:"detached_backend" yaml:"detached_backend"`
	DefaultShell    string `json:"default_shell" yaml:"default_shell"`
	TmuxPrefix      string `json:"tmux_prefix" yaml:"tmux_prefix"`
	KeepaliveSec    int    `json:"keepalive_sec" yaml:"keepalive_sec"`
	PoolSize        int    `json:"pool_size" yaml:"pool_size"`
}

type SafetyConfig struct {
	BlockedDevices     []string `json:"blocked_devices" yaml:"blocked_devices"`
	BlockedPaths       []string `json:"blocked_paths" yaml:"blocked_paths"`
	ConfirmDestructive bool     `json:"confirm_destructive" yaml:"confirm_destructive"`
}

type AlertConfig struct {
	WaylandNotify bool   `json:"wayland_notify" yaml:"wayland_notify"`
	WebhookURLEnv string `json:"webhook_url_env" yaml:"webhook_url_env"`
	WebhookURL    string `json:"webhook_url" yaml:"webhook_url"`
}

type Config struct {
	mu          sync.RWMutex               `json:"-" yaml:"-"`
	Server      ServerConfig               `json:"server" yaml:"server"`
	Mesh        MeshConfig                 `json:"mesh" yaml:"mesh"`
	DefaultPeer string                     `json:"default_peer" yaml:"default_peer"`
	Peers       map[string]*PeerConfig     `json:"peers" yaml:"peers"`
	Execution   ExecutionConfig            `json:"execution" yaml:"execution"`
	Safety      SafetyConfig               `json:"safety" yaml:"safety"`
	Alerts      AlertConfig                `json:"alerts" yaml:"alerts"`
}

func UserConfigDir() string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "sysbridge")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/sysbridge/config"
	}
	return filepath.Join(home, ".config", "sysbridge")
}

func UserCacheDir() string {
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, "sysbridge")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "/tmp/sysbridge/cache"
	}
	return filepath.Join(home, ".cache", "sysbridge")
}

func UserRuntimeDir() string {
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		dir := filepath.Join(xdg, "sysbridge")
		if err := os.MkdirAll(dir, 0700); err == nil {
			return dir
		}
	}
	return UserCacheDir()
}

func ExpandPath(p string) string {
	if p == "" {
		return ""
	}
	if strings.HasPrefix(p, "~/") || p == "~" {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			if p == "~" {
				return home
			}
			return filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

func DefaultConfig() *Config {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "sysbridge-node"
	}

	role := "phone"
	defaultPeer := "laptop"
	if hostname == "daemon" {
		role = "laptop"
		defaultPeer = "phone"
	}

	cfgDir := UserConfigDir()
	cacheDir := UserCacheDir()
	runDir := UserRuntimeDir()

	currUser := "root"
	if u, err := user.Current(); err == nil && u.Username != "" {
		currUser = u.Username
	}

	return &Config{
		Server: ServerConfig{
			Transport:    "stdio",
			Listen:       "127.0.0.1:8787",
			UnixSocket:   filepath.Join(runDir, "sysbridge.sock"),
			AuthTokenEnv: "SYSBRIDGE_TOKEN",
			ToolProfile:  "full",
		},
		Mesh: MeshConfig{
			Enabled:           true,
			NodeName:          hostname,
			Role:              role,
			UDPPort:           42424,
			BeaconIntervalSec: 10,
			SecretKeyPath:     filepath.Join(cfgDir, "secret.key"),
			StatePath:         filepath.Join(cacheDir, "peers.json"),
			ManageEtcHosts:    false,
			NetlinkBurst:      true,
		},
		DefaultPeer: defaultPeer,
		Peers: map[string]*PeerConfig{
			"laptop": {
				Name:     "laptop",
				Host:     "auto",
				Domains:  []string{"laptop.local", "daemon.local"},
				User:     "akash",
				SSHPort:  22,
				MoshPort: 60000,
				Auth: AuthConfig{
					Method:       "key",
					IdentityFile: "~/.ssh/id_ed25519",
					SSHAgentSock: "/tmp/ssh-agent-shared.sock",
				},
				Sudo: SudoConfig{
					Mode: "agent_forward",
				},
				VFS: VFSConfig{
					Backend:       "auto",
					WorkspaceRoot: "/home/akash",
					DownloadsDir:  "/home/akash/Downloads",
				},
				Discovery: DiscoveryHints{
					WiFiMAC:           "00:e0:29:2d:04:f8",
					USBMAC:            "1a:9a:3a:63:52:a0",
					ADBNeighborLookup: true,
				},
			},
			"phone": {
				Name:     "phone",
				Host:     "auto",
				Domains:  []string{"phone.local", "termux.local"},
				User:     currUser,
				SSHPort:  8022,
				MoshPort: 60000,
				Auth: AuthConfig{
					Method:       "key",
					IdentityFile: "~/.ssh/scalingo_account3",
					SSHAgentSock: "/tmp/ssh-agent-shared.sock",
				},
				Sudo: SudoConfig{
					Mode: "disabled",
				},
				VFS: VFSConfig{
					Backend:       "auto",
					WorkspaceRoot: "/root",
					DownloadsDir:  "/sdcard/Download",
				},
			},
		},
		Execution: ExecutionConfig{
			AutoDetachMs:    5000,
			DetachedBackend: "auto",
			DefaultShell:    "/bin/sh",
			TmuxPrefix:      "sysbridge",
			KeepaliveSec:    5,
			PoolSize:        4,
		},
		Safety: SafetyConfig{
			BlockedDevices:     []string{"/dev/sda", "/dev/sda1", "/dev/sda2", "/dev/sda3", "/dev/sda4"},
			BlockedPaths:       []string{"/boot/efi"},
			ConfirmDestructive: true,
		},
		Alerts: AlertConfig{
			WaylandNotify: true,
			WebhookURLEnv: "SYSBRIDGE_WEBHOOK_URL",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if path == "" {
		yamlCandidate := filepath.Join(UserConfigDir(), "config.yaml")
		jsonCandidate := filepath.Join(UserConfigDir(), "config.json")
		if _, err := os.Stat(yamlCandidate); err == nil {
			path = yamlCandidate
		} else if _, err := os.Stat(jsonCandidate); err == nil {
			path = jsonCandidate
		}
	}

	if path != "" {
		expanded := ExpandPath(path)
		data, err := os.ReadFile(expanded)
		if err != nil {
			return nil, fmt.Errorf("read config %s: %w", expanded, err)
		}
		if strings.HasSuffix(expanded, ".json") {
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse json config: %w", err)
			}
		} else {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("parse yaml config: %w", err)
			}
		}
	}

	for name, peer := range cfg.Peers {
		if peer.Name == "" {
			peer.Name = name
		}
		if peer.SSHPort == 0 {
			peer.SSHPort = 22
		}
		if peer.MoshPort == 0 {
			peer.MoshPort = 60000
		}
		if peer.VFS.Backend == "" {
			peer.VFS.Backend = "auto"
		}
		if peer.Sudo.Mode == "" {
			peer.Sudo.Mode = "disabled"
		}
	}

	return cfg, nil
}

func Save(path string, cfg *Config) error {
	if path == "" {
		path = filepath.Join(UserConfigDir(), "config.yaml")
	}
	expanded := ExpandPath(path)
	if err := os.MkdirAll(filepath.Dir(expanded), 0700); err != nil {
		return err
	}
	var data []byte
	var err error
	if strings.HasSuffix(expanded, ".json") {
		data, err = json.MarshalIndent(cfg, "", "  ")
	} else {
		data, err = yaml.Marshal(cfg)
	}
	if err != nil {
		return err
	}
	return os.WriteFile(expanded, data, 0600)
}

func (c *Config) SetDefaultPeer(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if name == "local" || name == "localhost" {
		c.DefaultPeer = "local"
		return nil
	}
	if _, ok := c.Peers[name]; !ok {
		return fmt.Errorf("unknown peer %q", name)
	}
	c.DefaultPeer = name
	return nil
}

func (c *Config) UpsertPeer(peer *PeerConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Peers == nil {
		c.Peers = make(map[string]*PeerConfig)
	}
	if peer.SSHPort == 0 {
		peer.SSHPort = 22
	}
	if peer.MoshPort == 0 {
		peer.MoshPort = 60000
	}
	if peer.VFS.Backend == "" {
		peer.VFS.Backend = "auto"
	}
	if peer.Sudo.Mode == "" {
		peer.Sudo.Mode = "disabled"
	}
	c.Peers[peer.Name] = peer
}

func (c *Config) ResolvePeer(name string) (*PeerConfig, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if name == "" {
		name = c.DefaultPeer
	}
	if name == "local" || name == "localhost" {
		home, _ := os.UserHomeDir()
		currUser := "user"
		if u, err := user.Current(); err == nil {
			currUser = u.Username
		}
		return &PeerConfig{
			Name:    "local",
			Host:    "127.0.0.1",
			User:    currUser,
			SSHPort: 22,
			Sudo:    SudoConfig{Mode: "disabled"},
			VFS: VFSConfig{
				Backend:       "local-mount",
				WorkspaceRoot: home,
				DownloadsDir:  filepath.Join(home, "Downloads"),
			},
		}, nil
	}

	if p, ok := c.Peers[name]; ok {
		return p, nil
	}

	for _, p := range c.Peers {
		for _, dom := range p.Domains {
			if strings.EqualFold(dom, name) {
				return p, nil
			}
		}
	}

	return nil, fmt.Errorf("peer %q not found in configuration", name)
}
