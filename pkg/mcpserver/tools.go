package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/discovery"
	"github.com/0xOpCode/sysbridge-mcp/pkg/runner"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	syncpkg "github.com/0xOpCode/sysbridge-mcp/pkg/sync"
	"github.com/0xOpCode/sysbridge-mcp/pkg/sysinfo"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
	"github.com/0xOpCode/sysbridge-mcp/pkg/tunnel"
	"github.com/0xOpCode/sysbridge-mcp/pkg/vfs"
)

type EngineSuite struct {
	Config     *config.Config
	Guard      *safety.Guard
	Store      *discovery.StateStore
	Resolver   *discovery.Resolver
	Pool       *transport.Pool
	VFS        *vfs.Engine
	Runner     *runner.Manager
	Tunnel     *tunnel.Supervisor
	Sync       *syncpkg.Engine
	SysBridge  *sysinfo.Bridge
	ConfigPath string
}

func NewEngineSuite(cfg *config.Config, cfgPath string) *EngineSuite {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	guard := safety.NewGuard(cfg.Safety.BlockedDevices, cfg.Safety.BlockedPaths, cfg.Safety.ConfirmDestructive)
	store := discovery.NewStateStore(cfg.Mesh.StatePath)
	resolver := discovery.NewResolver(cfg, store)
	pool := transport.NewPool(cfg, guard, resolver.ResolvePeerHost)

	return &EngineSuite{
		Config:     cfg,
		Guard:      guard,
		Store:      store,
		Resolver:   resolver,
		Pool:       pool,
		VFS:        vfs.NewEngine(pool),
		Runner:     runner.NewManager(pool, cfg),
		Tunnel:     tunnel.NewSupervisor(pool),
		Sync:       syncpkg.NewEngine(pool),
		SysBridge:  sysinfo.NewBridge(pool, cfg),
		ConfigPath: cfgPath,
	}
}

func (e *EngineSuite) Close() {
	if e.Tunnel != nil {
		e.Tunnel.Close()
	}
	if e.Pool != nil {
		_ = e.Pool.Close()
	}
}

func RegisterAll(srv *Server, suite *EngineSuite) {
	registerPeerTools(srv, suite)
	registerVFSTools(srv, suite)
	registerComputeTools(srv, suite)
	registerNetworkTools(srv, suite)
	registerSystemTools(srv, suite)
	registerResourcesAndPrompts(srv, suite)
}

func registerPeerTools(srv *Server, suite *EngineSuite) {
	srv.RegisterTool(ToolDefinition{
		Name:        "peer_list",
		Description: "List configured and discovered remote peers, active default peer, IP resolution method, VFS backend tier, and sudo mode.",
		Annotations: ToolAnnotations{Title: "List Peers", ReadOnlyHint: true, IdempotentHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"probe": map[string]any{
					"type":        "boolean",
					"description": "Probe TCP SSH port reachability and measure RTT latency for each peer.",
				},
			},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		doProbe := boolArg(args, "probe", false)
		discovered, _ := suite.Store.Load()

		type peerSummary struct {
			Name            string               `json:"name"`
			IsDefault       bool                 `json:"is_default"`
			ConfiguredHost  string               `json:"configured_host"`
			ResolvedHost    string               `json:"resolved_host,omitempty"`
			ResolutionStage string               `json:"resolution_stage,omitempty"`
			User            string               `json:"user"`
			SSHPort         int                  `json:"ssh_port"`
			MoshPort        int                  `json:"mosh_port"`
			SudoMode        string               `json:"sudo_mode"`
			VFSBackend      string               `json:"vfs_backend"`
			WorkspaceRoot   string               `json:"workspace_root"`
			Reachable       *bool                `json:"reachable,omitempty"`
			RTTMs           float64              `json:"rtt_ms,omitempty"`
			MeshState       *discovery.PeerState `json:"mesh_state,omitempty"`
		}

		var list []peerSummary
		for name, p := range suite.Config.Peers {
			item := peerSummary{
				Name:           name,
				IsDefault:      name == suite.Config.DefaultPeer,
				ConfiguredHost: p.Host,
				User:           p.User,
				SSHPort:        p.SSHPort,
				MoshPort:       p.MoshPort,
				SudoMode:       p.Sudo.Mode,
				VFSBackend:     p.VFS.Backend,
				WorkspaceRoot:  p.VFS.WorkspaceRoot,
			}
			if st, ok := suite.Store.Get(name); ok {
				item.MeshState = st
			}
			if _, host, port, method, err := suite.Pool.ResolveTarget(name); err == nil {
				item.ResolvedHost = host
				item.ResolutionStage = method
				if doProbe && host != "" && port > 0 {
					rtt, pErr := suite.Pool.ProbeTCP(host, port, 1200*time.Millisecond)
					okReach := pErr == nil
					item.Reachable = &okReach
					if pErr == nil {
						item.RTTMs = float64(rtt.Microseconds()) / 1000.0
					}
				}
			}
			list = append(list, item)
		}

		return TextResult(map[string]any{
			"default_peer":     suite.Config.DefaultPeer,
			"configured_peers": list,
			"mesh_peers":       discovered,
		}), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "peer_connect",
		Description: "Test connection to a peer, switch the default active peer, or register/update a remote SSH/VPS peer at runtime.",
		Annotations: ToolAnnotations{Title: "Connect or Register Peer", IdempotentHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":           map[string]any{"type": "string", "description": "Peer name (e.g. laptop, phone, vps, local)."},
				"host":           map[string]any{"type": "string", "description": "IP, hostname, or 'auto' for 7-stage discovery."},
				"user":           map[string]any{"type": "string", "description": "SSH login user."},
				"ssh_port":       map[string]any{"type": "integer", "description": "SSH port (default 22)."},
				"mosh_port":      map[string]any{"type": "integer", "description": "Mosh UDP start port (default 60000)."},
				"identity_file":  map[string]any{"type": "string", "description": "Path to private SSH key."},
				"sudo_mode":      map[string]any{"type": "string", "description": "disabled | agent_forward."},
				"workspace_root": map[string]any{"type": "string", "description": "Default remote workspace root path."},
				"set_default":    map[string]any{"type": "boolean", "description": "Set this peer as the active default peer."},
				"save_config":    map[string]any{"type": "boolean", "description": "Persist updated peer configuration to disk."},
			},
			"required": []string{"peer"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peerName := strArg(args, "peer", "")
		if peerName == "" {
			return nil, fmt.Errorf("peer name is required")
		}

		existing, err := suite.Config.ResolvePeer(peerName)
		if err != nil {
			existing = &config.PeerConfig{
				Name:     peerName,
				Host:     "auto",
				User:     "root",
				SSHPort:  22,
				MoshPort: 60000,
				Sudo:     config.SudoConfig{Mode: "disabled"},
				VFS:      config.VFSConfig{Backend: "auto", WorkspaceRoot: "/tmp"},
			}
		}

		if v := strArg(args, "host", ""); v != "" {
			existing.Host = v
		}
		if v := strArg(args, "user", ""); v != "" {
			existing.User = v
		}
		if v := intArg(args, "ssh_port", 0); v > 0 {
			existing.SSHPort = v
		}
		if v := intArg(args, "mosh_port", 0); v > 0 {
			existing.MoshPort = v
		}
		if v := strArg(args, "identity_file", ""); v != "" {
			existing.Auth.Method = "key"
			existing.Auth.IdentityFile = v
		}
		if v := strArg(args, "sudo_mode", ""); v != "" {
			existing.Sudo.Mode = v
		}
		if v := strArg(args, "workspace_root", ""); v != "" {
			existing.VFS.WorkspaceRoot = v
		}

		if peerName != "local" && peerName != "localhost" {
			suite.Config.UpsertPeer(existing)
		}
		if boolArg(args, "set_default", true) {
			_ = suite.Config.SetDefaultPeer(peerName)
		}
		if boolArg(args, "save_config", false) {
			_ = config.Save(suite.ConfigPath, suite.Config)
		}

		res, execErr := suite.Pool.Exec(ctx, peerName, "uname -srm && id -un && pwd", transport.ExecOptions{
			Timeout: 8 * time.Second,
		})
		if execErr != nil {
			return TextResult(map[string]any{
				"peer":         peerName,
				"default_peer": suite.Config.DefaultPeer,
				"connected":    false,
				"error":        execErr.Error(),
			}), nil
		}

		return TextResult(map[string]any{
			"peer":           peerName,
			"default_peer":   suite.Config.DefaultPeer,
			"connected":      res.ExitCode == 0,
			"resolved_host":  res.ResolvedHost,
			"transport_used": res.TransportUsed,
			"probe_output":   strings.TrimSpace(res.Stdout),
			"duration_ms":    res.DurationMs,
		}), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "peer_provision",
		Description: "Audit remote peer capabilities (sftp, tmux, mosh, rsync, pam_ssh_agent_auth) or opt-in configure user-space UDP mesh daemon or cryptographic SSH agent sudo.",
		Annotations: ToolAnnotations{Title: "Provision Peer Capabilities"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":       map[string]any{"type": "string", "description": "Target peer name (defaults to default_peer)."},
				"action":     map[string]any{"type": "string", "enum": []string{"audit", "setup_user_mesh", "setup_pam_ssh_sudo"}, "description": "Provisioning action."},
				"public_key": map[string]any{"type": "string", "description": "Authorized SSH public key line for setup_pam_ssh_sudo."},
				"apply":      map[string]any{"type": "boolean", "description": "Apply configuration on target peer (false returns dry-run commands)."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		action := strArg(args, "action", "audit")
		pubKey := strArg(args, "public_key", "")
		apply := boolArg(args, "apply", false)

		rep, err := suite.SysBridge.ProvisionPeer(ctx, peer, action, pubKey, apply)
		if err != nil {
			return nil, err
		}
		return TextResult(rep), nil
	})
}

func registerVFSTools(srv *Server, suite *EngineSuite) {
	srv.RegisterTool(ToolDefinition{
		Name:        "fs_read",
		Description: "Read a file from the target peer via the 3-tier Mountless VFS (sftp-vfs, ssh-stream, local-mount). Supports line ranges and binary/image base64 reads.",
		Annotations: ToolAnnotations{Title: "Read File (VFS)", ReadOnlyHint: true, IdempotentHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":   map[string]any{"type": "string", "description": "Target peer name (optional, uses default_peer)."},
				"path":   map[string]any{"type": "string", "description": "File path on target peer."},
				"offset": map[string]any{"type": "integer", "description": "1-based starting line number (optional)."},
				"limit":  map[string]any{"type": "integer", "description": "Maximum number of lines to read (optional)."},
			},
			"required": []string{"path"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		path := strArg(args, "path", "")
		offset := intArg(args, "offset", 0)
		limit := intArg(args, "limit", 0)

		res, err := suite.VFS.ReadFile(ctx, peer, path, offset, limit)
		if err != nil {
			return nil, err
		}
		if res.IsBinary && res.Base64Data != "" {
			ext := strings.ToLower(filepath.Ext(res.Path))
			switch ext {
			case ".png", ".jpg", ".jpeg", ".webp", ".gif":
				mime := "image/png"
				if ext == ".jpg" || ext == ".jpeg" {
					mime = "image/jpeg"
				} else if ext == ".webp" {
					mime = "image/webp"
				} else if ext == ".gif" {
					mime = "image/gif"
				}
				summary := fmt.Sprintf("Read binary image %s (%d bytes) via %s", res.Path, res.Size, res.Backend)
				return ImageAndTextResult(res.Base64Data, mime, summary), nil
			}
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "fs_write",
		Description: "Atomically create or overwrite a file on the target peer via the Mountless VFS (writes temp file, syncs, and renames).",
		Annotations: ToolAnnotations{Title: "Write File (VFS)", IdempotentHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":    map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"path":    map[string]any{"type": "string", "description": "Destination file path on target peer."},
				"content": map[string]any{"type": "string", "description": "Full text content to write."},
				"mode":    map[string]any{"type": "string", "description": "Optional octal file permissions (e.g. '0644' or '0755')."},
			},
			"required": []string{"path", "content"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		path := strArg(args, "path", "")
		content := strArg(args, "content", "")
		mode := parseOctalMode(strArg(args, "mode", ""))

		res, err := suite.VFS.WriteFile(ctx, peer, path, content, mode)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "fs_edit",
		Description: "Perform surgical exact string replacement on a remote file via VFS without shell escaping issues. Returns unified diff.",
		Annotations: ToolAnnotations{Title: "Surgical Edit File (VFS)"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":        map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"path":        map[string]any{"type": "string", "description": "File path on target peer."},
				"old_string":  map[string]any{"type": "string", "description": "Exact existing text block to replace."},
				"new_string":  map[string]any{"type": "string", "description": "Replacement text block."},
				"replace_all": map[string]any{"type": "boolean", "description": "Replace all occurrences instead of requiring a unique match."},
			},
			"required": []string{"path", "old_string", "new_string"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		path := strArg(args, "path", "")
		oldStr := strArg(args, "old_string", "")
		newStr := strArg(args, "new_string", "")
		replaceAll := boolArg(args, "replace_all", false)

		res, err := suite.VFS.EditFile(ctx, peer, path, oldStr, newStr, replaceAll)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "fs_multi_edit",
		Description: "Apply multiple sequential surgical edits to a file on the target peer in a single atomic VFS transaction.",
		Annotations: ToolAnnotations{Title: "Multi-Hunk Edit File (VFS)"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer": map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"path": map[string]any{"type": "string", "description": "File path on target peer."},
				"edits": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"old_string":  map[string]any{"type": "string"},
							"new_string":  map[string]any{"type": "string"},
							"replace_all": map[string]any{"type": "boolean"},
						},
						"required": []string{"old_string", "new_string"},
					},
				},
			},
			"required": []string{"path", "edits"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		path := strArg(args, "path", "")
		rawEdits, _ := json.Marshal(args["edits"])
		var edits []vfs.EditOp
		if err := json.Unmarshal(rawEdits, &edits); err != nil {
			return nil, fmt.Errorf("invalid edits array: %w", err)
		}

		res, err := suite.VFS.MultiEdit(ctx, peer, path, edits)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "fs_search",
		Description: "Search for files by glob pattern or search file contents by regex/query on the target peer via VFS.",
		Annotations: ToolAnnotations{Title: "Search Files & Content (VFS)", ReadOnlyHint: true, IdempotentHint: true},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":        map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"path":        map[string]any{"type": "string", "description": "Root directory to search (defaults to peer workspace_root)."},
				"query":       map[string]any{"type": "string", "description": "Content regex or substring to grep for."},
				"glob":        map[string]any{"type": "string", "description": "File glob pattern (e.g. '*.go', '**/*.ts')."},
				"max_results": map[string]any{"type": "integer", "description": "Maximum matches to return (default 100)."},
			},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		path := strArg(args, "path", "")
		query := strArg(args, "query", "")
		glob := strArg(args, "glob", "")
		maxRes := intArg(args, "max_results", 100)

		res, err := suite.VFS.Search(ctx, peer, path, query, glob, maxRes)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "fs_ops",
		Description: "Execute filesystem metadata and directory operations on the target peer: ls, tree, stat, mkdir, mv, cp, chmod, rm, sha256.",
		Annotations: ToolAnnotations{Title: "Filesystem Operations (VFS)"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":    map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"action":  map[string]any{"type": "string", "enum": []string{"ls", "tree", "stat", "mkdir", "mv", "cp", "chmod", "rm", "sha256"}, "description": "Filesystem operation."},
				"path":    map[string]any{"type": "string", "description": "Target file or directory path."},
				"dest":    map[string]any{"type": "string", "description": "Destination path for mv or cp."},
				"mode":    map[string]any{"type": "string", "description": "Octal mode for chmod or mkdir (e.g. '0755')."},
				"confirm": map[string]any{"type": "boolean", "description": "Required true when action is 'rm' and confirm_destructive is enabled."},
			},
			"required": []string{"action", "path"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		action := strArg(args, "action", "")
		path := strArg(args, "path", "")
		dest := strArg(args, "dest", "")
		mode := parseOctalMode(strArg(args, "mode", ""))
		confirm := boolArg(args, "confirm", false)

		res, err := suite.VFS.Ops(ctx, peer, action, path, dest, mode, confirm)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})
}

func registerComputeTools(srv *Server, suite *EngineSuite) {
	srv.RegisterTool(ToolDefinition{
		Name:        "exec_run",
		Description: "Run a shell command on the target peer over the warm SSH pool. Commands exceeding auto_detach_ms or with detached=true automatically detach into remote tmux or nohup so broken pipes never kill long builds.",
		Annotations: ToolAnnotations{Title: "Execute Command on Peer"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":       map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"command":    map[string]any{"type": "string", "description": "Shell command to execute."},
				"cwd":        map[string]any{"type": "string", "description": "Working directory on remote peer."},
				"env":        map[string]any{"type": "object", "description": "Environment variables map."},
				"sudo":       map[string]any{"type": "boolean", "description": "Execute with sudo (requires peer sudo.mode='agent_forward' for pam_ssh_agent_auth)."},
				"detached":   map[string]any{"type": "boolean", "description": "Immediately run detached in background tmux or nohup session."},
				"task_name":  map[string]any{"type": "string", "description": "Custom identifier for detached background task."},
				"timeout_ms": map[string]any{"type": "integer", "description": "Custom auto-detach/timeout threshold in milliseconds."},
			},
			"required": []string{"command"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		envMap := make(map[string]string)
		if rawEnv, ok := args["env"].(map[string]any); ok {
			for k, v := range rawEnv {
				envMap[k] = fmt.Sprintf("%v", v)
			}
		}
		opts := runner.RunOptions{
			Peer:      strArg(args, "peer", suite.Config.DefaultPeer),
			Command:   strArg(args, "command", ""),
			Cwd:       strArg(args, "cwd", ""),
			Env:       envMap,
			Sudo:      boolArg(args, "sudo", false),
			Detached:  boolArg(args, "detached", false),
			TaskName:  strArg(args, "task_name", ""),
			TimeoutMs: intArg(args, "timeout_ms", 0),
		}
		out, err := suite.Runner.Run(ctx, opts)
		if err != nil {
			return nil, err
		}
		return TextResult(out), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "task_control",
		Description: "Inspect and manage detached background tasks (tmux sessions or nohup jobs) on a peer: list, status, tail, send_keys, kill.",
		Annotations: ToolAnnotations{Title: "Manage Detached Tasks"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":    map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"action":  map[string]any{"type": "string", "enum": []string{"list", "status", "tail", "send_keys", "kill"}, "description": "Task management action."},
				"task_id": map[string]any{"type": "string", "description": "Task ID returned by exec_run."},
				"keys":    map[string]any{"type": "string", "description": "Keys to send when action='send_keys' (e.g. 'C-c' or 'q')."},
				"lines":   map[string]any{"type": "integer", "description": "Number of log lines to fetch for tail (default 50)."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		action := strArg(args, "action", "list")
		taskID := strArg(args, "task_id", "")
		keys := strArg(args, "keys", "")
		lines := intArg(args, "lines", 50)

		res, err := suite.Runner.TaskAction(ctx, peer, action, taskID, keys, lines)
		if err != nil {
			return nil, err
		}
		return TextResult(res), nil
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "mosh_control",
		Description: "Bootstrap a roaming Mosh UDP session on the target peer, verify UDP port reachability, and return the MOSH_KEY and connection command.",
		Annotations: ToolAnnotations{Title: "Bootstrap Mosh UDP Session"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer":         map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"predict_mode": map[string]any{"type": "string", "enum": []string{"never", "adaptive", "always"}, "description": "Mosh local echo prediction mode (default 'never')."},
			},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		predict := strArg(args, "predict_mode", "never")
		info, err := suite.Pool.StartMosh(ctx, peer, predict)
		if err != nil {
			return nil, err
		}
		return TextResult(info), nil
	})
}

func registerNetworkTools(srv *Server, suite *EngineSuite) {
	srv.RegisterTool(ToolDefinition{
		Name:        "tunnel_manage",
		Description: "Create, list, or remove persistent or RAM-only SSH port forwarding tunnels (-L local and -R reverse) in native Go.",
		Annotations: ToolAnnotations{Title: "Manage SSH Port Tunnels"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":      map[string]any{"type": "string", "enum": []string{"add", "list", "remove", "sync"}, "description": "Tunnel action."},
				"name":        map[string]any{"type": "string", "description": "Unique tunnel rule name."},
				"peer":        map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"local_port":  map[string]any{"type": "integer", "description": "Local TCP port."},
				"remote_port": map[string]any{"type": "integer", "description": "Remote TCP port."},
				"target_host": map[string]any{"type": "string", "description": "Target bind/forward host (default 127.0.0.1)."},
				"type":        map[string]any{"type": "string", "enum": []string{"local", "reverse"}, "description": "'local' (-L) or 'reverse' (-R)."},
				"temporary":   map[string]any{"type": "boolean", "description": "Store rule in ephemeral RAM directory only."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		action := strArg(args, "action", "list")
		switch action {
		case "list":
			return TextResult(map[string]any{"tunnels": suite.Tunnel.ListRules()}), nil
		case "sync":
			suite.Tunnel.SyncAll(ctx)
			return TextResult(map[string]any{"status": "synced", "tunnels": suite.Tunnel.ListRules()}), nil
		case "remove":
			name := strArg(args, "name", "")
			if err := suite.Tunnel.RemoveRule(name); err != nil {
				return nil, err
			}
			return TextResult(map[string]any{"removed": name}), nil
		case "add":
			rule := &tunnel.Rule{
				Name:       strArg(args, "name", ""),
				Peer:       strArg(args, "peer", suite.Config.DefaultPeer),
				LocalPort:  intArg(args, "local_port", 0),
				RemotePort: intArg(args, "remote_port", 0),
				TargetHost: strArg(args, "target_host", "127.0.0.1"),
				Type:       strArg(args, "type", "local"),
				Temporary:  boolArg(args, "temporary", false),
				Enabled:    true,
			}
			created, err := suite.Tunnel.AddRule(ctx, rule)
			if err != nil {
				return nil, err
			}
			return TextResult(created), nil
		default:
			return nil, fmt.Errorf("unsupported tunnel action %q", action)
		}
	})

	srv.RegisterTool(ToolDefinition{
		Name:        "sync_transfer",
		Description: "Transfer files (push/pull via SFTP/SCP), delta-sync directories (rsync/SFTP), or manage live background directory watchers.",
		Annotations: ToolAnnotations{Title: "File Transfer & Directory Sync"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"action":       map[string]any{"type": "string", "enum": []string{"push", "pull", "sync_dir", "watch_start", "watch_stop", "watch_list"}, "description": "Transfer or sync action."},
				"peer":         map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"local_path":   map[string]any{"type": "string", "description": "Local file or directory path."},
				"remote_path":  map[string]any{"type": "string", "description": "Remote file or directory path (optional for push, defaults to DownloadsDir)."},
				"delete_extra": map[string]any{"type": "boolean", "description": "Delete extraneous files on target during sync_dir."},
				"interval_sec": map[string]any{"type": "integer", "description": "Polling interval in seconds for watch_start (default 2)."},
				"watch_id":     map[string]any{"type": "string", "description": "Watch job ID for watch_stop."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		action := strArg(args, "action", "")
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		localPath := strArg(args, "local_path", "")
		remotePath := strArg(args, "remote_path", "")

		switch action {
		case "push":
			res, err := suite.Sync.PushFile(ctx, peer, localPath, remotePath)
			if err != nil {
				return nil, err
			}
			return TextResult(res), nil
		case "pull":
			res, err := suite.Sync.PullFile(ctx, peer, remotePath, localPath)
			if err != nil {
				return nil, err
			}
			return TextResult(res), nil
		case "sync_dir":
			res, err := suite.Sync.SyncDir(ctx, peer, localPath, remotePath, boolArg(args, "delete_extra", false))
			if err != nil {
				return nil, err
			}
			return TextResult(res), nil
		case "watch_start":
			id, err := suite.Sync.StartWatch(ctx, peer, localPath, remotePath, intArg(args, "interval_sec", 2))
			if err != nil {
				return nil, err
			}
			return TextResult(map[string]any{"watch_id": id, "status": "watching", "local_path": localPath, "remote_path": remotePath}), nil
		case "watch_stop":
			watchID := strArg(args, "watch_id", "")
			if err := suite.Sync.StopWatch(watchID); err != nil {
				return nil, err
			}
			return TextResult(map[string]any{"stopped": watchID}), nil
		case "watch_list":
			return TextResult(map[string]any{"active_watches": suite.Sync.ListWatches()}), nil
		default:
			return nil, fmt.Errorf("unsupported sync_transfer action %q", action)
		}
	})
}

func registerSystemTools(srv *Server, suite *EngineSuite) {
	srv.RegisterTool(ToolDefinition{
		Name:        "sys_bridge",
		Description: "Inspect remote hardware/OS telemetry, control systemd services, or drive Wayland/Sway/Android GUI (screenshots, workspaces, lockscreen, wallpaper, clipboard, notifications).",
		Annotations: ToolAnnotations{Title: "OS Telemetry, Services & Desktop Bridge"},
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer": map[string]any{"type": "string", "description": "Target peer name (optional)."},
				"action": map[string]any{
					"type": "string",
					"enum": []string{
						"telemetry",
						"service_status", "service_start", "service_stop", "service_restart", "service_logs",
						"sway_tree", "sway_workspaces", "sway_focus", "sway_exec",
						"lock_screen", "set_wallpaper", "screenshot",
						"clipboard_get", "clipboard_set", "notify",
					},
					"description": "System or desktop action to perform.",
				},
				"service":    map[string]any{"type": "string", "description": "Service unit name for service_* actions."},
				"user_scope": map[string]any{"type": "boolean", "description": "Run systemctl in --user scope (rootless)."},
				"sudo":       map[string]any{"type": "boolean", "description": "Use sudo for system-level service control."},
				"payload":    map[string]any{"type": "string", "description": "Target window criteria, wallpaper path, clipboard text, or notification message."},
			},
			"required": []string{"action"},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer := strArg(args, "peer", suite.Config.DefaultPeer)
		action := strArg(args, "action", "telemetry")

		if action == "telemetry" {
			rep, err := suite.SysBridge.CollectTelemetry(ctx, peer)
			if err != nil {
				return nil, err
			}
			return TextResult(rep), nil
		}

		if strings.HasPrefix(action, "service_") {
			svcAction := strings.TrimPrefix(action, "service_")
			svcName := strArg(args, "service", "")
			userScope := boolArg(args, "user_scope", false)
			sudo := boolArg(args, "sudo", false)
			out, err := suite.SysBridge.ServiceAction(ctx, peer, svcName, svcAction, userScope, sudo)
			if err != nil {
				return nil, err
			}
			return TextResult(map[string]any{"peer": peer, "service": svcName, "action": svcAction, "output": out}), nil
		}

		payload := strArg(args, "payload", "")
		res, err := suite.SysBridge.DesktopAction(ctx, peer, action, payload)
		if err != nil {
			return nil, err
		}
		if action == "screenshot" {
			if b64, ok := res["base64_png"].(string); ok && b64 != "" {
				mime, _ := res["mime_type"].(string)
				return ImageAndTextResult(b64, mime, fmt.Sprintf("Captured screenshot from peer %s", peer)), nil
			}
		}
		return TextResult(res), nil
	})
}

func registerResourcesAndPrompts(srv *Server, suite *EngineSuite) {
	srv.RegisterResource(ResourceDefinition{
		URI:         "sysbridge://config",
		Name:        "sysbridge-mcp Configuration",
		Description: "Active user-space configuration, peers, VFS backends, and safety blocklists.",
		MimeType:    "application/json",
	}, func(ctx context.Context, uri string) ([]ResourceContents, error) {
		b, _ := json.MarshalIndent(suite.Config, "", "  ")
		return []ResourceContents{{URI: uri, MimeType: "application/json", Text: string(b)}}, nil
	})

	srv.RegisterResource(ResourceDefinition{
		URI:         "sysbridge://peers",
		Name:        "Discovered Mesh Peers",
		Description: "Live P2P UDP mesh discovery state and peer telemetry.",
		MimeType:    "application/json",
	}, func(ctx context.Context, uri string) ([]ResourceContents, error) {
		peers, _ := suite.Store.Load()
		b, _ := json.MarshalIndent(peers, "", "  ")
		return []ResourceContents{{URI: uri, MimeType: "application/json", Text: string(b)}}, nil
	})

	srv.RegisterPrompt(PromptDefinition{
		Name:        "audit-remote-peer",
		Description: "Audit a remote workstation or VPS and recommend optimal VFS, Mosh, and sudo settings.",
		Arguments: []PromptArgument{
			{Name: "peer", Description: "Target peer name", Required: true},
		},
	}, func(ctx context.Context, args map[string]string) (string, []PromptMessage, error) {
		peer := args["peer"]
		if peer == "" {
			peer = suite.Config.DefaultPeer
		}
		promptText := fmt.Sprintf("Run `peer_connect`, `peer_provision` (action='audit'), and `sys_bridge` (action='telemetry') on peer %q. Summarize its hardware, active VFS backend, and whether tmux, mosh-server, or pam_ssh_agent_auth are available.", peer)
		return "Audit remote peer capabilities and telemetry", []PromptMessage{
			{Role: "user", Content: ContentBlock{Type: "text", Text: promptText}},
		}, nil
	})
}

func strArg(args map[string]any, key, def string) string {
	if v, ok := args[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok && v != nil {
		switch val := v.(type) {
		case int:
			return val
		case float64:
			return int(val)
		case string:
			if n, err := strconv.Atoi(val); err == nil {
				return n
			}
		}
	}
	return def
}

func boolArg(args map[string]any, key string, def bool) bool {
	if v, ok := args[key]; ok && v != nil {
		switch val := v.(type) {
		case bool:
			return val
		case string:
			return strings.EqualFold(val, "true") || val == "1"
		}
	}
	return def
}

func parseOctalMode(s string) uint32 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	val, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0
	}
	return uint32(val)
}
