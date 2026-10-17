# sysbridge-mcp Developer Notes & Architecture Plan

`sysbridge-mcp` is a single-binary Model Context Protocol (MCP) server and Go SDK that bridges AI agents to remote Linux workstations, VPS instances, and Android/Termux nodes over SSH, SFTP, Mosh, and an optional UDP P2P mesh.

---

## 1. Design Mandates

1. **Zero-Install Remote Default (Tier 0):** Target hosts require only a standard OpenSSH daemon (`sshd`). No binary, agent, or root access is required on the remote machine for filesystem operations, command execution, or port forwarding.
2. **Rootless / Non-Sudo Operation:** Both the local MCP host (including Android Termux / PRoot) and the remote target operate under unprivileged user accounts by default. All state, keys, sockets, and caches reside in user-space XDG paths.
3. **Mountless Virtual Filesystem (Termux Safe):** Kernel FUSE (`sshfs`) is unavailable on unprivileged Android Termux and container environments. `sysbridge-mcp` exposes a unified MCP filesystem toolset backed by an in-memory Go SFTP Virtual Filesystem (`sftp-vfs`) with automatic fallback to raw SSH byte-stream primitives (`ssh-stream`).
4. **Opt-In Cryptographic Sudo (`pam_ssh_agent_auth`):** When privileged execution is requested by the user, `sysbridge-mcp` supports SSH Agent socket forwarding into the remote session so `pam_ssh_agent_auth` authenticates `sudo` via cryptographic key challenge without storing passwords or enabling global `NOPASSWD`.
5. **Progressive Peer Provisioning:** Advanced capabilities (`buddy-link` bidirectional UDP mesh, `mosh-server`, `tmux` task persistence, and `pam_ssh_agent_auth` setup) are modular opt-in upgrades triggered via the `peer_provision` tool.

---

## 2. Virtual Filesystem (VFS) Abstraction (`pkg/vfs`)

The agent interacts with a single set of filesystem tools (`fs_read`, `fs_write`, `fs_edit`, `fs_multi_edit`, `fs_list`, `fs_glob`, `fs_grep`, `fs_ops`). The MCP server selects the transport backend transparently per peer:

| Tier | Backend Driver | Mechanism | When Used |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Default)** | `sftp-vfs` | Multiplexed `github.com/pkg/sftp` over warm `golang.org/x/crypto/ssh` connection pool | Default on all SSH targets (VPS, PC, Laptop, Termux). Zero kernel mount required. |
| **Tier 2 (Fallback)** | `ssh-stream` | POSIX shell/python byte-range readers, atomic temp-file writes, and `sha256sum` verification over SSH `exec` channel | Automatic fallback when remote `sshd_config` disables the SFTP subsystem. |
| **Tier 3 (Optional)** | `local-mount` | Direct `os.*` syscalls on an existing local path or optional user-space `sshfs` mount | When target path is already mounted or running in local-host mode. |

### VFS Guarantees
- **Atomic Writes:** Writes stream to `<target>.sysbridge.tmp.<nonce>`, flush to disk, preserve existing `chmod` bits, and execute an atomic POSIX `rename`.
- **Surgical Edits:** `fs_edit` reads the target file into Go memory via SFTP, verifies exact match uniqueness, applies replacements, writes atomically, and returns a unified diff alongside the active VFS backend label.
- **Remote Search:** `fs_grep` and `fs_glob` detect remote `rg` (ripgrep) or `fd`, falling back to POSIX `grep -rn` / `find`, and walk the SFTP tree directly if shell execution is restricted.

---

## 3. Rootless Execution & Optional Sudo Architecture

### 3.1 User-Space Path Layout (No Root Required)
Old `buddy-link` paths (`/etc/buddy-link`, `/run/buddy-peer.json`, `/etc/hosts`) required root privileges. `sysbridge-mcp` relocates all paths to user-space with legacy compatibility fallback:
- **Config:** `$XDG_CONFIG_HOME/sysbridge/config.yaml` (`~/.config/sysbridge/config.yaml`)
- **Mesh Key:** `~/.config/sysbridge/secret.key` (`0600`)
- **Runtime State:** `$XDG_RUNTIME_DIR/sysbridge/peers.json` (falls back to `~/.cache/sysbridge/peers.json`)
- **Tunnel Rules:** `~/.config/sysbridge/tunnels.d/` (persistent) and `~/.cache/sysbridge/tunnels.ram/` (ephemeral)
- **Internal DNS Dialer:** `sysbridge-mcp` resolves logical hostnames (`laptop.local`, `vps.local`, `phone.local`) inside its Go network dialer directly from `peers.json`. Editing `/etc/hosts` is never required for MCP operation.

### 3.2 Cryptographic Sudo Bridge (`pam_ssh_agent_auth`)
For users who want their agent to perform system administration on a remote PC/VPS without exposing sudo passwords to the LLM context or weakening local physical security with `NOPASSWD`:

1. **Mechanism:** Linux `pam_ssh_agent_auth.so` validates `sudo` requests against the forwarded `SSH_AUTH_SOCK` agent socket using a cryptographic signature from the client's private SSH key (`/etc/security/authorized_keys`).
2. **Per-Peer Sudo Modes in Config:**
   - `sudo_mode: "disabled"` (Default): Blocks or runs without privilege elevation; remote user operates strictly within standard account permissions.
   - `sudo_mode: "agent_forward"`: Attaches the local `ssh-agent` socket (`ForwardAgent`) to the SSH session channel when `sudo: true` is passed to `exec_run`, allowing `pam_ssh_agent_auth` on the remote host to verify the key signature.
   - `sudo_mode: "askpass_elicitation"`: Uses MCP Elicitation to prompt the human user for one-time approval/password if neither agent-auth nor passwordless sudo is configured.
3. **Guided Remote Setup (`peer_provision`):**
   - Can inspect whether `pam_ssh_agent_auth` is installed on the remote host (`Arch: pam_ssh_agent_auth`, `Debian/Ubuntu: libpam-ssh-agent-auth`).
   - Generates the exact `/etc/security/authorized_keys`, `/etc/sudoers.d/sysbridge-agent`, and `/etc/pam.d/sudo` snippet while keeping an open root verification session to prevent lockout.

---

## 4. Progressive Peer Tiers (Any VPS/PC vs Full Buddy-Link Mesh)

| Capability | Mode A: Standard SSH Target (Any VPS / PC) | Mode B: Mesh-Enabled Peer (`buddy-link` Daemon Active) |
| :--- | :--- | :--- |
| **Remote Installation** | None (0 files installed on remote) | Single `sysbridge` binary running `sysbridge daemon` (user-level systemd/termux service) |
| **Privileges Needed** | Standard non-root SSH user | Standard non-root SSH user |
| **Filesystem (`fs_*`)** | Full support (`sftp-vfs` / `ssh-stream`) | Full support (`sftp-vfs` / `ssh-stream`) |
| **Command Exec (`exec_run`)** | Full support (SSH session + auto-tmux if tmux exists, else `nohup` background) | Full support (SSH + Mosh + detached tmux supervisor) |
| **Port Tunnels (`tunnel_*`)** | Full support (`-L` local & `-R` reverse via Go SSH mux) | Auto-healing tunnels that rebind on peer IP change |
| **IP Discovery** | Static IP, DNS hostname, or `~/.ssh/config` host alias | Sub-5ms UDP `:42424` HMAC-SHA256 broadcast + Netlink burst + USB/Hotspot/ADB 7-stage cascade |
| **Telemetry** | Collected on-demand via SSH (`uname`, `/proc`, `df`, `free`) | Continuous passive beacon telemetry (battery, load, active workspace) + on-demand deep probe |

---

## 5. MCP Transport Protocols (`pkg/mcpserver`)

Single binary supports all MCP transport specifications:
- `stdio` (default): Standard input/output JSON-RPC 2.0 for Claude Code, Claude Desktop, Cursor, Windsurf, Zed, Neovim.
- `http`: Streamable HTTP (`/mcp` endpoint, session management, chunked streaming).
- `sse`: Legacy HTTP + Server-Sent Events (`/sse` and `/message`) for n8n and older gateways.
- `dual`: Simultaneous `/mcp` (Streamable HTTP), `/sse` + `/message` (Legacy SSE), and `/healthz` on one listener port.
- `unix`: Local Unix domain socket (`~/.cache/sysbridge/mcp.sock`) so multiple local agent instances share one persistent SSH/SFTP connection pool.

---

## 6. MCP Tool Catalog (~14 Focused Tools)

1. **`peer_list`**: List configured and auto-discovered peers, connection state, active VFS backend (`sftp-vfs` / `ssh-stream`), latency, and capability tier.
2. **`peer_connect`**: Test, switch active default peer, or register a new SSH/Mosh host on the fly.
3. **`peer_provision`**: Optional bootstrapper to install/configure user-space `sysbridge daemon` (UDP mesh), `tmux`, `mosh`, or `pam_ssh_agent_auth` on a target peer.
4. **`fs_read`**: Read remote file (line ranges, text, or base64 image/PDF) via VFS.
5. **`fs_write`**: Atomic create/overwrite of remote file via VFS.
6. **`fs_edit`**: Exact string/block surgical replacement (`old_string` -> `new_string`, multi-hunk support) returning unified diff.
7. **`fs_search`**: Combined remote `glob` (file names) and `grep` (content regex) with structured JSON output.
8. **`fs_ops`**: Directory listing (`ls`/`tree`), `stat`, `mkdir`, `mv`, `cp`, `chmod`, `rm` (with blocklist and delete confirmation guard).
9. **`exec_run`**: Execute command on target peer. Supports `sudo: bool`, custom `cwd`, `env`, and automatic detachment to `tmux` / `nohup` when execution exceeds threshold (`5s`).
10. **`task_control`**: Manage detached background jobs (`list`, `status`, `tail`, `send_keys`, `kill`).
11. **`mosh_control`**: Spawn `mosh-server`, verify UDP port reachability (`60000-61000`), and return session connection metadata.
12. **`tunnel_manage`**: Add, list, or remove persistent or RAM-only local (`-L`) and reverse (`-R`) SSH tunnels using native Go net listeners bridged over SSH channels.
13. **`sync_transfer`**: High-speed SFTP push/pull file transfer, one-shot `rsync` delta sync, and background directory auto-sync watcher.
14. **`sys_bridge`**: Collect remote hardware/OS telemetry, manage user/system services, capture Wayland/Android screenshots, sync clipboards, or trigger desktop/webhook notifications.

---

## 7. Configuration Schema (`~/.config/sysbridge/config.yaml`)

```yaml
server:
  transport: "stdio"                # stdio | http | sse | dual | unix
  listen: "127.0.0.1:8787"
  unix_socket: "~/.cache/sysbridge/mcp.sock"
  auth_token_env: "SYSBRIDGE_TOKEN"
  tool_profile: "full"              # full | core | readonly

mesh:
  enabled: true                     # Optional UDP P2P discovery (works rootless)
  node_name: "termux-node"
  role: "client"
  udp_port: 42424
  beacon_interval_sec: 10
  secret_key_path: "~/.config/sysbridge/secret.key"
  state_path: "~/.cache/sysbridge/peers.json"
  netlink_burst: true               # Graceful fallback if AF_NETLINK is restricted

default_peer: "workstation"

peers:
  workstation:
    host: "auto"                    # "auto" (7-stage resolver) or IP/domain/ssh-config alias
    user: "akash"
    ssh_port: 22
    mosh_port: 60000
    auth:
      method: "key"                 # key | agent | password_env
      identity_file: "~/.ssh/id_ed25519"
      ssh_agent_sock: "/tmp/ssh-agent-shared.sock"
    sudo:
      mode: "agent_forward"         # disabled | agent_forward | askpass_elicitation
    vfs:
      backend: "auto"               # auto (sftp-vfs -> ssh-stream) | sftp | ssh-stream
      workspace_root: "/home/akash"
    discovery_hints:
      wifi_mac: "00:e0:29:2d:04:f8"
      usb_mac: "1a:9a:3a:63:52:a0"
      adb_neighbor_lookup: true

  prod_vps:
    host: "203.0.113.42"            # Pure SSH target, zero remote install, non-sudo
    user: "deploy"
    ssh_port: 22
    auth:
      method: "key"
      identity_file: "~/.ssh/id_ed25519"
    sudo:
      mode: "disabled"
    vfs:
      backend: "auto"
      workspace_root: "/srv/app"

execution:
  auto_detach_ms: 5000
  detached_backend: "auto"          # auto (tmux -> nohup) | tmux | nohup
  keepalive_sec: 5

safety:
  blocked_devices:
    - "/dev/sda"
  blocked_paths:
    - "/boot/efi"
  confirm_destructive: true
```

---

## 8. Build, Packaging & GitHub Actions Plan

- **Module Path:** `github.com/0xOpCode/sysbridge-mcp`
- **Binary Name:** `sysbridge-mcp` (with optional symlink/alias `sysbridge`)
- **CI Pipeline (`.github/workflows/ci.yml`):**
  - Triggers on every push and PR.
  - Runs `go vet`, `golangci-lint`, `go test -v -race ./...`, and cross-compile verification across `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`.
- **Release Pipeline (`.github/workflows/release.yml` + `.goreleaser.yaml`):**
  - Builds static `CGO_ENABLED=0` binaries for Linux (`amd64`, `arm64`, `armv7`), macOS (`amd64`, `arm64`), Windows (`amd64`, `arm64`), and FreeBSD.
  - Publishes `.deb`, `.rpm`, `.apk`, Arch `PKGBUILD`, Homebrew formula, multi-arch `ghcr.io` container, and `install.sh` (detects Linux, macOS, and Termux `$PREFIX/bin`).
