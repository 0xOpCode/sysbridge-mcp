# ADR 0001: sysbridge-mcp Rootless VFS and Progressive SSH/Mesh Architecture

## Status
Accepted (2026-10-17)

## Context
AI coding agents running on constrained or mobile environments (such as Android Termux/PRoot or lightweight laptops) need to operate on remote workstations, homelabs, and cloud VPS nodes as if running natively on the target filesystem.

Existing SSH-based MCP servers execute raw shell strings (`ssh host "cmd"`), which breaks on complex file edits, requires repeated TCP/SSH handshakes, drops long-running builds on network roam, and fails when kernel FUSE (`sshfs`) or root privileges are unavailable. Meanwhile, the existing `buddy-link` daemon written in Go provides sub-5ms UDP peer discovery and tunnel supervision, but relies on root-owned paths (`/etc/hosts`, `/etc/buddy-link`, `/run/buddy-peer.json`) and standalone CLI commands.

## Decision

1. **Unified Go Binary & SDK (`sysbridge-mcp`):**
   Merge the `buddy-link` P2P discovery/tunnel/sync engine and the `arch-assistant` / `personal-assistant` remote execution workflows into a single zero-CGO Go binary (`CGO_ENABLED=0`) and importable library (`pkg/*`).

2. **Mountless User-Space Virtual Filesystem (`pkg/vfs`):**
   Do not depend on kernel FUSE (`sshfs`), which fails on Termux and unprivileged containers. Expose a single set of MCP filesystem tools backed by an in-process SFTP client (`sftp-vfs`) multiplexed over a persistent `golang.org/x/crypto/ssh` connection pool, with automatic fallback to POSIX byte-stream commands (`ssh-stream`) if the remote SFTP subsystem is disabled.

3. **Zero-Sudo & Zero-Install Remote Default:**
   - Move all local daemon state, keys, and tunnel definitions to XDG user directories (`~/.config/sysbridge/`, `~/.cache/sysbridge/`).
   - Resolve peer domain aliases (`laptop.local`, `phone.local`) inside the Go SSH dialer using the local state file rather than mutating `/etc/hosts`.
   - Require zero installed binaries on the remote target for core operations (VFS, command execution, native Go SSH port forwarding, SFTP file transfer).
   - Fall back from `tmux` to `nohup` + PID/log sentinel tracking when `tmux` is not installed on a minimal VPS.

4. **Opt-In Cryptographic Sudo via `pam_ssh_agent_auth`:**
   Keep remote `sudo` disabled by default. Provide an opt-in `sudo.mode: "agent_forward"` configuration that forwards the caller's `SSH_AUTH_SOCK` over the SSH channel only when authorized. On targets configured with `pam_ssh_agent_auth.so`, the remote PAM stack verifies a cryptographic signature from the forwarded SSH key, granting passwordless root execution to the agent without exposing plaintext passwords or weakening local physical console security.

5. **Multi-Protocol MCP Transport Layer:**
   Support `stdio`, Streamable HTTP (`/mcp`), Legacy SSE (`/sse` + `/message`), Dual HTTP, and Unix domain sockets from the same binary.

## Consequences
- Any standard SSH server (VPS, cloud VM, macOS, Linux desktop, or Android Termux) works out of the box with zero remote installation and zero root privileges.
- Users who want sub-5ms roaming discovery across Hotspot/USB/Wi-Fi or passwordless agent sudo can opt in per peer using `peer_provision`.
- Tool schemas remain identical across Termux, Linux, and macOS hosts regardless of underlying VFS or process detachment fallback.
