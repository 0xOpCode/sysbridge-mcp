package sysinfo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

type ProvisionReport struct {
	Peer         string          `json:"peer"`
	Action       string          `json:"action"`
	Capabilities map[string]bool `json:"capabilities"`
	Instructions string          `json:"instructions"`
	Applied      bool            `json:"applied"`
	Output       string          `json:"output"`
}

const auditProbeScript = `
check_bin() {
	if command -v "$1" >/dev/null 2>&1; then
		echo "$2=true"
	else
		echo "$2=false"
	fi
}

if command -v sftp >/dev/null 2>&1 || [ -x /usr/lib/ssh/sftp-server ] || [ -x /usr/libexec/sftp-server ] || [ -x /usr/lib/openssh/sftp-server ]; then
	echo "sftp=true"
else
	echo "sftp=false"
fi

check_bin tmux "tmux"
check_bin mosh-server "mosh-server"
check_bin rsync "rsync"
check_bin rg "rg"

if command -v sysbridge-mcp >/dev/null 2>&1 || command -v sysbridge >/dev/null 2>&1; then
	echo "sysbridge=true"
else
	echo "sysbridge=false"
fi

if [ -f /usr/lib/security/pam_ssh_agent_auth.so ] || [ -f /lib/security/pam_ssh_agent_auth.so ] || [ -f /usr/lib/x86_64-linux-gnu/security/pam_ssh_agent_auth.so ] || [ -f /usr/lib/aarch64-linux-gnu/security/pam_ssh_agent_auth.so ]; then
	echo "pam_ssh_agent_auth.so=true"
else
	echo "pam_ssh_agent_auth.so=false"
fi

if systemctl --user status >/dev/null 2>&1 || [ -d "/run/user/$(id -u)/systemd" ]; then
	echo "systemd --user=true"
else
	echo "systemd --user=false"
fi

if [ -f /etc/arch-release ]; then
	echo "os=arch"
elif [ -f /etc/debian_version ]; then
	echo "os=debian"
else
	echo "os=generic"
fi
`

func (b *Bridge) ProvisionPeer(ctx context.Context, peerName, action, publicKey string, apply bool) (*ProvisionReport, error) {
	resolvedPeer := peerName
	var peerCfg *config.PeerConfig
	if b.cfg != nil {
		if p, err := b.cfg.ResolvePeer(peerName); err == nil {
			resolvedPeer = p.Name
			peerCfg = p
		}
	}

	probeRes, err := b.pool.Exec(ctx, resolvedPeer, auditProbeScript, transport.ExecOptions{
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("probe peer %s: %w", resolvedPeer, err)
	}

	caps, detectedOS := parseAuditOutput(probeRes.Stdout)

	report := &ProvisionReport{
		Peer:         resolvedPeer,
		Action:       action,
		Capabilities: caps,
		Applied:      false,
	}

	switch action {
	case "audit":
		report.Instructions = buildAuditSummary(caps, detectedOS)
		report.Output = strings.TrimSpace(probeRes.Stdout)
		return report, nil

	case "setup_user_mesh":
		udpPort := 42424
		if b.cfg != nil && b.cfg.Mesh.UDPPort > 0 {
			udpPort = b.cfg.Mesh.UDPPort
		}
		script := buildUserMeshScript(udpPort)
		report.Instructions = script
		if !apply {
			report.Output = "dry-run: set apply=true to install ~/.config/systemd/user/sysbridge-mesh.service"
			return report, nil
		}

		res, err := b.pool.Exec(ctx, resolvedPeer, script, transport.ExecOptions{
			Sudo:    false,
			Timeout: 20 * time.Second,
		})
		if err != nil {
			return report, fmt.Errorf("apply user mesh on %s: %w", resolvedPeer, err)
		}
		report.Output = strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
		if res.ExitCode != 0 {
			return report, fmt.Errorf("setup_user_mesh exited with %d: %s", res.ExitCode, report.Output)
		}
		report.Applied = true
		return report, nil

	case "setup_pam_ssh_sudo":
		pubKey := strings.TrimSpace(publicKey)
		if pubKey == "" {
			pubKey = resolveLocalPublicKey(peerCfg)
		}
		script := buildPamSSHSudoScript(detectedOS, caps["pam_ssh_agent_auth.so"], pubKey)
		report.Instructions = script
		if !apply {
			report.Output = fmt.Sprintf("dry-run (os=%s, pam_module_present=%v): review instructions or pass apply=true", detectedOS, caps["pam_ssh_agent_auth.so"])
			return report, nil
		}

		if peerCfg != nil && peerCfg.Sudo.Mode == "disabled" {
			return report, fmt.Errorf("cannot apply setup_pam_ssh_sudo on %q: sudo.mode is disabled", resolvedPeer)
		}

		res, err := b.pool.Exec(ctx, resolvedPeer, script, transport.ExecOptions{
			Sudo:    true,
			Timeout: 30 * time.Second,
		})
		if err != nil {
			return report, fmt.Errorf("apply pam_ssh_agent_auth on %s: %w", resolvedPeer, err)
		}
		report.Output = strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
		if res.ExitCode != 0 {
			return report, fmt.Errorf("setup_pam_ssh_sudo exited with %d: %s", res.ExitCode, report.Output)
		}
		report.Applied = true
		return report, nil

	default:
		return nil, fmt.Errorf("unsupported provision action %q", action)
	}
}

func parseAuditOutput(stdout string) (map[string]bool, string) {
	caps := map[string]bool{
		"sftp":                  false,
		"tmux":                  false,
		"mosh-server":           false,
		"rsync":                 false,
		"rg":                    false,
		"sysbridge":             false,
		"pam_ssh_agent_auth.so": false,
		"systemd --user":        false,
	}
	detectedOS := "generic"

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k, v := parts[0], parts[1]
		if k == "os" {
			detectedOS = v
			continue
		}
		caps[k] = (v == "true")
	}
	return caps, detectedOS
}

func buildAuditSummary(caps map[string]bool, detectedOS string) string {
	var missing []string
	order := []string{"sftp", "tmux", "mosh-server", "rsync", "rg", "sysbridge", "pam_ssh_agent_auth.so", "systemd --user"}
	for _, k := range order {
		if !caps[k] {
			missing = append(missing, k)
		}
	}
	if len(missing) == 0 {
		return fmt.Sprintf("os=%s: all capabilities present", detectedOS)
	}
	return fmt.Sprintf("os=%s: missing capabilities: %s", detectedOS, strings.Join(missing, ", "))
}

func buildUserMeshScript(udpPort int) string {
	return fmt.Sprintf(`set -e
mkdir -p "$HOME/.config/systemd/user"
cat <<'EOF' > "$HOME/.config/systemd/user/sysbridge-mesh.service"
[Unit]
Description=SysBridge Rootless UDP Mesh Daemon (:%d)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env sysbridge-mcp daemon --port %d
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
	systemctl --user daemon-reload
	systemctl --user enable --now sysbridge-mesh.service
fi
`, udpPort, udpPort)
}

func buildPamSSHSudoScript(detectedOS string, moduleInstalled bool, pubKey string) string {
	var b strings.Builder
	b.WriteString("set -e\n")

	if !moduleInstalled {
		switch detectedOS {
		case "arch":
			b.WriteString("# Install pam_ssh_agent_auth on Arch Linux (AUR or prebuilt repo)\n")
			b.WriteString("if ! [ -f /usr/lib/security/pam_ssh_agent_auth.so ] && ! [ -f /lib/security/pam_ssh_agent_auth.so ]; then\n")
			b.WriteString("  pacman -S --needed --noconfirm pam_ssh_agent_auth || true\n")
			b.WriteString("fi\n")
		case "debian":
			b.WriteString("# Install libpam-ssh-agent-auth on Debian/Ubuntu\n")
			b.WriteString("if ! [ -f /usr/lib/security/pam_ssh_agent_auth.so ] && ! [ -f /lib/security/pam_ssh_agent_auth.so ]; then\n")
			b.WriteString("  DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y libpam-ssh-agent-auth\n")
			b.WriteString("fi\n")
		}
	}

	keyLine := pubKey
	if keyLine == "" {
		keyLine = "# Replace with controller SSH public key (e.g. ssh-ed25519 AAAA...)"
	}

	b.WriteString("chown root:root /etc\n")
	b.WriteString("chmod 0755 /etc\n")
	b.WriteString("install -d -m 0755 -o root -g root /etc/security\n")
	b.WriteString("touch /etc/security/authorized_keys\n")
	b.WriteString("chown root:root /etc/security/authorized_keys\n")
	b.WriteString("chmod 0644 /etc/security/authorized_keys\n")
	if pubKey != "" {
		qKey := shellQuote(pubKey)
		b.WriteString(fmt.Sprintf("grep -qxF %s /etc/security/authorized_keys || echo %s >> /etc/security/authorized_keys\n", qKey, qKey))
	} else {
		b.WriteString(fmt.Sprintf("%s\n", keyLine))
	}

	b.WriteString("cat <<'EOF' > /etc/sudoers.d/sysbridge-agent\n")
	b.WriteString("Defaults env_keep += \"SSH_AUTH_SOCK\"\n")
	b.WriteString("EOF\n")
	b.WriteString("chown root:root /etc/sudoers.d/sysbridge-agent\n")
	b.WriteString("chmod 0440 /etc/sudoers.d/sysbridge-agent\n")
	b.WriteString("visudo -cf /etc/sudoers.d/sysbridge-agent\n")

	b.WriteString("PAM_LINE='auth sufficient pam_ssh_agent_auth.so file=/etc/security/authorized_keys'\n")
	b.WriteString("if [ -f /etc/pam.d/sudo ] && ! grep -qF 'pam_ssh_agent_auth.so' /etc/pam.d/sudo; then\n")
	b.WriteString("  cp /etc/pam.d/sudo /etc/pam.d/sudo.bak\n")
	b.WriteString("  awk -v line=\"$PAM_LINE\" '!inserted && /^auth/ { print line; inserted=1 } { print }' /etc/pam.d/sudo.bak > /etc/pam.d/sudo\n")
	b.WriteString("fi\n")

	return b.String()
}

func resolveLocalPublicKey(peer *config.PeerConfig) string {
	var candidates []string
	if peer != nil && peer.Auth.IdentityFile != "" {
		expanded := config.ExpandPath(peer.Auth.IdentityFile)
		if !strings.HasSuffix(expanded, ".pub") {
			expanded += ".pub"
		}
		candidates = append(candidates, expanded)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".ssh", "id_ed25519.pub"),
			filepath.Join(home, ".ssh", "scalingo_account3.pub"),
			filepath.Join(home, ".ssh", "id_rsa.pub"),
		)
	}
	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			if trimmed := strings.TrimSpace(string(data)); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}
