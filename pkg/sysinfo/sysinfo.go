package sysinfo

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

var validServiceName = regexp.MustCompile(`^[a-zA-Z0-9_.@-]+$`)

type Bridge struct {
	pool *transport.Pool
	cfg  *config.Config
}

type TelemetryReport struct {
	Peer           string `json:"peer"`
	Hostname       string `json:"hostname"`
	Kernel         string `json:"kernel"`
	Arch           string `json:"arch"`
	Uptime         string `json:"uptime"`
	LoadAvg        string `json:"load_avg"`
	CPUModel       string `json:"cpu_model"`
	MemorySummary  string `json:"memory_summary"`
	ZramSummary    string `json:"zram_summary"`
	DiskSummary    string `json:"disk_summary"`
	BatterySummary string `json:"battery_summary"`
	ThermalSummary string `json:"thermal_summary"`
	BlockDevices   string `json:"block_devices"`
	VaultStatus    string `json:"vault_status"`
	WaylandActive  bool   `json:"wayland_active"`
}

func NewBridge(pool *transport.Pool, cfg *config.Config) *Bridge {
	return &Bridge{
		pool: pool,
		cfg:  cfg,
	}
}

const compositeTelemetryScript = `
echo "===SECTION:HOSTNAME==="
hostname 2>/dev/null || uname -n 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown"

echo "===SECTION:KERNEL==="
uname -srmo 2>/dev/null || uname -sr 2>/dev/null || echo "unknown"

echo "===SECTION:ARCH==="
uname -m 2>/dev/null || echo "unknown"

echo "===SECTION:UPTIME==="
if [ -r /proc/uptime ]; then
	awk '{printf "%d days, %02d:%02d:%02d (raw: %ss)\n", $1/86400, ($1%86400)/3600, ($1%3600)/60, $1%60, $1}' /proc/uptime 2>/dev/null || cat /proc/uptime 2>/dev/null
else
	uptime 2>/dev/null || echo "unknown"
fi

echo "===SECTION:LOADAVG==="
cat /proc/loadavg 2>/dev/null || uptime 2>/dev/null || echo "unknown"

echo "===SECTION:CPU==="
grep -m1 -E 'model name|Hardware|Processor' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^[[:space:]]*//' || lscpu 2>/dev/null | grep -m1 'Model name' | cut -d: -f2- | sed 's/^[[:space:]]*//' || echo "unknown"

echo "===SECTION:MEMORY==="
free -h 2>/dev/null || head -n 6 /proc/meminfo 2>/dev/null || echo "unavailable"

echo "===SECTION:ZRAM==="
swapon --show 2>/dev/null || cat /proc/swaps 2>/dev/null || echo "none"

echo "===SECTION:DISK==="
df -h / /home 2>/dev/null || df -h / 2>/dev/null || echo "unavailable"

echo "===SECTION:LSBLK==="
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null || lsblk 2>/dev/null || echo "unavailable"

echo "===SECTION:BATTERY==="
if ls /sys/class/power_supply/BAT*/capacity >/dev/null 2>&1; then
	for b in /sys/class/power_supply/BAT*; do
		cap=$(cat "$b/capacity" 2>/dev/null)
		st=$(cat "$b/status" 2>/dev/null)
		echo "$(basename "$b"): ${cap}% (${st:-unknown})"
	done
elif command -v termux-battery-status >/dev/null 2>&1; then
	termux-battery-status 2>/dev/null
elif command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then
	adb shell dumpsys battery 2>/dev/null | grep -E 'level|status|temperature|AC powered|USB powered'
else
	echo "no battery"
fi

echo "===SECTION:THERMAL==="
if ls /sys/class/thermal/thermal_zone*/temp >/dev/null 2>&1; then
	for z in /sys/class/thermal/thermal_zone*; do
		t=$(cat "$z/temp" 2>/dev/null)
		typ=$(cat "$z/type" 2>/dev/null)
		if [ -n "$t" ]; then
			echo "${typ:-$(basename "$z")}: $((t / 1000))C"
		fi
	done
else
	echo "unavailable"
fi

echo "===SECTION:VAULT==="
if [ -e /dev/mapper/daemon_vault ]; then
	cryptsetup status daemon_vault 2>/dev/null || echo "active (/dev/mapper/daemon_vault present)"
elif command -v cryptsetup >/dev/null 2>&1; then
	cryptsetup status daemon_vault 2>/dev/null || echo "inactive"
else
	echo "inactive"
fi

echo "===SECTION:WAYLAND==="
if [ -n "$WAYLAND_DISPLAY" ] || ls /run/user/*/wayland-* >/dev/null 2>&1; then
	echo "active"
else
	echo "inactive"
fi
`

func (b *Bridge) CollectTelemetry(ctx context.Context, peerName string) (*TelemetryReport, error) {
	resolvedPeer := peerName
	if b.cfg != nil {
		if p, err := b.cfg.ResolvePeer(peerName); err == nil {
			resolvedPeer = p.Name
		}
	}

	res, err := b.pool.Exec(ctx, resolvedPeer, compositeTelemetryScript, transport.ExecOptions{
		Timeout: 15 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("collect telemetry on %s: %w", resolvedPeer, err)
	}

	sections := parseSections(res.Stdout)
	waylandRaw := strings.TrimSpace(sections["WAYLAND"])

	return &TelemetryReport{
		Peer:           resolvedPeer,
		Hostname:       strings.TrimSpace(sections["HOSTNAME"]),
		Kernel:         strings.TrimSpace(sections["KERNEL"]),
		Arch:           strings.TrimSpace(sections["ARCH"]),
		Uptime:         strings.TrimSpace(sections["UPTIME"]),
		LoadAvg:        strings.TrimSpace(sections["LOADAVG"]),
		CPUModel:       strings.TrimSpace(sections["CPU"]),
		MemorySummary:  strings.TrimSpace(sections["MEMORY"]),
		ZramSummary:    strings.TrimSpace(sections["ZRAM"]),
		DiskSummary:    strings.TrimSpace(sections["DISK"]),
		BatterySummary: strings.TrimSpace(sections["BATTERY"]),
		ThermalSummary: strings.TrimSpace(sections["THERMAL"]),
		BlockDevices:   strings.TrimSpace(sections["LSBLK"]),
		VaultStatus:    strings.TrimSpace(sections["VAULT"]),
		WaylandActive:  waylandRaw == "active",
	}, nil
}

func (b *Bridge) ServiceAction(ctx context.Context, peerName, service, action string, userScope bool, sudo bool) (string, error) {
	if !validServiceName.MatchString(service) {
		return "", fmt.Errorf("invalid service name %q", service)
	}

	scopeFlag := ""
	if userScope {
		scopeFlag = "--user "
	}

	var cmd string
	switch action {
	case "status", "start", "stop", "restart":
		cmd = fmt.Sprintf("systemctl %s%s %s --no-pager", scopeFlag, action, service)
	case "logs":
		cmd = fmt.Sprintf("journalctl %s-u %s -n 50 --no-pager", scopeFlag, service)
	default:
		return "", fmt.Errorf("unsupported service action %q", action)
	}

	res, err := b.pool.Exec(ctx, peerName, cmd, transport.ExecOptions{
		Sudo:    sudo && !userScope,
		Timeout: 20 * time.Second,
	})
	if err != nil {
		return "", fmt.Errorf("service %s %s on %s: %w", service, action, peerName, err)
	}

	combined := strings.TrimSpace(res.Stdout + "\n" + res.Stderr)
	if res.ExitCode != 0 && action != "status" && action != "logs" {
		return combined, fmt.Errorf("service %s %s exited with %d: %s", service, action, res.ExitCode, combined)
	}
	if combined == "" {
		return "ok", nil
	}
	return combined, nil
}

func (b *Bridge) DesktopAction(ctx context.Context, peerName, action, payload string) (map[string]any, error) {
	resolvedPeer := peerName
	if b.cfg != nil {
		if p, err := b.cfg.ResolvePeer(peerName); err == nil {
			resolvedPeer = p.Name
		}
	}

	waylandEnvPrefix := `export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"; ` +
		`if [ -z "$SWAYSOCK" ]; then export SWAYSOCK=$(ls "$XDG_RUNTIME_DIR"/sway-ipc.*.sock 2>/dev/null | head -n1); fi; ` +
		`if [ -z "$WAYLAND_DISPLAY" ]; then wd=$(ls "$XDG_RUNTIME_DIR"/wayland-* 2>/dev/null | grep -v '\.lock$' | head -n1); [ -n "$wd" ] && export WAYLAND_DISPLAY=$(basename "$wd"); fi; `

	switch action {
	case "sway_tree":
		res, err := b.pool.Exec(ctx, resolvedPeer, waylandEnvPrefix+"swaymsg -t get_tree", transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("sway_tree failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "output": strings.TrimSpace(res.Stdout)}, nil

	case "sway_workspaces":
		res, err := b.pool.Exec(ctx, resolvedPeer, waylandEnvPrefix+"swaymsg -t get_workspaces", transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("sway_workspaces failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "output": strings.TrimSpace(res.Stdout)}, nil

	case "sway_focus":
		if strings.TrimSpace(payload) == "" {
			return nil, fmt.Errorf("sway_focus requires target criteria or workspace in payload")
		}
		cmd := waylandEnvPrefix + "swaymsg " + shellQuote(payload)
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("sway_focus failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "output": strings.TrimSpace(res.Stdout)}, nil

	case "sway_exec":
		if strings.TrimSpace(payload) == "" {
			return nil, fmt.Errorf("sway_exec requires command payload")
		}
		cmd := waylandEnvPrefix + "swaymsg exec -- " + shellQuote(payload)
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("sway_exec failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "output": strings.TrimSpace(res.Stdout)}, nil

	case "lock_screen":
		cmd := waylandEnvPrefix + "if command -v daemon-lock >/dev/null 2>&1; then daemon-lock; elif command -v swaylock >/dev/null 2>&1; then swaylock -f; else loginctl lock-session; fi"
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("lock_screen failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "status": "locked"}, nil

	case "set_wallpaper":
		if strings.TrimSpace(payload) == "" {
			return nil, fmt.Errorf("set_wallpaper requires file path in payload")
		}
		qPath := shellQuote(payload)
		cmd := waylandEnvPrefix + fmt.Sprintf("if command -v daemon-wallpaper >/dev/null 2>&1; then daemon-wallpaper %s; else swaymsg output '*' bg %s fill; fi", qPath, qPath)
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("set_wallpaper failed: %s", strings.TrimSpace(res.Stderr+"\n"+res.Stdout))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "wallpaper": payload}, nil

	case "screenshot":
		cmd := waylandEnvPrefix + `if command -v grim >/dev/null 2>&1 && [ -n "$WAYLAND_DISPLAY" ]; then grim -; elif command -v adb >/dev/null 2>&1 && adb get-state >/dev/null 2>&1; then adb exec-out screencap -p; elif command -v import >/dev/null 2>&1; then import -window root png:-; else exit 127; fi`
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 || len(res.Stdout) == 0 {
			return nil, fmt.Errorf("screenshot capture failed (exit %d): %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
		b64 := base64.StdEncoding.EncodeToString([]byte(res.Stdout))
		return map[string]any{
			"peer":      resolvedPeer,
			"action":    action,
			"mime":      "image/png",
			"mime_type": "image/png",
			"data":      b64,
			"base64":    b64,
		}, nil

	case "clipboard_get":
		cmd := waylandEnvPrefix + `if command -v wl-paste >/dev/null 2>&1 && [ -n "$WAYLAND_DISPLAY" ]; then wl-paste --no-newline; elif command -v termux-clipboard-get >/dev/null 2>&1; then termux-clipboard-get; elif command -v xclip >/dev/null 2>&1; then xclip -o -selection clipboard; elif command -v xsel >/dev/null 2>&1; then xsel -ob; else exit 127; fi`
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("clipboard_get failed: %s", strings.TrimSpace(res.Stderr))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "content": res.Stdout}, nil

	case "clipboard_set":
		cmd := waylandEnvPrefix + `if command -v wl-copy >/dev/null 2>&1 && [ -n "$WAYLAND_DISPLAY" ]; then wl-copy; elif command -v termux-clipboard-set >/dev/null 2>&1; then termux-clipboard-set; elif command -v xclip >/dev/null 2>&1; then xclip -i -selection clipboard; elif command -v xsel >/dev/null 2>&1; then xsel -ib; else exit 127; fi`
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{
			Stdin:   []byte(payload),
			Timeout: 10 * time.Second,
		})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("clipboard_set failed: %s", strings.TrimSpace(res.Stderr))
		}
		return map[string]any{"peer": resolvedPeer, "action": action, "bytes": len(payload)}, nil

	case "notify":
		if strings.TrimSpace(payload) == "" {
			return nil, fmt.Errorf("notify requires message payload")
		}
		cmd := waylandEnvPrefix + fmt.Sprintf(`if command -v notify-send >/dev/null 2>&1; then notify-send "SysBridge" %s; elif command -v termux-notification >/dev/null 2>&1; then termux-notification --title "SysBridge" --content %s; fi`, shellQuote(payload), shellQuote(payload))
		res, err := b.pool.Exec(ctx, resolvedPeer, cmd, transport.ExecOptions{Timeout: 10 * time.Second})
		if err != nil {
			return nil, err
		}
		webhookSent := false
		if webhookURL := b.resolveWebhookURL(); webhookURL != "" {
			if wErr := postWebhook(ctx, webhookURL, resolvedPeer, payload); wErr == nil {
				webhookSent = true
			}
		}
		return map[string]any{
			"peer":         resolvedPeer,
			"action":       action,
			"notified":     res.ExitCode == 0,
			"webhook_sent": webhookSent,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported desktop action %q", action)
	}
}

func (b *Bridge) resolveWebhookURL() string {
	if b.cfg == nil {
		return ""
	}
	if b.cfg.Alerts.WebhookURL != "" {
		return b.cfg.Alerts.WebhookURL
	}
	if b.cfg.Alerts.WebhookURLEnv != "" {
		return os.Getenv(b.cfg.Alerts.WebhookURLEnv)
	}
	return ""
}

func postWebhook(ctx context.Context, url, peer, message string) error {
	body, err := json.Marshal(map[string]string{
		"peer":    peer,
		"message": message,
		"content": fmt.Sprintf("[%s] %s", peer, message),
	})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func parseSections(output string) map[string]string {
	sections := make(map[string]string)
	var current string
	var buf strings.Builder

	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "===SECTION:") && strings.HasSuffix(line, "===") {
			if current != "" {
				sections[current] = strings.TrimSpace(buf.String())
			}
			current = strings.TrimSuffix(strings.TrimPrefix(line, "===SECTION:"), "===")
			buf.Reset()
			continue
		}
		if current != "" {
			buf.WriteString(line)
			buf.WriteByte('\n')
		}
	}
	if current != "" {
		sections[current] = strings.TrimSpace(buf.String())
	}
	return sections
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
