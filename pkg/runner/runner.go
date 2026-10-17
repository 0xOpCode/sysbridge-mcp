package runner

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

var (
	taskSeq         uint64
	exitMarkerRegex = regexp.MustCompile(`__SYSBRIDGE_EXIT:(-?\d+)__`)
)

type Manager struct {
	pool *transport.Pool
	cfg  *config.Config
}

type RunOptions struct {
	Peer      string            `json:"peer"`
	Command   string            `json:"command"`
	Cwd       string            `json:"cwd"`
	Env       map[string]string `json:"env"`
	Sudo      bool              `json:"sudo"`
	Detached  bool              `json:"detached"`
	TaskName  string            `json:"task_name"`
	TimeoutMs int               `json:"timeout_ms"`
}

type RunOutput struct {
	Peer         string `json:"peer"`
	ResolvedHost string `json:"resolved_host"`
	Detached     bool   `json:"detached"`
	TaskID       string `json:"task_id,omitempty"`
	LogPath      string `json:"log_path,omitempty"`
	Backend      string `json:"backend"`
	ExitCode     int    `json:"exit_code"`
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	DurationMs   int64  `json:"duration_ms"`
}

func NewManager(pool *transport.Pool, cfg *config.Config) *Manager {
	if cfg == nil && pool != nil {
		cfg = pool.Config()
	}
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	return &Manager{
		pool: pool,
		cfg:  cfg,
	}
}

func (m *Manager) Run(ctx context.Context, opts RunOptions) (*RunOutput, error) {
	if strings.TrimSpace(opts.Command) == "" {
		return nil, errors.New("command cannot be empty")
	}
	if m.pool != nil && m.pool.Guard() != nil {
		if err := m.pool.Guard().CheckCommand(opts.Command); err != nil {
			return nil, err
		}
	}

	peer, host, _, _, err := m.pool.ResolveTarget(opts.Peer)
	if err != nil {
		return nil, err
	}

	if opts.Detached {
		return m.startDetachedTask(ctx, peer, host, opts)
	}

	windowMs := m.cfg.Execution.AutoDetachMs
	if opts.TimeoutMs > 0 {
		windowMs = opts.TimeoutMs
	}
	if windowMs <= 0 {
		windowMs = 5000
	}

	window := time.Duration(windowMs) * time.Millisecond
	execCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()

	type execOutcome struct {
		res *transport.ExecResult
		err error
	}
	doneCh := make(chan execOutcome, 1)
	go func() {
		r, e := m.pool.Exec(execCtx, peer.Name, opts.Command, transport.ExecOptions{
			Cwd:     opts.Cwd,
			Env:     opts.Env,
			Sudo:    opts.Sudo,
			Timeout: window,
		})
		doneCh <- execOutcome{res: r, err: e}
	}()

	timer := time.NewTimer(window)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		cancel()
		return nil, ctx.Err()
	case <-timer.C:
		cancel()
		return m.startDetachedTask(ctx, peer, host, opts)
	case outcome := <-doneCh:
		if errors.Is(outcome.err, context.DeadlineExceeded) || errors.Is(execCtx.Err(), context.DeadlineExceeded) {
			if ctx.Err() == nil {
				return m.startDetachedTask(ctx, peer, host, opts)
			}
		}
		if outcome.err != nil {
			if outcome.res != nil {
				return &RunOutput{
					Peer:         peer.Name,
					ResolvedHost: outcome.res.ResolvedHost,
					Detached:     false,
					Backend:      outcome.res.TransportUsed,
					ExitCode:     outcome.res.ExitCode,
					Stdout:       outcome.res.Stdout,
					Stderr:       outcome.res.Stderr,
					DurationMs:   outcome.res.DurationMs,
				}, outcome.err
			}
			return nil, outcome.err
		}
		return &RunOutput{
			Peer:         peer.Name,
			ResolvedHost: outcome.res.ResolvedHost,
			Detached:     false,
			Backend:      outcome.res.TransportUsed,
			ExitCode:     outcome.res.ExitCode,
			Stdout:       outcome.res.Stdout,
			Stderr:       outcome.res.Stderr,
			DurationMs:   outcome.res.DurationMs,
		}, nil
	}
}

func (m *Manager) startDetachedTask(ctx context.Context, peer *config.PeerConfig, resolvedHost string, opts RunOptions) (*RunOutput, error) {
	start := time.Now()
	taskID := m.buildTaskID(opts.TaskName)
	logPath := fmt.Sprintf("/tmp/%s.log", taskID)
	pidPath := fmt.Sprintf("/tmp/%s.pid", taskID)

	innerCmd := wrapTaskCommand(opts.Command, opts.Cwd, opts.Env, opts.Sudo)
	payloadScript := fmt.Sprintf("(%s) > %s 2>&1; echo __SYSBRIDGE_EXIT:$?__ >> %s", innerCmd, shellSingleQuote(logPath), shellSingleQuote(logPath))

	backendPref := strings.ToLower(strings.TrimSpace(m.cfg.Execution.DetachedBackend))
	useTmux := false
	if backendPref != "nohup" {
		checkRes, err := m.pool.Exec(ctx, peer.Name, "command -v tmux >/dev/null 2>&1", transport.ExecOptions{
			Timeout: 5 * time.Second,
		})
		if err == nil && checkRes.ExitCode == 0 {
			useTmux = true
		}
	}

	if useTmux {
		tmuxShellCmd := fmt.Sprintf("sh -c %s", shellSingleQuote(payloadScript))
		tmuxLaunch := fmt.Sprintf("tmux new-session -d -s %s %s", shellSingleQuote(taskID), shellSingleQuote(tmuxShellCmd))
		res, err := m.pool.Exec(ctx, peer.Name, tmuxLaunch, transport.ExecOptions{
			Timeout: 8 * time.Second,
		})
		if err == nil && res.ExitCode == 0 {
			return &RunOutput{
				Peer:         peer.Name,
				ResolvedHost: resolvedHost,
				Detached:     true,
				TaskID:       taskID,
				LogPath:      logPath,
				Backend:      "tmux",
				ExitCode:     0,
				DurationMs:   time.Since(start).Milliseconds(),
			}, nil
		}
		if backendPref == "tmux" {
			if err != nil {
				return nil, fmt.Errorf("tmux launch failed: %w", err)
			}
			return nil, fmt.Errorf("tmux launch exited with code %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
		}
	}

	nohupLaunch := fmt.Sprintf(
		"nohup sh -c %s </dev/null >/dev/null 2>&1 & echo $! > %s",
		shellSingleQuote(payloadScript),
		shellSingleQuote(pidPath),
	)
	res, err := m.pool.Exec(ctx, peer.Name, nohupLaunch, transport.ExecOptions{
		Timeout: 8 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("nohup launch failed: %w", err)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("nohup launch exited with code %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	return &RunOutput{
		Peer:         peer.Name,
		ResolvedHost: resolvedHost,
		Detached:     true,
		TaskID:       taskID,
		LogPath:      logPath,
		Backend:      "nohup",
		ExitCode:     0,
		DurationMs:   time.Since(start).Milliseconds(),
	}, nil
}

func (m *Manager) TaskAction(ctx context.Context, peerName, action, taskID, keys string, lines int) (map[string]any, error) {
	peer, _, _, _, err := m.pool.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	act := strings.ToLower(strings.TrimSpace(action))
	if lines <= 0 {
		lines = 50
	}

	switch act {
	case "list":
		return m.listTasks(ctx, peer.Name)
	case "status":
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		return m.taskStatus(ctx, peer.Name, taskID)
	case "tail":
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		return m.tailTask(ctx, peer.Name, taskID, lines)
	case "send_keys":
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		return m.sendKeysTask(ctx, peer.Name, taskID, keys)
	case "kill":
		if err := validateTaskID(taskID); err != nil {
			return nil, err
		}
		return m.killTask(ctx, peer.Name, taskID)
	default:
		return nil, fmt.Errorf("unsupported task action %q", action)
	}
}

func (m *Manager) listTasks(ctx context.Context, peerName string) (map[string]any, error) {
	prefix := m.tmuxPrefix()
	cleanPrefix := sanitizeIdent(prefix)
	script := fmt.Sprintf(
		"tmux list-sessions -F 'TMUX:#{session_name}' 2>/dev/null || true; "+
			"for f in /tmp/%s_*.log /tmp/sysbridge_*.log; do [ -e \"$f\" ] && echo \"LOG:$f\"; done; "+
			"for p in /tmp/%s_*.pid /tmp/sysbridge_*.pid; do [ -e \"$p\" ] && echo \"PID:$p\"; done",
		cleanPrefix, cleanPrefix,
	)
	res, err := m.pool.Exec(ctx, peerName, script, transport.ExecOptions{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}

	type itemInfo struct {
		backend string
		hasTmux bool
		hasLog  bool
		hasPid  bool
	}
	found := make(map[string]*itemInfo)
	ensure := func(id string) *itemInfo {
		if entry, ok := found[id]; ok {
			return entry
		}
		entry := &itemInfo{backend: "nohup"}
		found[id] = entry
		return entry
	}

	for _, rawLine := range strings.Split(res.Stdout, "\n") {
		line := strings.TrimSpace(rawLine)
		switch {
		case strings.HasPrefix(line, "TMUX:"):
			id := strings.TrimPrefix(line, "TMUX:")
			if id != "" {
				entry := ensure(id)
				entry.hasTmux = true
				entry.backend = "tmux"
			}
		case strings.HasPrefix(line, "LOG:"):
			p := strings.TrimPrefix(line, "LOG:")
			base := strings.TrimSuffix(filepath.Base(p), ".log")
			if base != "" {
				entry := ensure(base)
				entry.hasLog = true
			}
		case strings.HasPrefix(line, "PID:"):
			p := strings.TrimPrefix(line, "PID:")
			base := strings.TrimSuffix(filepath.Base(p), ".pid")
			if base != "" {
				entry := ensure(base)
				entry.hasPid = true
			}
		}
	}

	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	tasks := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		st, stErr := m.taskStatus(ctx, peerName, id)
		if stErr == nil {
			tasks = append(tasks, st)
		} else {
			tasks = append(tasks, map[string]any{
				"task_id":  id,
				"backend":  found[id].backend,
				"log_path": fmt.Sprintf("/tmp/%s.log", id),
			})
		}
	}

	return map[string]any{
		"peer":     peerName,
		"action":   "list",
		"count":    len(tasks),
		"task_ids": ids,
		"tasks":    tasks,
	}, nil
}

func (m *Manager) taskStatus(ctx context.Context, peerName, taskID string) (map[string]any, error) {
	logPath := fmt.Sprintf("/tmp/%s.log", taskID)
	pidPath := fmt.Sprintf("/tmp/%s.pid", taskID)
	qTask := shellSingleQuote(taskID)
	qLog := shellSingleQuote(logPath)
	qPid := shellSingleQuote(pidPath)

	script := fmt.Sprintf(
		"if command -v tmux >/dev/null 2>&1 && tmux has-session -t %s 2>/dev/null; then echo TMUX_ALIVE=1; else echo TMUX_ALIVE=0; fi; "+
			"if [ -f %s ]; then pid=$(cat %s 2>/dev/null); if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then echo PID_ALIVE=1; else echo PID_ALIVE=0; fi; else echo PID_ALIVE=0; fi; "+
			"if [ -f %s ]; then echo LOG_EXISTS=1; grep -o '__SYSBRIDGE_EXIT:[-0-9]*__' %s 2>/dev/null | tail -n 1 || true; else echo LOG_EXISTS=0; fi; "+
			"if [ -f %s ]; then echo PID_EXISTS=1; else echo PID_EXISTS=0; fi",
		qTask, qPid, qPid, qLog, qLog, qPid,
	)

	res, err := m.pool.Exec(ctx, peerName, script, transport.ExecOptions{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}

	tmuxAlive := strings.Contains(res.Stdout, "TMUX_ALIVE=1")
	pidAlive := strings.Contains(res.Stdout, "PID_ALIVE=1")
	logExists := strings.Contains(res.Stdout, "LOG_EXISTS=1")
	pidExists := strings.Contains(res.Stdout, "PID_EXISTS=1")

	exitCode := 0
	hasExitCode := false
	if matches := exitMarkerRegex.FindStringSubmatch(res.Stdout); len(matches) == 2 {
		if parsed, convErr := strconv.Atoi(matches[1]); convErr == nil {
			exitCode = parsed
			hasExitCode = true
		}
	}

	running := (tmuxAlive || pidAlive) && !hasExitCode
	backend := "nohup"
	if tmuxAlive || (!pidExists && !pidAlive && strings.ToLower(m.cfg.Execution.DetachedBackend) == "tmux") {
		backend = "tmux"
	}

	status := "not_found"
	switch {
	case running:
		status = "running"
	case hasExitCode && exitCode == 0:
		status = "completed"
	case hasExitCode && exitCode != 0:
		status = "failed"
	case logExists || pidExists:
		status = "stopped"
	}

	out := map[string]any{
		"peer":     peerName,
		"action":   "status",
		"task_id":  taskID,
		"running":  running,
		"status":   status,
		"backend":  backend,
		"log_path": logPath,
	}
	if hasExitCode {
		out["exit_code"] = exitCode
	}
	return out, nil
}

func (m *Manager) tailTask(ctx context.Context, peerName, taskID string, lines int) (map[string]any, error) {
	logPath := fmt.Sprintf("/tmp/%s.log", taskID)
	qLog := shellSingleQuote(logPath)
	qTask := shellSingleQuote(taskID)

	script := fmt.Sprintf(
		"if [ -f %s ]; then tail -n %d %s; "+
			"elif command -v tmux >/dev/null 2>&1 && tmux has-session -t %s 2>/dev/null; then tmux capture-pane -pt %s -S -%d; "+
			"else exit 44; fi",
		qLog, lines, qLog, qTask, qTask, lines,
	)

	res, err := m.pool.Exec(ctx, peerName, script, transport.ExecOptions{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 44 {
		return nil, fmt.Errorf("task %q log not found at %s", taskID, logPath)
	}

	cleanedLines := make([]string, 0)
	for _, line := range strings.Split(res.Stdout, "\n") {
		if exitMarkerRegex.MatchString(line) {
			cleaned := strings.TrimSpace(exitMarkerRegex.ReplaceAllString(line, ""))
			if cleaned == "" {
				continue
			}
			cleanedLines = append(cleanedLines, cleaned)
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}
	output := strings.Join(cleanedLines, "\n")

	return map[string]any{
		"peer":     peerName,
		"action":   "tail",
		"task_id":  taskID,
		"log_path": logPath,
		"lines":    lines,
		"output":   output,
		"stdout":   output,
	}, nil
}

func (m *Manager) sendKeysTask(ctx context.Context, peerName, taskID, keys string) (map[string]any, error) {
	qTask := shellSingleQuote(taskID)
	qKeys := shellSingleQuote(keys)

	script := fmt.Sprintf(
		"if command -v tmux >/dev/null 2>&1 && tmux has-session -t %s 2>/dev/null; then "+
			"tmux send-keys -t %s %s Enter; "+
			"else exit 45; fi",
		qTask, qTask, qKeys,
	)
	res, err := m.pool.Exec(ctx, peerName, script, transport.ExecOptions{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 45 {
		return nil, fmt.Errorf("tmux session %q is not active for send_keys", taskID)
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("tmux send-keys failed with code %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}

	return map[string]any{
		"peer":    peerName,
		"action":  "send_keys",
		"task_id": taskID,
		"sent":    true,
	}, nil
}

func (m *Manager) killTask(ctx context.Context, peerName, taskID string) (map[string]any, error) {
	pidPath := fmt.Sprintf("/tmp/%s.pid", taskID)
	qTask := shellSingleQuote(taskID)
	qPid := shellSingleQuote(pidPath)

	script := fmt.Sprintf(
		"killed=0; "+
			"if command -v tmux >/dev/null 2>&1 && tmux has-session -t %s 2>/dev/null; then tmux kill-session -t %s 2>/dev/null && killed=1; fi; "+
			"if [ -f %s ]; then pid=$(cat %s 2>/dev/null); if [ -n \"$pid\" ]; then kill -TERM \"$pid\" 2>/dev/null || true; kill -KILL \"$pid\" 2>/dev/null || true; killed=1; fi; rm -f %s; fi; "+
			"echo KILLED=$killed",
		qTask, qTask, qPid, qPid, qPid,
	)
	res, err := m.pool.Exec(ctx, peerName, script, transport.ExecOptions{Timeout: 8 * time.Second})
	if err != nil {
		return nil, err
	}

	killed := strings.Contains(res.Stdout, "KILLED=1")
	return map[string]any{
		"peer":    peerName,
		"action":  "kill",
		"task_id": taskID,
		"killed":  killed,
		"status":  "killed",
	}, nil
}

func (m *Manager) tmuxPrefix() string {
	if m.cfg != nil && m.cfg.Execution.TmuxPrefix != "" {
		return m.cfg.Execution.TmuxPrefix
	}
	return "sysbridge"
}

func (m *Manager) buildTaskID(taskName string) string {
	prefix := sanitizeIdent(m.tmuxPrefix())
	if prefix == "" {
		prefix = "sysbridge"
	}
	cleanName := sanitizeIdent(taskName)
	seq := atomic.AddUint64(&taskSeq, 1)
	if cleanName != "" {
		if strings.HasPrefix(cleanName, prefix+"_") {
			return cleanName
		}
		return fmt.Sprintf("%s_%s_%d", prefix, cleanName, seq)
	}
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().Unix(), seq)
}

func validateTaskID(taskID string) error {
	trimmed := strings.TrimSpace(taskID)
	if trimmed == "" {
		return errors.New("task_id is required")
	}
	if strings.ContainsAny(trimmed, "/\\ \t\n\r;&|`$") {
		return fmt.Errorf("invalid task_id %q", taskID)
	}
	return nil
}

func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func wrapTaskCommand(command, cwd string, env map[string]string, sudo bool) string {
	var b strings.Builder
	if len(env) > 0 {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if isValidShellVar(k) {
				b.WriteString(fmt.Sprintf("export %s=%s; ", k, shellSingleQuote(env[k])))
			}
		}
	}
	if cwd != "" {
		b.WriteString(fmt.Sprintf("cd %s && ", shellSingleQuote(cwd)))
	}
	if sudo {
		b.WriteString("sudo -E /bin/sh -c ")
		b.WriteString(shellSingleQuote(command))
	} else {
		b.WriteString(command)
	}
	return b.String()
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isValidShellVar(k string) bool {
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
