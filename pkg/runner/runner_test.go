package runner

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

func newTestManager(detachedBackend string) *Manager {
	cfg := config.DefaultConfig()
	cfg.DefaultPeer = "local"
	cfg.Execution.DetachedBackend = detachedBackend
	cfg.Execution.AutoDetachMs = 200
	guard := safety.NewGuard(cfg.Safety.BlockedDevices, cfg.Safety.BlockedPaths, cfg.Safety.ConfirmDestructive)
	pool := transport.NewPool(cfg, guard, nil)
	return NewManager(pool, cfg)
}

func TestRunSyncAndGuard(t *testing.T) {
	mgr := newTestManager("nohup")
	ctx := context.Background()

	_, err := mgr.Run(ctx, RunOptions{
		Peer:    "local",
		Command: "mkfs.ext4 /dev/sda1",
	})
	if err == nil || !strings.Contains(err.Error(), "safety guard") {
		t.Fatalf("expected safety guard error, got %v", err)
	}

	tmpDir := t.TempDir()
	out, err := mgr.Run(ctx, RunOptions{
		Peer:    "local",
		Command: "printf '%s:%s' \"$TEST_TOKEN\" \"$(pwd)\"",
		Cwd:     tmpDir,
		Env:     map[string]string{"TEST_TOKEN": "alpha42"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if out.Detached {
		t.Fatalf("expected synchronous execution, got detached")
	}
	if out.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", out.ExitCode)
	}
	want := "alpha42:" + tmpDir
	if strings.TrimSpace(out.Stdout) != want {
		t.Fatalf("stdout = %q, want %q", out.Stdout, want)
	}
}

func TestDetachedNohupLifecycle(t *testing.T) {
	mgr := newTestManager("nohup")
	ctx := context.Background()

	out, err := mgr.Run(ctx, RunOptions{
		Peer:     "local",
		Command:  "echo line_one; echo line_two",
		Detached: true,
		TaskName: "unit_nohup",
	})
	if err != nil {
		t.Fatalf("detached Run failed: %v", err)
	}
	if !out.Detached || out.TaskID == "" || out.Backend != "nohup" {
		t.Fatalf("unexpected detached output: %+v", out)
	}
	defer func() {
		_ = os.Remove(out.LogPath)
		_ = os.Remove("/tmp/" + out.TaskID + ".pid")
	}()

	deadline := time.Now().Add(3 * time.Second)
	var statusMap map[string]any
	for time.Now().Before(deadline) {
		statusMap, err = mgr.TaskAction(ctx, "local", "status", out.TaskID, "", 0)
		if err != nil {
			t.Fatalf("status action failed: %v", err)
		}
		if statusMap["status"] == "completed" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if statusMap["status"] != "completed" {
		t.Fatalf("expected status completed, got %+v", statusMap)
	}

	tailMap, err := mgr.TaskAction(ctx, "local", "tail", out.TaskID, "", 20)
	if err != nil {
		t.Fatalf("tail action failed: %v", err)
	}
	tailOut, _ := tailMap["output"].(string)
	if !strings.Contains(tailOut, "line_one") || !strings.Contains(tailOut, "line_two") {
		t.Fatalf("unexpected tail output: %q", tailOut)
	}
	if strings.Contains(tailOut, "__SYSBRIDGE_EXIT") {
		t.Fatalf("tail output leaked exit marker: %q", tailOut)
	}

	listMap, err := mgr.TaskAction(ctx, "local", "list", "", "", 0)
	if err != nil {
		t.Fatalf("list action failed: %v", err)
	}
	count, _ := listMap["count"].(int)
	if count < 1 {
		t.Fatalf("expected at least 1 task in list, got %+v", listMap)
	}
}

func TestAutoDetachOnTimeout(t *testing.T) {
	mgr := newTestManager("nohup")
	ctx := context.Background()

	out, err := mgr.Run(ctx, RunOptions{
		Peer:      "local",
		Command:   "sleep 2; echo done_after_sleep",
		TaskName:  "autodetach_job",
		TimeoutMs: 120,
	})
	if err != nil {
		t.Fatalf("Run auto-detach failed: %v", err)
	}
	if !out.Detached || out.TaskID == "" {
		t.Fatalf("expected task to auto-detach, got %+v", out)
	}
	defer func() {
		_, _ = mgr.TaskAction(ctx, "local", "kill", out.TaskID, "", 0)
		_ = os.Remove(out.LogPath)
		_ = os.Remove("/tmp/" + out.TaskID + ".pid")
	}()

	killRes, err := mgr.TaskAction(ctx, "local", "kill", out.TaskID, "", 0)
	if err != nil {
		t.Fatalf("kill action failed: %v", err)
	}
	if killRes["status"] != "killed" {
		t.Fatalf("unexpected kill response: %+v", killRes)
	}
}
