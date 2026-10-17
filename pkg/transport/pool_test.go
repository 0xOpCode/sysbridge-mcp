package transport

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
)

func TestPoolLocalExecAndSafetyGuard(t *testing.T) {
	cfg := config.DefaultConfig()
	guard := safety.NewGuard(cfg.Safety.BlockedDevices, cfg.Safety.BlockedPaths, true)
	pool := NewPool(cfg, guard, nil)
	defer pool.Close()

	ctx := context.Background()
	res, err := pool.Exec(ctx, "local", "printf 'sysbridge_ok'", ExecOptions{
		Timeout: 5 * time.Second,
		Env:     map[string]string{"TEST_VAR": "hello"},
	})
	if err != nil {
		t.Fatalf("local exec failed: %v", err)
	}
	if res.ExitCode != 0 || !strings.Contains(res.Stdout, "sysbridge_ok") {
		t.Fatalf("unexpected exec result: %+v", res)
	}

	if _, err := pool.Exec(ctx, "local", "fdisk /dev/sda", ExecOptions{}); err == nil {
		t.Fatal("expected blocked device command to fail")
	}
}
