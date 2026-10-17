package tunnel

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

func startEchoServer(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return port, func() { _ = ln.Close() }
}

func TestSupervisorAddForwardAndPersist(t *testing.T) {
	tmpCfg := t.TempDir()
	tmpRun := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmpCfg)
	t.Setenv("XDG_RUNTIME_DIR", tmpRun)

	echoPort, stopEcho := startEchoServer(t)
	defer stopEcho()

	cfg := config.DefaultConfig()
	cfg.DefaultPeer = "local"
	guard := safety.NewGuard(nil, nil, false)
	pool := transport.NewPool(cfg, guard, nil)

	sup := NewSupervisor(pool)
	defer sup.Close()

	ctx := context.Background()
	localRule, err := sup.AddRule(ctx, &Rule{
		Name:       "echo_local",
		Peer:       "local",
		LocalPort:  0,
		RemotePort: echoPort,
		TargetHost: "127.0.0.1",
		Type:       "local",
		Temporary:  false,
	})
	if err != nil {
		t.Fatalf("AddRule local failed: %v", err)
	}
	if localRule.LocalPort <= 0 || localRule.Status != "active" {
		t.Fatalf("unexpected local rule state: %+v", localRule)
	}

	persistPath := filepath.Join(config.UserConfigDir(), "tunnels.d", "echo_local.json")
	if _, err := os.Stat(persistPath); err != nil {
		t.Fatalf("expected persistent rule file at %s: %v", persistPath, err)
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(localRule.LocalPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial local forward port failed: %v", err)
	}
	defer conn.Close()

	msg := "ping_sysbridge_tunnel"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write to tunnel failed: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read from tunnel failed: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", string(buf), msg)
	}

	revRule, err := sup.AddRule(ctx, &Rule{
		Name:       "echo_reverse",
		Peer:       "local",
		LocalPort:  echoPort,
		RemotePort: 0,
		TargetHost: "127.0.0.1",
		Type:       "reverse",
		Temporary:  true,
	})
	if err != nil {
		t.Fatalf("AddRule reverse failed: %v", err)
	}

	ramPath := filepath.Join(config.UserRuntimeDir(), "tunnels.ram", "echo_reverse.json")
	if _, err := os.Stat(ramPath); err != nil {
		t.Fatalf("expected temporary rule file at %s: %v", ramPath, err)
	}

	rConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(revRule.RemotePort)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial reverse forward port failed: %v", err)
	}
	defer rConn.Close()

	if _, err := rConn.Write([]byte(msg)); err != nil {
		t.Fatalf("write reverse tunnel failed: %v", err)
	}
	if _, err := io.ReadFull(rConn, buf); err != nil {
		t.Fatalf("read reverse tunnel failed: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("reverse got %q, want %q", string(buf), msg)
	}

	rules := sup.ListRules()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	if err := sup.RemoveRule("echo_reverse"); err != nil {
		t.Fatalf("RemoveRule failed: %v", err)
	}
	if _, err := os.Stat(ramPath); !os.IsNotExist(err) {
		t.Fatalf("expected ram rule file removed, err=%v", err)
	}

	sup.Close()

	sup2 := NewSupervisor(pool)
	defer sup2.Close()
	sup2.SyncAll(ctx)

	reloaded := sup2.ListRules()
	if len(reloaded) != 1 || reloaded[0].Name != "echo_local" || reloaded[0].Status != "active" {
		t.Fatalf("expected reloaded active rule echo_local, got %+v", reloaded)
	}
}
