package sysinfo

import (
	"context"
	"strings"
	"testing"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

func newTestBridge() *Bridge {
	cfg := config.DefaultConfig()
	guard := safety.NewGuard(cfg.Safety.BlockedDevices, cfg.Safety.BlockedPaths, cfg.Safety.ConfirmDestructive)
	pool := transport.NewPool(cfg, guard, nil)
	return NewBridge(pool, cfg)
}

func TestCollectTelemetryLocal(t *testing.T) {
	b := newTestBridge()
	rep, err := b.CollectTelemetry(context.Background(), "local")
	if err != nil {
		t.Fatalf("CollectTelemetry on local failed: %v", err)
	}
	if rep.Peer != "local" {
		t.Errorf("expected Peer 'local', got %q", rep.Peer)
	}
	if rep.Hostname == "" {
		t.Errorf("expected non-empty Hostname")
	}
	if rep.Kernel == "" {
		t.Errorf("expected non-empty Kernel")
	}
	if rep.Arch == "" {
		t.Errorf("expected non-empty Arch")
	}
	if rep.Uptime == "" {
		t.Errorf("expected non-empty Uptime")
	}
	if rep.MemorySummary == "" {
		t.Errorf("expected non-empty MemorySummary")
	}
}

func TestProvisionPeerAuditLocal(t *testing.T) {
	b := newTestBridge()
	rep, err := b.ProvisionPeer(context.Background(), "local", "audit", "", false)
	if err != nil {
		t.Fatalf("ProvisionPeer audit on local failed: %v", err)
	}
	if rep.Peer != "local" {
		t.Errorf("expected Peer 'local', got %q", rep.Peer)
	}
	if rep.Action != "audit" {
		t.Errorf("expected Action 'audit', got %q", rep.Action)
	}
	expectedKeys := []string{
		"sftp",
		"tmux",
		"mosh-server",
		"rsync",
		"rg",
		"sysbridge",
		"pam_ssh_agent_auth.so",
		"systemd --user",
	}
	for _, k := range expectedKeys {
		if _, exists := rep.Capabilities[k]; !exists {
			t.Errorf("expected capability key %q in Capabilities map", k)
		}
	}
}

func TestProvisionPeerPamSSHSudoDryRun(t *testing.T) {
	b := newTestBridge()
	dummyKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@sysbridge"
	rep, err := b.ProvisionPeer(context.Background(), "local", "setup_pam_ssh_sudo", dummyKey, false)
	if err != nil {
		t.Fatalf("ProvisionPeer setup_pam_ssh_sudo dry-run failed: %v", err)
	}
	if rep.Applied {
		t.Errorf("expected Applied=false on dry-run")
	}
	mustContain := []string{
		"/etc/security/authorized_keys",
		"/etc/sudoers.d/sysbridge-agent",
		`Defaults env_keep += "SSH_AUTH_SOCK"`,
		"auth sufficient pam_ssh_agent_auth.so file=/etc/security/authorized_keys",
		dummyKey,
	}
	for _, needle := range mustContain {
		if !strings.Contains(rep.Instructions, needle) {
			t.Errorf("expected Instructions to contain %q, got:\n%s", needle, rep.Instructions)
		}
	}

	meshRep, err := b.ProvisionPeer(context.Background(), "local", "setup_user_mesh", "", false)
	if err != nil {
		t.Fatalf("ProvisionPeer setup_user_mesh dry-run failed: %v", err)
	}
	if meshRep.Applied {
		t.Errorf("expected Applied=false on setup_user_mesh dry-run")
	}
	if !strings.Contains(meshRep.Instructions, "sysbridge-mesh.service") || !strings.Contains(meshRep.Instructions, "42424") {
		t.Errorf("expected setup_user_mesh instructions to reference sysbridge-mesh.service and port 42424, got:\n%s", meshRep.Instructions)
	}
}
