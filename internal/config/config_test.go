package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAndSaveLoadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.yaml")

	cfg := DefaultConfig()
	if cfg.Server.Transport != "stdio" {
		t.Fatalf("expected default transport stdio, got %s", cfg.Server.Transport)
	}

	cfg.UpsertPeer(&PeerConfig{
		Name:    "vps",
		Host:    "203.0.113.10",
		User:    "ubuntu",
		SSHPort: 2222,
	})

	if err := Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config failed: %v", err)
	}

	loaded, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config failed: %v", err)
	}

	peer, err := loaded.ResolvePeer("vps")
	if err != nil {
		t.Fatalf("resolve peer vps failed: %v", err)
	}
	if peer.Host != "203.0.113.10" || peer.SSHPort != 2222 {
		t.Fatalf("unexpected peer config: %+v", peer)
	}

	localPeer, err := loaded.ResolvePeer("local")
	if err != nil {
		t.Fatalf("resolve local peer failed: %v", err)
	}
	if localPeer.VFS.Backend != "local-mount" {
		t.Fatalf("expected local-mount backend for local peer, got %s", localPeer.VFS.Backend)
	}

	byDomain, err := loaded.ResolvePeer("laptop.local")
	if err != nil || byDomain.Name != "laptop" {
		t.Fatalf("domain resolution failed: %v, peer=%+v", err, byDomain)
	}

	_ = os.Remove(cfgPath)
}
