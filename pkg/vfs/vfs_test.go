package vfs

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
)

func setupTestEngine(t *testing.T) (*Engine, string) {
	t.Helper()
	tmpDir := t.TempDir()

	cfg := config.DefaultConfig()
	cfg.DefaultPeer = "local"
	cfg.UpsertPeer(&config.PeerConfig{
		Name: "local-peer",
		Host: "127.0.0.1",
		VFS: config.VFSConfig{
			Backend:       "local-mount",
			WorkspaceRoot: tmpDir,
		},
	})

	guard := safety.NewGuard(
		cfg.Safety.BlockedDevices,
		cfg.Safety.BlockedPaths,
		cfg.Safety.ConfirmDestructive,
	)
	pool := transport.NewPool(cfg, guard, nil)
	return NewEngine(pool), tmpDir
}

func TestWriteAndReadFile(t *testing.T) {
	eng, tmpDir := setupTestEngine(t)
	ctx := context.Background()

	target := filepath.Join(tmpDir, "notes", "hello.txt")
	content := "line1\nline2\nline3\nline4"

	wRes, err := eng.WriteFile(ctx, "local-peer", "notes/hello.txt", content, 0640)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if wRes.Backend != "local-mount" {
		t.Fatalf("expected backend local-mount, got %s", wRes.Backend)
	}
	if wRes.Path != target {
		t.Fatalf("expected path %s, got %s", target, wRes.Path)
	}
	if wRes.BytesWritten != len(content) {
		t.Fatalf("expected %d bytes written, got %d", len(content), wRes.BytesWritten)
	}
	if wRes.SHA256 == "" {
		t.Fatal("expected non-empty sha256")
	}

	rRes, err := eng.ReadFile(ctx, "local-peer", target, 0, 0)
	if err != nil {
		t.Fatalf("ReadFile full failed: %v", err)
	}
	if rRes.Content != content {
		t.Fatalf("expected content %q, got %q", content, rRes.Content)
	}
	if rRes.TotalLines != 4 {
		t.Fatalf("expected 4 total lines, got %d", rRes.TotalLines)
	}

	sliceRes, err := eng.ReadFile(ctx, "local-peer", target, 1, 2)
	if err != nil {
		t.Fatalf("ReadFile slice failed: %v", err)
	}
	if sliceRes.Content != "line2\nline3" {
		t.Fatalf("expected sliced content 'line2\\nline3', got %q", sliceRes.Content)
	}
	if sliceRes.StartLine != 2 || sliceRes.EndLine != 3 {
		t.Fatalf("unexpected line bounds: start=%d end=%d", sliceRes.StartLine, sliceRes.EndLine)
	}

	binPath := filepath.Join(tmpDir, "bin.dat")
	if err := os.WriteFile(binPath, []byte{0x00, 0x01, 0x02, 0xff}, 0600); err != nil {
		t.Fatalf("write binary file: %v", err)
	}
	binRes, err := eng.ReadFile(ctx, "local-peer", binPath, 0, 0)
	if err != nil {
		t.Fatalf("ReadFile binary failed: %v", err)
	}
	if !binRes.IsBinary || binRes.Base64Data == "" {
		t.Fatalf("expected binary detection with base64 payload, got %+v", binRes)
	}
}

func TestEditAndMultiEdit(t *testing.T) {
	eng, tmpDir := setupTestEngine(t)
	ctx := context.Background()

	target := filepath.Join(tmpDir, "config.ini")
	initial := "host = 127.0.0.1\nport = 8080\nmode = debug\ndebug_flag = debug\n"
	if _, err := eng.WriteFile(ctx, "local-peer", target, initial, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	eRes, err := eng.EditFile(ctx, "local-peer", target, "port = 8080", "port = 9090", false)
	if err != nil {
		t.Fatalf("EditFile failed: %v", err)
	}
	if eRes.Replacements != 1 {
		t.Fatalf("expected 1 replacement, got %d", eRes.Replacements)
	}

	if _, err := eng.EditFile(ctx, "local-peer", target, "debug", "prod", false); err == nil {
		t.Fatal("expected error when multiple occurrences match with replaceAll=false")
	}

	mRes, err := eng.MultiEdit(ctx, "local-peer", target, []EditOp{
		{OldString: "host = 127.0.0.1", NewString: "host = 0.0.0.0", ReplaceAll: false},
		{OldString: "debug", NewString: "release", ReplaceAll: true},
	})
	if err != nil {
		t.Fatalf("MultiEdit failed: %v", err)
	}
	if mRes.Replacements != 4 {
		t.Fatalf("expected 4 total replacements, got %d", mRes.Replacements)
	}

	rRes, err := eng.ReadFile(ctx, "local-peer", target, 0, 0)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	expected := "host = 0.0.0.0\nport = 9090\nmode = release\nrelease_flag = release\n"
	if rRes.Content != expected {
		t.Fatalf("expected %q, got %q", expected, rRes.Content)
	}

	st, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("expected atomic write to preserve 0600 permissions, got %04o", st.Mode().Perm())
	}
}

func TestSearch(t *testing.T) {
	eng, tmpDir := setupTestEngine(t)
	ctx := context.Background()

	_, _ = eng.WriteFile(ctx, "local-peer", "src/alpha.go", "package main\nfunc AlphaTarget() {}\n", 0644)
	_, _ = eng.WriteFile(ctx, "local-peer", "src/beta.txt", "nothing here\nAlphaTarget in text\n", 0644)

	sRes, err := eng.Search(ctx, "local-peer", tmpDir, "AlphaTarget", "*.go", 10)
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(sRes.Matches) != 1 {
		t.Fatalf("expected 1 match for *.go, got %d", len(sRes.Matches))
	}
	if sRes.Matches[0].Line != 2 {
		t.Fatalf("expected match on line 2, got %d", sRes.Matches[0].Line)
	}

	fRes, err := eng.Search(ctx, "local-peer", tmpDir, "", "*.txt", 10)
	if err != nil {
		t.Fatalf("Search file list failed: %v", err)
	}
	if len(fRes.Files) != 1 || !strings.HasSuffix(fRes.Files[0], "beta.txt") {
		t.Fatalf("expected beta.txt in file search, got %+v", fRes.Files)
	}
}

func TestOpsAndSafetyGuard(t *testing.T) {
	eng, tmpDir := setupTestEngine(t)
	ctx := context.Background()

	dirA := filepath.Join(tmpDir, "dirA")
	if _, err := eng.Ops(ctx, "local-peer", "mkdir", dirA, "", 0755, false); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	fileA := filepath.Join(dirA, "item.txt")
	if _, err := eng.WriteFile(ctx, "local-peer", fileA, "payload", 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	statRes, err := eng.Ops(ctx, "local-peer", "stat", fileA, "", 0, false)
	if err != nil || statRes.Stat == nil || statRes.Stat.Size != 7 {
		t.Fatalf("stat failed: err=%v res=%+v", err, statRes)
	}

	shaRes, err := eng.Ops(ctx, "local-peer", "sha256", fileA, "", 0, false)
	if err != nil || len(shaRes.SHA256) != 64 {
		t.Fatalf("sha256 failed: err=%v res=%+v", err, shaRes)
	}

	if _, err := eng.Ops(ctx, "local-peer", "chmod", fileA, "", 0600, false); err != nil {
		t.Fatalf("chmod failed: %v", err)
	}

	fileB := filepath.Join(dirA, "copied.txt")
	if _, err := eng.Ops(ctx, "local-peer", "cp", fileA, fileB, 0, false); err != nil {
		t.Fatalf("cp failed: %v", err)
	}

	fileC := filepath.Join(dirA, "moved.txt")
	if _, err := eng.Ops(ctx, "local-peer", "mv", fileB, fileC, 0, false); err != nil {
		t.Fatalf("mv failed: %v", err)
	}

	lsRes, err := eng.Ops(ctx, "local-peer", "ls", dirA, "", 0, false)
	if err != nil || len(lsRes.Entries) != 2 {
		t.Fatalf("ls failed: err=%v entries=%d", err, len(lsRes.Entries))
	}

	treeRes, err := eng.Ops(ctx, "local-peer", "tree", tmpDir, "", 0, false)
	if err != nil || len(treeRes.Entries) < 3 {
		t.Fatalf("tree failed: err=%v entries=%d", err, len(treeRes.Entries))
	}

	if _, err := eng.Ops(ctx, "local-peer", "rm", fileC, "", 0, false); err == nil {
		t.Fatal("expected rm without confirm=true to be rejected by safety guard")
	}

	if _, err := eng.Ops(ctx, "local-peer", "rm", fileC, "", 0, true); err != nil {
		t.Fatalf("rm with confirm=true failed: %v", err)
	}

	if _, err := eng.ReadFile(ctx, "local-peer", "/dev/sda", 0, 0); err == nil {
		t.Fatal("expected safety guard to reject /dev/sda on ReadFile")
	}
	if _, err := eng.WriteFile(ctx, "local-peer", "/dev/sda1", "bad", 0644); err == nil {
		t.Fatal("expected safety guard to reject /dev/sda1 on WriteFile")
	}
	if _, err := eng.Ops(ctx, "local-peer", "stat", "/dev/sda", "", 0, false); err == nil {
		t.Fatal("expected safety guard to reject /dev/sda on Ops")
	}
}
