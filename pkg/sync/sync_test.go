package sync

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/safety"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
	"github.com/pkg/sftp"
)

func newTestEngine() *Engine {
	cfg := config.DefaultConfig()
	cfg.DefaultPeer = "local"
	guard := safety.NewGuard(cfg.Safety.BlockedDevices, cfg.Safety.BlockedPaths, cfg.Safety.ConfirmDestructive)
	pool := transport.NewPool(cfg, guard, nil)
	return NewEngine(pool)
}

func startPipeSFTP(t *testing.T) (*sftp.Client, func()) {
	t.Helper()
	c1, c2 := net.Pipe()
	srv, err := sftp.NewServer(c1)
	if err != nil {
		t.Fatalf("new sftp server: %v", err)
	}
	go func() {
		_ = srv.Serve()
	}()
	cli, err := sftp.NewClientPipe(c2, c2)
	if err != nil {
		_ = c1.Close()
		_ = c2.Close()
		t.Fatalf("new sftp client pipe: %v", err)
	}
	cleanup := func() {
		_ = cli.Close()
		_ = srv.Close()
		_ = c1.Close()
		_ = c2.Close()
	}
	return cli, cleanup
}

func TestPushPullAndSafety(t *testing.T) {
	eng := newTestEngine()
	ctx := context.Background()

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	srcFile := filepath.Join(srcDir, "payload.txt")
	content := []byte("sysbridge_sync_payload_data")
	if err := os.WriteFile(srcFile, content, 0640); err != nil {
		t.Fatalf("write src file: %v", err)
	}

	if _, err := eng.PushFile(ctx, "local", srcFile, "/boot/efi/payload.txt"); err == nil {
		t.Fatalf("expected safety guard error for /boot/efi")
	}

	dstFile := filepath.Join(dstDir, "pushed.txt")
	pushRes, err := eng.PushFile(ctx, "local", srcFile, dstFile)
	if err != nil {
		t.Fatalf("PushFile failed: %v", err)
	}
	if pushRes.BytesTransferred != int64(len(content)) || pushRes.FilesSynced != 1 {
		t.Fatalf("unexpected PushFile result: %+v", pushRes)
	}

	pulledFile := filepath.Join(srcDir, "pulled.txt")
	pullRes, err := eng.PullFile(ctx, "local", dstFile, pulledFile)
	if err != nil {
		t.Fatalf("PullFile failed: %v", err)
	}
	if pullRes.BytesTransferred != int64(len(content)) {
		t.Fatalf("unexpected PullFile result: %+v", pullRes)
	}

	got, err := os.ReadFile(pulledFile)
	if err != nil || string(got) != string(content) {
		t.Fatalf("pulled content = %q, want %q (err=%v)", string(got), string(content), err)
	}
}

func TestSyncDirSkipsAndDeletesExtra(t *testing.T) {
	eng := newTestEngine()
	ctx := context.Background()

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	mustWrite := func(base, rel, data string) {
		full := filepath.Join(base, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(data), 0644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	mustWrite(srcDir, "app/main.go", "package main")
	mustWrite(srcDir, ".git/config", "gitdata")
	mustWrite(srcDir, "node_modules/pkg/index.js", "module")
	mustWrite(srcDir, "bin/compiled", "binary")
	mustWrite(srcDir, "app/cache.tmp", "temp")
	mustWrite(dstDir, "stale.txt", "remove_me")

	res, err := eng.SyncDir(ctx, "local", srcDir, dstDir, true)
	if err != nil {
		t.Fatalf("SyncDir failed: %v", err)
	}
	if res.FilesSynced != 1 {
		t.Fatalf("expected 1 synced file, got %d", res.FilesSynced)
	}

	if _, err := os.Stat(filepath.Join(dstDir, "app/main.go")); err != nil {
		t.Fatalf("expected app/main.go to exist: %v", err)
	}
	for _, skipped := range []string{".git/config", "node_modules/pkg/index.js", "bin/compiled", "app/cache.tmp", "stale.txt"} {
		if _, err := os.Stat(filepath.Join(dstDir, skipped)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be absent in dstDir", skipped)
		}
	}
}

func TestSFTPDeltaAndTransfer(t *testing.T) {
	sftpCli, cleanup := startPipeSFTP(t)
	defer cleanup()

	srcDir := t.TempDir()
	dstDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(srcDir, "hello.txt"), []byte("sftp_content"), 0644); err != nil {
		t.Fatalf("write hello.txt: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(srcDir, ".git"), 0755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, ".git", "HEAD"), []byte("ref"), 0644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}

	n, files, err := syncSFTPDelta(context.Background(), sftpCli, srcDir, dstDir, true)
	if err != nil {
		t.Fatalf("syncSFTPDelta failed: %v", err)
	}
	if files != 1 || n != int64(len("sftp_content")) {
		t.Fatalf("unexpected syncSFTPDelta stats: files=%d bytes=%d", files, n)
	}

	dlPath := filepath.Join(t.TempDir(), "downloaded.txt")
	dlBytes, err := downloadViaSFTP(sftpCli, filepath.Join(dstDir, "hello.txt"), dlPath)
	if err != nil {
		t.Fatalf("downloadViaSFTP failed: %v", err)
	}
	if dlBytes != int64(len("sftp_content")) {
		t.Fatalf("dlBytes = %d", dlBytes)
	}
	f, err := os.Open(dlPath)
	if err != nil {
		t.Fatalf("open dlPath: %v", err)
	}
	defer f.Close()
	data, _ := io.ReadAll(f)
	if string(data) != "sftp_content" {
		t.Fatalf("downloaded data = %q", string(data))
	}
}

func TestWatchLifecycle(t *testing.T) {
	eng := newTestEngine()
	ctx := context.Background()

	srcDir := t.TempDir()
	dstDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "watched.txt"), []byte("v1"), 0644); err != nil {
		t.Fatalf("write watched.txt: %v", err)
	}

	watchID, err := eng.StartWatch(ctx, "local", srcDir, dstDir, 1)
	if err != nil {
		t.Fatalf("StartWatch failed: %v", err)
	}

	watches := eng.ListWatches()
	if len(watches) != 1 || watches[0] != watchID {
		t.Fatalf("unexpected watches list: %+v", watches)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dstDir, "watched.txt")); err == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "watched.txt")); err != nil {
		t.Fatalf("expected watched.txt synced to dstDir: %v", err)
	}

	if err := eng.StopWatch(watchID); err != nil {
		t.Fatalf("StopWatch failed: %v", err)
	}
	if len(eng.ListWatches()) != 0 {
		t.Fatalf("expected 0 active watches after StopWatch")
	}
}
