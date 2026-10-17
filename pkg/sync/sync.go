package sync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
	"github.com/pkg/sftp"
)

var watchSeq uint64

type TransferResult struct {
	Action           string `json:"action"`
	Peer             string `json:"peer"`
	LocalPath        string `json:"local_path"`
	RemotePath       string `json:"remote_path"`
	BytesTransferred int64  `json:"bytes_transferred"`
	FilesSynced      int    `json:"files_synced"`
	Method           string `json:"method"`
	DurationMs       int64  `json:"duration_ms"`
}

type watchJob struct {
	id        string
	peer      string
	localDir  string
	remoteDir string
	interval  time.Duration
	cancel    context.CancelFunc
}

type Engine struct {
	mu      sync.Mutex
	pool    *transport.Pool
	watches map[string]*watchJob
}

func NewEngine(pool *transport.Pool) *Engine {
	return &Engine{
		pool:    pool,
		watches: make(map[string]*watchJob),
	}
}

func (e *Engine) PushFile(ctx context.Context, peerName, localPath, remotePath string) (*TransferResult, error) {
	start := time.Now()
	if strings.TrimSpace(localPath) == "" {
		return nil, errors.New("local_path is required")
	}
	absLocal := config.ExpandPath(localPath)
	if err := e.checkPath(absLocal); err != nil {
		return nil, err
	}

	info, err := os.Stat(absLocal)
	if err != nil {
		return nil, fmt.Errorf("stat local file %s: %w", absLocal, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("local_path %s is a directory; use SyncDir instead", absLocal)
	}

	peer, host, port, _, err := e.pool.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	targetRemote := strings.TrimSpace(remotePath)
	if targetRemote == "" {
		if peer.VFS.DownloadsDir != "" {
			targetRemote = path.Join(filepath.ToSlash(peer.VFS.DownloadsDir), filepath.Base(absLocal))
		} else {
			targetRemote = path.Join("/tmp", filepath.Base(absLocal))
		}
	} else if strings.HasSuffix(targetRemote, "/") {
		targetRemote = path.Join(filepath.ToSlash(targetRemote), filepath.Base(absLocal))
	}

	if err := e.checkPath(targetRemote); err != nil {
		return nil, err
	}

	if peer.Name == "local" {
		if st, stErr := os.Stat(targetRemote); stErr == nil && st.IsDir() {
			targetRemote = filepath.Join(targetRemote, filepath.Base(absLocal))
		}
		n, cpErr := copyLocalFile(absLocal, targetRemote, info.Mode())
		if cpErr != nil {
			return nil, cpErr
		}
		return &TransferResult{
			Action:           "push",
			Peer:             peer.Name,
			LocalPath:        absLocal,
			RemotePath:       targetRemote,
			BytesTransferred: n,
			FilesSynced:      1,
			Method:           "local-copy",
			DurationMs:       time.Since(start).Milliseconds(),
		}, nil
	}

	sftpCli, _, sftpErr := e.pool.GetSFTPClient(ctx, peer.Name)
	if sftpErr == nil && sftpCli != nil {
		if st, stErr := sftpCli.Stat(targetRemote); stErr == nil && st.IsDir() {
			targetRemote = path.Join(filepath.ToSlash(targetRemote), filepath.Base(absLocal))
		}
		n, upErr := uploadViaSFTP(sftpCli, absLocal, targetRemote, info.Mode())
		if upErr == nil {
			return &TransferResult{
				Action:           "push",
				Peer:             peer.Name,
				LocalPath:        absLocal,
				RemotePath:       targetRemote,
				BytesTransferred: n,
				FilesSynced:      1,
				Method:           "sftp",
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
	}

	if err := e.scpTransfer(ctx, peer, host, port, absLocal, targetRemote, true); err != nil {
		return nil, err
	}

	return &TransferResult{
		Action:           "push",
		Peer:             peer.Name,
		LocalPath:        absLocal,
		RemotePath:       targetRemote,
		BytesTransferred: info.Size(),
		FilesSynced:      1,
		Method:           "scp",
		DurationMs:       time.Since(start).Milliseconds(),
	}, nil
}

func (e *Engine) PullFile(ctx context.Context, peerName, remotePath, localPath string) (*TransferResult, error) {
	start := time.Now()
	if strings.TrimSpace(remotePath) == "" {
		return nil, errors.New("remote_path is required")
	}
	if err := e.checkPath(remotePath); err != nil {
		return nil, err
	}

	peer, host, port, _, err := e.pool.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	targetLocal := config.ExpandPath(strings.TrimSpace(localPath))
	if targetLocal == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			targetLocal = filepath.Join(home, "Downloads", path.Base(filepath.ToSlash(remotePath)))
		} else {
			targetLocal = filepath.Join("/tmp", path.Base(filepath.ToSlash(remotePath)))
		}
	} else if strings.HasSuffix(targetLocal, string(os.PathSeparator)) || strings.HasSuffix(targetLocal, "/") {
		targetLocal = filepath.Join(targetLocal, path.Base(filepath.ToSlash(remotePath)))
	} else if st, stErr := os.Stat(targetLocal); stErr == nil && st.IsDir() {
		targetLocal = filepath.Join(targetLocal, path.Base(filepath.ToSlash(remotePath)))
	}

	if err := e.checkPath(targetLocal); err != nil {
		return nil, err
	}

	if peer.Name == "local" {
		st, stErr := os.Stat(remotePath)
		if stErr != nil {
			return nil, fmt.Errorf("stat source file %s: %w", remotePath, stErr)
		}
		n, cpErr := copyLocalFile(remotePath, targetLocal, st.Mode())
		if cpErr != nil {
			return nil, cpErr
		}
		return &TransferResult{
			Action:           "pull",
			Peer:             peer.Name,
			LocalPath:        targetLocal,
			RemotePath:       remotePath,
			BytesTransferred: n,
			FilesSynced:      1,
			Method:           "local-copy",
			DurationMs:       time.Since(start).Milliseconds(),
		}, nil
	}

	sftpCli, _, sftpErr := e.pool.GetSFTPClient(ctx, peer.Name)
	if sftpErr == nil && sftpCli != nil {
		n, dlErr := downloadViaSFTP(sftpCli, remotePath, targetLocal)
		if dlErr == nil {
			return &TransferResult{
				Action:           "pull",
				Peer:             peer.Name,
				LocalPath:        targetLocal,
				RemotePath:       remotePath,
				BytesTransferred: n,
				FilesSynced:      1,
				Method:           "sftp",
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(targetLocal), 0755); err != nil {
		return nil, err
	}
	if err := e.scpTransfer(ctx, peer, host, port, targetLocal, remotePath, false); err != nil {
		return nil, err
	}
	var size int64
	if st, stErr := os.Stat(targetLocal); stErr == nil {
		size = st.Size()
	}

	return &TransferResult{
		Action:           "pull",
		Peer:             peer.Name,
		LocalPath:        targetLocal,
		RemotePath:       remotePath,
		BytesTransferred: size,
		FilesSynced:      1,
		Method:           "scp",
		DurationMs:       time.Since(start).Milliseconds(),
	}, nil
}

func (e *Engine) SyncDir(ctx context.Context, peerName, localDir, remoteDir string, deleteExtra bool) (*TransferResult, error) {
	start := time.Now()
	if strings.TrimSpace(localDir) == "" || strings.TrimSpace(remoteDir) == "" {
		return nil, errors.New("local_dir and remote_dir are required")
	}

	absLocal := config.ExpandPath(localDir)
	if err := e.checkPath(absLocal); err != nil {
		return nil, err
	}
	if err := e.checkPath(remoteDir); err != nil {
		return nil, err
	}

	st, err := os.Stat(absLocal)
	if err != nil {
		return nil, fmt.Errorf("stat local_dir %s: %w", absLocal, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("local_dir %s is not a directory", absLocal)
	}

	peer, host, port, _, err := e.pool.ResolveTarget(peerName)
	if err != nil {
		return nil, err
	}

	if peer.Name == "local" {
		bytesCopied, filesSynced, syncErr := syncLocalDelta(absLocal, remoteDir, deleteExtra)
		if syncErr != nil {
			return nil, syncErr
		}
		return &TransferResult{
			Action:           "sync",
			Peer:             peer.Name,
			LocalPath:        absLocal,
			RemotePath:       remoteDir,
			BytesTransferred: bytesCopied,
			FilesSynced:      filesSynced,
			Method:           "delta-local",
			DurationMs:       time.Since(start).Milliseconds(),
		}, nil
	}

	if _, lookErr := exec.LookPath("rsync"); lookErr == nil {
		if err := e.rsyncTransfer(ctx, peer, host, port, absLocal, remoteDir, deleteExtra); err == nil {
			totalBytes, totalFiles := countLocalEligibleFiles(absLocal)
			return &TransferResult{
				Action:           "sync",
				Peer:             peer.Name,
				LocalPath:        absLocal,
				RemotePath:       remoteDir,
				BytesTransferred: totalBytes,
				FilesSynced:      totalFiles,
				Method:           "rsync",
				DurationMs:       time.Since(start).Milliseconds(),
			}, nil
		}
	}

	sftpCli, _, sftpErr := e.pool.GetSFTPClient(ctx, peer.Name)
	if sftpErr != nil {
		return nil, fmt.Errorf("sftp fallback unavailable after rsync failure: %w", sftpErr)
	}

	bytesCopied, filesSynced, walkErr := syncSFTPDelta(ctx, sftpCli, absLocal, remoteDir, deleteExtra)
	if walkErr != nil {
		return nil, walkErr
	}

	return &TransferResult{
		Action:           "sync",
		Peer:             peer.Name,
		LocalPath:        absLocal,
		RemotePath:       remoteDir,
		BytesTransferred: bytesCopied,
		FilesSynced:      filesSynced,
		Method:           "sftp-delta",
		DurationMs:       time.Since(start).Milliseconds(),
	}, nil
}

func (e *Engine) StartWatch(ctx context.Context, peerName, localDir, remoteDir string, intervalSec int) (string, error) {
	if strings.TrimSpace(localDir) == "" || strings.TrimSpace(remoteDir) == "" {
		return "", errors.New("local_dir and remote_dir are required")
	}
	absLocal := config.ExpandPath(localDir)
	if err := e.checkPath(absLocal); err != nil {
		return "", err
	}
	if err := e.checkPath(remoteDir); err != nil {
		return "", err
	}
	if intervalSec <= 0 {
		intervalSec = 5
	}

	seq := atomic.AddUint64(&watchSeq, 1)
	watchID := fmt.Sprintf("watch_%d_%d", time.Now().Unix(), seq)
	watchCtx, cancel := context.WithCancel(ctx)

	job := &watchJob{
		id:        watchID,
		peer:      peerName,
		localDir:  absLocal,
		remoteDir: remoteDir,
		interval:  time.Duration(intervalSec) * time.Second,
		cancel:    cancel,
	}

	e.mu.Lock()
	e.watches[watchID] = job
	e.mu.Unlock()

	go func() {
		_, _ = e.SyncDir(watchCtx, job.peer, job.localDir, job.remoteDir, false)
		ticker := time.NewTicker(job.interval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				_, _ = e.SyncDir(watchCtx, job.peer, job.localDir, job.remoteDir, false)
			}
		}
	}()

	return watchID, nil
}

func (e *Engine) StopWatch(watchID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	job, ok := e.watches[watchID]
	if !ok {
		return fmt.Errorf("watch %q not found", watchID)
	}
	job.cancel()
	delete(e.watches, watchID)
	return nil
}

func (e *Engine) ListWatches() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make([]string, 0, len(e.watches))
	for id := range e.watches {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (e *Engine) checkPath(p string) error {
	if e.pool != nil && e.pool.Guard() != nil {
		return e.pool.Guard().CheckPath(p)
	}
	return nil
}

func shouldSkipSyncEntry(name string) bool {
	switch name {
	case ".git", "node_modules", "bin":
		return true
	}
	return strings.HasSuffix(name, ".tmp")
}

func syncLocalDelta(localDir, remoteDir string, deleteExtra bool) (int64, int, error) {
	if err := os.MkdirAll(remoteDir, 0755); err != nil {
		return 0, 0, err
	}

	seenRel := make(map[string]bool)
	var bytesTransferred int64
	var filesSynced int

	err := filepath.WalkDir(localDir, func(curPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(localDir, curPath)
		if err != nil || rel == "." {
			return err
		}
		if shouldSkipSyncEntry(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		seenRel[rel] = true
		dstPath := filepath.Join(remoteDir, rel)

		if d.IsDir() {
			return os.MkdirAll(dstPath, 0755)
		}

		srcInfo, err := d.Info()
		if err != nil {
			return err
		}
		if dstInfo, stErr := os.Stat(dstPath); stErr == nil && !dstInfo.IsDir() {
			if dstInfo.Size() == srcInfo.Size() && !srcInfo.ModTime().After(dstInfo.ModTime()) {
				return nil
			}
		}

		n, err := copyLocalFile(curPath, dstPath, srcInfo.Mode())
		if err != nil {
			return err
		}
		_ = os.Chtimes(dstPath, srcInfo.ModTime(), srcInfo.ModTime())
		bytesTransferred += n
		filesSynced++
		return nil
	})
	if err != nil {
		return bytesTransferred, filesSynced, err
	}

	if deleteExtra {
		_ = filepath.WalkDir(remoteDir, func(curPath string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, err := filepath.Rel(remoteDir, curPath)
			if err != nil || rel == "." {
				return nil
			}
			if shouldSkipSyncEntry(d.Name()) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !seenRel[rel] {
				_ = os.RemoveAll(curPath)
				if d.IsDir() {
					return filepath.SkipDir
				}
			}
			return nil
		})
	}

	return bytesTransferred, filesSynced, nil
}

func syncSFTPDelta(ctx context.Context, sftpCli *sftp.Client, localDir, remoteDir string, deleteExtra bool) (int64, int, error) {
	remoteSlash := filepath.ToSlash(remoteDir)
	if err := sftpCli.MkdirAll(remoteSlash); err != nil {
		return 0, 0, fmt.Errorf("sftp mkdir %s: %w", remoteSlash, err)
	}

	seenRel := make(map[string]bool)
	var bytesTransferred int64
	var filesSynced int

	err := filepath.WalkDir(localDir, func(curPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rel, err := filepath.Rel(localDir, curPath)
		if err != nil || rel == "." {
			return err
		}
		if shouldSkipSyncEntry(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		relSlash := filepath.ToSlash(rel)
		seenRel[relSlash] = true
		dstRemote := path.Join(remoteSlash, relSlash)

		if d.IsDir() {
			return sftpCli.MkdirAll(dstRemote)
		}

		srcInfo, err := d.Info()
		if err != nil {
			return err
		}
		if rInfo, stErr := sftpCli.Stat(dstRemote); stErr == nil && !rInfo.IsDir() {
			if rInfo.Size() == srcInfo.Size() && !srcInfo.ModTime().Truncate(time.Second).After(rInfo.ModTime().Truncate(time.Second)) {
				return nil
			}
		}

		n, err := uploadViaSFTP(sftpCli, curPath, dstRemote, srcInfo.Mode())
		if err != nil {
			return err
		}
		_ = sftpCli.Chtimes(dstRemote, srcInfo.ModTime(), srcInfo.ModTime())
		bytesTransferred += n
		filesSynced++
		return nil
	})
	if err != nil {
		return bytesTransferred, filesSynced, err
	}

	if deleteExtra {
		pruneExtraSFTP(sftpCli, remoteSlash, "", seenRel)
	}

	return bytesTransferred, filesSynced, nil
}

func pruneExtraSFTP(sftpCli *sftp.Client, baseRemote, relPrefix string, seenRel map[string]bool) {
	curRemote := baseRemote
	if relPrefix != "" {
		curRemote = path.Join(baseRemote, relPrefix)
	}
	entries, err := sftpCli.ReadDir(curRemote)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if shouldSkipSyncEntry(name) {
			continue
		}
		rel := name
		if relPrefix != "" {
			rel = path.Join(relPrefix, name)
		}
		fullRemote := path.Join(baseRemote, rel)
		if entry.IsDir() {
			pruneExtraSFTP(sftpCli, baseRemote, rel, seenRel)
			if !seenRel[rel] {
				_ = sftpCli.RemoveDirectory(fullRemote)
			}
		} else if !seenRel[rel] {
			_ = sftpCli.Remove(fullRemote)
		}
	}
}

func uploadViaSFTP(sftpCli *sftp.Client, localPath, remotePath string, mode fs.FileMode) (int64, error) {
	remoteSlash := filepath.ToSlash(remotePath)
	parentDir := path.Dir(remoteSlash)
	if parentDir != "" && parentDir != "." && parentDir != "/" {
		if err := sftpCli.MkdirAll(parentDir); err != nil {
			return 0, fmt.Errorf("sftp mkdir %s: %w", parentDir, err)
		}
	}

	srcFile, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := sftpCli.OpenFile(remoteSlash, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return n, err
	}
	_ = dstFile.Chmod(mode.Perm())
	return n, nil
}

func downloadViaSFTP(sftpCli *sftp.Client, remotePath, localPath string) (int64, error) {
	remoteSlash := filepath.ToSlash(remotePath)
	srcFile, err := sftpCli.Open(remoteSlash)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return 0, err
	}

	dstFile, err := os.OpenFile(localPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	n, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return n, err
	}
	if st, stErr := srcFile.Stat(); stErr == nil {
		_ = os.Chmod(localPath, st.Mode().Perm())
	}
	return n, nil
}

func copyLocalFile(src, dst string, mode fs.FileMode) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return 0, err
	}
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	perm := mode.Perm()
	if perm == 0 {
		perm = 0644
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	return io.Copy(out, in)
}

func (e *Engine) scpTransfer(ctx context.Context, peer *config.PeerConfig, host string, port int, localPath, remotePath string, push bool) error {
	if port <= 0 {
		port = peer.SSHPort
	}
	if port <= 0 {
		port = 22
	}
	args := []string{
		"-P", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=8",
	}
	if key := config.ExpandPath(peer.Auth.IdentityFile); key != "" {
		if st, err := os.Stat(key); err == nil && !st.IsDir() {
			args = append(args, "-i", key)
		}
	}
	remoteSpec := fmt.Sprintf("%s@%s:%s", peer.User, host, remotePath)
	if push {
		args = append(args, localPath, remoteSpec)
	} else {
		args = append(args, remoteSpec, localPath)
	}

	cmd := exec.CommandContext(ctx, "scp", args...)
	if sock := config.ExpandPath(peer.Auth.SSHAgentSock); sock != "" {
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scp failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *Engine) rsyncTransfer(ctx context.Context, peer *config.PeerConfig, host string, port int, localDir, remoteDir string, deleteExtra bool) error {
	if port <= 0 {
		port = peer.SSHPort
	}
	if port <= 0 {
		port = 22
	}
	sshParts := []string{
		"ssh",
		"-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "LogLevel=ERROR",
		"-o", "ConnectTimeout=8",
	}
	if key := config.ExpandPath(peer.Auth.IdentityFile); key != "" {
		if st, err := os.Stat(key); err == nil && !st.IsDir() {
			sshParts = append(sshParts, "-i", key)
		}
	}

	args := []string{
		"-az",
		"--exclude=.git",
		"--exclude=node_modules",
		"--exclude=bin",
		"--exclude=*.tmp",
		"-e", strings.Join(sshParts, " "),
	}
	if deleteExtra {
		args = append(args, "--delete")
	}

	src := strings.TrimRight(localDir, "/") + "/"
	dst := fmt.Sprintf("%s@%s:%s/", peer.User, host, strings.TrimRight(remoteDir, "/"))
	args = append(args, src, dst)

	cmd := exec.CommandContext(ctx, "rsync", args...)
	if sock := config.ExpandPath(peer.Auth.SSHAgentSock); sock != "" {
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rsync failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func countLocalEligibleFiles(localDir string) (int64, int) {
	var totalBytes int64
	var totalFiles int
	_ = filepath.WalkDir(localDir, func(curPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if curPath == localDir {
			return nil
		}
		if shouldSkipSyncEntry(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			if info, err := d.Info(); err == nil {
				totalBytes += info.Size()
				totalFiles++
			}
		}
		return nil
	})
	return totalBytes, totalFiles
}
