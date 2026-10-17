package vfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/0xOpCode/sysbridge-mcp/internal/config"
	"github.com/0xOpCode/sysbridge-mcp/pkg/transport"
	"github.com/pkg/sftp"
)

type Engine struct {
	pool *transport.Pool
}

func NewEngine(pool *transport.Pool) *Engine {
	return &Engine{pool: pool}
}

type ReadResult struct {
	Path       string `json:"path"`
	Backend    string `json:"backend"`
	Content    string `json:"content,omitempty"`
	TotalLines int    `json:"total_lines,omitempty"`
	StartLine  int    `json:"start_line,omitempty"`
	EndLine    int    `json:"end_line,omitempty"`
	Size       int64  `json:"size"`
	IsBinary   bool   `json:"is_binary"`
	Base64Data string `json:"base64_data,omitempty"`
}

type WriteResult struct {
	Path         string `json:"path"`
	Backend      string `json:"backend"`
	BytesWritten int    `json:"bytes_written"`
	SHA256       string `json:"sha256"`
}

type EditOp struct {
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all"`
}

type EditResult struct {
	Path         string `json:"path"`
	Backend      string `json:"backend"`
	Replacements int    `json:"replacements"`
	Diff         string `json:"diff"`
}

type FileEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

type SearchMatch struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

type SearchResult struct {
	Backend string        `json:"backend"`
	Files   []string      `json:"files,omitempty"`
	Matches []SearchMatch `json:"matches,omitempty"`
}

type OpsResult struct {
	Action  string      `json:"action"`
	Path    string      `json:"path"`
	Backend string      `json:"backend"`
	Entries []FileEntry `json:"entries,omitempty"`
	Stat    *FileEntry  `json:"stat,omitempty"`
	SHA256  string      `json:"sha256,omitempty"`
	Message string      `json:"message,omitempty"`
}

func (e *Engine) resolvePeerAndPath(peerName, rawPath string) (*config.PeerConfig, string, error) {
	if guard := e.pool.Guard(); guard != nil && rawPath != "" {
		if err := guard.CheckPath(rawPath); err != nil {
			return nil, "", err
		}
	}

	peer, err := e.pool.Config().ResolvePeer(peerName)
	if err != nil {
		return nil, "", err
	}

	isLocal := peer.Name == "local" || peer.VFS.Backend == "local-mount"
	wsRoot := peer.VFS.WorkspaceRoot
	if wsRoot == "" {
		if isLocal {
			wsRoot, _ = os.UserHomeDir()
		} else if peer.User == "root" {
			wsRoot = "/root"
		} else if peer.User != "" {
			wsRoot = "/home/" + peer.User
		} else {
			wsRoot = "/"
		}
	}

	resolved := strings.TrimSpace(rawPath)
	if resolved == "" {
		resolved = wsRoot
	} else if resolved == "~" {
		if isLocal {
			resolved = config.ExpandPath(resolved)
		} else {
			resolved = wsRoot
		}
	} else if strings.HasPrefix(resolved, "~/") {
		if isLocal {
			resolved = config.ExpandPath(resolved)
		} else {
			resolved = filepath.Join(wsRoot, resolved[2:])
		}
	} else if !strings.HasPrefix(resolved, "/") {
		resolved = filepath.Join(wsRoot, resolved)
	} else {
		resolved = filepath.Clean(resolved)
	}

	if guard := e.pool.Guard(); guard != nil {
		if err := guard.CheckPath(resolved); err != nil {
			return nil, "", err
		}
	}

	return peer, resolved, nil
}

func (e *Engine) selectTier(ctx context.Context, peer *config.PeerConfig) (string, *sftp.Client) {
	if peer.Name == "local" || peer.VFS.Backend == "local-mount" {
		return "local-mount", nil
	}
	if peer.VFS.Backend == "ssh-stream" {
		return "ssh-stream", nil
	}
	sftpCli, _, err := e.pool.GetSFTPClient(ctx, peer.Name)
	if err == nil && sftpCli != nil {
		return "sftp-vfs", sftpCli
	}
	return "ssh-stream", nil
}

func (e *Engine) ReadFile(ctx context.Context, peerName, targetPath string, offset, limit int) (*ReadResult, error) {
	peer, resolved, err := e.resolvePeerAndPath(peerName, targetPath)
	if err != nil {
		return nil, err
	}

	data, backend, err := e.readRaw(ctx, peer, resolved)
	if err != nil {
		return nil, err
	}

	if isBinaryData(data) {
		return &ReadResult{
			Path:       resolved,
			Backend:    backend,
			Size:       int64(len(data)),
			IsBinary:   true,
			Base64Data: base64.StdEncoding.EncodeToString(data),
		}, nil
	}

	text := string(data)
	if len(data) == 0 {
		return &ReadResult{
			Path:       resolved,
			Backend:    backend,
			Content:    "",
			TotalLines: 0,
			StartLine:  0,
			EndLine:    0,
			Size:       0,
			IsBinary:   false,
		}, nil
	}

	lines := strings.Split(text, "\n")
	totalLines := len(lines)
	if offset <= 0 && limit <= 0 {
		return &ReadResult{
			Path:       resolved,
			Backend:    backend,
			Content:    text,
			TotalLines: totalLines,
			StartLine:  1,
			EndLine:    totalLines,
			Size:       int64(len(data)),
			IsBinary:   false,
		}, nil
	}

	startIdx := offset
	if startIdx < 0 {
		startIdx = 0
	}
	if startIdx > totalLines {
		startIdx = totalLines
	}

	endIdx := totalLines
	if limit > 0 && startIdx+limit < endIdx {
		endIdx = startIdx + limit
	}

	sliced := strings.Join(lines[startIdx:endIdx], "\n")
	startLine := 0
	if endIdx > startIdx {
		startLine = startIdx + 1
	}

	return &ReadResult{
		Path:       resolved,
		Backend:    backend,
		Content:    sliced,
		TotalLines: totalLines,
		StartLine:  startLine,
		EndLine:    endIdx,
		Size:       int64(len(data)),
		IsBinary:   false,
	}, nil
}

func (e *Engine) WriteFile(ctx context.Context, peerName, targetPath, content string, mode uint32) (*WriteResult, error) {
	peer, resolved, err := e.resolvePeerAndPath(peerName, targetPath)
	if err != nil {
		return nil, err
	}

	data := []byte(content)
	backend, err := e.writeRawAtomic(ctx, peer, resolved, data, mode)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(data)
	return &WriteResult{
		Path:         resolved,
		Backend:      backend,
		BytesWritten: len(data),
		SHA256:       hex.EncodeToString(sum[:]),
	}, nil
}

func (e *Engine) EditFile(ctx context.Context, peerName, targetPath, oldStr, newStr string, replaceAll bool) (*EditResult, error) {
	return e.MultiEdit(ctx, peerName, targetPath, []EditOp{
		{
			OldString:  oldStr,
			NewString:  newStr,
			ReplaceAll: replaceAll,
		},
	})
}

func (e *Engine) MultiEdit(ctx context.Context, peerName, targetPath string, edits []EditOp) (*EditResult, error) {
	if len(edits) == 0 {
		return nil, fmt.Errorf("no edit operations provided")
	}

	peer, resolved, err := e.resolvePeerAndPath(peerName, targetPath)
	if err != nil {
		return nil, err
	}

	data, _, err := e.readRaw(ctx, peer, resolved)
	if err != nil {
		return nil, err
	}

	original := string(data)
	current := original
	totalReplacements := 0

	for i, op := range edits {
		if op.OldString == "" {
			return nil, fmt.Errorf("edit[%d]: old_string cannot be empty", i)
		}
		count := strings.Count(current, op.OldString)
		if count == 0 {
			return nil, fmt.Errorf("edit[%d]: old_string not found in %s", i, resolved)
		}
		if !op.ReplaceAll && count > 1 {
			return nil, fmt.Errorf("edit[%d]: old_string matches %d locations in %s (set replace_all=true to replace all)", i, count, resolved)
		}
		if op.ReplaceAll {
			current = strings.ReplaceAll(current, op.OldString, op.NewString)
			totalReplacements += count
		} else {
			current = strings.Replace(current, op.OldString, op.NewString, 1)
			totalReplacements++
		}
	}

	backend, err := e.writeRawAtomic(ctx, peer, resolved, []byte(current), 0)
	if err != nil {
		return nil, err
	}

	return &EditResult{
		Path:         resolved,
		Backend:      backend,
		Replacements: totalReplacements,
		Diff:         buildUnifiedSummary(resolved, original, current),
	}, nil
}

func (e *Engine) Search(ctx context.Context, peerName, rootPath, query, globPattern string, maxResults int) (*SearchResult, error) {
	peer, resolvedRoot, err := e.resolvePeerAndPath(peerName, rootPath)
	if err != nil {
		return nil, err
	}
	if maxResults <= 0 {
		maxResults = 100
	}

	backend, sftpCli := e.selectTier(ctx, peer)
	switch backend {
	case "local-mount":
		return e.searchLocal(ctx, resolvedRoot, query, globPattern, maxResults)
	case "sftp-vfs":
		res, sftpErr := e.searchSFTP(ctx, sftpCli, resolvedRoot, query, globPattern, maxResults)
		if sftpErr == nil {
			return res, nil
		}
		return e.searchSSHStream(ctx, peer, resolvedRoot, query, globPattern, maxResults)
	default:
		return e.searchSSHStream(ctx, peer, resolvedRoot, query, globPattern, maxResults)
	}
}

func (e *Engine) Ops(ctx context.Context, peerName, action, targetPath, destPath string, mode uint32, confirm bool) (*OpsResult, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	peer, resolvedTarget, err := e.resolvePeerAndPath(peerName, targetPath)
	if err != nil {
		return nil, err
	}

	var resolvedDest string
	if destPath != "" {
		_, resolvedDest, err = e.resolvePeerAndPath(peerName, destPath)
		if err != nil {
			return nil, err
		}
	}

	if action == "rm" {
		if guard := e.pool.Guard(); guard != nil {
			if err := guard.RequireDeleteConfirmation(confirm, resolvedTarget); err != nil {
				return nil, err
			}
		}
	}

	backend, sftpCli := e.selectTier(ctx, peer)
	switch backend {
	case "local-mount":
		return e.opsLocal(action, resolvedTarget, resolvedDest, mode)
	case "sftp-vfs":
		res, sftpErr := e.opsSFTP(sftpCli, action, resolvedTarget, resolvedDest, mode)
		if sftpErr == nil {
			return res, nil
		}
		return e.opsSSHStream(ctx, peer, action, resolvedTarget, resolvedDest, mode)
	default:
		return e.opsSSHStream(ctx, peer, action, resolvedTarget, resolvedDest, mode)
	}
}

func (e *Engine) readRaw(ctx context.Context, peer *config.PeerConfig, resolvedPath string) ([]byte, string, error) {
	backend, sftpCli := e.selectTier(ctx, peer)
	if backend == "local-mount" {
		data, err := os.ReadFile(resolvedPath)
		if err != nil {
			return nil, "local-mount", err
		}
		return data, "local-mount", nil
	}

	if backend == "sftp-vfs" && sftpCli != nil {
		f, err := sftpCli.Open(resolvedPath)
		if err == nil {
			data, readErr := io.ReadAll(f)
			_ = f.Close()
			if readErr == nil {
				return data, "sftp-vfs", nil
			}
		}
	}

	cmd := fmt.Sprintf("base64 < %s", shellQuote(resolvedPath))
	res, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		return nil, "ssh-stream", err
	}
	if res.ExitCode != 0 {
		return nil, "ssh-stream", fmt.Errorf("remote read %s failed (exit %d): %s", resolvedPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, res.Stdout)
	decoded, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, "ssh-stream", fmt.Errorf("decode base64 from %s: %w", resolvedPath, err)
	}
	return decoded, "ssh-stream", nil
}

func (e *Engine) writeRawAtomic(ctx context.Context, peer *config.PeerConfig, resolvedPath string, data []byte, mode uint32) (string, error) {
	backend, sftpCli := e.selectTier(ctx, peer)
	tmpPath := fmt.Sprintf("%s.sysbridge.tmp.%d", resolvedPath, time.Now().UnixNano())

	if backend == "local-mount" {
		perm := os.FileMode(0644)
		if mode != 0 {
			perm = os.FileMode(mode)
		} else if st, err := os.Stat(resolvedPath); err == nil {
			perm = st.Mode().Perm()
		}
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
			return "local-mount", err
		}
		if err := os.WriteFile(tmpPath, data, perm); err != nil {
			_ = os.Remove(tmpPath)
			return "local-mount", err
		}
		if err := os.Chmod(tmpPath, perm); err != nil {
			_ = os.Remove(tmpPath)
			return "local-mount", err
		}
		if err := os.Rename(tmpPath, resolvedPath); err != nil {
			_ = os.Remove(tmpPath)
			return "local-mount", err
		}
		return "local-mount", nil
	}

	if backend == "sftp-vfs" && sftpCli != nil {
		perm := os.FileMode(0644)
		if mode != 0 {
			perm = os.FileMode(mode)
		} else if st, err := sftpCli.Stat(resolvedPath); err == nil {
			perm = st.Mode().Perm()
		}
		_ = sftpCli.MkdirAll(filepath.Dir(resolvedPath))
		f, err := sftpCli.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err == nil {
			_, writeErr := f.Write(data)
			closeErr := f.Close()
			if writeErr == nil && closeErr == nil {
				_ = sftpCli.Chmod(tmpPath, perm)
				if renameErr := sftpCli.PosixRename(tmpPath, resolvedPath); renameErr == nil {
					return "sftp-vfs", nil
				}
				_ = sftpCli.Remove(resolvedPath)
				if renameErr := sftpCli.Rename(tmpPath, resolvedPath); renameErr == nil {
					return "sftp-vfs", nil
				}
			}
			_ = sftpCli.Remove(tmpPath)
		}
	}

	octalMode := "0644"
	if mode != 0 {
		octalMode = fmt.Sprintf("%04o", mode&07777)
	}
	parentDir := filepath.Dir(resolvedPath)
	var cmd string
	if mode != 0 {
		cmd = fmt.Sprintf(
			"mkdir -p %s && base64 -d > %s && chmod %s %s && mv -f %s %s",
			shellQuote(parentDir),
			shellQuote(tmpPath),
			octalMode,
			shellQuote(tmpPath),
			shellQuote(tmpPath),
			shellQuote(resolvedPath),
		)
	} else {
		cmd = fmt.Sprintf(
			"mkdir -p %s && orig_mode=$(stat -c '%%a' %s 2>/dev/null || echo 0644) && base64 -d > %s && chmod \"$orig_mode\" %s && mv -f %s %s",
			shellQuote(parentDir),
			shellQuote(resolvedPath),
			shellQuote(tmpPath),
			shellQuote(tmpPath),
			shellQuote(tmpPath),
			shellQuote(resolvedPath),
		)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	res, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{
		Stdin:   []byte(encoded),
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return "ssh-stream", err
	}
	if res.ExitCode != 0 {
		return "ssh-stream", fmt.Errorf("remote atomic write %s failed (exit %d): %s", resolvedPath, res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return "ssh-stream", nil
}

func (e *Engine) searchLocal(ctx context.Context, rootPath, query, globPattern string, maxResults int) (*SearchResult, error) {
	res := &SearchResult{
		Backend: "local-mount",
		Files:   []string{},
		Matches: []SearchMatch{},
	}
	seenFiles := make(map[string]bool)

	err := filepath.WalkDir(rootPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if d.Name() == ".git" && p != rootPath {
				return filepath.SkipDir
			}
			return nil
		}
		if globPattern != "" && !matchGlob(globPattern, d.Name(), p, rootPath) {
			return nil
		}
		if query == "" {
			if !seenFiles[p] {
				seenFiles[p] = true
				res.Files = append(res.Files, p)
			}
			if len(res.Files) >= maxResults {
				return io.EOF
			}
			return nil
		}

		data, err := os.ReadFile(p)
		if err != nil || isBinaryData(data) {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for idx, line := range lines {
			if strings.Contains(line, query) {
				if !seenFiles[p] {
					seenFiles[p] = true
					res.Files = append(res.Files, p)
				}
				res.Matches = append(res.Matches, SearchMatch{
					Path:    p,
					Line:    idx + 1,
					Content: line,
				})
				if len(res.Matches) >= maxResults {
					return io.EOF
				}
			}
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return nil, err
	}
	return res, nil
}

func (e *Engine) searchSFTP(ctx context.Context, sftpCli *sftp.Client, rootPath, query, globPattern string, maxResults int) (*SearchResult, error) {
	if _, err := sftpCli.Stat(rootPath); err != nil {
		return nil, err
	}
	res := &SearchResult{
		Backend: "sftp-vfs",
		Files:   []string{},
		Matches: []SearchMatch{},
	}
	seenFiles := make(map[string]bool)

	walker := sftpCli.Walk(rootPath)
	for walker.Step() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if walker.Err() != nil {
			continue
		}
		p := walker.Path()
		st := walker.Stat()
		if st.IsDir() {
			if st.Name() == ".git" && p != rootPath {
				walker.SkipDir()
			}
			continue
		}
		if globPattern != "" && !matchGlob(globPattern, st.Name(), p, rootPath) {
			continue
		}
		if query == "" {
			if !seenFiles[p] {
				seenFiles[p] = true
				res.Files = append(res.Files, p)
			}
			if len(res.Files) >= maxResults {
				break
			}
			continue
		}

		f, err := sftpCli.Open(p)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(f)
		_ = f.Close()
		if readErr != nil || isBinaryData(data) {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for idx, line := range lines {
			if strings.Contains(line, query) {
				if !seenFiles[p] {
					seenFiles[p] = true
					res.Files = append(res.Files, p)
				}
				res.Matches = append(res.Matches, SearchMatch{
					Path:    p,
					Line:    idx + 1,
					Content: line,
				})
				if len(res.Matches) >= maxResults {
					return res, nil
				}
			}
		}
	}
	return res, nil
}

func (e *Engine) searchSSHStream(ctx context.Context, peer *config.PeerConfig, rootPath, query, globPattern string, maxResults int) (*SearchResult, error) {
	res := &SearchResult{
		Backend: "ssh-stream",
		Files:   []string{},
		Matches: []SearchMatch{},
	}
	seenFiles := make(map[string]bool)

	if query == "" {
		nameFilter := ""
		if globPattern != "" {
			nameFilter = "-name " + shellQuote(globPattern)
		}
		cmd := fmt.Sprintf("find %s -type f %s 2>/dev/null | head -n %d", shellQuote(rootPath), nameFilter, maxResults)
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 30 * time.Second})
		if err != nil {
			return nil, err
		}
		for _, line := range strings.Split(strings.TrimSpace(execRes.Stdout), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !seenFiles[line] {
				seenFiles[line] = true
				res.Files = append(res.Files, line)
			}
		}
		return res, nil
	}

	includeFlag := ""
	if globPattern != "" {
		includeFlag = "--include=" + shellQuote(globPattern)
	}
	cmd := fmt.Sprintf("grep -rnI %s -F -- %s %s 2>/dev/null | head -n %d", includeFlag, shellQuote(query), shellQuote(rootPath), maxResults)
	execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 30 * time.Second})
	if err != nil {
		return nil, err
	}
	for _, rawLine := range strings.Split(strings.TrimSpace(execRes.Stdout), "\n") {
		if rawLine == "" {
			continue
		}
		parts := strings.SplitN(rawLine, ":", 3)
		if len(parts) < 3 {
			continue
		}
		lineNum, convErr := strconv.Atoi(parts[1])
		if convErr != nil {
			continue
		}
		filePath := parts[0]
		if !seenFiles[filePath] {
			seenFiles[filePath] = true
			res.Files = append(res.Files, filePath)
		}
		res.Matches = append(res.Matches, SearchMatch{
			Path:    filePath,
			Line:    lineNum,
			Content: parts[2],
		})
	}
	return res, nil
}

func (e *Engine) opsLocal(action, targetPath, destPath string, mode uint32) (*OpsResult, error) {
	res := &OpsResult{
		Action:  action,
		Path:    targetPath,
		Backend: "local-mount",
	}

	switch action {
	case "ls":
		st, err := os.Stat(targetPath)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			entry := fileInfoToEntry(targetPath, st)
			res.Entries = []FileEntry{entry}
			return res, nil
		}
		dirEntries, err := os.ReadDir(targetPath)
		if err != nil {
			return nil, err
		}
		res.Entries = make([]FileEntry, 0, len(dirEntries))
		for _, de := range dirEntries {
			info, infoErr := de.Info()
			if infoErr != nil {
				continue
			}
			res.Entries = append(res.Entries, fileInfoToEntry(filepath.Join(targetPath, de.Name()), info))
		}
		return res, nil

	case "tree":
		var entries []FileEntry
		err := filepath.WalkDir(targetPath, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if p == targetPath {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			entries = append(entries, fileInfoToEntry(p, info))
			if len(entries) >= 500 {
				return io.EOF
			}
			return nil
		})
		if err != nil && err != io.EOF {
			return nil, err
		}
		res.Entries = entries
		return res, nil

	case "stat":
		st, err := os.Stat(targetPath)
		if err != nil {
			return nil, err
		}
		entry := fileInfoToEntry(targetPath, st)
		res.Stat = &entry
		return res, nil

	case "mkdir":
		perm := os.FileMode(0755)
		if mode != 0 {
			perm = os.FileMode(mode)
		}
		if err := os.MkdirAll(targetPath, perm); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("created directory %s", targetPath)
		return res, nil

	case "mv":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for mv action")
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return nil, err
		}
		if err := os.Rename(targetPath, destPath); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("moved %s to %s", targetPath, destPath)
		return res, nil

	case "cp":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for cp action")
		}
		if err := copyLocalPath(targetPath, destPath); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("copied %s to %s", targetPath, destPath)
		return res, nil

	case "chmod":
		if mode == 0 {
			return nil, fmt.Errorf("non-zero mode is required for chmod action")
		}
		if err := os.Chmod(targetPath, os.FileMode(mode)); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("chmod %04o on %s", mode&07777, targetPath)
		return res, nil

	case "rm":
		if err := os.RemoveAll(targetPath); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("removed %s", targetPath)
		return res, nil

	case "sha256":
		f, err := os.Open(targetPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, err
		}
		res.SHA256 = hex.EncodeToString(h.Sum(nil))
		return res, nil

	default:
		return nil, fmt.Errorf("unsupported vfs ops action %q", action)
	}
}

func (e *Engine) opsSFTP(sftpCli *sftp.Client, action, targetPath, destPath string, mode uint32) (*OpsResult, error) {
	res := &OpsResult{
		Action:  action,
		Path:    targetPath,
		Backend: "sftp-vfs",
	}

	switch action {
	case "ls":
		st, err := sftpCli.Stat(targetPath)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			res.Entries = []FileEntry{fileInfoToEntry(targetPath, st)}
			return res, nil
		}
		infos, err := sftpCli.ReadDir(targetPath)
		if err != nil {
			return nil, err
		}
		sort.Slice(infos, func(i, j int) bool { return infos[i].Name() < infos[j].Name() })
		res.Entries = make([]FileEntry, 0, len(infos))
		for _, info := range infos {
			res.Entries = append(res.Entries, fileInfoToEntry(filepath.Join(targetPath, info.Name()), info))
		}
		return res, nil

	case "tree":
		if _, err := sftpCli.Stat(targetPath); err != nil {
			return nil, err
		}
		var entries []FileEntry
		walker := sftpCli.Walk(targetPath)
		for walker.Step() {
			if walker.Err() != nil {
				continue
			}
			p := walker.Path()
			if p == targetPath {
				continue
			}
			entries = append(entries, fileInfoToEntry(p, walker.Stat()))
			if len(entries) >= 500 {
				break
			}
		}
		res.Entries = entries
		return res, nil

	case "stat":
		st, err := sftpCli.Stat(targetPath)
		if err != nil {
			return nil, err
		}
		entry := fileInfoToEntry(targetPath, st)
		res.Stat = &entry
		return res, nil

	case "mkdir":
		if err := sftpCli.MkdirAll(targetPath); err != nil {
			return nil, err
		}
		if mode != 0 {
			_ = sftpCli.Chmod(targetPath, os.FileMode(mode))
		}
		res.Message = fmt.Sprintf("created directory %s", targetPath)
		return res, nil

	case "mv":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for mv action")
		}
		_ = sftpCli.MkdirAll(filepath.Dir(destPath))
		if err := sftpCli.PosixRename(targetPath, destPath); err != nil {
			if rErr := sftpCli.Rename(targetPath, destPath); rErr != nil {
				return nil, rErr
			}
		}
		res.Message = fmt.Sprintf("moved %s to %s", targetPath, destPath)
		return res, nil

	case "cp":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for cp action")
		}
		srcFile, err := sftpCli.Open(targetPath)
		if err != nil {
			return nil, err
		}
		defer srcFile.Close()
		st, err := srcFile.Stat()
		if err != nil {
			return nil, err
		}
		if st.IsDir() {
			return nil, fmt.Errorf("sftp directory copy fallback required")
		}
		_ = sftpCli.MkdirAll(filepath.Dir(destPath))
		dstFile, err := sftpCli.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			return nil, err
		}
		_, copyErr := io.Copy(dstFile, srcFile)
		closeErr := dstFile.Close()
		if copyErr != nil {
			return nil, copyErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		_ = sftpCli.Chmod(destPath, st.Mode().Perm())
		res.Message = fmt.Sprintf("copied %s to %s", targetPath, destPath)
		return res, nil

	case "chmod":
		if mode == 0 {
			return nil, fmt.Errorf("non-zero mode is required for chmod action")
		}
		if err := sftpCli.Chmod(targetPath, os.FileMode(mode)); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("chmod %04o on %s", mode&07777, targetPath)
		return res, nil

	case "rm":
		if err := removeSFTPRecursive(sftpCli, targetPath); err != nil {
			return nil, err
		}
		res.Message = fmt.Sprintf("removed %s", targetPath)
		return res, nil

	case "sha256":
		f, err := sftpCli.Open(targetPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return nil, err
		}
		res.SHA256 = hex.EncodeToString(h.Sum(nil))
		return res, nil

	default:
		return nil, fmt.Errorf("unsupported vfs ops action %q", action)
	}
}

func (e *Engine) opsSSHStream(ctx context.Context, peer *config.PeerConfig, action, targetPath, destPath string, mode uint32) (*OpsResult, error) {
	res := &OpsResult{
		Action:  action,
		Path:    targetPath,
		Backend: "ssh-stream",
	}

	switch action {
	case "ls":
		cmd := fmt.Sprintf("find %s -maxdepth 1 -mindepth 1 -printf '%%f\\t%%p\\t%%s\\t%%M\\t%%T@\\t%%y\\n' 2>/dev/null", shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote ls %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Entries = parseFindOutput(execRes.Stdout)
		return res, nil

	case "tree":
		cmd := fmt.Sprintf("find %s -mindepth 1 -printf '%%f\\t%%p\\t%%s\\t%%M\\t%%T@\\t%%y\\n' 2>/dev/null | head -n 500", shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote tree %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Entries = parseFindOutput(execRes.Stdout)
		return res, nil

	case "stat":
		cmd := fmt.Sprintf("stat -c '%%n\\t%%s\\t%%A\\t%%Y\\t%%F' %s", shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 15 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote stat %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		parts := strings.Split(strings.TrimSpace(execRes.Stdout), "\t")
		if len(parts) < 5 {
			return nil, fmt.Errorf("unexpected stat output for %s", targetPath)
		}
		sz, _ := strconv.ParseInt(parts[1], 10, 64)
		sec, _ := strconv.ParseInt(parts[3], 10, 64)
		entry := FileEntry{
			Name:    filepath.Base(targetPath),
			Path:    targetPath,
			Size:    sz,
			Mode:    parts[2],
			ModTime: time.Unix(sec, 0).UTC().Format(time.RFC3339),
			IsDir:   strings.Contains(strings.ToLower(parts[4]), "directory"),
		}
		res.Stat = &entry
		return res, nil

	case "mkdir":
		permFlag := ""
		if mode != 0 {
			permFlag = fmt.Sprintf("-m %04o ", mode&07777)
		}
		cmd := fmt.Sprintf("mkdir -p %s%s", permFlag, shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 15 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote mkdir %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Message = fmt.Sprintf("created directory %s", targetPath)
		return res, nil

	case "mv":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for mv action")
		}
		cmd := fmt.Sprintf("mkdir -p %s && mv -f %s %s", shellQuote(filepath.Dir(destPath)), shellQuote(targetPath), shellQuote(destPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote mv %s to %s failed: %s", targetPath, destPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Message = fmt.Sprintf("moved %s to %s", targetPath, destPath)
		return res, nil

	case "cp":
		if destPath == "" {
			return nil, fmt.Errorf("destPath is required for cp action")
		}
		cmd := fmt.Sprintf("mkdir -p %s && cp -a %s %s", shellQuote(filepath.Dir(destPath)), shellQuote(targetPath), shellQuote(destPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 30 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote cp %s to %s failed: %s", targetPath, destPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Message = fmt.Sprintf("copied %s to %s", targetPath, destPath)
		return res, nil

	case "chmod":
		if mode == 0 {
			return nil, fmt.Errorf("non-zero mode is required for chmod action")
		}
		cmd := fmt.Sprintf("chmod %04o %s", mode&07777, shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 15 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote chmod %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Message = fmt.Sprintf("chmod %04o on %s", mode&07777, targetPath)
		return res, nil

	case "rm":
		cmd := fmt.Sprintf("rm -rf -- %s", shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote rm %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.Message = fmt.Sprintf("removed %s", targetPath)
		return res, nil

	case "sha256":
		cmd := fmt.Sprintf("sha256sum %s | awk '{print $1}'", shellQuote(targetPath))
		execRes, err := e.pool.Exec(ctx, peer.Name, cmd, transport.ExecOptions{Timeout: 20 * time.Second})
		if err != nil {
			return nil, err
		}
		if execRes.ExitCode != 0 {
			return nil, fmt.Errorf("remote sha256sum %s failed: %s", targetPath, strings.TrimSpace(execRes.Stderr))
		}
		res.SHA256 = strings.TrimSpace(execRes.Stdout)
		return res, nil

	default:
		return nil, fmt.Errorf("unsupported vfs ops action %q", action)
	}
}

func fileInfoToEntry(fullPath string, info fs.FileInfo) FileEntry {
	return FileEntry{
		Name:    info.Name(),
		Path:    fullPath,
		Size:    info.Size(),
		Mode:    info.Mode().String(),
		ModTime: info.ModTime().UTC().Format(time.RFC3339),
		IsDir:   info.IsDir(),
	}
}

func parseFindOutput(out string) []FileEntry {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	entries := make([]FileEntry, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) < 6 {
			continue
		}
		sz, _ := strconv.ParseInt(parts[2], 10, 64)
		tsFloat, _ := strconv.ParseFloat(parts[4], 64)
		entries = append(entries, FileEntry{
			Name:    parts[0],
			Path:    parts[1],
			Size:    sz,
			Mode:    parts[3],
			ModTime: time.Unix(int64(tsFloat), 0).UTC().Format(time.RFC3339),
			IsDir:   parts[5] == "d",
		})
	}
	return entries
}

func removeSFTPRecursive(sftpCli *sftp.Client, targetPath string) error {
	st, err := sftpCli.Lstat(targetPath)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return sftpCli.Remove(targetPath)
	}
	entries, err := sftpCli.ReadDir(targetPath)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(targetPath, entry.Name())
		if err := removeSFTPRecursive(sftpCli, child); err != nil {
			return err
		}
	}
	return sftpCli.RemoveDirectory(targetPath)
}

func copyLocalPath(src, dst string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return copyLocalFile(src, dst, st.Mode().Perm())
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		return copyLocalFile(p, target, info.Mode().Perm())
	})
}

func copyLocalFile(src, dst string, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func isBinaryData(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 8000 {
		sample = sample[:8000]
	}
	return bytes.IndexByte(sample, 0) != -1
}

func matchGlob(pattern, name, fullPath, rootPath string) bool {
	if matched, err := filepath.Match(pattern, name); err == nil && matched {
		return true
	}
	if rel, err := filepath.Rel(rootPath, fullPath); err == nil {
		if matched, mErr := filepath.Match(pattern, rel); mErr == nil && matched {
			return true
		}
	}
	return false
}

func buildUnifiedSummary(path, before, after string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n", filepath.Base(path), filepath.Base(path)))
	oldLines := strings.Split(before, "\n")
	newLines := strings.Split(after, "\n")

	maxLen := len(oldLines)
	if len(newLines) > maxLen {
		maxLen = len(newLines)
	}
	for i := 0; i < maxLen; i++ {
		var o, n string
		hasO := i < len(oldLines)
		hasN := i < len(newLines)
		if hasO {
			o = oldLines[i]
		}
		if hasN {
			n = newLines[i]
		}
		if hasO && hasN && o == n {
			continue
		}
		if hasO {
			b.WriteString(fmt.Sprintf("-%d: %s\n", i+1, o))
		}
		if hasN {
			b.WriteString(fmt.Sprintf("+%d: %s\n", i+1, n))
		}
	}
	return strings.TrimSpace(b.String())
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
