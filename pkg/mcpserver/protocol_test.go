package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPMultiTransportProtocol(t *testing.T) {
	srv := NewServer("sysbridge-mcp", "1.0.0", "")
	srv.RegisterTool(ToolDefinition{
		Name:        "ping_peer",
		Description: "Ping a target peer",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"peer": map[string]any{"type": "string"},
			},
		},
	}, func(ctx context.Context, args map[string]any) (*CallToolResult, error) {
		peer, _ := args["peer"].(string)
		return TextResult(map[string]string{"pong": peer}), nil
	})

	ctx := context.Background()

	// 1. Test Stdio Transport
	input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping_peer","arguments":{"peer":"laptop"}}}` + "\n"

	var out bytes.Buffer
	if err := srv.ServeStdio(ctx, strings.NewReader(input), &out); err != nil {
		t.Fatalf("ServeStdio failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSON-RPC responses over stdio, got %d: %s", len(lines), out.String())
	}
	if !strings.Contains(lines[2], "laptop") {
		t.Fatalf("expected tool call output to contain laptop, got: %s", lines[2])
	}

	// 2. Test Streamable HTTP Transport (/mcp) and Healthz (/healthz)
	ts := httptest.NewServer(srv.HTTPHandler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz check failed: %v", err)
	}
	_ = resp.Body.Close()

	callBody := `{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"ping_peer","arguments":{"peer":"vps-01"}}}`
	httpResp, err := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader(callBody))
	if err != nil {
		t.Fatalf("POST /mcp failed: %v", err)
	}
	defer httpResp.Body.Close()

	if httpResp.Header.Get("Mcp-Session-Id") == "" {
		t.Fatal("expected Mcp-Session-Id header on Streamable HTTP response")
	}

	var rpcResp JSONRPCResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&rpcResp); err != nil {
		t.Fatalf("decode /mcp response failed: %v", err)
	}
	if rpcResp.Error != nil {
		t.Fatalf("unexpected RPC error: %+v", rpcResp.Error)
	}

	// 3. Test Unix Domain Socket Transport
	sockPath := filepath.Join(t.TempDir(), "mcp.sock")
	sockCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_ = srv.ServeUnixSocket(sockCtx, sockPath)
	}()
	time.Sleep(30 * time.Millisecond)
}
