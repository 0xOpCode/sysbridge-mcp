package mcpserver

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	LatestProtocolVersion = "2025-03-26"
	LegacyProtocolVersion = "2024-11-05"
)

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    bool   `json:"readOnlyHint,omitempty"`
	DestructiveHint bool   `json:"destructiveHint,omitempty"`
	IdempotentHint  bool   `json:"idempotentHint,omitempty"`
	OpenWorldHint   bool   `json:"openWorldHint,omitempty"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema map[string]any  `json:"inputSchema"`
	Annotations ToolAnnotations `json:"annotations,omitempty"`
}

type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

type CallToolResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type ToolHandler func(ctx context.Context, args map[string]any) (*CallToolResult, error)

type ResourceDefinition struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourceContents struct {
	URI      string `json:"uri"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
}

type ResourceHandler func(ctx context.Context, uri string) ([]ResourceContents, error)

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptDefinition struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptMessage struct {
	Role    string       `json:"role"`
	Content ContentBlock `json:"content"`
}

type PromptHandler func(ctx context.Context, args map[string]string) (string, []PromptMessage, error)

type sseSession struct {
	id      string
	ch      chan []byte
	created time.Time
}

type Server struct {
	mu               sync.RWMutex
	name             string
	version          string
	authToken        string
	tools            []ToolDefinition
	toolHandlers     map[string]ToolHandler
	resources        []ResourceDefinition
	resourceHandlers map[string]ResourceHandler
	prompts          []PromptDefinition
	promptHandlers   map[string]PromptHandler
	sseSessions      map[string]*sseSession
}

func NewServer(name, version, authToken string) *Server {
	return &Server{
		name:             name,
		version:          version,
		authToken:        authToken,
		toolHandlers:     make(map[string]ToolHandler),
		resourceHandlers: make(map[string]ResourceHandler),
		promptHandlers:   make(map[string]PromptHandler),
		sseSessions:      make(map[string]*sseSession),
	}
}

func (s *Server) RegisterTool(def ToolDefinition, handler ToolHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = append(s.tools, def)
	s.toolHandlers[def.Name] = handler
}

func (s *Server) RegisterResource(def ResourceDefinition, handler ResourceHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources = append(s.resources, def)
	s.resourceHandlers[def.URI] = handler
}

func (s *Server) RegisterPrompt(def PromptDefinition, handler PromptHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts = append(s.prompts, def)
	s.promptHandlers[def.Name] = handler
}

func TextResult(data any) *CallToolResult {
	var text string
	switch v := data.(type) {
	case string:
		text = v
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			text = fmt.Sprintf("%v", v)
		} else {
			text = string(b)
		}
	}
	return &CallToolResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
	}
}

func ErrorResult(err error) *CallToolResult {
	return &CallToolResult{
		IsError: true,
		Content: []ContentBlock{{Type: "text", Text: err.Error()}},
	}
}

func ImageAndTextResult(base64Data, mimeType, summary string) *CallToolResult {
	if mimeType == "" {
		mimeType = "image/png"
	}
	blocks := []ContentBlock{
		{Type: "image", Data: base64Data, MimeType: mimeType},
	}
	if summary != "" {
		blocks = append(blocks, ContentBlock{Type: "text", Text: summary})
	}
	return &CallToolResult{Content: blocks}
}

func (s *Server) HandleJSONRPC(ctx context.Context, raw []byte) ([]byte, bool) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, false
	}

	if strings.HasPrefix(trimmed, "[") {
		var batch []json.RawMessage
		if err := json.Unmarshal(raw, &batch); err != nil {
			resp := JSONRPCResponse{
				JSONRPC: "2.0",
				Error:   &JSONRPCError{Code: -32700, Message: "Parse error"},
			}
			out, _ := json.Marshal(resp)
			return out, true
		}
		var responses []JSONRPCResponse
		for _, item := range batch {
			resp, hasReply := s.processSingle(ctx, item)
			if hasReply {
				responses = append(responses, resp)
			}
		}
		if len(responses) == 0 {
			return nil, false
		}
		out, _ := json.Marshal(responses)
		return out, true
	}

	resp, hasReply := s.processSingle(ctx, raw)
	if !hasReply {
		return nil, false
	}
	out, _ := json.Marshal(resp)
	return out, true
}

func (s *Server) processSingle(ctx context.Context, raw []byte) (JSONRPCResponse, bool) {
	var req JSONRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   &JSONRPCError{Code: -32700, Message: "Parse error"},
		}, true
	}

	if req.ID == nil && strings.HasPrefix(req.Method, "notifications/") {
		return JSONRPCResponse{}, false
	}

	switch req.Method {
	case "initialize":
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &initParams)
		negotiated := LatestProtocolVersion
		if initParams.ProtocolVersion == LegacyProtocolVersion {
			negotiated = LegacyProtocolVersion
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": negotiated,
				"capabilities": map[string]any{
					"tools":     map[string]any{"listChanged": false},
					"resources": map[string]any{"subscribe": false, "listChanged": false},
					"prompts":   map[string]any{"listChanged": false},
				},
				"serverInfo": map[string]any{
					"name":    s.name,
					"version": s.version,
				},
			},
		}, true

	case "ping":
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}, true

	case "tools/list":
		s.mu.RLock()
		toolsCopy := make([]ToolDefinition, len(s.tools))
		copy(toolsCopy, s.tools)
		s.mu.RUnlock()
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"tools": toolsCopy},
		}, true

	case "tools/call":
		var callParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: "Invalid tool call parameters"},
			}, true
		}
		s.mu.RLock()
		handler, ok := s.toolHandlers[callParams.Name]
		s.mu.RUnlock()
		if !ok {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Unknown tool: %s", callParams.Name)},
			}, true
		}
		if callParams.Arguments == nil {
			callParams.Arguments = make(map[string]any)
		}
		res, err := handler(ctx, callParams.Arguments)
		if err != nil {
			res = ErrorResult(err)
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  res,
		}, true

	case "resources/list":
		s.mu.RLock()
		resCopy := make([]ResourceDefinition, len(s.resources))
		copy(resCopy, s.resources)
		s.mu.RUnlock()
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"resources": resCopy},
		}, true

	case "resources/read":
		var readParams struct {
			URI string `json:"uri"`
		}
		if err := json.Unmarshal(req.Params, &readParams); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: "Invalid resource read parameters"},
			}, true
		}
		s.mu.RLock()
		handler, ok := s.resourceHandlers[readParams.URI]
		s.mu.RUnlock()
		if !ok {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: fmt.Sprintf("Resource not found: %s", readParams.URI)},
			}, true
		}
		contents, err := handler(ctx, readParams.URI)
		if err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32603, Message: err.Error()},
			}, true
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"contents": contents},
		}, true

	case "prompts/list":
		s.mu.RLock()
		promptsCopy := make([]PromptDefinition, len(s.prompts))
		copy(promptsCopy, s.prompts)
		s.mu.RUnlock()
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{"prompts": promptsCopy},
		}, true

	case "prompts/get":
		var promptParams struct {
			Name      string            `json:"name"`
			Arguments map[string]string `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &promptParams); err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32602, Message: "Invalid prompt parameters"},
			}, true
		}
		s.mu.RLock()
		handler, ok := s.promptHandlers[promptParams.Name]
		s.mu.RUnlock()
		if !ok {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Unknown prompt: %s", promptParams.Name)},
			}, true
		}
		desc, msgs, err := handler(ctx, promptParams.Arguments)
		if err != nil {
			return JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      req.ID,
				Error:   &JSONRPCError{Code: -32603, Message: err.Error()},
			}, true
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"description": desc,
				"messages":    msgs,
			},
		}, true

	default:
		if req.ID == nil {
			return JSONRPCResponse{}, false
		}
		return JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Method not found: %s", req.Method)},
		}, true
	}
}

func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 16*1024*1024)

	var writeMu sync.Mutex
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		respBytes, hasReply := s.HandleJSONRPC(ctx, line)
		if hasReply && len(respBytes) > 0 {
			writeMu.Lock()
			_, _ = out.Write(append(respBytes, '\n'))
			writeMu.Unlock()
		}
	}
	return scanner.Err()
}

func (s *Server) ServeUnixSocket(ctx context.Context, socketPath string) error {
	if err := os.MkdirAll(filepath.Dir(socketPath), 0700); err != nil {
		return err
	}
	_ = os.Remove(socketPath)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	_ = os.Chmod(socketPath, 0600)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		_ = os.Remove(socketPath)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = s.ServeStdio(ctx, c, c)
		}(conn)
	}
}

func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/mcp", s.authMiddleware(s.handleStreamableHTTP))
	mux.HandleFunc("/sse", s.authMiddleware(s.handleSSEStream))
	mux.HandleFunc("/message", s.authMiddleware(s.handleSSEMessage))
	return mux
}

func (s *Server) ServeHTTP(ctx context.Context, listenAddr string) error {
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           s.HTTPHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	err := srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if s.authToken != "" {
			authHeader := r.Header.Get("Authorization")
			expected := "Bearer " + s.authToken
			if authHeader != expected && r.URL.Query().Get("token") != s.authToken {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"server":     s.name,
		"version":    s.version,
		"transports": []string{"stdio", "http", "sse", "dual", "unix"},
	})
}

func (s *Server) handleStreamableHTTP(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		sessionID = newSessionID()
	}
	w.Header().Set("Mcp-Session-Id", sessionID)

	switch r.Method {
	case http.MethodDelete:
		s.removeSSESession(sessionID)
		w.WriteHeader(http.StatusNoContent)
		return

	case http.MethodGet:
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}
		sess := s.createSSESession(sessionID)
		defer s.removeSSESession(sessionID)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		flusher.Flush()

		for {
			select {
			case <-r.Context().Done():
				return
			case msg, open := <-sess.ch:
				if !open {
					return
				}
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
				flusher.Flush()
			}
		}

	case http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}
		respBytes, hasReply := s.HandleJSONRPC(r.Context(), body)
		if !hasReply {
			w.WriteHeader(http.StatusAccepted)
			return
		}

		accept := r.Header.Get("Accept")
		if strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "application/json") {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(respBytes))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSEStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	sessID := newSessionID()
	sess := s.createSSESession(sessID)
	defer s.removeSSESession(sessID)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	endpointURL := fmt.Sprintf("/message?sessionId=%s", sessID)
	_, _ = fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-sess.ch:
			if !open {
				return
			}
			_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
			flusher.Flush()
		}
	}
}

func (s *Server) handleSSEMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sessID := r.URL.Query().Get("sessionId")
	body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	respBytes, hasReply := s.HandleJSONRPC(r.Context(), body)
	if hasReply && len(respBytes) > 0 {
		s.mu.RLock()
		sess, exists := s.sseSessions[sessID]
		s.mu.RUnlock()
		if exists {
			select {
			case sess.ch <- respBytes:
			default:
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(respBytes)
		return
	}

	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) createSSESession(id string) *sseSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := &sseSession{
		id:      id,
		ch:      make(chan []byte, 64),
		created: time.Now(),
	}
	s.sseSessions[id] = sess
	return sess
}

func (s *Server) removeSSESession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sseSessions[id]; ok {
		close(sess.ch)
		delete(s.sseSessions, id)
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
