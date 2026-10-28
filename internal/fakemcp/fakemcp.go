// Package fakemcp is a tiny Streamable HTTP MCP server used by tests and the
// local demo. It requires its own bearer credential (the one the gateway
// injects), issues a session id on initialize, and records the headers it
// receives so tests can assert what crossed the gateway.
package fakemcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
)

// Tool is a fake tool.
type Tool struct {
	Name        string
	Description string
	Schema      map[string]any
	Handle      func(args map[string]any, h http.Header) string
}

// Server is the fake upstream.
type Server struct {
	Token string // expected "Authorization: Bearer <Token>"
	Tools []Tool
	SSE   bool // answer tools/call as text/event-stream

	mu       sync.Mutex
	sessions map[string]bool
	Seen     []http.Header // headers of every request
	Calls    []string      // raw arguments of every tools/call
}

func obj(props ...string) map[string]any {
	p := map[string]any{}
	for _, n := range props {
		p[n] = map[string]any{"type": "string"}
	}
	return map[string]any{"type": "object", "properties": p, "required": props}
}

// FilesServer exposes read_file, write_file and debug_echo_auth. The last one
// returns the Authorization header it received, standing in for an upstream
// that leaks its credential in an error message or a debug field.
func FilesServer(token string) *Server {
	return &Server{Token: token, Tools: []Tool{
		{Name: "read_file", Description: "Read a UTF-8 text file.", Schema: obj("path"),
			Handle: func(a map[string]any, _ http.Header) string { return fmt.Sprintf("contents of %v", a["path"]) }},
		{Name: "write_file", Description: "Write a UTF-8 text file.", Schema: obj("path", "content"),
			Handle: func(a map[string]any, _ http.Header) string { return fmt.Sprintf("wrote %v", a["path"]) }},
		{Name: "debug_echo_auth", Description: "Return request diagnostics.", Schema: obj(),
			Handle: func(_ map[string]any, h http.Header) string {
				return "upstream saw Authorization: " + h.Get("Authorization")
			}},
	}}
}

// WebServer exposes search_web and send_email.
func WebServer(token string) *Server {
	return &Server{Token: token, Tools: []Tool{
		{Name: "search_web", Description: "Search the web and return result snippets.", Schema: obj("query"),
			Handle: func(a map[string]any, _ http.Header) string { return fmt.Sprintf("3 results for %v", a["query"]) }},
		{Name: "send_email", Description: "Send an email.", Schema: obj("to", "subject", "body"),
			Handle: func(a map[string]any, _ http.Header) string { return fmt.Sprintf("sent to %v", a["to"]) }},
	}}
}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.Seen = append(s.Seen, r.Header.Clone())
	if s.sessions == nil {
		s.sessions = map[string]bool{}
	}
	s.mu.Unlock()
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+s.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req rpcReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", 400)
		return
	}
	if req.Method != "initialize" {
		s.mu.Lock()
		ok := s.sessions[r.Header.Get("Mcp-Session-Id")]
		s.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound) // unknown session: client must re-initialize
			return
		}
	}
	if len(req.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		sid := hex.EncodeToString(b)
		s.mu.Lock()
		s.sessions[sid] = true
		s.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", sid)
		result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "fakemcp", "version": "0"}}
	case "tools/list":
		var tools []map[string]any
		for _, t := range s.Tools {
			tools = append(tools, map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Schema})
		}
		sort.Slice(tools, func(i, j int) bool { return tools[i]["name"].(string) < tools[j]["name"].(string) })
		result = map[string]any{"tools": tools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		_ = json.Unmarshal(req.Params, &p)
		s.mu.Lock()
		s.Calls = append(s.Calls, string(p.Arguments))
		s.mu.Unlock()
		var args map[string]any
		_ = json.Unmarshal(p.Arguments, &args)
		var tool *Tool
		for i := range s.Tools {
			if s.Tools[i].Name == p.Name {
				tool = &s.Tools[i]
			}
		}
		if tool == nil {
			writeRPC(w, req.ID, nil, map[string]any{"code": -32602, "message": "unknown tool"}, false)
			return
		}
		result = map[string]any{"content": []map[string]any{{"type": "text", "text": tool.Handle(args, r.Header)}}, "isError": false}
		writeRPC(w, req.ID, result, nil, s.SSE)
		return
	default:
		writeRPC(w, req.ID, nil, map[string]any{"code": -32601, "message": "method not found"}, false)
		return
	}
	writeRPC(w, req.ID, result, nil, false)
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result, rpcErr any, sse bool) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if rpcErr != nil {
		msg["error"] = rpcErr
	} else {
		msg["result"] = result
	}
	b, _ := json.Marshal(msg)
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// CallsSnapshot returns the recorded tools/call arguments.
func (s *Server) CallsSnapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.Calls...)
}

// SeenSnapshot returns the recorded request headers.
func (s *Server) SeenSnapshot() []http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]http.Header(nil), s.Seen...)
}

// DropSessions forgets all sessions (simulates an upstream restart).
func (s *Server) DropSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]bool{}
}
