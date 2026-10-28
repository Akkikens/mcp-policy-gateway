package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/creds"
	"github.com/Akkikens/mcp-policy-gateway/internal/jsonrpc"
)

// ProtocolVersion is the MCP revision the gateway speaks upstream.
const ProtocolVersion = "2025-06-18"

const maxUpstreamBytes = 4 << 20

// ToolDef is a tool as advertised by an upstream.
type ToolDef struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
}

// Upstream is an MCP client for one upstream server.
type Upstream struct {
	Name   string
	URL    string
	Client *http.Client
	Vault  *creds.Vault

	nextID  atomic.Int64
	mu      sync.Mutex
	session string
	ready   bool
}

var errSessionGone = errors.New("upstream session expired")

func (u *Upstream) post(ctx context.Context, msg any, wantID int64) (*jsonrpc.Response, error) {
	body, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", ProtocolVersion)
	u.mu.Lock()
	if u.session != "" {
		req.Header.Set("Mcp-Session-Id", u.session)
	}
	u.mu.Unlock()
	// The upstream credential is set here and only here.
	u.Vault.Apply(u.Name, req.Header)

	client := u.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound && u.session != "" {
		return nil, errSessionGone
	}
	if wantID == 0 { // notification
		if resp.StatusCode/100 != 2 {
			return nil, fmt.Errorf("upstream %s: status %d", u.Name, resp.StatusCode)
		}
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream %s: status %d", u.Name, resp.StatusCode)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		u.mu.Lock()
		u.session = sid
		u.mu.Unlock()
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	limited := io.LimitReader(resp.Body, maxUpstreamBytes)
	if ct == "text/event-stream" {
		return readSSE(limited, wantID)
	}
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	return jsonrpc.ParseResponse(b)
}

// readSSE returns the first JSON-RPC response with the wanted id from an SSE
// stream, skipping server requests and notifications sent before it.
func readSSE(r io.Reader, wantID int64) (*jsonrpc.Response, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), maxUpstreamBytes)
	var data []string
	want := fmt.Sprint(wantID)
	flush := func() (*jsonrpc.Response, bool) {
		if len(data) == 0 {
			return nil, false
		}
		payload := strings.Join(data, "\n")
		data = data[:0]
		resp, err := jsonrpc.ParseResponse([]byte(payload))
		if err != nil || string(resp.ID) != want {
			return nil, false
		}
		return resp, true
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			if resp, ok := flush(); ok {
				return resp, nil
			}
			continue
		}
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
		}
	}
	if resp, ok := flush(); ok {
		return resp, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("event stream ended without a response")
}

func (u *Upstream) initialize(ctx context.Context) error {
	u.mu.Lock()
	u.session, u.ready = "", false
	u.mu.Unlock()
	id := u.nextID.Add(1)
	resp, err := u.post(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": "initialize", "params": map[string]any{
		"protocolVersion": ProtocolVersion, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "mcp-policy-gateway", "version": Version},
	}}, id)
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return fmt.Errorf("upstream %s initialize: %s", u.Name, resp.Error.Message)
	}
	if _, err := u.post(ctx, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, 0); err != nil {
		return err
	}
	u.mu.Lock()
	u.ready = true
	u.mu.Unlock()
	return nil
}

// Call sends one request, initializing (or re-initializing once, if the
// upstream dropped the session) as needed.
func (u *Upstream) Call(ctx context.Context, method string, params any) (*jsonrpc.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		u.mu.Lock()
		ready := u.ready
		u.mu.Unlock()
		if !ready {
			if err := u.initialize(ctx); err != nil {
				return nil, err
			}
		}
		id := u.nextID.Add(1)
		resp, err := u.post(ctx, map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}, id)
		if errors.Is(err, errSessionGone) {
			u.mu.Lock()
			u.ready = false
			u.mu.Unlock()
			continue
		}
		return resp, err
	}
	return nil, fmt.Errorf("upstream %s: session could not be re-established", u.Name)
}

// ListTools fetches the upstream's tools, following pagination cursors.
func (u *Upstream) ListTools(ctx context.Context) ([]ToolDef, error) {
	var all []ToolDef
	cursor := ""
	for page := 0; page < 50; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		resp, err := u.Call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("upstream %s tools/list: %s", u.Name, resp.Error.Message)
		}
		var res struct {
			Tools      []ToolDef `json:"tools"`
			NextCursor string    `json:"nextCursor"`
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			return nil, fmt.Errorf("upstream %s tools/list: %w", u.Name, err)
		}
		all = append(all, res.Tools...)
		if res.NextCursor == "" {
			return all, nil
		}
		cursor = res.NextCursor
	}
	return nil, fmt.Errorf("upstream %s: too many tools/list pages", u.Name)
}
