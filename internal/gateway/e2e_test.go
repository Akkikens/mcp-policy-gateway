package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/audit"
	"github.com/Akkikens/mcp-policy-gateway/internal/auth"
	"github.com/Akkikens/mcp-policy-gateway/internal/creds"
	"github.com/Akkikens/mcp-policy-gateway/internal/fakemcp"
	"github.com/Akkikens/mcp-policy-gateway/internal/policy"
	"github.com/Akkikens/mcp-policy-gateway/internal/scim"
)

const (
	filesSecret = "files-upstream-secret-7f3a"
	webSecret   = "web-upstream-secret-91bc"
	scimToken   = "scim-provisioning-token"
)

type env struct {
	t       *testing.T
	gw      *Gateway
	srv     *httptest.Server
	iss     *auth.DevIssuer
	files   *fakemcp.Server
	web     *fakemcp.Server
	cfg     *Config
	priv    ed25519.PrivateKey
	dir     string
	mu      sync.Mutex
	now     time.Time
	logs    *bytes.Buffer
	userIDs map[string]string
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func (e *env) writeBundle(version uint64, ttl time.Duration) {
	e.t.Helper()
	src, err := os.ReadFile("../../policies/gateway.cedar")
	if err != nil {
		e.t.Fatal(err)
	}
	now := e.clock()
	m := policy.Manifest{Version: version, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(ttl), Policies: map[string]string{"gateway.cedar": string(src)}}
	b, err := policy.SignJSON(policy.TypeBundle, m, "test-1", e.priv)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.cfg.Policy.Bundle, b, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, now: time.Now().Truncate(time.Second), dir: t.TempDir(), logs: &bytes.Buffer{}, userIDs: map[string]string{}}
	var err error
	e.iss, err = auth.NewDevIssuer("https://idp.test")
	if err != nil {
		t.Fatal(err)
	}
	e.iss.Now = e.clock
	idp := httptest.NewServer(e.iss.JWKSHandler())
	t.Cleanup(idp.Close)

	e.files = fakemcp.FilesServer(filesSecret)
	e.web = fakemcp.WebServer(webSecret)
	e.web.SSE = true // exercise the text/event-stream response path
	fs := httptest.NewServer(e.files)
	ws := httptest.NewServer(e.web)
	t.Cleanup(fs.Close)
	t.Cleanup(ws.Close)
	t.Setenv("FILES_TOKEN", filesSecret)
	t.Setenv("WEB_TOKEN", webSecret)
	t.Setenv("SCIM_TOKEN", scimToken)

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.priv = priv
	keysPath := filepath.Join(e.dir, "trusted_keys.json")
	kb, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"keyid": "test-1", "ed25519": base64.StdEncoding.EncodeToString(pub)}}})
	_ = os.WriteFile(keysPath, kb, 0o600)

	// The gateway's public URL must be known before it starts, so reserve
	// the listener first.
	e.srv = httptest.NewUnstartedServer(nil)
	public := "http://" + e.srv.Listener.Addr().String()
	e.cfg = &Config{
		PublicURL: public, Issuer: e.iss.Issuer, JWKSURL: idp.URL, AuthorizationServers: []string{e.iss.Issuer},
		RequiredScopes: []string{"mcp:tools"}, SCIMTokenEnv: "SCIM_TOKEN", AuditLog: filepath.Join(e.dir, "audit.jsonl"),
		Policy: PolicyConfig{Bundle: filepath.Join(e.dir, "bundle.json"), TrustedKeys: keysPath, State: filepath.Join(e.dir, "state.json")},
		Upstreams: []UpstreamConfig{
			{Name: "files", URL: fs.URL, Credential: credSpec("FILES_TOKEN")},
			{Name: "web", URL: ws.URL, Credential: credSpec("WEB_TOKEN")},
		},
	}
	e.writeBundle(1, 24*time.Hour)
	e.gw, err = New(e.cfg, Deps{Now: e.clock, Logger: slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Config.Handler = e.gw.Handler()
	e.srv.Start()
	t.Cleanup(func() { e.srv.Close(); _ = e.gw.Close() })

	// provision through the SCIM API, as an IdP would
	for _, u := range []string{"alice", "bob", "carol"} {
		_, body := e.scim("POST", "/Users", `{"userName":"`+u+`"}`)
		e.userIDs[u] = body["id"].(string)
	}
	e.scim("POST", "/Groups", `{"displayName":"engineering","members":[{"value":"`+e.userIDs["alice"]+`"}]}`)
	e.scim("POST", "/Groups", `{"displayName":"admins","members":[{"value":"`+e.userIDs["carol"]+`"}]}`)
	return e
}

func (e *env) scim(method, path, body string) (int, map[string]any) {
	req, _ := http.NewRequest(method, e.srv.URL+"/scim/v2"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+scimToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func (e *env) token(sub string, scopes ...string) string {
	if len(scopes) == 0 {
		scopes = []string{"mcp:tools"}
	}
	tok, err := e.iss.Mint(auth.TokenOptions{Subject: sub, Audience: e.cfg.Resource(), Scopes: scopes})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

type rpcResp struct {
	Status int
	Header http.Header
	Raw    string
	Result json.RawMessage
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
}

func (e *env) rpc(tok, method string, params any) rpcResp {
	e.t.Helper()
	msg := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
	if params != nil {
		msg["params"] = params
	}
	b, _ := json.Marshal(msg)
	return e.raw(tok, b)
}

func (e *env) raw(tok string, body []byte) rpcResp {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := rpcResp{Status: resp.StatusCode, Header: resp.Header, Raw: string(rb)}
	_ = json.Unmarshal(rb, &out)
	return out
}

func (e *env) listNames(tok string) []string {
	e.t.Helper()
	r := e.rpc(tok, "tools/list", map[string]any{})
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		e.t.Fatalf("tools/list: %s", r.Raw)
	}
	var names []string
	for _, t := range res.Tools {
		names = append(names, t.Name)
	}
	return names
}

func call(name string, args map[string]any) map[string]any {
	return map[string]any{"name": name, "arguments": args}
}

func resultText(t *testing.T, r rpcResp) string {
	t.Helper()
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if r.Error != nil || json.Unmarshal(r.Result, &res) != nil || len(res.Content) == 0 {
		t.Fatalf("expected a tool result, got %s", r.Raw)
	}
	return res.Content[0].Text
}

func TestEndToEnd(t *testing.T) {
	e := newEnv(t)
	alice := e.token("alice")

	t.Run("no token gets a 401 pointing at resource metadata", func(t *testing.T) {
		r := e.rpc("", "tools/list", nil)
		if r.Status != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Fatalf("%d %q", r.Status, r.Header.Get("WWW-Authenticate"))
		}
		resp, _ := http.Get(e.srv.URL + "/.well-known/oauth-protected-resource/mcp")
		var m auth.ProtectedResourceMetadata
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
		if m.Resource != e.cfg.Resource() || m.AuthorizationServers[0] != e.iss.Issuer {
			t.Fatalf("metadata %+v", m)
		}
	})

	t.Run("token for another resource is rejected", func(t *testing.T) {
		tok, _ := e.iss.Mint(auth.TokenOptions{Subject: "alice", Audience: "https://other.test/mcp", Scopes: []string{"mcp:tools"}})
		if r := e.rpc(tok, "tools/list", nil); r.Status != 401 {
			t.Fatalf("status %d", r.Status)
		}
	})

	t.Run("missing scope is 403 insufficient_scope", func(t *testing.T) {
		r := e.rpc(e.token("alice", "profile"), "tools/list", nil)
		if r.Status != 403 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "insufficient_scope") {
			t.Fatalf("%d %q", r.Status, r.Header.Get("WWW-Authenticate"))
		}
	})

	t.Run("valid token for an unprovisioned subject is denied", func(t *testing.T) {
		if r := e.rpc(e.token("mallory"), "tools/list", nil); r.Status != 403 {
			t.Fatalf("status %d %s", r.Status, r.Raw)
		}
	})

	t.Run("foreign Origin is refused", func(t *testing.T) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Authorization", "Bearer "+alice)
		req.Header.Set("Origin", "http://evil.test")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("initialize", func(t *testing.T) {
		r := e.rpc(alice, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}})
		if r.Error != nil || !strings.Contains(string(r.Result), `"protocolVersion":"2025-06-18"`) {
			t.Fatalf("%s", r.Raw)
		}
		if r := e.raw(alice, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)); r.Status != 202 {
			t.Fatalf("notification status %d", r.Status)
		}
	})

	t.Run("policy projection: each principal sees only their tools", func(t *testing.T) {
		cases := map[string][]string{
			"alice": {"files__read_file", "web__search_web", "web__send_email"},
			"bob":   {"web__search_web"},
			"carol": {"files__debug_echo_auth", "files__read_file", "files__write_file", "web__search_web", "web__send_email"},
		}
		for who, want := range cases {
			if got := e.listNames(e.token(who)); !slices.Equal(got, want) {
				t.Errorf("%s sees %v, want %v", who, got, want)
			}
		}
	})

	t.Run("argument constraints", func(t *testing.T) {
		if txt := resultText(t, e.rpc(alice, "tools/call", call("files__read_file", map[string]any{"path": "/srv/docs/readme.md"}))); txt != "contents of /srv/docs/readme.md" {
			t.Fatalf("allowed call: %q", txt)
		}
		for _, p := range []string{"/etc/passwd", "/srv/docs/../../etc/passwd"} {
			r := e.rpc(alice, "tools/call", call("files__read_file", map[string]any{"path": p}))
			if r.Error == nil || r.Error.Code != -32003 {
				t.Fatalf("path %q not denied: %s", p, r.Raw)
			}
		}
		if r := e.rpc(alice, "tools/call", call("web__send_email", map[string]any{"to": "x@evil.test", "subject": "s", "body": "b"})); r.Error == nil || r.Error.Code != -32003 {
			t.Fatalf("external email allowed: %s", r.Raw)
		}
		if txt := resultText(t, e.rpc(alice, "tools/call", call("web__send_email", map[string]any{"to": "c@example.com", "subject": "s", "body": "b"}))); txt != "sent to c@example.com" {
			t.Fatalf("internal email: %q", txt)
		}
	})

	t.Run("scope-gated tool", func(t *testing.T) {
		if r := e.rpc(e.token("bob"), "tools/call", call("web__search_web", map[string]any{"query": "go"})); r.Error == nil {
			t.Fatalf("search without web:search allowed: %s", r.Raw)
		}
		r := e.rpc(e.token("bob", "mcp:tools", "web:search"), "tools/call", call("web__search_web", map[string]any{"query": "go"}))
		if txt := resultText(t, r); txt != "3 results for go" {
			t.Fatalf("search: %q", txt)
		}
	})

	t.Run("hidden tools look like missing tools", func(t *testing.T) {
		hidden := e.rpc(e.token("bob"), "tools/call", call("files__write_file", map[string]any{"path": "/srv/workspace/a"}))
		missing := e.rpc(e.token("bob"), "tools/call", call("files__no_such_tool", map[string]any{}))
		if hidden.Error == nil || missing.Error == nil || hidden.Error.Code != missing.Error.Code || hidden.Error.Code != -32602 {
			t.Fatalf("hidden %s / missing %s", hidden.Raw, missing.Raw)
		}
	})

	t.Run("forbid overrides an admin permit", func(t *testing.T) {
		carol := e.token("carol")
		if r := e.rpc(carol, "tools/call", call("files__write_file", map[string]any{"path": "/etc/cron.d/x", "content": "c"})); r.Error == nil || r.Error.Code != -32003 {
			t.Fatalf("write outside workspace: %s", r.Raw)
		}
		if txt := resultText(t, e.rpc(carol, "tools/call", call("files__write_file", map[string]any{"path": "/srv/workspace/a", "content": "c"}))); txt != "wrote /srv/workspace/a" {
			t.Fatalf("workspace write: %q", txt)
		}
	})

	t.Run("credential mediation", func(t *testing.T) {
		r := e.rpc(e.token("carol"), "tools/call", call("files__debug_echo_auth", map[string]any{}))
		txt := resultText(t, r)
		if strings.Contains(r.Raw, filesSecret) || !strings.Contains(txt, "[REDACTED]") {
			t.Fatalf("upstream credential reached the client: %s", r.Raw)
		}
		for _, srv := range []*fakemcp.Server{e.files, e.web} {
			for _, h := range srv.SeenSnapshot() {
				if strings.Contains(h.Get("Authorization"), alice) || strings.Contains(h.Get("Authorization"), "eyJ") {
					t.Fatal("client token was forwarded to an upstream")
				}
			}
		}
		if strings.Contains(e.logs.String(), filesSecret) || strings.Contains(e.logs.String(), webSecret) {
			t.Fatal("upstream credential in gateway logs")
		}
	})

	t.Run("forwarded arguments are the canonical evaluated bytes", func(t *testing.T) {
		before := len(e.files.CallsSnapshot())
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"arguments":{"path":"/srv/docs/b.md"},"name":"files__read_file"}}`
		if r := e.raw(alice, []byte(body)); r.Error != nil {
			t.Fatal(r.Raw)
		}
		calls := e.files.CallsSnapshot()
		if len(calls) != before+1 || calls[len(calls)-1] != `{"path":"/srv/docs/b.md"}` {
			t.Fatalf("forwarded %v", calls[before:])
		}
	})

	t.Run("duplicate keys are rejected before policy", func(t *testing.T) {
		body := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"files__read_file","arguments":{"path":"/srv/docs/a","path":"/etc/shadow"}}}`
		if r := e.raw(alice, []byte(body)); r.Status != 400 || r.Error == nil {
			t.Fatalf("duplicate key accepted: %d %s", r.Status, r.Raw)
		}
	})

	t.Run("unmediated methods are not exposed", func(t *testing.T) {
		if r := e.rpc(alice, "resources/list", map[string]any{}); r.Error == nil || r.Error.Code != -32601 {
			t.Fatalf("%s", r.Raw)
		}
	})

	t.Run("upstream session loss is recovered", func(t *testing.T) {
		e.files.DropSessions()
		if txt := resultText(t, e.rpc(alice, "tools/call", call("files__read_file", map[string]any{"path": "/srv/docs/c"}))); txt != "contents of /srv/docs/c" {
			t.Fatalf("after session loss: %q", txt)
		}
	})

	t.Run("deprovisioning via SCIM takes effect on the next call", func(t *testing.T) {
		patch := `{"schemas":["` + scim.SchemaPatch + `"],"Operations":[{"op":"replace","path":"active","value":false}]}`
		if code, _ := e.scim("PATCH", "/Users/"+e.userIDs["alice"], patch); code != 200 {
			t.Fatalf("patch %d", code)
		}
		if r := e.rpc(alice, "tools/list", nil); r.Status != 403 {
			t.Fatalf("deactivated user still served: %d", r.Status)
		}
		patch = strings.Replace(patch, "false", "true", 1)
		e.scim("PATCH", "/Users/"+e.userIDs["alice"], patch)
	})

	t.Run("rollback at runtime is rejected and v2 keeps serving", func(t *testing.T) {
		e.writeBundle(2, 24*time.Hour)
		if err := e.gw.ReloadPolicy(); err != nil {
			t.Fatal(err)
		}
		e.writeBundle(1, 24*time.Hour)
		if err := e.gw.ReloadPolicy(); err == nil || !strings.Contains(err.Error(), "rollback") {
			t.Fatalf("rollback not rejected: %v", err)
		}
		if got := e.listNames(alice); len(got) != 3 {
			t.Fatalf("policy lost after rejected rollback: %v", got)
		}
	})

	t.Run("expired policy fails closed", func(t *testing.T) {
		e.advance(25 * time.Hour)
		defer e.advance(-25 * time.Hour)
		tok := e.token("carol")
		if got := e.listNames(tok); len(got) != 0 {
			t.Fatalf("stale policy still projects tools: %v", got)
		}
		r := e.rpc(tok, "tools/call", call("files__read_file", map[string]any{"path": "/srv/docs/a"}))
		if r.Error == nil {
			t.Fatalf("stale policy allowed a call: %s", r.Raw)
		}
		resp, _ := http.Get(e.srv.URL + "/readyz")
		resp.Body.Close()
		if resp.StatusCode != 503 {
			t.Fatalf("readyz %d with stale policy", resp.StatusCode)
		}
	})

	t.Run("audit log verifies and records denies", func(t *testing.T) {
		n, _, err := audit.VerifyFile(e.cfg.AuditLog)
		if err != nil || n < 10 {
			t.Fatalf("verify: n=%d err=%v", n, err)
		}
		b, _ := os.ReadFile(e.cfg.AuditLog)
		s := string(b)
		for _, want := range []string{`"event":"deny"`, `"event":"allow"`, `"event":"list"`, `"binding":"`, "principal_inactive", "not_visible"} {
			if !strings.Contains(s, want) {
				t.Errorf("audit log has no %s", want)
			}
		}
		if strings.Contains(s, "/srv/docs/readme.md") || strings.Contains(s, filesSecret) {
			t.Error("audit log stores argument values or secrets")
		}
	})
}

func TestNoPolicyFailsClosedAtStartup(t *testing.T) {
	e := newEnv(t)
	_ = os.Remove(e.cfg.Policy.Bundle)
	_ = os.Remove(e.cfg.Policy.State)
	cfg := *e.cfg
	cfg.AuditLog = filepath.Join(t.TempDir(), "a.jsonl")
	cfg.Policy.State = filepath.Join(t.TempDir(), "s.json")
	gw, err := New(&cfg, Deps{Now: e.clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close()
	srv := httptest.NewServer(gw.Handler())
	defer srv.Close()
	resp, _ := http.Get(srv.URL + "/readyz")
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("readyz %d without policy", resp.StatusCode)
	}
}

func credSpec(env string) creds.Spec { return creds.Spec{Prefix: "Bearer ", Env: env} }
