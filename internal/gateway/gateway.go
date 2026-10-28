// Package gateway is the MCP policy gateway: a Streamable HTTP endpoint that
// authenticates the caller (OAuth 2.1 bearer JWT), resolves them through the
// SCIM directory, projects and authorizes tools with signed Cedar policy, and
// forwards allowed calls to upstream MCP servers with gateway-held
// credentials. Every decision is written to a hash-chained audit log.
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/audit"
	"github.com/Akkikens/mcp-policy-gateway/internal/auth"
	"github.com/Akkikens/mcp-policy-gateway/internal/creds"
	"github.com/Akkikens/mcp-policy-gateway/internal/jsonrpc"
	"github.com/Akkikens/mcp-policy-gateway/internal/policy"
	"github.com/Akkikens/mcp-policy-gateway/internal/scim"
)

// SupportedProtocolVersions are the MCP revisions accepted from clients.
var SupportedProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

const (
	toolSep      = "__" // advertised name = <upstream>__<tool>
	toolCacheTTL = 60 * time.Second
)

// Deps are injectable dependencies.
type Deps struct {
	HTTPClient *http.Client
	Now        func() time.Time
	Logger     *slog.Logger
	Directory  *scim.Store
}

type toolCache struct {
	at    time.Time
	tools map[string]ToolDef
}

// Gateway is the server.
type Gateway struct {
	cfg       *Config
	validator *auth.Validator
	dir       *scim.Store
	scim      http.Handler
	store     *policy.Store
	engine    *policy.Engine
	audit     *audit.Log
	vault     *creds.Vault
	upstreams map[string]*Upstream
	order     []string
	log       *slog.Logger
	now       func() time.Time

	cacheMu sync.Mutex
	cache   map[string]toolCache

	policyMu  sync.Mutex
	policyErr error
}

// New builds a gateway. A policy bundle that fails to load is not fatal: the
// gateway starts and denies everything until a valid bundle appears.
func New(cfg *Config, d Deps) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	now := d.Now
	if now == nil {
		now = time.Now
	}
	specs := map[string]creds.Spec{}
	for _, u := range cfg.Upstreams {
		specs[u.Name] = u.Credential
	}
	vault, err := creds.New(specs)
	if err != nil {
		return nil, err
	}
	logger := d.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	logger = slog.New(creds.NewRedactingHandler(logger.Handler(), vault))

	keys, err := policy.LoadTrustedKeys(cfg.Policy.TrustedKeys)
	if err != nil {
		return nil, fmt.Errorf("trusted keys: %w", err)
	}
	store := &policy.Store{
		Keys: keys, StatePath: cfg.Policy.State, MinVersion: cfg.Policy.MinVersion,
		RequireRevocations: cfg.Policy.RequireRevocations, Skew: time.Minute, Now: now,
	}
	al, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return nil, err
	}
	al.Now = now
	dir := d.Directory
	if dir == nil {
		dir = scim.NewStore()
	}
	scimToken := ""
	if cfg.SCIMTokenEnv != "" {
		scimToken = os.Getenv(cfg.SCIMTokenEnv)
	}
	g := &Gateway{
		cfg: cfg, dir: dir, store: store, engine: &policy.Engine{Store: store}, audit: al, vault: vault,
		upstreams: map[string]*Upstream{}, log: logger, now: now, cache: map[string]toolCache{},
		scim: &scim.Handler{Store: dir, Token: scimToken, BaseURL: strings.TrimRight(cfg.PublicURL, "/") + "/scim/v2"},
		validator: &auth.Validator{
			Issuer: cfg.Issuer, Resource: cfg.Resource(), RequiredScopes: cfg.RequiredScopes, Leeway: 30 * time.Second, Now: now,
			Keys: &auth.JWKSCache{URL: cfg.JWKSURL, Client: d.HTTPClient, Now: now},
		},
	}
	for _, u := range cfg.Upstreams {
		g.upstreams[u.Name] = &Upstream{Name: u.Name, URL: u.URL, Client: d.HTTPClient, Vault: vault}
		g.order = append(g.order, u.Name)
	}
	if err := g.ReloadPolicy(); err != nil {
		logger.Error("policy not loaded; failing closed", "err", err)
	}
	return g, nil
}

// Close releases the audit log.
func (g *Gateway) Close() error { return g.audit.Close() }

// ReloadPolicy re-reads the revocation list and bundle from disk. A rejected
// file leaves the current policy in place.
func (g *Gateway) ReloadPolicy() error {
	var errs []error
	if p := g.cfg.Policy.Revocations; p != "" {
		if b, err := os.ReadFile(p); err != nil {
			errs = append(errs, fmt.Errorf("revocations: %w", err))
		} else if err := g.store.LoadRevocations(b); err != nil {
			errs = append(errs, fmt.Errorf("revocations: %w", err))
		}
	}
	if b, err := os.ReadFile(g.cfg.Policy.Bundle); err != nil {
		errs = append(errs, fmt.Errorf("bundle: %w", err))
	} else if act, err := g.store.Load(b); err != nil {
		errs = append(errs, fmt.Errorf("bundle: %w", err))
	} else {
		g.log.Info("policy active", "version", act.Manifest.Version, "digest", act.Digest[:12], "expires_at", act.Manifest.ExpiresAt)
	}
	err := errors.Join(errs...)
	g.policyMu.Lock()
	g.policyErr = err
	g.policyMu.Unlock()
	return err
}

// Run reloads policy on an interval until ctx is done.
func (g *Gateway) Run(ctx context.Context) {
	iv := g.cfg.Policy.ReloadInterval.Duration
	if iv <= 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := g.ReloadPolicy(); err != nil {
				g.log.Warn("policy reload rejected", "err", err)
			}
		}
	}
}

// Handler returns the HTTP routes.
func (g *Gateway) Handler() http.Handler {
	mux := http.NewServeMux()
	meta := auth.MetadataHandler(auth.ProtectedResourceMetadata{
		Resource: g.cfg.Resource(), AuthorizationServers: g.cfg.AuthorizationServers,
		ScopesSupported: g.cfg.RequiredScopes, BearerMethodsSupported: []string{"header"}, ResourceName: "mcp-policy-gateway",
	})
	mux.Handle("/.well-known/oauth-protected-resource", meta)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", meta)
	mux.Handle("/scim/v2/", g.scim)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/readyz", g.ready)
	mux.HandleFunc("/mcp", g.serveMCP)
	return mux
}

func (g *Gateway) ready(w http.ResponseWriter, _ *http.Request) {
	if _, err := g.store.Current(); err != nil {
		http.Error(w, "policy unavailable: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	_, _ = io.WriteString(w, "ready\n")
}

func (g *Gateway) metadataURL() string {
	return strings.TrimRight(g.cfg.PublicURL, "/") + "/.well-known/oauth-protected-resource/mcp"
}

func (g *Gateway) record(r audit.Record) {
	if _, err := g.audit.Append(r); err != nil {
		g.log.Error("audit append failed", "err", err)
	}
}

func writeRPC(w http.ResponseWriter, status int, resp *jsonrpc.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (g *Gateway) serveMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// No server-initiated SSE stream and no client sessions to DELETE.
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// DNS-rebinding protection required by the Streamable HTTP transport.
	if o := r.Header.Get("Origin"); o != "" && !slices.Contains(g.cfg.AllowedOrigins, o) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(SupportedProtocolVersions, v) {
		http.Error(w, "unsupported MCP-Protocol-Version", http.StatusBadRequest)
		return
	}

	tok, ok := auth.BearerToken(r)
	if !ok {
		auth.Challenge(w, g.metadataURL(), nil, "")
		return
	}
	claims, err := g.validator.Validate(r.Context(), tok)
	if err != nil {
		sub := ""
		if claims != nil {
			sub = claims.Subject
		}
		g.record(audit.Record{Event: "deny", Subject: sub, Reason: "auth: " + err.Error()})
		auth.Challenge(w, g.metadataURL(), err, strings.Join(g.cfg.RequiredScopes, " "))
		return
	}
	// A valid token is not enough: the subject must be provisioned and
	// active in the directory, so deprovisioning takes effect immediately.
	principal, found := g.dir.Lookup(claims.Subject)
	if !found || !principal.Active {
		reason := "principal_not_provisioned"
		if found {
			reason = "principal_inactive"
		}
		g.record(audit.Record{Event: "deny", Subject: claims.Subject, ClientID: claims.ClientID, Reason: reason})
		writeRPC(w, http.StatusForbidden, jsonrpc.NewError(nil, &jsonrpc.Error{Code: jsonrpc.CodeForbidden, Message: "principal is not provisioned or inactive"}))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, jsonrpc.MaxMessageBytes+1))
	if err != nil {
		writeRPC(w, http.StatusBadRequest, jsonrpc.NewError(nil, &jsonrpc.Error{Code: jsonrpc.CodeParseError, Message: "read error"}))
		return
	}
	req, perr := jsonrpc.ParseRequest(body)
	if perr != nil {
		writeRPC(w, http.StatusBadRequest, jsonrpc.NewError(nil, perr))
		return
	}
	if req.IsNotification() {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	c := &caller{claims: claims, principal: principal}
	resp := g.dispatch(r.Context(), c, req)
	writeRPC(w, http.StatusOK, resp)
}

type caller struct {
	claims    *auth.Claims
	principal scim.Principal
}

func (c *caller) input(server, tool string, args map[string]any) policy.Input {
	return policy.Input{Subject: c.claims.Subject, Groups: c.principal.Groups, Scopes: c.claims.Scopes, Server: server, Tool: tool, Args: args}
}

func (g *Gateway) dispatch(ctx context.Context, c *caller, req *jsonrpc.Request) *jsonrpc.Response {
	ok := func(v any) *jsonrpc.Response {
		resp, err := jsonrpc.NewResult(req.ID, v)
		if err != nil {
			return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeInternal, Message: "encode error"})
		}
		return resp
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := ProtocolVersion
		if slices.Contains(SupportedProtocolVersions, p.ProtocolVersion) {
			v = p.ProtocolVersion
		}
		return ok(map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "mcp-policy-gateway", "version": Version},
		})
	case "ping":
		return ok(map[string]any{})
	case "tools/list":
		tools, err := g.listTools(ctx, c)
		if err != nil {
			// Details (upstream URLs, network errors) stay in the server log.
			g.log.Error("tools/list failed", "err", err)
			return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeUpstream, Message: "upstream unavailable"})
		}
		return ok(map[string]any{"tools": tools})
	case "tools/call":
		return g.callTool(ctx, c, req)
	default:
		// Resources, prompts, sampling etc. are not mediated, so they are
		// not exposed at all rather than passed through unchecked.
		return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "method not found"})
	}
}

func (g *Gateway) tools(ctx context.Context, server string, refresh bool) (map[string]ToolDef, error) {
	g.cacheMu.Lock()
	tc, ok := g.cache[server]
	g.cacheMu.Unlock()
	if ok && !refresh && g.now().Sub(tc.at) < toolCacheTTL {
		return tc.tools, nil
	}
	defs, err := g.upstreams[server].ListTools(ctx)
	if err != nil {
		return nil, err
	}
	m := map[string]ToolDef{}
	for _, d := range defs {
		if validToolName(d.Name) {
			m[d.Name] = d
		} else {
			g.log.Warn("dropping upstream tool with invalid name", "upstream", server, "tool", d.Name)
		}
	}
	g.cacheMu.Lock()
	g.cache[server] = toolCache{at: g.now(), tools: m}
	g.cacheMu.Unlock()
	return m, nil
}

func validToolName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// listTools is policy projection: a tool is advertised only if list_tool is
// permitted for this principal, so unauthorized tools are never shown to the
// client or the model.
func (g *Gateway) listTools(ctx context.Context, c *caller) ([]ToolDef, error) {
	var out []ToolDef
	total := 0
	var errs []string
	for _, name := range g.order {
		defs, err := g.tools(ctx, name, true)
		if err != nil {
			// One broken upstream does not hide the others' tools.
			errs = append(errs, err.Error())
			g.log.Warn("upstream tools/list failed", "upstream", name, "err", err)
			continue
		}
		for _, d := range defs {
			total++
			if dec := g.engine.Decide(policy.ActionList, c.input(name, d.Name, nil)); dec.Allow {
				d.Name = name + toolSep + d.Name
				out = append(out, d)
			}
		}
	}
	if len(errs) == len(g.order) {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	names := make([]string, len(out))
	for i, d := range out {
		names[i] = d.Name
	}
	g.record(audit.Record{Event: "list", Subject: c.claims.Subject, ClientID: c.claims.ClientID, Method: "tools/list",
		Reason: fmt.Sprintf("projected %d of %d tools", len(out), total), Matched: names})
	return out, nil
}

func (g *Gateway) callTool(ctx context.Context, c *caller, req *jsonrpc.Request) *jsonrpc.Response {
	params, args, perr := jsonrpc.ParseCallParams(req.Params)
	if perr != nil {
		return jsonrpc.NewError(req.ID, perr)
	}
	unknown := jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "unknown tool: " + params.Name})
	server, tool, found := strings.Cut(params.Name, toolSep)
	up := g.upstreams[server]
	if !found || up == nil || !validToolName(tool) {
		return unknown
	}
	defs, err := g.tools(ctx, server, false)
	if err == nil {
		if _, ok := defs[tool]; !ok {
			defs, err = g.tools(ctx, server, true)
		}
	}
	if err != nil {
		g.log.Error("upstream tools/list failed", "upstream", server, "err", err)
		return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeUpstream, Message: "upstream unavailable"})
	}
	if _, ok := defs[tool]; !ok {
		return unknown
	}
	rec := audit.Record{Subject: c.claims.Subject, ClientID: c.claims.ClientID, Method: "tools/call", Server: server, Tool: tool}

	// A tool the principal cannot see does not exist for them: same answer
	// as a missing tool, so calls cannot probe for hidden tools.
	if vis := g.engine.Decide(policy.ActionList, c.input(server, tool, nil)); !vis.Allow {
		rec.Event, rec.Reason, rec.PolicyVersion, rec.Binding = "deny", "not_visible: "+vis.Reason, vis.PolicyVersion, vis.Binding
		g.record(rec)
		return unknown
	}
	dec := g.engine.Decide(policy.ActionCall, c.input(server, tool, args))
	rec.ArgsSHA256, rec.PolicyVersion, rec.Binding, rec.Matched = dec.ArgsSHA256, dec.PolicyVersion, dec.Binding, dec.Matched
	if !dec.Allow {
		rec.Event, rec.Reason = "deny", dec.Reason
		g.record(rec)
		return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeForbidden, Message: "denied by policy", Data: map[string]string{"decision": dec.Binding}})
	}

	// Forward exactly the canonical bytes that were evaluated.
	upParams := map[string]any{"name": tool, "arguments": json.RawMessage(dec.CanonicalArgs)}
	resp, err := up.Call(ctx, "tools/call", upParams)
	if err != nil {
		rec.Event, rec.Reason = "error", g.vault.Scrub(err.Error())
		g.record(rec)
		return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: jsonrpc.CodeUpstream, Message: "upstream call failed"})
	}
	rec.Event, rec.Reason = "allow", dec.Reason
	g.record(rec)
	if resp.Error != nil {
		return jsonrpc.NewError(req.ID, &jsonrpc.Error{Code: resp.Error.Code, Message: g.vault.Scrub(resp.Error.Message)})
	}
	// Credentials never flow back toward the client or the model.
	return &jsonrpc.Response{JSONRPC: jsonrpc.Version, ID: req.ID, Result: g.vault.ScrubBytes(resp.Result)}
}
