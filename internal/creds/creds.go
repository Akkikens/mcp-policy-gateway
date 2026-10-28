// Package creds holds upstream credentials inside the gateway. They are
// injected into upstream requests per allowed call, never forwarded from or
// returned to the client, and scrubbed from logs and tool results.
package creds

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
)

// Redacted replaces secret material.
const Redacted = "[REDACTED]"

// Spec says where an upstream credential comes from and how it is sent.
type Spec struct {
	Header string `json:"header"` // default Authorization
	Prefix string `json:"prefix"` // e.g. "Bearer "
	Env    string `json:"env"`    // environment variable holding the secret
	File   string `json:"file"`   // or a file (e.g. a mounted Secret Manager secret)
}

type cred struct {
	header string
	value  string
}

// Vault maps upstream name to its credential.
type Vault struct {
	creds   map[string]cred
	secrets []string
}

// New builds a vault, reading each secret from its env var or file.
func New(specs map[string]Spec) (*Vault, error) {
	v := &Vault{creds: map[string]cred{}}
	for name, s := range specs {
		var secret string
		switch {
		case s.Env != "":
			secret = os.Getenv(s.Env)
		case s.File != "":
			b, err := os.ReadFile(s.File)
			if err != nil {
				return nil, fmt.Errorf("upstream %s credential: %w", name, err)
			}
			secret = strings.TrimSpace(string(b))
		default:
			continue
		}
		if secret == "" {
			return nil, fmt.Errorf("upstream %s credential is empty", name)
		}
		h := s.Header
		if h == "" {
			h = "Authorization"
		}
		v.creds[name] = cred{header: http.CanonicalHeaderKey(h), value: s.Prefix + secret}
		v.secrets = append(v.secrets, secret)
	}
	return v, nil
}

// headers the client sends that must never reach an upstream: the MCP spec
// forbids token passthrough, and cookies or forwarded identity headers would
// let a client speak for the gateway.
var stripped = []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Forwarded-For", "X-Forwarded-User", "X-Api-Key"}

// Apply sets the upstream credential on h after removing client-supplied
// credentials.
func (v *Vault) Apply(upstream string, h http.Header) {
	for _, k := range stripped {
		h.Del(k)
	}
	if c, ok := v.creds[upstream]; ok {
		h.Set(c.header, c.value)
	}
}

var bearerRe = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._~+/\-]+=*`)

// Scrub removes every known secret and any bearer token from s.
func (v *Vault) Scrub(s string) string {
	for _, sec := range v.secrets {
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, Redacted)
		}
	}
	return bearerRe.ReplaceAllString(s, "${1}"+Redacted)
}

// ScrubBytes is Scrub for byte slices that are valid JSON: secrets inside
// JSON strings are replaced in place, and Redacted contains no characters
// that need escaping, so the document stays valid.
func (v *Vault) ScrubBytes(b []byte) []byte { return []byte(v.Scrub(string(b))) }

// RedactingHandler scrubs secrets from log messages and string attributes.
type RedactingHandler struct {
	inner slog.Handler
	v     *Vault
}

// NewRedactingHandler wraps inner.
func NewRedactingHandler(inner slog.Handler, v *Vault) *RedactingHandler {
	return &RedactingHandler{inner: inner, v: v}
}

func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	nr := slog.NewRecord(r.Time, r.Level, h.v.Scrub(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		nr.AddAttrs(h.scrubAttr(a))
		return true
	})
	return h.inner.Handle(ctx, nr)
}

func (h *RedactingHandler) scrubAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindString:
		return slog.String(a.Key, h.v.Scrub(a.Value.String()))
	case slog.KindGroup:
		var as []any
		for _, g := range a.Value.Group() {
			as = append(as, h.scrubAttr(g))
		}
		return slog.Group(a.Key, as...)
	default:
		if a.Value.Kind() == slog.KindAny {
			return slog.String(a.Key, h.v.Scrub(fmt.Sprint(a.Value.Any())))
		}
		return a
	}
}

func (h *RedactingHandler) WithAttrs(as []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(as))
	for i, a := range as {
		out[i] = h.scrubAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(out), v: h.v}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name), v: h.v}
}
