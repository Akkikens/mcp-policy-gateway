package creds

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestApplyAndScrub(t *testing.T) {
	t.Setenv("FILES_TOKEN", "upstream-secret-123")
	v, err := New(map[string]Spec{"files": {Env: "FILES_TOKEN", Prefix: "Bearer "}, "web": {Header: "x-api-key", Env: "FILES_TOKEN"}})
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer client-token")
	h.Set("Cookie", "s=1")
	v.Apply("files", h)
	if h.Get("Authorization") != "Bearer upstream-secret-123" || h.Get("Cookie") != "" {
		t.Fatalf("headers %v", h)
	}
	h2 := http.Header{"Authorization": {"Bearer client-token"}}
	v.Apply("unknown", h2)
	if h2.Get("Authorization") != "" {
		t.Fatal("client token forwarded to an upstream without a credential")
	}
	v.Apply("web", h2)
	if h2.Get("X-Api-Key") != "upstream-secret-123" || h2.Get("Authorization") != "" {
		t.Fatalf("custom header: %v", h2)
	}

	in := `{"text":"got upstream-secret-123 and Authorization: Bearer eyJhbGciOi.x.y"}`
	out := v.Scrub(in)
	if strings.Contains(out, "upstream-secret-123") || strings.Contains(out, "eyJhbGciOi") {
		t.Fatalf("not scrubbed: %s", out)
	}
}

func TestEmptyCredentialRejected(t *testing.T) {
	t.Setenv("EMPTY", "")
	if _, err := New(map[string]Spec{"x": {Env: "EMPTY"}}); err == nil {
		t.Fatal("empty credential accepted")
	}
}

func TestRedactingHandler(t *testing.T) {
	t.Setenv("S", "hunter2-long-secret")
	v, _ := New(map[string]Spec{"x": {Env: "S"}})
	var buf bytes.Buffer
	log := slog.New(NewRedactingHandler(slog.NewJSONHandler(&buf, nil), v))
	log.With("hdr", "Bearer hunter2-long-secret").Info("upstream said hunter2-long-secret", "err", errString("bad hunter2-long-secret"), slog.Group("g", "k", "hunter2-long-secret"))
	if strings.Contains(buf.String(), "hunter2") {
		t.Fatalf("secret in logs: %s", buf.String())
	}
}

type errString string

func (e errString) Error() string { return string(e) }
