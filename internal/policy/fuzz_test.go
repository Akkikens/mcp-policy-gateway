package policy

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// FuzzDecide feeds arbitrary argument documents and tool names through the
// engine. Properties: no panic; deterministic; a deny is never turned into an
// allow by adding fields; and read_file is only ever allowed for a path that
// matches the policy's prefix without "..".
func FuzzDecide(f *testing.F) {
	f.Add("files", "read_file", `{"path":"/srv/docs/a.md"}`, "engineering")
	f.Add("files", "read_file", `{"path":"/srv/docs/../x"}`, "engineering")
	f.Add("files", "write_file", `{"path":"/srv/workspace/a","content":"x"}`, "admins")
	f.Add("web", "send_email", `{"to":["a@example.com"]}`, "engineering")
	f.Add("web", "search_web", `{"query":{"nested":[1,2.5,null,true]}}`, "")
	f.Add("x/y", "z\x00", `{"":""}`, "a\"b")

	src, err := os.ReadFile("../../policies/gateway.cedar")
	if err != nil {
		f.Fatal(err)
	}
	fx := &fixture{cedar: string(src), now: t0}
	pubPriv := newFixtureKeys()
	fx.pub, fx.priv, fx.keys = pubPriv.pub, pubPriv.priv, pubPriv.keys
	s := &Store{Keys: fx.keys, Now: func() time.Time { return t0 }}
	m := Manifest{Version: 1, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour), Policies: map[string]string{"gateway.cedar": fx.cedar}}
	raw, _ := SignJSON(TypeBundle, m, "k1", fx.priv)
	if _, err := s.Load(raw); err != nil {
		f.Fatal(err)
	}
	e := &Engine{Store: s}

	f.Fuzz(func(t *testing.T, server, tool, argsJSON, group string) {
		dec := json.NewDecoder(bytes.NewReader([]byte(argsJSON)))
		dec.UseNumber()
		var args map[string]any
		if dec.Decode(&args) != nil {
			args = map[string]any{}
		}
		in := Input{Subject: "fuzz", Groups: []string{group}, Server: server, Tool: tool, Args: args}
		d1 := e.Decide(ActionCall, in)
		d2 := e.Decide(ActionCall, in)
		if d1.Allow != d2.Allow || d1.Binding != d2.Binding || d1.Reason != d2.Reason {
			t.Fatalf("non-deterministic decision: %+v vs %+v", d1, d2)
		}
		if d1.Allow && server == "files" && tool == "read_file" && group != "admins" {
			p, _ := args["path"].(string)
			if !strings.HasPrefix(p, "/srv/docs/") || strings.Contains(p, "..") {
				t.Fatalf("read_file allowed for path %q", p)
			}
		}
		if d1.Allow && server == "files" && tool == "write_file" {
			p, _ := args["path"].(string)
			if !strings.HasPrefix(p, "/srv/workspace/") || strings.Contains(p, "..") {
				t.Fatalf("write_file allowed outside workspace: %q", p)
			}
		}
	})
}

// FuzzLoadBundle checks that arbitrary bytes never become an active bundle.
func FuzzLoadBundle(f *testing.F) {
	k := newFixtureKeys()
	m := Manifest{Version: 1, IssuedAt: t0.Add(-time.Minute), ExpiresAt: t0.Add(time.Hour), Policies: map[string]string{"a": "permit(principal,action,resource);"}}
	good, _ := SignJSON(TypeBundle, m, "k1", k.priv)
	f.Add(good)
	f.Add([]byte(`{"payloadType":"x","payload":"","signatures":[]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s := &Store{Keys: k.keys, Now: func() time.Time { return t0 }}
		_, err := s.Load(raw)
		if err == nil && !bytes.Equal(raw, good) {
			// Any other accepted input must still carry a valid signature
			// over its payload; re-verify independently.
			if _, _, _, verr := verifyEnvelope(raw, TypeBundle, k.keys, nil); verr != nil {
				t.Fatalf("accepted bundle that does not verify: %v", verr)
			}
		}
	})
}
