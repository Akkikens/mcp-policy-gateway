package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

type fixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	keys   TrustedKeys
	cedar  string
	now    time.Time
	stateP string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src, err := os.ReadFile("../../policies/gateway.cedar")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{pub: pub, priv: priv, keys: TrustedKeys{"k1": pub}, cedar: string(src), now: t0,
		stateP: filepath.Join(t.TempDir(), "state.json")}
}

func (f *fixture) store() *Store {
	return &Store{Keys: f.keys, StatePath: f.stateP, Skew: time.Minute, Now: func() time.Time { return f.now }}
}

func (f *fixture) bundle(t *testing.T, version uint64, mut func(*Manifest)) []byte {
	t.Helper()
	m := Manifest{Version: version, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(24 * time.Hour), Policies: map[string]string{"gateway.cedar": f.cedar}}
	if mut != nil {
		mut(&m)
	}
	b, err := SignJSON(TypeBundle, m, "k1", f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) revocations(t *testing.T, seq uint64, mut func(*Revocations)) []byte {
	r := Revocations{Sequence: seq, IssuedAt: f.now.Add(-time.Minute), ExpiresAt: f.now.Add(24 * time.Hour)}
	if mut != nil {
		mut(&r)
	}
	b, err := SignJSON(TypeRevocations, r, "k1", f.priv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleNegative(t *testing.T) {
	f := newFixture(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	otherSigned, _ := SignJSON(TypeBundle, Manifest{Version: 9, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour), Policies: map[string]string{"a": f.cedar}}, "k1", otherPriv)
	untrusted, _ := SignJSON(TypeBundle, Manifest{Version: 9, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour), Policies: map[string]string{"a": f.cedar}}, "k2", otherPriv)

	tamper := func(raw []byte) []byte {
		var env Envelope
		_ = json.Unmarshal(raw, &env)
		p, _ := base64.StdEncoding.DecodeString(env.Payload)
		p = []byte(strings.Replace(string(p), `"version":5`, `"version":6`, 1))
		env.Payload = base64.StdEncoding.EncodeToString(p)
		b, _ := json.Marshal(env)
		return b
	}
	typeSwap := func(raw []byte) []byte {
		var env Envelope
		_ = json.Unmarshal(raw, &env)
		env.PayloadType = TypeBundle
		b, _ := json.Marshal(env)
		return b
	}

	cases := []struct {
		name string
		raw  []byte
		want error
	}{
		{"bad signature (other key, same kid)", otherSigned, ErrSignature},
		{"untrusted key id", untrusted, ErrUntrustedKey},
		{"tampered payload", tamper(f.bundle(t, 5, nil)), ErrSignature},
		{"revocation list replayed as bundle", typeSwap(f.revocations(t, 1, nil)), ErrSignature},
		{"wrong payload type", f.revocations(t, 1, nil), ErrWrongType},
		{"expired", f.bundle(t, 5, func(m *Manifest) { m.IssuedAt = f.now.Add(-48 * time.Hour); m.ExpiresAt = f.now.Add(-time.Hour) }), ErrExpired},
		{"issued in the future", f.bundle(t, 5, func(m *Manifest) { m.IssuedAt = f.now.Add(time.Hour); m.ExpiresAt = f.now.Add(2 * time.Hour) }), ErrNotYetValid},
		{"version zero", f.bundle(t, 0, nil), ErrBadManifest},
		{"no policies", f.bundle(t, 5, func(m *Manifest) { m.Policies = nil }), ErrBadManifest},
		{"cedar syntax error", f.bundle(t, 5, func(m *Manifest) { m.Policies = map[string]string{"x": "permit (principal"} }), ErrBadManifest},
		{"not json", []byte("nope"), ErrBadEnvelope},
		{"no signatures", []byte(`{"payloadType":"` + TypeBundle + `","payload":"e30=","signatures":[]}`), ErrBadEnvelope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := f.store()
			if _, err := s.Load(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if _, err := s.Current(); !errors.Is(err, ErrNoPolicy) {
				t.Fatalf("a rejected bundle must not become active: %v", err)
			}
		})
	}
}

func TestRollbackAndEquivocation(t *testing.T) {
	f := newFixture(t)
	s := f.store()
	if _, err := s.Load(f.bundle(t, 5, nil)); err != nil {
		t.Fatal(err)
	}
	v5 := f.bundle(t, 5, nil) // same content re-signed: ed25519 is deterministic, same digest
	if _, err := s.Load(v5); err != nil {
		t.Fatalf("idempotent reload of v5 rejected: %v", err)
	}
	if _, err := s.Load(f.bundle(t, 4, nil)); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback to v4: %v", err)
	}
	if _, err := s.Load(f.bundle(t, 5, func(m *Manifest) { m.Comment = "different" })); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation: %v", err)
	}
	if a, _ := s.Current(); a.Manifest.Version != 5 {
		t.Fatal("active bundle changed after rejected loads")
	}
	if _, err := s.Load(f.bundle(t, 6, nil)); err != nil {
		t.Fatal(err)
	}

	// The floor survives a restart: a new store over the same state file
	// refuses v5 even though it has nothing active.
	s2 := f.store()
	if _, err := s2.Load(f.bundle(t, 5, nil)); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback after restart: %v", err)
	}
	// ...and an operator-pinned floor applies with no state file at all.
	s3 := &Store{Keys: f.keys, MinVersion: 10, Now: func() time.Time { return f.now }}
	if _, err := s3.Load(f.bundle(t, 9, nil)); !errors.Is(err, ErrRollback) {
		t.Fatalf("min version floor: %v", err)
	}
	// A corrupt state file fails closed instead of resetting the floor.
	_ = os.WriteFile(f.stateP, []byte("{garbage"), 0o600)
	if _, err := f.store().Load(f.bundle(t, 7, nil)); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt state: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	f := newFixture(t)
	s := f.store()
	s.RequireRevocations = true
	if _, err := s.Load(f.bundle(t, 3, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(); !errors.Is(err, ErrNoRevocations) {
		t.Fatalf("required revocations missing: %v", err)
	}
	if err := s.LoadRevocations(f.revocations(t, 1, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(); err != nil {
		t.Fatal(err)
	}
	// revoke the active version while loaded: it stops authorizing at once
	if err := s.LoadRevocations(f.revocations(t, 2, func(r *Revocations) { r.RevokedVersions = []uint64{3} })); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked active bundle still served: %v", err)
	}
	if _, err := s.Load(f.bundle(t, 3, nil)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked version re-loaded: %v", err)
	}
	// revocation list sequence cannot go backwards
	if err := s.LoadRevocations(f.revocations(t, 1, nil)); !errors.Is(err, ErrRollback) {
		t.Fatalf("revocation rollback: %v", err)
	}
	// revoke by digest
	b4 := f.bundle(t, 4, nil)
	_, digest, _, _ := verifyEnvelope(b4, TypeBundle, f.keys, nil)
	if err := s.LoadRevocations(f.revocations(t, 3, func(r *Revocations) { r.RevokedDigests = []string{digest} })); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(b4); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked digest: %v", err)
	}
	// revoke the signing key: new bundles from it are refused and the active one stops
	if _, err := s.Load(f.bundle(t, 5, nil)); err != nil {
		t.Fatal(err)
	}
	if err := s.LoadRevocations(f.revocations(t, 4, func(r *Revocations) { r.RevokedKeyIDs = []string{"k1"} })); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current(); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("revoked key bundle still served: %v", err)
	}
	if _, err := s.Load(f.bundle(t, 6, nil)); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("bundle from revoked key: %v", err)
	}
	// key revocation is sticky: a later list signed by the revoked key that
	// omits it is refused, and so is one from a fresh store over the same state
	if err := s.LoadRevocations(f.revocations(t, 5, nil)); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("revoked key un-revoked itself: %v", err)
	}
	if err := f.store().LoadRevocations(f.revocations(t, 9, nil)); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("key revocation lost across restart: %v", err)
	}
	// stale revocation list fails closed
	f2 := newFixture(t)
	s2 := f2.store()
	s2.RequireRevocations = true
	_, _ = s2.Load(f2.bundle(t, 1, nil))
	_ = s2.LoadRevocations(f2.revocations(t, 1, func(r *Revocations) { r.ExpiresAt = f2.now.Add(time.Hour) }))
	f2.now = f2.now.Add(2 * time.Hour)
	if _, err := s2.Current(); !errors.Is(err, ErrStale) {
		t.Fatalf("stale revocation list: %v", err)
	}
}

func TestDecide(t *testing.T) {
	f := newFixture(t)
	s := f.store()
	e := &Engine{Store: s}
	in := func(sub string, groups []string, tool string, args map[string]any, scopes ...string) Input {
		srv, name, _ := strings.Cut(tool, "/")
		return Input{Subject: sub, Groups: groups, Scopes: scopes, Server: srv, Tool: name, Args: args}
	}
	eng := []string{"engineering"}
	adm := []string{"admins"}

	// fail closed before any bundle is loaded
	if d := e.Decide(ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/srv/docs/a"})); d.Allow || !strings.HasPrefix(d.Reason, "policy_unavailable") {
		t.Fatalf("no policy: %+v", d)
	}
	if _, err := s.Load(f.bundle(t, 1, nil)); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		action string
		in     Input
		allow  bool
		reason string
	}{
		{"eng lists read_file", ActionList, in("alice", eng, "files/read_file", nil), true, "permit"},
		{"eng cannot list write_file", ActionList, in("alice", eng, "files/write_file", nil), false, "no_matching_permit"},
		{"no group cannot list read_file", ActionList, in("bob", nil, "files/read_file", nil), false, "no_matching_permit"},
		{"eng reads docs", ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/srv/docs/a.md"}), true, "permit"},
		{"eng reads /etc/passwd", ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/etc/passwd"}), false, "no_matching_permit"},
		{"eng path traversal", ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/srv/docs/../../etc/passwd"}), false, "no_matching_permit"},
		{"eng missing path", ActionCall, in("alice", eng, "files/read_file", map[string]any{}), false, "no_matching_permit"},
		{"eng path wrong type", ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": json.Number("7")}), false, "policy_evaluation_error"},
		{"search without scope", ActionCall, in("bob", nil, "web/search_web", map[string]any{"query": "x"}), false, "no_matching_permit"},
		{"search with scope", ActionCall, in("bob", nil, "web/search_web", map[string]any{"query": "x"}, "web:search"), true, "permit"},
		{"email internal", ActionCall, in("alice", eng, "web/send_email", map[string]any{"to": "c@example.com"}), true, "permit"},
		{"email external", ActionCall, in("alice", eng, "web/send_email", map[string]any{"to": "x@evil.test"}), false, "no_matching_permit"},
		{"admin writes workspace", ActionCall, in("carol", adm, "files/write_file", map[string]any{"path": "/srv/workspace/a"}), true, "permit"},
		{"admin write outside workspace is forbidden", ActionCall, in("carol", adm, "files/write_file", map[string]any{"path": "/etc/cron.d/x"}), false, "forbid"},
		{"unknown action", "delete_everything", in("carol", adm, "files/write_file", nil), false, "unknown_action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Decide(tc.action, tc.in)
			if d.Allow != tc.allow || !strings.HasPrefix(d.Reason, tc.reason) {
				t.Fatalf("got allow=%v reason=%q matched=%v, want allow=%v reason=%q", d.Allow, d.Reason, d.Matched, tc.allow, tc.reason)
			}
			if d.PolicyVersion != 1 || d.Binding == "" {
				t.Fatalf("decision not bound: %+v", d)
			}
		})
	}

	t.Run("binding covers subject, tool and args", func(t *testing.T) {
		a := e.Decide(ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/srv/docs/a"}))
		b := e.Decide(ActionCall, in("alice", eng, "files/read_file", map[string]any{"path": "/srv/docs/b"}))
		c := e.Decide(ActionCall, in("alicf", eng, "files/read_file", map[string]any{"path": "/srv/docs/a"}))
		if a.Binding == b.Binding || a.Binding == c.Binding {
			t.Fatal("binding does not change with args/subject")
		}
		if Bind(a.PolicyDigest, "alice", ActionCall, "files", "read_file", a.ArgsSHA256) != a.Binding {
			t.Fatal("binding not reproducible")
		}
		if string(a.CanonicalArgs) != `{"path":"/srv/docs/a"}` {
			t.Fatalf("canonical args %s", a.CanonicalArgs)
		}
	})

	t.Run("expiry while loaded fails closed", func(t *testing.T) {
		f.now = f.now.Add(25 * time.Hour)
		defer func() { f.now = t0 }()
		d := e.Decide(ActionList, in("alice", eng, "files/read_file", nil))
		if d.Allow || !strings.Contains(d.Reason, "stale") {
			t.Fatalf("stale bundle: %+v", d)
		}
	})

	t.Run("deep args denied", func(t *testing.T) {
		var v any = "x"
		for i := 0; i < MaxArgDepth+2; i++ {
			v = map[string]any{"a": v}
		}
		d := e.Decide(ActionCall, in("carol", adm, "files/read_file", map[string]any{"path": v}))
		if d.Allow || !strings.HasPrefix(d.Reason, "invalid_arguments") {
			t.Fatalf("deep args: %+v", d)
		}
	})
}

type keyset struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	keys TrustedKeys
}

func newFixtureKeys() keyset {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return keyset{pub: pub, priv: priv, keys: TrustedKeys{"k1": pub}}
}
