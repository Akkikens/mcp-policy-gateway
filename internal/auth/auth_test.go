package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const resource = "https://gw.example.com/mcp"

func setup(t *testing.T) (*DevIssuer, *Validator, *httptest.Server, *atomic.Int32) {
	t.Helper()
	iss, err := NewDevIssuer("https://idp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		iss.JWKSHandler().ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	v := &Validator{
		Issuer: iss.Issuer, Resource: resource, RequiredScopes: []string{"mcp:tools"},
		Keys: &JWKSCache{URL: srv.URL}, Leeway: 30 * time.Second,
	}
	return iss, v, srv, &hits
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestValidateNegative(t *testing.T) {
	iss, v, _, _ := setup(t)
	good := TokenOptions{Subject: "alice", Audience: resource, Scopes: []string{"mcp:tools"}}
	mint := func(o TokenOptions) string {
		tok, err := iss.Mint(o)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	foreign, _ := SignES256(otherKey, iss.Kid, map[string]any{"iss": iss.Issuer, "sub": "alice", "aud": resource, "exp": time.Now().Add(time.Hour).Unix(), "scope": "mcp:tools"})

	goodTok := mint(good)
	parts := strings.Split(goodTok, ".")
	// alg=none: header swapped, signature dropped
	none := b64(map[string]string{"alg": "none", "typ": "JWT"}) + "." + parts[1] + "."
	// HS256 signed with the JWKS JSON as the "secret" (classic key confusion)
	jwks, _ := json.Marshal(iss.JWKS())
	hsHead := b64(map[string]string{"alg": "HS256", "kid": iss.Kid})
	mac := hmac.New(sha256.New, jwks)
	mac.Write([]byte(hsHead + "." + parts[1]))
	hs := hsHead + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	// claims tampered after signing
	tampered := parts[0] + "." + b64(map[string]any{"iss": iss.Issuer, "sub": "root", "aud": resource, "exp": time.Now().Add(time.Hour).Unix(), "scope": "mcp:tools"}) + "." + parts[2]

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"wrong audience", mint(TokenOptions{Subject: "alice", Audience: "https://other.example.com/mcp", Scopes: good.Scopes}), ErrInvalidToken},
		{"audience is issuer", mint(TokenOptions{Subject: "alice", Audience: iss.Issuer, Scopes: good.Scopes}), ErrInvalidToken},
		{"expired", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, TTL: -time.Hour}), ErrInvalidToken},
		{"not yet valid", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, Extra: map[string]any{"nbf": time.Now().Add(time.Hour).Unix()}}), ErrInvalidToken},
		{"wrong issuer", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, Issuer: "https://evil.example.com"}), ErrInvalidToken},
		{"unknown kid", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, Kid: "nope"}), ErrInvalidToken},
		{"missing sub", mint(TokenOptions{Audience: resource, Scopes: good.Scopes}), ErrInvalidToken},
		{"missing exp", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, Extra: map[string]any{"exp": nil}}), ErrInvalidToken},
		{"signed by another key", foreign, ErrInvalidToken},
		{"alg none", none, ErrInvalidToken},
		{"hs256 key confusion", hs, ErrInvalidToken},
		{"tampered claims", tampered, ErrInvalidToken},
		{"garbage", "a.b.c", ErrInvalidToken},
		{"two segments", "a.b", ErrInvalidToken},
		{"empty", "", ErrInvalidToken},
		{"oversized", strings.Repeat("a", 9000), ErrInvalidToken},
		{"missing scope", mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: []string{"profile"}}), ErrInsufficientScope},
		{"no scopes", mint(TokenOptions{Subject: "alice", Audience: resource}), ErrInsufficientScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Validate(context.Background(), tc.token)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		c, err := v.Validate(context.Background(), goodTok)
		if err != nil {
			t.Fatal(err)
		}
		if c.Subject != "alice" || !c.HasScope("mcp:tools") {
			t.Fatalf("claims %+v", c)
		}
	})
	t.Run("audience array", func(t *testing.T) {
		tok := mint(TokenOptions{Subject: "alice", Scopes: good.Scopes, Extra: map[string]any{"aud": []string{"x", resource}}})
		if _, err := v.Validate(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("expired within leeway", func(t *testing.T) {
		tok := mint(TokenOptions{Subject: "alice", Audience: resource, Scopes: good.Scopes, TTL: -10 * time.Second})
		if _, err := v.Validate(context.Background(), tok); err != nil {
			t.Fatal(err)
		}
	})
}

func TestJWKSRefreshIsRateLimited(t *testing.T) {
	iss, v, _, hits := setup(t)
	for i := 0; i < 20; i++ {
		tok, _ := iss.Mint(TokenOptions{Subject: "a", Audience: resource, Scopes: []string{"mcp:tools"}, Kid: "forged-" + string(rune('a'+i))})
		_, _ = v.Validate(context.Background(), tok)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("JWKS fetched %d times for 20 unknown kids, want 1", n)
	}
}

func TestJWKSRotation(t *testing.T) {
	iss, v, _, _ := setup(t)
	now := time.Now()
	cache := v.Keys.(*JWKSCache)
	cache.Now = func() time.Time { return now }
	tok, _ := iss.Mint(TokenOptions{Subject: "a", Audience: resource, Scopes: []string{"mcp:tools"}})
	if _, err := v.Validate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	// rotate the issuer key; the new kid is fetched once MinRefresh has passed
	k2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iss.key, iss.Kid = k2, "dev-2"
	tok2, _ := iss.Mint(TokenOptions{Subject: "a", Audience: resource, Scopes: []string{"mcp:tools"}})
	if _, err := v.Validate(context.Background(), tok2); err == nil {
		t.Fatal("new kid accepted before refresh window")
	}
	now = now.Add(time.Minute)
	if _, err := v.Validate(context.Background(), tok2); err != nil {
		t.Fatalf("rotated key not picked up: %v", err)
	}
}

func TestRS256(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	set := JWKSet{Keys: []JWK{{
		Kty: "RSA", Kid: "r1", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(set) }))
	defer srv.Close()
	v := &Validator{Issuer: "i", Resource: resource, Keys: &JWKSCache{URL: srv.URL}}
	signing := b64(map[string]string{"alg": "RS256", "kid": "r1"}) + "." + b64(map[string]any{"iss": "i", "sub": "s", "aud": resource, "exp": time.Now().Add(time.Hour).Unix()})
	d := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
	tok := signing + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := v.Validate(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	// ES256 header against an RSA key must fail (alg/key mismatch)
	bad := b64(map[string]string{"alg": "ES256", "kid": "r1"}) + "." + strings.Split(tok, ".")[1] + "." + strings.Split(tok, ".")[2]
	if _, err := v.Validate(context.Background(), bad); err == nil {
		t.Fatal("alg/key mismatch accepted")
	}
}

func TestChallengeAndMetadata(t *testing.T) {
	rec := httptest.NewRecorder()
	Challenge(rec, "https://gw/.well-known/oauth-protected-resource", nil, "")
	if rec.Code != 401 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `resource_metadata="https://gw/.well-known/oauth-protected-resource"`) {
		t.Fatalf("bad 401 challenge: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	rec = httptest.NewRecorder()
	Challenge(rec, "m", ErrInsufficientScope, "mcp:tools")
	if rec.Code != 403 || !strings.Contains(rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope", scope="mcp:tools"`) {
		t.Fatalf("bad 403 challenge: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
	rec = httptest.NewRecorder()
	MetadataHandler(ProtectedResourceMetadata{Resource: resource, AuthorizationServers: []string{"https://idp"}, BearerMethodsSupported: []string{"header"}}).
		ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil))
	var m ProtectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m.Resource != resource || m.AuthorizationServers[0] != "https://idp" {
		t.Fatalf("metadata %s", rec.Body.String())
	}
	r := httptest.NewRequest("GET", "/?access_token=x", nil)
	if _, ok := BearerToken(r); ok {
		t.Fatal("query-string token accepted")
	}
}
