package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// DevIssuer is a local stand-in for an authorization server: it holds an
// ES256 key, publishes a JWKS and mints access tokens. It exists for tests
// and the local demo only; it implements no OAuth flow (no /authorize, no
// PKCE, no client registration).
type DevIssuer struct {
	Issuer string
	Kid    string
	key    *ecdsa.PrivateKey
	Now    func() time.Time
}

// NewDevIssuer creates an issuer with a fresh P-256 key.
func NewDevIssuer(issuer string) (*DevIssuer, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &DevIssuer{Issuer: issuer, Kid: "dev-1", key: k}, nil
}

// JWKS returns the public key set.
func (d *DevIssuer) JWKS() JWKSet {
	return JWKSet{Keys: []JWK{ECJWK(d.Kid, &d.key.PublicKey)}}
}

// TokenOptions describes a token to mint.
type TokenOptions struct {
	Subject  string
	Audience string
	Scopes   []string
	TTL      time.Duration
	Issuer   string // override, for negative tests
	Kid      string // override, for negative tests
	Extra    map[string]any
}

// Mint signs an access token.
func (d *DevIssuer) Mint(o TokenOptions) (string, error) {
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	if o.TTL == 0 {
		o.TTL = 15 * time.Minute
	}
	iss := d.Issuer
	if o.Issuer != "" {
		iss = o.Issuer
	}
	kid := d.Kid
	if o.Kid != "" {
		kid = o.Kid
	}
	claims := map[string]any{
		"iss": iss, "sub": o.Subject, "aud": o.Audience,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(o.TTL).Unix(),
		"scope": strings.Join(o.Scopes, " "), "client_id": "dev-client",
		"jti": base64.RawURLEncoding.EncodeToString(randBytes(9)),
	}
	for k, v := range o.Extra {
		claims[k] = v
	}
	return SignES256(d.key, kid, claims)
}

// SignES256 builds a compact JWS over claims.
func SignES256(key *ecdsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "at+jwt", "kid": kid})
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// Signer exposes the private key for negative tests.
func (d *DevIssuer) Signer() crypto.Signer { return d.key }

// JWKSHandler serves the JWKS.
func (d *DevIssuer) JWKSHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(d.JWKS())
	})
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}
