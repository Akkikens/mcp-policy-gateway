// Package auth implements the OAuth 2.1 resource-server side of the MCP
// authorization spec: bearer JWT validation against an authorization
// server's JWKS, audience (RFC 8707 resource indicator) and scope checks, and
// the RFC 9728 protected-resource metadata document.
package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ErrInvalidToken maps to HTTP 401 with error="invalid_token".
var ErrInvalidToken = errors.New("invalid_token")

// ErrInsufficientScope maps to HTTP 403 with error="insufficient_scope".
var ErrInsufficientScope = errors.New("insufficient_scope")

// Claims is the validated subset of an access token.
type Claims struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
	ClientID string
	Expiry   time.Time
	TokenID  string
}

// HasScope reports whether the token carries scope s.
func (c *Claims) HasScope(s string) bool {
	for _, x := range c.Scopes {
		if x == s {
			return true
		}
	}
	return false
}

// KeySource resolves a verification key by key id.
type KeySource interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, string, error) // key, alg
}

// Validator validates bearer access tokens for one protected resource.
type Validator struct {
	Issuer         string
	Resource       string // expected audience, the gateway's canonical MCP URL
	RequiredScopes []string
	Keys           KeySource
	Leeway         time.Duration
	MaxTokenBytes  int
	Now            func() time.Time
}

type header struct {
	Alg  string `json:"alg"`
	Kid  string `json:"kid"`
	Typ  string `json:"typ"`
	Crit any    `json:"crit,omitempty"`
}

type rawClaims struct {
	Iss      string          `json:"iss"`
	Sub      string          `json:"sub"`
	Aud      json.RawMessage `json:"aud"`
	Exp      *json.Number    `json:"exp"`
	Nbf      *json.Number    `json:"nbf"`
	Iat      *json.Number    `json:"iat"`
	Scope    string          `json:"scope"`
	Scp      []string        `json:"scp"`
	ClientID string          `json:"client_id"`
	Azp      string          `json:"azp"`
	Jti      string          `json:"jti"`
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, fmt.Sprintf(format, a...))
}

// Validate checks signature, issuer, audience, time claims and required scopes.
func (v *Validator) Validate(ctx context.Context, token string) (*Claims, error) {
	maxLen := v.MaxTokenBytes
	if maxLen == 0 {
		maxLen = 8 << 10
	}
	if len(token) == 0 || len(token) > maxLen {
		return nil, invalid("token length")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, invalid("not a compact JWS")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, invalid("header encoding")
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, invalid("header json")
	}
	if h.Crit != nil {
		return nil, invalid("crit header not supported")
	}
	switch h.Alg {
	case "RS256", "ES256":
	default:
		// Rejects "none" and every HMAC alg: a resource server must never
		// accept a token it could have been tricked into treating as signed
		// with a public key as the HMAC secret.
		return nil, invalid("alg %q not allowed", h.Alg)
	}
	switch strings.ToLower(h.Typ) {
	case "", "jwt", "at+jwt", "application/at+jwt":
	default:
		return nil, invalid("typ %q not allowed", h.Typ)
	}
	key, keyAlg, err := v.Keys.Key(ctx, h.Kid)
	if err != nil {
		return nil, invalid("key %q: %v", h.Kid, err)
	}
	if keyAlg != "" && keyAlg != h.Alg {
		return nil, invalid("alg %q does not match key alg %q", h.Alg, keyAlg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, invalid("signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := verifySig(h.Alg, key, digest[:], sig); err != nil {
		return nil, invalid("signature: %v", err)
	}

	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, invalid("claims encoding")
	}
	dec := json.NewDecoder(strings.NewReader(string(cb)))
	dec.UseNumber()
	var rc rawClaims
	if err := dec.Decode(&rc); err != nil {
		return nil, invalid("claims json")
	}
	if rc.Iss != v.Issuer {
		return nil, invalid("issuer %q", rc.Iss)
	}
	if rc.Sub == "" {
		return nil, invalid("missing sub")
	}
	aud, err := parseAud(rc.Aud)
	if err != nil {
		return nil, invalid("aud: %v", err)
	}
	if !contains(aud, v.Resource) {
		// RFC 8707 / MCP: a token minted for another resource must not be
		// accepted here (prevents token replay across MCP servers).
		return nil, invalid("audience %v does not include %q", aud, v.Resource)
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	exp, err := numericDate(rc.Exp)
	if err != nil || exp.IsZero() {
		return nil, invalid("missing or bad exp")
	}
	if !now.Before(exp.Add(v.Leeway)) {
		return nil, invalid("token expired")
	}
	if nbf, err := numericDate(rc.Nbf); err != nil {
		return nil, invalid("bad nbf")
	} else if !nbf.IsZero() && now.Add(v.Leeway).Before(nbf) {
		return nil, invalid("token not yet valid")
	}
	if iat, err := numericDate(rc.Iat); err != nil {
		return nil, invalid("bad iat")
	} else if !iat.IsZero() && now.Add(v.Leeway).Before(iat) {
		return nil, invalid("token issued in the future")
	}

	scopes := strings.Fields(rc.Scope)
	if len(scopes) == 0 {
		scopes = rc.Scp
	}
	c := &Claims{
		Subject: rc.Sub, Issuer: rc.Iss, Audience: aud, Scopes: scopes,
		ClientID: firstNonEmpty(rc.ClientID, rc.Azp), Expiry: exp, TokenID: rc.Jti,
	}
	for _, s := range v.RequiredScopes {
		if !c.HasScope(s) {
			return c, fmt.Errorf("%w: missing scope %q", ErrInsufficientScope, s)
		}
	}
	return c, nil
}

func verifySig(alg string, key crypto.PublicKey, digest, sig []byte) error {
	switch alg {
	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return errors.New("key is not RSA")
		}
		if k.N.BitLen() < 2048 {
			return errors.New("RSA key shorter than 2048 bits")
		}
		return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig)
	case "ES256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("key is not EC")
		}
		if k.Curve != elliptic.P256() {
			return errors.New("ES256 requires P-256")
		}
		if len(sig) != 64 {
			return errors.New("ES256 signature must be 64 bytes")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, digest, r, s) {
			return errors.New("verification failed")
		}
		return nil
	}
	return errors.New("unsupported alg")
}

func parseAud(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, errors.New("missing")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("must be a string or array of strings")
	}
	return many, nil
}

func numericDate(n *json.Number) (time.Time, error) {
	if n == nil {
		return time.Time{}, nil
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e11 {
		return time.Time{}, errors.New("bad NumericDate")
	}
	return time.Unix(int64(f), 0), nil
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
