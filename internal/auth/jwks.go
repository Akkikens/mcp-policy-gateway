package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// JWK is the subset of RFC 7517 the gateway understands.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet is a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type parsedKey struct {
	key crypto.PublicKey
	alg string
}

// JWKSCache fetches an authorization server's JWKS and caches it. An unknown
// kid triggers a refetch (key rotation), rate-limited by MinRefresh so a
// stream of forged kids cannot be used to hammer the authorization server.
type JWKSCache struct {
	URL        string
	Client     *http.Client
	TTL        time.Duration
	MinRefresh time.Duration
	Now        func() time.Time

	mu      sync.Mutex
	keys    map[string]parsedKey
	fetched time.Time
}

func (c *JWKSCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Key implements KeySource.
func (c *JWKSCache) Key(ctx context.Context, kid string) (crypto.PublicKey, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := c.TTL
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	minRefresh := c.MinRefresh
	if minRefresh == 0 {
		minRefresh = 30 * time.Second
	}
	now := c.now()
	stale := c.keys == nil || now.Sub(c.fetched) > ttl
	_, known := c.keys[kid]
	if stale || (!known && now.Sub(c.fetched) > minRefresh) {
		if err := c.refresh(ctx); err != nil && c.keys == nil {
			return nil, "", err
		}
	}
	k, ok := c.keys[kid]
	if !ok {
		return nil, "", errors.New("unknown kid")
	}
	return k.key, k.alg, nil
}

func (c *JWKSCache) refresh(ctx context.Context) error {
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	var set JWKSet
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}
	keys, err := ParseJWKSet(set)
	if err != nil {
		return err
	}
	c.keys = keys
	c.fetched = c.now()
	return nil
}

// ParseJWKSet converts signing keys; keys marked for encryption or of an
// unsupported type are skipped.
func ParseJWKSet(set JWKSet) (map[string]parsedKey, error) {
	out := map[string]parsedKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(e) > 4 {
				return nil, fmt.Errorf("jwk %q: bad RSA params", k.Kid)
			}
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			out[k.Kid] = parsedKey{key: pub, alg: defaultAlg(k.Alg, "RS256")}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
				return nil, fmt.Errorf("jwk %q: bad EC params", k.Kid)
			}
			// ParseUncompressedPublicKey rejects points that are not on the curve.
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
			if err != nil {
				return nil, fmt.Errorf("jwk %q: %v", k.Kid, err)
			}
			out[k.Kid] = parsedKey{key: pub, alg: defaultAlg(k.Alg, "ES256")}
		}
	}
	return out, nil
}

func defaultAlg(alg, def string) string {
	if alg == "" {
		return def
	}
	return alg
}

// ECJWK encodes a P-256 public key as a JWK.
func ECJWK(kid string, pub *ecdsa.PublicKey) JWK {
	raw, _ := pub.Bytes() // 0x04 || X || Y
	enc := base64.RawURLEncoding.EncodeToString
	return JWK{Kty: "EC", Kid: kid, Alg: "ES256", Use: "sig", Crv: "P-256", X: enc(raw[1:33]), Y: enc(raw[33:65])}
}
