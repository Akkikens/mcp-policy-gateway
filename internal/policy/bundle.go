// Package policy holds the gateway's authorization policy: Cedar policies
// shipped as ed25519-signed, versioned, expiring bundles, verified for
// signature, freshness, revocation and rollback before they are activated,
// and evaluated per principal, tool and arguments.
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Payload types. The type is covered by the signature, so a signed
// revocation list cannot be replayed as a bundle or vice versa.
const (
	TypeBundle      = "application/vnd.mcpgw.policy-bundle.v1+json"
	TypeRevocations = "application/vnd.mcpgw.revocations.v1+json"
)

// Verification errors. Every one of them leaves the previously active
// bundle (if any) in place.
var (
	ErrBadEnvelope   = errors.New("malformed envelope")
	ErrSignature     = errors.New("signature verification failed")
	ErrUntrustedKey  = errors.New("signing key is not trusted")
	ErrRevokedKey    = errors.New("signing key is revoked")
	ErrWrongType     = errors.New("unexpected payload type")
	ErrExpired       = errors.New("expired")
	ErrNotYetValid   = errors.New("issued in the future")
	ErrRevoked       = errors.New("bundle is revoked")
	ErrRollback      = errors.New("rollback: version is older than the highest accepted version")
	ErrEquivocation  = errors.New("equivocation: same version, different content")
	ErrBadManifest   = errors.New("invalid manifest")
	ErrNoPolicy      = errors.New("no policy loaded")
	ErrStale         = errors.New("policy is stale")
	ErrNoRevocations = errors.New("revocation list required but not loaded")
)

// Envelope is a DSSE-style signed container: the signature covers the
// pre-authentication encoding of (payloadType, payload), never re-serialized
// JSON, so there is no canonicalization step to get wrong.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64 (std)
	Signatures  []Signature `json:"signatures"`
}

// Signature is one ed25519 signature over PAE(payloadType, payload).
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Manifest is the signed content of a policy bundle.
type Manifest struct {
	Version   uint64            `json:"version"`
	IssuedAt  time.Time         `json:"issued_at"`
	ExpiresAt time.Time         `json:"expires_at"`
	Policies  map[string]string `json:"policies"` // file name -> Cedar source
	Comment   string            `json:"comment,omitempty"`
}

// Revocations is the signed content of a revocation list.
type Revocations struct {
	Sequence        uint64    `json:"sequence"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	RevokedVersions []uint64  `json:"revoked_versions,omitempty"`
	RevokedDigests  []string  `json:"revoked_digests,omitempty"` // hex sha256 of bundle payload
	RevokedKeyIDs   []string  `json:"revoked_key_ids,omitempty"`
}

// PAE is the DSSE pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " " + string(payload))
}

// Sign produces an envelope over payload.
func Sign(payloadType string, payload []byte, keyID string, priv ed25519.PrivateKey) Envelope {
	sig := ed25519.Sign(priv, PAE(payloadType, payload))
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}
}

// SignJSON marshals v and signs it.
func SignJSON(payloadType string, v any, keyID string, priv ed25519.PrivateKey) ([]byte, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Sign(payloadType, p, keyID, priv), "", "  ")
}

// TrustedKeys maps key id to ed25519 public key.
type TrustedKeys map[string]ed25519.PublicKey

// TrustedKeysFile is the on-disk form of TrustedKeys.
type TrustedKeysFile struct {
	Keys []struct {
		KeyID     string `json:"keyid"`
		PublicKey string `json:"ed25519"` // base64 std
	} `json:"keys"`
}

// LoadTrustedKeys reads a trusted-keys file.
func LoadTrustedKeys(path string) (TrustedKeys, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f TrustedKeysFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	out := TrustedKeys{}
	for _, k := range f.Keys {
		raw, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key %q: bad ed25519 public key", k.KeyID)
		}
		out[k.KeyID] = ed25519.PublicKey(raw)
	}
	if len(out) == 0 {
		return nil, errors.New("no trusted keys")
	}
	return out, nil
}

// verifyEnvelope returns the payload, its digest and the signing key id when
// at least one signature from a trusted, non-revoked key verifies.
func verifyEnvelope(raw []byte, wantType string, keys TrustedKeys, revokedKeys map[string]bool) (payload []byte, digest, kid string, err error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, "", "", fmt.Errorf("%w: %v", ErrBadEnvelope, err)
	}
	if env.PayloadType != wantType {
		return nil, "", "", fmt.Errorf("%w: %q", ErrWrongType, env.PayloadType)
	}
	payload, err = base64.StdEncoding.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 {
		return nil, "", "", fmt.Errorf("%w: payload encoding", ErrBadEnvelope)
	}
	if len(env.Signatures) == 0 || len(env.Signatures) > 8 {
		return nil, "", "", fmt.Errorf("%w: signature count", ErrBadEnvelope)
	}
	msg := PAE(env.PayloadType, payload)
	lastErr := ErrSignature
	for _, s := range env.Signatures {
		pub, ok := keys[s.KeyID]
		if !ok {
			lastErr = fmt.Errorf("%w: %q", ErrUntrustedKey, s.KeyID)
			continue
		}
		if revokedKeys[s.KeyID] {
			lastErr = fmt.Errorf("%w: %q", ErrRevokedKey, s.KeyID)
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			lastErr = fmt.Errorf("%w: encoding", ErrSignature)
			continue
		}
		if ed25519.Verify(pub, msg, sig) {
			d := sha256.Sum256(payload)
			return payload, hex.EncodeToString(d[:]), s.KeyID, nil
		}
		lastErr = ErrSignature
	}
	return nil, "", "", lastErr
}
