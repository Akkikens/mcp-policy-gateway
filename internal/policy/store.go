package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go"
)

// Active is a verified, compiled bundle.
type Active struct {
	Manifest Manifest
	Digest   string
	KeyID    string
	Set      *cedar.PolicySet
	names    map[cedar.PolicyID]string // policy id -> @id annotation
}

// rollbackState is persisted so a restart cannot be used to roll back.
type rollbackState struct {
	HighestVersion  uint64   `json:"highest_version"`
	HighestDigest   string   `json:"highest_digest"`
	RevocationsSeq  uint64   `json:"revocations_sequence"`
	RevokedKeyIDs   []string `json:"revoked_key_ids,omitempty"`
	UpdatedAtRFC339 string   `json:"updated_at"`
}

// Store verifies and holds the active bundle and revocation list.
type Store struct {
	Keys               TrustedKeys
	StatePath          string        // rollback state file; empty = in memory only
	MinVersion         uint64        // operator-pinned floor (e.g. from deploy config)
	RequireRevocations bool          // fail closed without a fresh revocation list
	Skew               time.Duration // tolerated clock skew for issued_at
	Now                func() time.Time

	mu     sync.RWMutex
	active *Active
	revs   *Revocations
	state  rollbackState
	loaded bool
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Store) loadState() error {
	if s.loaded {
		return nil
	}
	s.loaded = true
	if s.StatePath == "" {
		return nil
	}
	b, err := os.ReadFile(s.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &s.state); err != nil {
		// A corrupt state file must not silently reset the floor to zero.
		return fmt.Errorf("rollback state %s is corrupt: %w", s.StatePath, err)
	}
	return nil
}

func (s *Store) saveState(st rollbackState) error {
	if s.StatePath == "" {
		return nil
	}
	st.UpdatedAtRFC339 = s.now().UTC().Format(time.RFC3339)
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := s.StatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Clean(s.StatePath))
}

func (s *Store) revokedKeys() map[string]bool {
	m := map[string]bool{}
	for _, k := range s.state.RevokedKeyIDs {
		m[k] = true
	}
	if s.revs != nil {
		for _, k := range s.revs.RevokedKeyIDs {
			m[k] = true
		}
	}
	return m
}

// LoadRevocations verifies and installs a revocation list. Its sequence must
// not go backwards.
func (s *Store) LoadRevocations(raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadState(); err != nil {
		return err
	}
	payload, _, _, err := verifyEnvelope(raw, TypeRevocations, s.Keys, s.revokedKeys())
	if err != nil {
		return err
	}
	var r Revocations
	if err := strictUnmarshal(payload, &r); err != nil {
		return fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	now := s.now()
	if r.IssuedAt.After(now.Add(s.Skew)) {
		return ErrNotYetValid
	}
	if !now.Before(r.ExpiresAt) {
		return fmt.Errorf("revocation list %w", ErrExpired)
	}
	if r.Sequence < s.state.RevocationsSeq || (s.revs != nil && r.Sequence < s.revs.Sequence) {
		return fmt.Errorf("%w (revocation list sequence %d)", ErrRollback, r.Sequence)
	}
	// Key revocation is sticky: revoked key ids are unioned into the
	// persisted state, so a later list (perhaps signed by the stolen key
	// itself before anyone noticed) cannot un-revoke a key, and nothing
	// signed by a revoked key is accepted again.
	st := s.state
	st.RevocationsSeq = r.Sequence
	known := map[string]bool{}
	for _, k := range st.RevokedKeyIDs {
		known[k] = true
	}
	st.RevokedKeyIDs = append([]string(nil), st.RevokedKeyIDs...)
	for _, k := range r.RevokedKeyIDs {
		if !known[k] {
			known[k] = true
			st.RevokedKeyIDs = append(st.RevokedKeyIDs, k)
		}
	}
	if err := s.saveState(st); err != nil {
		return err
	}
	s.state = st
	s.revs = &r
	return nil
}

// Load verifies and activates a bundle. On any error the current bundle stays.
func (s *Store) Load(raw []byte) (*Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadState(); err != nil {
		return nil, err
	}
	payload, digest, kid, err := verifyEnvelope(raw, TypeBundle, s.Keys, s.revokedKeys())
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := strictUnmarshal(payload, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadManifest, err)
	}
	if m.Version == 0 || m.IssuedAt.IsZero() || m.ExpiresAt.IsZero() || !m.ExpiresAt.After(m.IssuedAt) || len(m.Policies) == 0 {
		return nil, fmt.Errorf("%w: version, issued_at, expires_at and policies are required", ErrBadManifest)
	}
	now := s.now()
	if m.IssuedAt.After(now.Add(s.Skew)) {
		return nil, ErrNotYetValid
	}
	if !now.Before(m.ExpiresAt) {
		return nil, ErrExpired
	}
	if err := s.checkRevoked(m.Version, digest); err != nil {
		return nil, err
	}
	floor := max(s.state.HighestVersion, s.MinVersion)
	switch {
	case m.Version < floor:
		return nil, fmt.Errorf("%w (got %d, floor %d)", ErrRollback, m.Version, floor)
	case m.Version == s.state.HighestVersion && s.state.HighestDigest != "" && digest != s.state.HighestDigest:
		return nil, fmt.Errorf("%w (version %d)", ErrEquivocation, m.Version)
	}
	act, err := compile(m, digest, kid)
	if err != nil {
		return nil, err
	}
	// Persist the new floor before serving with it.
	st := s.state
	st.HighestVersion, st.HighestDigest = m.Version, digest
	if err := s.saveState(st); err != nil {
		return nil, fmt.Errorf("persist rollback state: %w", err)
	}
	s.state = st
	s.active = act
	return act, nil
}

func (s *Store) checkRevoked(version uint64, digest string) error {
	if s.revs == nil {
		return nil
	}
	for _, v := range s.revs.RevokedVersions {
		if v == version {
			return fmt.Errorf("%w (version %d)", ErrRevoked, version)
		}
	}
	for _, d := range s.revs.RevokedDigests {
		if strings.EqualFold(d, digest) {
			return fmt.Errorf("%w (digest %s)", ErrRevoked, digest[:12])
		}
	}
	return nil
}

// Current returns the active bundle if it is still usable right now. The
// freshness and revocation checks run on every call, not only at load time,
// so a bundle that expires or is revoked while loaded stops authorizing.
func (s *Store) Current() (*Active, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return nil, ErrNoPolicy
	}
	now := s.now()
	if !now.Before(s.active.Manifest.ExpiresAt) {
		return nil, fmt.Errorf("%w: bundle v%d expired at %s", ErrStale, s.active.Manifest.Version, s.active.Manifest.ExpiresAt.Format(time.RFC3339))
	}
	if s.RequireRevocations {
		if s.revs == nil {
			return nil, ErrNoRevocations
		}
		if !now.Before(s.revs.ExpiresAt) {
			return nil, fmt.Errorf("%w: revocation list expired", ErrStale)
		}
	}
	if err := s.checkRevoked(s.active.Manifest.Version, s.active.Digest); err != nil {
		return nil, err
	}
	if s.revokedKeys()[s.active.KeyID] {
		return nil, fmt.Errorf("%w: %q", ErrRevokedKey, s.active.KeyID)
	}
	return s.active, nil
}

func compile(m Manifest, digest, kid string) (*Active, error) {
	set := cedar.NewPolicySet()
	names := map[cedar.PolicyID]string{}
	files := make([]string, 0, len(m.Policies))
	for f := range m.Policies {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		list, err := cedar.NewPolicyListFromBytes(f, []byte(m.Policies[f]))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrBadManifest, f, err)
		}
		for i, p := range list {
			id := cedar.PolicyID(fmt.Sprintf("%s#%d", f, i))
			set.Add(id, p)
			names[id] = string(id)
			if a, ok := p.Annotations()["id"]; ok {
				names[id] = string(a)
			}
		}
	}
	return &Active{Manifest: m, Digest: digest, KeyID: kid, Set: set, names: names}, nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
