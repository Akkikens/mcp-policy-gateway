// Package scim is a minimal SCIM 2.0 (RFC 7643/7644) service provider for
// Users and Groups. An identity provider pushes principals and group
// membership here; the gateway's policy engine reads them back as Cedar
// entities. State is in memory.
package scim

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SchemaUser    = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaList    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatch   = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError   = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPC     = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	contentType   = "application/scim+json"
	maxBodyBytes  = 256 << 10
	defaultCount  = 100
	maxGroupNames = 256
)

// Meta is the SCIM resource meta attribute.
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
	Version      string    `json:"version,omitempty"`
}

// Ref is a reference to another resource (group member, user group).
type Ref struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// User is a SCIM user. Groups is read-only and computed from Group members.
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	DisplayName string   `json:"displayName,omitempty"`
	Active      *bool    `json:"active,omitempty"`
	Groups      []Ref    `json:"groups,omitempty"`
	Meta        Meta     `json:"meta"`
}

// Group is a SCIM group.
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Ref    `json:"members,omitempty"`
	Meta        Meta     `json:"meta"`
}

// Principal is what the gateway needs about a caller.
type Principal struct {
	ID       string
	UserName string
	Active   bool
	Groups   []string // group displayNames
}

// Store holds users and groups.
type Store struct {
	mu     sync.RWMutex
	users  map[string]*User
	groups map[string]*Group
	Now    func() time.Time
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{users: map[string]*User{}, groups: map[string]*Group{}}
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Lookup resolves a token subject to a principal. The subject is matched
// against userName first, then externalId.
func (s *Store) Lookup(subject string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var u *User
	for _, x := range s.users {
		if x.UserName == subject {
			u = x
			break
		}
	}
	if u == nil {
		for _, x := range s.users {
			if x.ExternalID != "" && x.ExternalID == subject {
				u = x
				break
			}
		}
	}
	if u == nil {
		return Principal{}, false
	}
	p := Principal{ID: u.ID, UserName: u.UserName, Active: u.Active == nil || *u.Active}
	for _, g := range s.groups {
		for _, m := range g.Members {
			if m.Value == u.ID {
				p.Groups = append(p.Groups, g.DisplayName)
				break
			}
		}
	}
	sort.Strings(p.Groups)
	return p, true
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Handler serves /scim/v2/... and requires the given bearer token.
type Handler struct {
	Store   *Store
	Token   string
	BaseURL string // e.g. https://gw.example.com/scim/v2
}

type scimError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

func writeErr(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(scimError{Schemas: []string{SchemaError}, Status: strconv.Itoa(status), ScimType: scimType, Detail: detail})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if h.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(h.Token)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
		writeErr(w, http.StatusUnauthorized, "", "invalid provisioning token")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/scim/v2")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "ServiceProviderConfig":
		writeJSON(w, 200, map[string]any{
			"schemas":               []string{SchemaSPC},
			"patch":                 map[string]bool{"supported": true},
			"bulk":                  map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
			"filter":                map[string]any{"supported": true, "maxResults": defaultCount},
			"changePassword":        map[string]bool{"supported": false},
			"sort":                  map[string]bool{"supported": false},
			"etag":                  map[string]bool{"supported": false},
			"authenticationSchemes": []map[string]string{{"type": "oauthbearertoken", "name": "Bearer token"}},
		})
	case parts[0] == "Users" && len(parts) <= 2:
		h.users(w, r, parts[1:])
	case parts[0] == "Groups" && len(parts) <= 2:
		h.groupsH(w, r, parts[1:])
	default:
		writeErr(w, 404, "", "not found")
	}
}

func readBody(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxBodyBytes {
		return fmt.Errorf("body too large")
	}
	return json.Unmarshal(b, v)
}

// filter supports the one form IdPs actually send for lookups:
// attr eq "value" (attr in userName, externalId, displayName).
var filterRe = regexp.MustCompile(`^\s*(userName|externalId|displayName)\s+eq\s+"((?:[^"\\]|\\.)*)"\s*$`)

func parseFilter(f string) (attr, val string, err error) {
	if f == "" {
		return "", "", nil
	}
	m := filterRe.FindStringSubmatch(f)
	if m == nil {
		return "", "", fmt.Errorf("unsupported filter")
	}
	v, err := strconv.Unquote(`"` + m[2] + `"`)
	if err != nil {
		return "", "", fmt.Errorf("bad filter value")
	}
	return m[1], v, nil
}

func paginate[T any](items []T, r *http.Request) (page []T, start int) {
	start, _ = strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count := defaultCount
	if c, err := strconv.Atoi(r.URL.Query().Get("count")); err == nil && c >= 0 && c < defaultCount {
		count = c
	}
	if start-1 >= len(items) {
		return []T{}, start
	}
	end := min(start-1+count, len(items))
	return items[start-1 : end], start
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request, rest []string) {
	s := h.Store
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			attr, val, err := parseFilter(r.URL.Query().Get("filter"))
			if err != nil {
				writeErr(w, 400, "invalidFilter", err.Error())
				return
			}
			s.mu.RLock()
			var out []User
			for _, u := range s.users {
				if attr == "" || (attr == "userName" && strings.EqualFold(u.UserName, val)) || (attr == "externalId" && u.ExternalID == val) || (attr == "displayName" && u.DisplayName == val) {
					out = append(out, h.userView(u))
				}
			}
			s.mu.RUnlock()
			sort.Slice(out, func(i, j int) bool { return out[i].UserName < out[j].UserName })
			page, start := paginate(out, r)
			writeJSON(w, 200, map[string]any{"schemas": []string{SchemaList}, "totalResults": len(out), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
		case http.MethodPost:
			var in User
			if err := readBody(r, &in); err != nil {
				writeErr(w, 400, "invalidSyntax", err.Error())
				return
			}
			if strings.TrimSpace(in.UserName) == "" {
				writeErr(w, 400, "invalidValue", "userName is required")
				return
			}
			s.mu.Lock()
			for _, u := range s.users {
				if strings.EqualFold(u.UserName, in.UserName) {
					s.mu.Unlock()
					writeErr(w, 409, "uniqueness", "userName already exists")
					return
				}
			}
			now := s.now()
			u := &User{ID: newID(), ExternalID: in.ExternalID, UserName: in.UserName, DisplayName: in.DisplayName, Active: in.Active,
				Meta: Meta{ResourceType: "User", Created: now, LastModified: now}}
			if u.Active == nil {
				t := true
				u.Active = &t
			}
			s.users[u.ID] = u
			view := h.userViewLocked(u)
			s.mu.Unlock()
			writeJSON(w, 201, view)
		default:
			writeErr(w, 405, "", "method not allowed")
		}
		return
	}
	id := rest[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		writeErr(w, 404, "", "user not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.userViewLocked(u))
	case http.MethodPut:
		var in User
		if err := readBody(r, &in); err != nil || in.UserName == "" {
			writeErr(w, 400, "invalidValue", "userName is required")
			return
		}
		u.UserName, u.ExternalID, u.DisplayName = in.UserName, in.ExternalID, in.DisplayName
		if in.Active != nil {
			u.Active = in.Active
		}
		u.Meta.LastModified = s.now()
		writeJSON(w, 200, h.userViewLocked(u))
	case http.MethodPatch:
		ops, err := readPatch(r)
		if err != nil {
			writeErr(w, 400, "invalidSyntax", err.Error())
			return
		}
		for _, op := range ops {
			if err := applyUserOp(u, op); err != nil {
				writeErr(w, 400, "invalidValue", err.Error())
				return
			}
		}
		u.Meta.LastModified = s.now()
		writeJSON(w, 200, h.userViewLocked(u))
	case http.MethodDelete:
		delete(s.users, id)
		for _, g := range s.groups {
			g.Members = removeMember(g.Members, id)
		}
		w.WriteHeader(204)
	default:
		writeErr(w, 405, "", "method not allowed")
	}
}

func (h *Handler) userView(u *User) User {
	// caller holds RLock
	return h.userViewLocked(u)
}

func (h *Handler) userViewLocked(u *User) User {
	v := *u
	v.Schemas = []string{SchemaUser}
	v.Meta.Location = h.BaseURL + "/Users/" + u.ID
	v.Groups = nil
	for _, g := range h.Store.groups {
		for _, m := range g.Members {
			if m.Value == u.ID {
				v.Groups = append(v.Groups, Ref{Value: g.ID, Display: g.DisplayName, Ref: h.BaseURL + "/Groups/" + g.ID})
				break
			}
		}
	}
	sort.Slice(v.Groups, func(i, j int) bool { return v.Groups[i].Display < v.Groups[j].Display })
	return v
}

type patchOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

func readPatch(r *http.Request) ([]patchOp, error) {
	var req struct {
		Schemas    []string  `json:"schemas"`
		Operations []patchOp `json:"Operations"`
	}
	if err := readBody(r, &req); err != nil {
		return nil, err
	}
	if len(req.Schemas) != 1 || req.Schemas[0] != SchemaPatch {
		return nil, fmt.Errorf("schemas must be [%q]", SchemaPatch)
	}
	if len(req.Operations) == 0 {
		return nil, fmt.Errorf("no operations")
	}
	return req.Operations, nil
}

// parseBool accepts JSON booleans and the "True"/"False" strings some IdPs
// (Entra ID) send.
func parseBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strconv.ParseBool(strings.ToLower(s))
	}
	return false, fmt.Errorf("expected boolean")
}

func applyUserOp(u *User, op patchOp) error {
	switch strings.ToLower(op.Op) {
	case "replace", "add":
	default:
		return fmt.Errorf("unsupported op %q for User", op.Op)
	}
	set := func(path string, raw json.RawMessage) error {
		switch path {
		case "active":
			b, err := parseBool(raw)
			if err != nil {
				return err
			}
			u.Active = &b
		case "displayName":
			return json.Unmarshal(raw, &u.DisplayName)
		case "externalId":
			return json.Unmarshal(raw, &u.ExternalID)
		case "userName":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil || s == "" {
				return fmt.Errorf("userName must be a non-empty string")
			}
			u.UserName = s
		default:
			return fmt.Errorf("unsupported path %q", path)
		}
		return nil
	}
	if op.Path != "" {
		return set(op.Path, op.Value)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(op.Value, &m); err != nil {
		return fmt.Errorf("value must be an object when path is empty")
	}
	for k, v := range m {
		if err := set(k, v); err != nil {
			return err
		}
	}
	return nil
}

func removeMember(ms []Ref, id string) []Ref {
	out := ms[:0]
	for _, m := range ms {
		if m.Value != id {
			out = append(out, m)
		}
	}
	return out
}

var memberPathRe = regexp.MustCompile(`^members\[value eq "([^"]+)"\]$`)

func (h *Handler) groupsH(w http.ResponseWriter, r *http.Request, rest []string) {
	s := h.Store
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			attr, val, err := parseFilter(r.URL.Query().Get("filter"))
			if err != nil || (attr != "" && attr != "displayName" && attr != "externalId") {
				writeErr(w, 400, "invalidFilter", "unsupported filter")
				return
			}
			s.mu.RLock()
			var out []Group
			for _, g := range s.groups {
				if attr == "" || (attr == "displayName" && g.DisplayName == val) || (attr == "externalId" && g.ExternalID == val) {
					out = append(out, h.groupView(g))
				}
			}
			s.mu.RUnlock()
			sort.Slice(out, func(i, j int) bool { return out[i].DisplayName < out[j].DisplayName })
			page, start := paginate(out, r)
			writeJSON(w, 200, map[string]any{"schemas": []string{SchemaList}, "totalResults": len(out), "startIndex": start, "itemsPerPage": len(page), "Resources": page})
		case http.MethodPost:
			var in Group
			if err := readBody(r, &in); err != nil {
				writeErr(w, 400, "invalidSyntax", err.Error())
				return
			}
			if !validGroupName(in.DisplayName) {
				writeErr(w, 400, "invalidValue", "displayName must match [A-Za-z0-9_.-]{1,64}")
				return
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.groups) >= maxGroupNames {
				writeErr(w, 400, "", "too many groups")
				return
			}
			for _, g := range s.groups {
				if g.DisplayName == in.DisplayName {
					writeErr(w, 409, "uniqueness", "displayName already exists")
					return
				}
			}
			members, err := s.resolveMembers(in.Members)
			if err != nil {
				writeErr(w, 400, "invalidValue", err.Error())
				return
			}
			now := s.now()
			g := &Group{ID: newID(), ExternalID: in.ExternalID, DisplayName: in.DisplayName, Members: members, Meta: Meta{ResourceType: "Group", Created: now, LastModified: now}}
			s.groups[g.ID] = g
			writeJSON(w, 201, h.groupView(g))
		default:
			writeErr(w, 405, "", "method not allowed")
		}
		return
	}
	id := rest[0]
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.groups[id]
	if !ok {
		writeErr(w, 404, "", "group not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, h.groupView(g))
	case http.MethodPatch:
		ops, err := readPatch(r)
		if err != nil {
			writeErr(w, 400, "invalidSyntax", err.Error())
			return
		}
		for _, op := range ops {
			if err := s.applyGroupOp(g, op); err != nil {
				writeErr(w, 400, "invalidValue", err.Error())
				return
			}
		}
		g.Meta.LastModified = s.now()
		writeJSON(w, 200, h.groupView(g))
	case http.MethodDelete:
		delete(s.groups, id)
		w.WriteHeader(204)
	default:
		writeErr(w, 405, "", "method not allowed")
	}
}

// Group names become Cedar entity ids (Group::"name"), so they are kept to a
// plain character set.
var groupNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func validGroupName(s string) bool { return groupNameRe.MatchString(s) }

func (s *Store) resolveMembers(in []Ref) ([]Ref, error) {
	var out []Ref
	seen := map[string]bool{}
	for _, m := range in {
		u, ok := s.users[m.Value]
		if !ok {
			return nil, fmt.Errorf("member %q is not a known user", m.Value)
		}
		if !seen[m.Value] {
			seen[m.Value] = true
			out = append(out, Ref{Value: u.ID, Display: u.UserName})
		}
	}
	return out, nil
}

func (s *Store) applyGroupOp(g *Group, op patchOp) error {
	switch strings.ToLower(op.Op) {
	case "add":
		if op.Path != "members" {
			return fmt.Errorf("add supports path \"members\" only")
		}
		var refs []Ref
		if err := json.Unmarshal(op.Value, &refs); err != nil {
			return fmt.Errorf("members value must be an array")
		}
		add, err := s.resolveMembers(refs)
		if err != nil {
			return err
		}
		for _, m := range add {
			if !hasMember(g.Members, m.Value) {
				g.Members = append(g.Members, m)
			}
		}
	case "remove":
		if m := memberPathRe.FindStringSubmatch(op.Path); m != nil {
			g.Members = removeMember(g.Members, m[1])
			return nil
		}
		if op.Path == "members" {
			if len(op.Value) == 0 {
				g.Members = nil
				return nil
			}
			var refs []Ref
			if err := json.Unmarshal(op.Value, &refs); err != nil {
				return fmt.Errorf("members value must be an array")
			}
			for _, r := range refs {
				g.Members = removeMember(g.Members, r.Value)
			}
			return nil
		}
		return fmt.Errorf("unsupported remove path %q", op.Path)
	case "replace":
		switch op.Path {
		case "members":
			var refs []Ref
			if err := json.Unmarshal(op.Value, &refs); err != nil {
				return fmt.Errorf("members value must be an array")
			}
			ms, err := s.resolveMembers(refs)
			if err != nil {
				return err
			}
			g.Members = ms
		case "displayName":
			var n string
			if err := json.Unmarshal(op.Value, &n); err != nil || !validGroupName(n) {
				return fmt.Errorf("invalid displayName")
			}
			g.DisplayName = n
		default:
			return fmt.Errorf("unsupported replace path %q", op.Path)
		}
	default:
		return fmt.Errorf("unsupported op %q", op.Op)
	}
	return nil
}

func hasMember(ms []Ref, id string) bool {
	for _, m := range ms {
		if m.Value == id {
			return true
		}
	}
	return false
}

func (h *Handler) groupView(g *Group) Group {
	v := *g
	v.Schemas = []string{SchemaGroup}
	v.Meta.Location = h.BaseURL + "/Groups/" + g.ID
	v.Members = append([]Ref(nil), g.Members...)
	for i := range v.Members {
		v.Members[i].Ref = h.BaseURL + "/Users/" + v.Members[i].Value
	}
	return v
}
