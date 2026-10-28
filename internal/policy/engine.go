package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// Actions the gateway asks Cedar about.
const (
	ActionList = "list_tool" // may this principal see the tool in tools/list
	ActionCall = "call_tool" // may this principal call it with these args
)

// MaxArgDepth bounds argument nesting converted into Cedar values.
const MaxArgDepth = 16

// Input is one authorization question.
type Input struct {
	Subject string   // token sub / SCIM userName
	Groups  []string // SCIM group displayNames
	Scopes  []string // OAuth scopes on the token
	Server  string   // upstream name
	Tool    string   // upstream tool name
	// Args are the decoded call arguments (numbers as json.Number). Nil for
	// ActionList.
	Args map[string]any
}

// Decision is the result, bound to exactly what was evaluated.
type Decision struct {
	Allow         bool     `json:"allow"`
	Reason        string   `json:"reason"`
	PolicyVersion uint64   `json:"policy_version,omitempty"`
	PolicyDigest  string   `json:"policy_digest,omitempty"`
	Matched       []string `json:"matched,omitempty"`
	// ArgsSHA256 is the hash of CanonicalArgs; the gateway forwards those
	// exact bytes, so the call the upstream sees is the call that was allowed.
	ArgsSHA256 string `json:"args_sha256,omitempty"`
	// Binding is sha256 over (policy digest, subject, action, server, tool,
	// args hash). An audit record carrying it can be re-checked later.
	Binding       string `json:"binding,omitempty"`
	CanonicalArgs []byte `json:"-"`
}

// Engine evaluates inputs against the store's current bundle.
type Engine struct {
	Store *Store
}

// CanonicalArgs encodes args deterministically (encoding/json sorts map
// keys; json.Number keeps the original digits).
func CanonicalArgs(args map[string]any) ([]byte, error) {
	if args == nil {
		args = map[string]any{}
	}
	return json.Marshal(args)
}

// Bind computes the decision binding.
func Bind(digest, subject, action, server, tool, argsSHA string) string {
	h := sha256.New()
	for _, part := range []string{"mcpgw-decision-v1", digest, subject, action, server, tool, argsSHA} {
		fmt.Fprintf(h, "%d:%s|", len(part), part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Decide answers one question. It fails closed: no bundle, a stale or
// revoked bundle, unconvertible arguments, or any Cedar evaluation error all
// produce a deny.
func (e *Engine) Decide(action string, in Input) Decision {
	d := Decision{}
	canon, err := CanonicalArgs(in.Args)
	if err != nil {
		d.Reason = "invalid_arguments"
		return d
	}
	sum := sha256.Sum256(canon)
	d.ArgsSHA256 = hex.EncodeToString(sum[:])
	d.CanonicalArgs = canon

	act, err := e.Store.Current()
	if err != nil {
		d.Reason = "policy_unavailable: " + err.Error()
		return d
	}
	d.PolicyVersion, d.PolicyDigest = act.Manifest.Version, act.Digest
	d.Binding = Bind(act.Digest, in.Subject, action, in.Server, in.Tool, d.ArgsSHA256)
	if action != ActionList && action != ActionCall {
		d.Reason = "unknown_action"
		return d
	}

	ctx := cedar.RecordMap{"scopes": stringSet(in.Scopes)}
	if action == ActionCall {
		v, err := toCedar(in.Args, 0)
		if err != nil {
			d.Reason = "invalid_arguments: " + err.Error()
			return d
		}
		ctx["args"] = v
	}
	user := cedar.NewEntityUID("User", cedar.String(in.Subject))
	server := cedar.NewEntityUID("Server", cedar.String(in.Server))
	tool := cedar.NewEntityUID("Tool", cedar.String(in.Server+"/"+in.Tool))
	parents := make([]cedar.EntityUID, 0, len(in.Groups))
	entities := cedar.EntityMap{}
	for _, g := range in.Groups {
		uid := cedar.NewEntityUID("Group", cedar.String(g))
		parents = append(parents, uid)
		entities[uid] = cedar.Entity{UID: uid}
	}
	entities[user] = cedar.Entity{UID: user, Parents: cedar.NewEntityUIDSet(parents...)}
	entities[server] = cedar.Entity{UID: server}
	entities[tool] = cedar.Entity{UID: tool, Parents: cedar.NewEntityUIDSet(server)}

	dec, diag := cedar.Authorize(act.Set, entities, cedar.Request{
		Principal: user,
		Action:    cedar.NewEntityUID("Action", cedar.String(action)),
		Resource:  tool,
		Context:   cedar.NewRecord(ctx),
	})
	for _, r := range diag.Reasons {
		d.Matched = append(d.Matched, act.names[r.PolicyID])
	}
	sort.Strings(d.Matched)
	if len(diag.Errors) > 0 {
		// Cedar skips a policy whose condition errors. For a forbid that is
		// fail-open, so any error denies. Policies should guard optional
		// attributes with `has`.
		var ids []string
		for _, e := range diag.Errors {
			ids = append(ids, act.names[e.PolicyID])
		}
		sort.Strings(ids)
		d.Reason = "policy_evaluation_error: " + strings.Join(ids, ",")
		return d
	}
	if dec == cedar.Allow {
		d.Allow, d.Reason = true, "permit"
		return d
	}
	if len(d.Matched) > 0 {
		d.Reason = "forbid"
	} else {
		d.Reason = "no_matching_permit"
	}
	return d
}

func stringSet(xs []string) cedar.Set {
	vs := make([]cedar.Value, 0, len(xs))
	for _, x := range xs {
		vs = append(vs, cedar.String(x))
	}
	return cedar.NewSet(vs...)
}

var errDepth = errors.New("arguments nested too deeply")

// toCedar maps JSON to Cedar: string->String, integer->Long, other
// numbers->String of their digits (Cedar has no floats), bool->Boolean,
// array->Set, object->Record. JSON null fields are dropped, so a policy sees
// them as absent (`has` is false).
func toCedar(v any, depth int) (cedar.Value, error) {
	if depth > MaxArgDepth {
		return nil, errDepth
	}
	switch t := v.(type) {
	case nil:
		return nil, nil
	case string:
		return cedar.String(t), nil
	case bool:
		return cedar.Boolean(t), nil
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return cedar.Long(i), nil
		}
		return cedar.String(t.String()), nil
	case float64:
		if t == float64(int64(t)) {
			return cedar.Long(int64(t)), nil
		}
		return cedar.String(fmt.Sprint(t)), nil
	case []any:
		vs := make([]cedar.Value, 0, len(t))
		for _, x := range t {
			cv, err := toCedar(x, depth+1)
			if err != nil {
				return nil, err
			}
			if cv != nil {
				vs = append(vs, cv)
			}
		}
		return cedar.NewSet(vs...), nil
	case map[string]any:
		rm := cedar.RecordMap{}
		for k, x := range t {
			cv, err := toCedar(x, depth+1)
			if err != nil {
				return nil, err
			}
			if cv != nil {
				rm[types.String(k)] = cv
			}
		}
		return cedar.NewRecord(rm), nil
	default:
		return nil, fmt.Errorf("unsupported argument type %T", v)
	}
}
