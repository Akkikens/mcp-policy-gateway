package jsonrpc

import (
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		code    int // 0 = ok
		notif   bool
		method  string
		wantMsg string
	}{
		{name: "ok", in: `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, method: "tools/list"},
		{name: "string id", in: `{"jsonrpc":"2.0","id":"a","method":"ping","params":{}}`, method: "ping"},
		{name: "notification", in: `{"jsonrpc":"2.0","method":"notifications/initialized"}`, notif: true, method: "notifications/initialized"},
		{name: "batch", in: `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, code: CodeInvalidRequest, wantMsg: "batch"},
		{name: "not object", in: `"x"`, code: CodeInvalidRequest},
		{name: "empty", in: ``, code: CodeParseError},
		{name: "garbage", in: `{"jsonrpc":`, code: CodeParseError},
		{name: "wrong version", in: `{"jsonrpc":"1.0","id":1,"method":"ping"}`, code: CodeInvalidRequest},
		{name: "no method", in: `{"jsonrpc":"2.0","id":1}`, code: CodeInvalidRequest},
		{name: "null id", in: `{"jsonrpc":"2.0","id":null,"method":"ping"}`, code: CodeInvalidRequest},
		{name: "float id", in: `{"jsonrpc":"2.0","id":1.5,"method":"ping"}`, code: CodeInvalidRequest},
		{name: "object id", in: `{"jsonrpc":"2.0","id":{},"method":"ping"}`, code: CodeInvalidRequest},
		{name: "unknown field", in: `{"jsonrpc":"2.0","id":1,"method":"ping","extra":1}`, code: CodeInvalidRequest},
		// encoding/json alone would accept this as "params".
		{name: "case-folded member", in: `{"jsonrpc":"2.0","id":1,"method":"ping","pArAms":{}}`, code: CodeInvalidRequest, wantMsg: "unknown member"},
		{name: "scalar params", in: `{"jsonrpc":"2.0","id":1,"method":"ping","params":3}`, code: CodeInvalidRequest},
		{name: "trailing data", in: `{"jsonrpc":"2.0","id":1,"method":"ping"} {}`, code: CodeParseError, wantMsg: "trailing"},
		// Parser differential: encoding/json keeps the last duplicate, other
		// parsers keep the first. Rejecting duplicates removes the ambiguity.
		{name: "duplicate method", in: `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}`, code: CodeInvalidRequest, wantMsg: "duplicate"},
		{name: "duplicate nested", in: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`, code: CodeInvalidRequest, wantMsg: "duplicate"},
		{name: "too deep", in: `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}}`, code: CodeParseError, wantMsg: "nesting"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, e := ParseRequest([]byte(tc.in))
			if tc.code == 0 {
				if e != nil {
					t.Fatalf("unexpected error %v", e)
				}
				if req.Method != tc.method || req.IsNotification() != tc.notif {
					t.Fatalf("got %+v", req)
				}
				return
			}
			if e == nil {
				t.Fatalf("expected error code %d, got %+v", tc.code, req)
			}
			if e.Code != tc.code {
				t.Fatalf("code = %d (%s), want %d", e.Code, e.Message, tc.code)
			}
			if tc.wantMsg != "" && !strings.Contains(e.Message, tc.wantMsg) {
				t.Fatalf("message %q does not contain %q", e.Message, tc.wantMsg)
			}
		})
	}
}

func TestParseRequestTooLarge(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":"` + strings.Repeat("a", MaxMessageBytes) + `"}}`
	if _, e := ParseRequest([]byte(big)); e == nil || e.Code != CodeInvalidRequest {
		t.Fatalf("expected too large, got %v", e)
	}
}

func TestParseCallParams(t *testing.T) {
	p, args, e := ParseCallParams([]byte(`{"name":"files__read_file","arguments":{"path":"/a","n":12345678901234567890}}`))
	if e != nil {
		t.Fatal(e)
	}
	if p.Name != "files__read_file" || args["path"] != "/a" {
		t.Fatalf("got %+v %v", p, args)
	}
	// numbers keep their exact text so re-encoding is lossless
	if n, ok := args["n"].(interface{ String() string }); !ok || n.String() != "12345678901234567890" {
		t.Fatalf("number not preserved: %#v", args["n"])
	}
	for _, bad := range []string{``, `{}`, `{"name":"x","arguments":[1]}`, `{"name":"x","arguments":"s"}`, `{"name":"x","bogus":1}`, `{"NAME":"x"}`} {
		if _, _, e := ParseCallParams([]byte(bad)); e == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
	if _, args, e := ParseCallParams([]byte(`{"name":"x","arguments":null}`)); e != nil || len(args) != 0 {
		t.Fatalf("null arguments should be empty, got %v %v", args, e)
	}
}

func TestParseResponse(t *testing.T) {
	if _, err := ParseResponse([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"jsonrpc":"2.0","id":1}`, `{"jsonrpc":"2.0","id":1,"result":{},"result":{}}`, `nope`} {
		if _, err := ParseResponse([]byte(bad)); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}
