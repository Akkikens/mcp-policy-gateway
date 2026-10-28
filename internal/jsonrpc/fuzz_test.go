package jsonrpc

import (
	"encoding/json"
	"testing"
)

// FuzzParseRequest checks that the parser never panics and that anything it
// accepts is a well-formed request that survives a re-encode round trip with
// the same method and id.
func FuzzParseRequest(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":"x","method":"tools/call","params":{"name":"a__b","arguments":{"p":[1,2,{"q":null}]}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":1,"method":"a","method":"b"}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":1e3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping"}garbage`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\\u0000\"}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		req, e := ParseRequest(b)
		if e != nil {
			if req != nil {
				t.Fatal("request returned together with error")
			}
			return
		}
		if req.JSONRPC != Version || req.Method == "" {
			t.Fatalf("accepted invalid request %+v", req)
		}
		out, err := json.Marshal(req)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		again, e2 := ParseRequest(out)
		if e2 != nil {
			t.Fatalf("re-encoded request rejected: %v (%s)", e2, out)
		}
		var id1, id2 any
		_ = json.Unmarshal(req.ID, &id1)
		_ = json.Unmarshal(again.ID, &id2)
		if again.Method != req.Method || id1 != id2 {
			t.Fatalf("round trip changed request: %+v vs %+v", req, again)
		}
		if req.Method == "tools/call" {
			_, _, _ = ParseCallParams(req.Params)
		}
	})
}
