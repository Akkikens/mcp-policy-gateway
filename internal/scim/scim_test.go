package scim

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type client struct {
	t   *testing.T
	srv *httptest.Server
	tok string
}

func (c client) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	req, _ := http.NewRequest(method, c.srv.URL+"/scim/v2"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.tok)
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func newTest(t *testing.T) (*Store, client) {
	s := NewStore()
	srv := httptest.NewServer(&Handler{Store: s, Token: "prov-secret", BaseURL: "https://gw/scim/v2"})
	t.Cleanup(srv.Close)
	return s, client{t: t, srv: srv, tok: "prov-secret"}
}

func TestProvisioningLifecycle(t *testing.T) {
	s, c := newTest(t)
	code, alice := c.do("POST", "/Users", `{"schemas":["`+SchemaUser+`"],"userName":"alice","externalId":"00u1"}`)
	if code != 201 || alice["id"] == "" {
		t.Fatalf("create user: %d %v", code, alice)
	}
	aliceID := alice["id"].(string)
	if code, _ := c.do("POST", "/Users", `{"userName":"ALICE"}`); code != 409 {
		t.Fatalf("duplicate userName: %d", code)
	}
	_, bob := c.do("POST", "/Users", `{"userName":"bob"}`)
	bobID := bob["id"].(string)

	code, eng := c.do("POST", "/Groups", `{"displayName":"engineering","members":[{"value":"`+aliceID+`"}]}`)
	if code != 201 {
		t.Fatalf("create group: %d %v", code, eng)
	}
	engID := eng["id"].(string)
	if code, _ := c.do("POST", "/Groups", `{"displayName":"bad\" name"}`); code != 400 {
		t.Fatalf("invalid group name accepted: %d", code)
	}
	if code, _ := c.do("POST", "/Groups", `{"displayName":"x","members":[{"value":"nope"}]}`); code != 400 {
		t.Fatalf("unknown member accepted: %d", code)
	}

	p, ok := s.Lookup("alice")
	if !ok || !p.Active || len(p.Groups) != 1 || p.Groups[0] != "engineering" {
		t.Fatalf("lookup alice: %+v %v", p, ok)
	}
	if p, ok := s.Lookup("00u1"); !ok || p.UserName != "alice" {
		t.Fatal("lookup by externalId failed")
	}

	// filter, as IdPs do before creating
	_, list := c.do("GET", `/Users?filter=userName%20eq%20%22bob%22`, "")
	if list["totalResults"].(float64) != 1 {
		t.Fatalf("filter: %v", list)
	}
	if code, _ := c.do("GET", `/Users?filter=userName%20co%20%22b%22`, ""); code != 400 {
		t.Fatalf("unsupported filter accepted: %d", code)
	}

	// add bob, then remove alice via the members[value eq ...] path form
	patch := `{"schemas":["` + SchemaPatch + `"],"Operations":[{"op":"add","path":"members","value":[{"value":"` + bobID + `"}]},{"op":"remove","path":"members[value eq \"` + aliceID + `\"]"}]}`
	if code, g := c.do("PATCH", "/Groups/"+engID, patch); code != 200 || len(g["members"].([]any)) != 1 {
		t.Fatalf("patch group: %d %v", code, g)
	}
	if p, _ := s.Lookup("alice"); len(p.Groups) != 0 {
		t.Fatalf("alice still in groups: %v", p.Groups)
	}
	if p, _ := s.Lookup("bob"); len(p.Groups) != 1 {
		t.Fatalf("bob groups: %v", p.Groups)
	}

	// deactivate with the Entra-style string boolean
	deact := `{"schemas":["` + SchemaPatch + `"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`
	if code, _ := c.do("PATCH", "/Users/"+bobID, deact); code != 200 {
		t.Fatalf("deactivate: %d", code)
	}
	if p, _ := s.Lookup("bob"); p.Active {
		t.Fatal("bob still active")
	}
	// path-less replace with a value map
	react := `{"schemas":["` + SchemaPatch + `"],"Operations":[{"op":"replace","value":{"active":true,"displayName":"Bob"}}]}`
	if code, u := c.do("PATCH", "/Users/"+bobID, react); code != 200 || u["active"] != true || u["displayName"] != "Bob" {
		t.Fatalf("reactivate: %d %v", code, u)
	}

	// delete removes membership too
	if code, _ := c.do("DELETE", "/Users/"+bobID, ""); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	if _, ok := s.Lookup("bob"); ok {
		t.Fatal("deleted user still resolves")
	}
	if _, g := c.do("GET", "/Groups/"+engID, ""); g["members"] != nil {
		t.Fatalf("deleted user still a member: %v", g["members"])
	}
}

func TestSCIMAuthAndErrors(t *testing.T) {
	_, c := newTest(t)
	bad := c
	bad.tok = "wrong"
	if code, _ := bad.do("GET", "/Users", ""); code != 401 {
		t.Fatalf("wrong token: %d", code)
	}
	empty := c
	empty.tok = ""
	if code, _ := empty.do("GET", "/Users", ""); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := c.do("GET", "/Users/nope", ""); code != 404 {
		t.Fatalf("missing user: %d", code)
	}
	if code, _ := c.do("POST", "/Users", `{}`); code != 400 {
		t.Fatalf("missing userName: %d", code)
	}
	if code, _ := c.do("PATCH", "/Users/x", `{}`); code != 404 {
		t.Fatalf("patch missing: %d", code)
	}
	_, u := c.do("POST", "/Users", `{"userName":"z"}`)
	if code, _ := c.do("PATCH", "/Users/"+u["id"].(string), `{"Operations":[]}`); code != 400 {
		t.Fatalf("patch without schema: %d", code)
	}
	if code, m := c.do("GET", "/ServiceProviderConfig", ""); code != 200 || m["patch"] == nil {
		t.Fatalf("spc: %d %v", code, m)
	}
}
