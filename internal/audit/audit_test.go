package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeN(t *testing.T, path string, n int) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < n; i++ {
		if _, err := l.Append(Record{Event: "allow", Subject: "alice", Tool: "read_file", ArgsSHA256: "ab"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainVerifiesAndReopens(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	writeN(t, p, 3)
	writeN(t, p, 2) // reopen continues the chain
	n, head, err := VerifyFile(p)
	if err != nil || n != 5 || head == Genesis {
		t.Fatalf("verify: n=%d head=%s err=%v", n, head, err)
	}
}

func TestTamperDetection(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]string) []string
		line   int
	}{
		{"edit a field", func(ls []string) []string {
			ls[1] = strings.Replace(ls[1], `"allow"`, `"deny"`, 1)
			return ls
		}, 2},
		{"delete a middle record", func(ls []string) []string { return append(ls[:1], ls[2:]...) }, 2},
		{"swap records", func(ls []string) []string { ls[0], ls[1] = ls[1], ls[0]; return ls }, 1},
		{"edit another field", func(ls []string) []string {
			ls[1] = strings.Replace(ls[1], `"alice"`, `"mallory"`, 1)
			return ls
		}, 2},
		{"garbage line", func(ls []string) []string { ls[2] = "{not json"; return ls }, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "audit.jsonl")
			writeN(t, p, 4)
			b, _ := os.ReadFile(p)
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			_ = os.WriteFile(p, []byte(strings.Join(tc.mutate(lines), "\n")+"\n"), 0o600)
			_, _, err := VerifyFile(p)
			var te *TamperError
			if !errors.As(err, &te) || te.Line != tc.line {
				t.Fatalf("got %v, want tamper at line %d", err, tc.line)
			}
			if _, err := Open(p); err == nil {
				t.Fatal("Open appended to a broken chain")
			}
		})
	}
}
