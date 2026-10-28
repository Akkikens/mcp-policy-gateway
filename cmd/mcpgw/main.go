// Command mcpgw runs the MCP policy gateway and its operator tooling.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/audit"
	"github.com/Akkikens/mcp-policy-gateway/internal/auth"
	"github.com/Akkikens/mcp-policy-gateway/internal/gateway"
	"github.com/Akkikens/mcp-policy-gateway/internal/policy"
)

const usage = `mcpgw <command> [flags]

commands:
  serve             run the gateway                     (-config gateway.json)
  keygen            create an ed25519 policy signing key (-out dir -keyid id)
  sign-bundle       sign a directory of .cedar files     (-key -keyid -version -ttl -policies -out)
  sign-revocations  sign a revocation list               (-key -keyid -seq -ttl -versions -digests -keys -out)
  audit-verify      verify the hash-chained audit log    (-log audit.jsonl)
  dev-issuer        local token issuer for the demo      (-addr -issuer)
  version           print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"serve": serve, "keygen": keygen, "sign-bundle": signBundle, "sign-revocations": signRevocations,
		"audit-verify": auditVerify, "dev-issuer": devIssuer,
		"version": func([]string) error { fmt.Println(gateway.Version); return nil },
	}
	cmd, ok := cmds[os.Args[1]]
	if !ok {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err := cmd(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "mcpgw:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "gateway.json", "config file")
	_ = fs.Parse(args)
	cfg, err := gateway.LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	listen := cfg.Listen
	if p := os.Getenv("PORT"); p != "" { // Cloud Run
		listen = ":" + p
	}
	if listen == "" {
		listen = ":8080"
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	gw, err := gateway.New(cfg, gateway.Deps{Logger: log})
	if err != nil {
		return err
	}
	defer gw.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go gw.Run(ctx)
	srv := &http.Server{Addr: listen, Handler: gw.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("listening", "addr", listen, "resource", cfg.Resource())
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", ".", "output directory")
	kid := fs.String("keyid", "policy-1", "key id")
	_ = fs.Parse(args)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	keyPath := filepath.Join(*out, *kid+".key")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	tk, _ := json.MarshalIndent(map[string]any{"keys": []map[string]string{{"keyid": *kid, "ed25519": base64.StdEncoding.EncodeToString(pub)}}}, "", "  ")
	tkPath := filepath.Join(*out, "trusted_keys.json")
	if err := os.WriteFile(tkPath, append(tk, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("private key: %s (keep offline)\ntrusted keys: %s\n", keyPath, tkPath)
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file must hold a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func signBundle(args []string) error {
	fs := flag.NewFlagSet("sign-bundle", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	kid := fs.String("keyid", "policy-1", "key id")
	version := fs.Uint64("version", 0, "bundle version (must increase)")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity")
	dir := fs.String("policies", "policies", "directory of .cedar files")
	out := fs.String("out", "bundle.json", "output file")
	comment := fs.String("comment", "", "free-text comment")
	_ = fs.Parse(args)
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	files, _ := filepath.Glob(filepath.Join(*dir, "*.cedar"))
	sort.Strings(files)
	if len(files) == 0 {
		return fmt.Errorf("no .cedar files in %s", *dir)
	}
	m := policy.Manifest{Version: *version, IssuedAt: time.Now().UTC().Truncate(time.Second), Policies: map[string]string{}, Comment: *comment}
	m.ExpiresAt = m.IssuedAt.Add(*ttl)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		m.Policies[filepath.Base(f)] = string(b)
	}
	// Refuse to sign something the gateway would reject.
	keys := policy.TrustedKeys{*kid: priv.Public().(ed25519.PublicKey)}
	b, err := policy.SignJSON(policy.TypeBundle, m, *kid, priv)
	if err != nil {
		return err
	}
	if _, err := (&policy.Store{Keys: keys}).Load(b); err != nil {
		return fmt.Errorf("bundle does not verify: %w", err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s: version %d, %d policy files, expires %s\n", *out, m.Version, len(files), m.ExpiresAt.Format(time.RFC3339))
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func signRevocations(args []string) error {
	fs := flag.NewFlagSet("sign-revocations", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file")
	kid := fs.String("keyid", "policy-1", "key id")
	seq := fs.Uint64("seq", 0, "sequence (must not decrease)")
	ttl := fs.Duration("ttl", 24*time.Hour, "validity")
	versions := fs.String("versions", "", "comma-separated revoked bundle versions")
	digests := fs.String("digests", "", "comma-separated revoked bundle sha256 digests")
	keyIDs := fs.String("keys", "", "comma-separated revoked key ids")
	out := fs.String("out", "revocations.json", "output file")
	_ = fs.Parse(args)
	priv, err := readKey(*keyPath)
	if err != nil {
		return err
	}
	r := policy.Revocations{Sequence: *seq, IssuedAt: time.Now().UTC().Truncate(time.Second), RevokedDigests: splitList(*digests), RevokedKeyIDs: splitList(*keyIDs)}
	r.ExpiresAt = r.IssuedAt.Add(*ttl)
	for _, v := range splitList(*versions) {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return fmt.Errorf("bad version %q", v)
		}
		r.RevokedVersions = append(r.RevokedVersions, n)
	}
	b, err := policy.SignJSON(policy.TypeRevocations, r, *kid, priv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s: sequence %d\n", *out, r.Sequence)
	return nil
}

func auditVerify(args []string) error {
	fs := flag.NewFlagSet("audit-verify", flag.ExitOnError)
	path := fs.String("log", "audit.jsonl", "audit log")
	_ = fs.Parse(args)
	n, head, err := audit.VerifyFile(*path)
	if err != nil {
		return err
	}
	fmt.Printf("ok: %d records, head %s\n", n, head)
	return nil
}

// devIssuer serves a JWKS and mints tokens over HTTP for the local demo. It
// binds to loopback only and is not an OAuth authorization server.
func devIssuer(args []string) error {
	fs := flag.NewFlagSet("dev-issuer", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:9000", "listen address (loopback only)")
	issuer := fs.String("issuer", "http://127.0.0.1:9000", "issuer")
	_ = fs.Parse(args)
	host, _, err := net.SplitHostPort(*addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return errors.New("dev-issuer only binds to loopback")
	}
	iss, err := auth.NewDevIssuer(*issuer)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", iss.JWKSHandler())
	mux.HandleFunc("/mint", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		tok, err := iss.Mint(auth.TokenOptions{Subject: q.Get("sub"), Audience: q.Get("aud"), Scopes: strings.Fields(q.Get("scope"))})
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintln(w, tok)
	})
	fmt.Fprintf(os.Stderr, "dev issuer %s on %s (GET /mint?sub=&aud=&scope=)\n", *issuer, *addr)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv.ListenAndServe()
}
