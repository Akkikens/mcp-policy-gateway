// Command fakemcp runs one of the fake upstream MCP servers for the demo.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/fakemcp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9100", "listen address")
	kind := flag.String("tools", "files", "files | web")
	tokenEnv := flag.String("token-env", "UPSTREAM_TOKEN", "env var holding the bearer token this server expects")
	flag.Parse()
	tok := os.Getenv(*tokenEnv)
	if tok == "" {
		fmt.Fprintf(os.Stderr, "fakemcp: %s is empty\n", *tokenEnv)
		os.Exit(2)
	}
	var s *fakemcp.Server
	switch *kind {
	case "files":
		s = fakemcp.FilesServer(tok)
	case "web":
		s = fakemcp.WebServer(tok)
	default:
		fmt.Fprintln(os.Stderr, "fakemcp: -tools must be files or web")
		os.Exit(2)
	}
	srv := &http.Server{Addr: *addr, Handler: s, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(os.Stderr, "fakemcp %s on %s\n", *kind, *addr)
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
