package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// ProtectedResourceMetadata is the RFC 9728 document the MCP authorization
// spec requires a protected MCP server to publish.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// MetadataHandler serves the protected-resource metadata document.
func MetadataHandler(m ProtectedResourceMetadata) http.Handler {
	b, _ := json.Marshal(m)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(b)
	})
}

// BearerToken extracts the token from an Authorization header. Tokens in the
// query string are not accepted (OAuth 2.1 / MCP forbid it).
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return "", false
	}
	return strings.TrimSpace(tok), true
}

// Challenge writes the WWW-Authenticate response for an auth failure: 401
// with a pointer to the metadata document, or 403 insufficient_scope.
func Challenge(w http.ResponseWriter, metadataURL string, err error, scope string) {
	status := http.StatusUnauthorized
	v := fmt.Sprintf(`Bearer resource_metadata=%q`, metadataURL)
	switch {
	case errors.Is(err, ErrInsufficientScope):
		status = http.StatusForbidden
		v += fmt.Sprintf(`, error="insufficient_scope", scope=%q`, scope)
	case err != nil:
		v += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	msg := "authentication required"
	if err != nil {
		msg = strings.SplitN(err.Error(), ":", 2)[0]
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
