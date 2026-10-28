package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Akkikens/mcp-policy-gateway/internal/creds"
)

// Version is set at build time with -ldflags.
var Version = "dev"

// Duration is a time.Duration that unmarshals from "30s".
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

// UpstreamConfig is one MCP server behind the gateway.
type UpstreamConfig struct {
	Name       string     `json:"name"`
	URL        string     `json:"url"`
	Credential creds.Spec `json:"credential"`
}

// PolicyConfig locates the signed policy material.
type PolicyConfig struct {
	Bundle             string   `json:"bundle"`
	Revocations        string   `json:"revocations,omitempty"`
	TrustedKeys        string   `json:"trusted_keys"`
	State              string   `json:"state,omitempty"`
	MinVersion         uint64   `json:"min_version,omitempty"`
	RequireRevocations bool     `json:"require_revocations,omitempty"`
	ReloadInterval     Duration `json:"reload_interval,omitempty"`
}

// Config is the gateway configuration file.
type Config struct {
	Listen               string           `json:"listen"`
	PublicURL            string           `json:"public_url"` // e.g. https://gw.example.com; the MCP resource is PublicURL + "/mcp"
	Issuer               string           `json:"issuer"`
	JWKSURL              string           `json:"jwks_url"`
	AuthorizationServers []string         `json:"authorization_servers"`
	RequiredScopes       []string         `json:"required_scopes"`
	AllowedOrigins       []string         `json:"allowed_origins,omitempty"`
	SCIMTokenEnv         string           `json:"scim_token_env"`
	AuditLog             string           `json:"audit_log"`
	Policy               PolicyConfig     `json:"policy"`
	Upstreams            []UpstreamConfig `json:"upstreams"`
}

// Resource is the canonical MCP server URL tokens must be minted for.
func (c *Config) Resource() string { return strings.TrimRight(c.PublicURL, "/") + "/mcp" }

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// LoadConfig reads and validates a config file. ${VAR} in string values is
// expanded from the environment (useful for PORT on Cloud Run).
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b = []byte(os.ExpandEnv(string(b)))
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.Validate()
}

// Validate checks required fields.
func (c *Config) Validate() error {
	var errs []error
	if _, err := url.ParseRequestURI(c.PublicURL); err != nil {
		errs = append(errs, errors.New("public_url must be an absolute URL"))
	}
	if c.Issuer == "" || c.JWKSURL == "" {
		errs = append(errs, errors.New("issuer and jwks_url are required"))
	}
	if c.Policy.Bundle == "" || c.Policy.TrustedKeys == "" {
		errs = append(errs, errors.New("policy.bundle and policy.trusted_keys are required"))
	}
	if c.AuditLog == "" {
		errs = append(errs, errors.New("audit_log is required"))
	}
	seen := map[string]bool{}
	for _, u := range c.Upstreams {
		if !nameRe.MatchString(u.Name) || seen[u.Name] {
			errs = append(errs, fmt.Errorf("upstream name %q must match %s and be unique", u.Name, nameRe))
		}
		seen[u.Name] = true
		if _, err := url.ParseRequestURI(u.URL); err != nil {
			errs = append(errs, fmt.Errorf("upstream %s: bad url", u.Name))
		}
	}
	if len(c.Upstreams) == 0 {
		errs = append(errs, errors.New("at least one upstream is required"))
	}
	return errors.Join(errs...)
}
