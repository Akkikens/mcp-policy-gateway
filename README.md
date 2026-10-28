# mcp-policy-gateway

An identity-aware **MCP gateway in Go**: a Streamable HTTP endpoint that sits in front of one or more MCP servers and decides, per caller, which tools exist and which calls go through. Callers authenticate with OAuth 2.1 bearer tokens (the resource-server half of the MCP authorization spec), are resolved through a **SCIM 2.0** directory that an identity provider provisions, and are authorized by **Cedar** policies that ship as **ed25519-signed, versioned, expiring bundles** with revocation and rollback protection. Upstream credentials live only in the gateway, and every decision lands in a hash-chained audit log. Built with Claude Code as a learning/portfolio project. It is not a production system, has no users, and is **not deployed anywhere**.

| Concern | What's here | Where |
|---|---|---|
| MCP gateway | `POST /mcp` speaking JSON-RPC 2.0 over Streamable HTTP; mediates `initialize`, `ping`, `tools/list`, `tools/call`; tools from N upstreams are namespaced `<upstream>__<tool>`; upstream client handles JSON and `text/event-stream` responses, `Mcp-Session-Id`, re-initialization after a dropped session, and `tools/list` pagination. Everything else (resources, prompts, sampling) answers "method not found" instead of passing through unchecked | `internal/gateway/` |
| Strict parsing | Rejects batches, duplicate keys at any depth, case-folded member names, nesting > 64, trailing data, null/float ids. Removes parser differentials between the gateway and an upstream (found by the fuzzer: `encoding/json` alone accepts `"pArAms"` as `params`) | `internal/jsonrpc/` |
| OAuth 2.1 resource server | Bearer JWT (RS256/ES256 only; `none` and HS* refused) validated against the authorization server's JWKS, with kid-rotation refetch rate-limited; `iss`, `exp`/`nbf`/`iat` with leeway; **audience must equal the gateway's resource URL** (RFC 8707), so tokens minted for another MCP server are refused; required scopes give `403 insufficient_scope`; `401` carries `WWW-Authenticate: Bearer resource_metadata=...`; RFC 9728 metadata at `/.well-known/oauth-protected-resource[/mcp]`; tokens in query strings are ignored | `internal/auth/` |
| SCIM 2.0 | `/scim/v2/Users` and `/Groups` (create, get, list with `eq` filters and paging, PUT, PATCH including Entra-style `"False"` strings and `members[value eq "..."]` removal, delete), `ServiceProviderConfig`, separate provisioning bearer token. A valid token for a subject that is not provisioned or is `active: false` is refused, so deprovisioning takes effect on the next request | `internal/scim/` |
| Policy as code | Cedar via [cedar-go](https://github.com/cedar-policy/cedar-go). Principal `User::"sub"` in `Group::"<scim group>"`; resource `Tool::"server/tool"` in `Server::"server"`; actions `list_tool` and `call_tool`; context carries the call arguments and token scopes, so policies constrain arguments (`context.args.path like "/srv/docs/*"`) | `policies/gateway.cedar`, `internal/policy/engine.go` |
| Signed bundles | DSSE-style envelope (signature over the pre-authentication encoding of type + payload, so no JSON canonicalization and no cross-type replay); manifest has version, issued_at, expires_at. Load checks: trusted key, signature, key not revoked, freshness, version/digest not revoked, **version never lower than the highest accepted** (persisted to disk, plus an operator floor), and same-version-different-digest is refused as equivocation. A rejected bundle leaves the current one in place | `internal/policy/bundle.go`, `store.go` |
| Revocation | Signed revocation list (versions, digests, key ids) with its own monotonic sequence and expiry. Key revocation is sticky: persisted, unioned across lists, and lists signed by a revoked key are refused, so a stolen key cannot un-revoke itself | `internal/policy/store.go` |
| Fail closed | Freshness and revocation are re-checked on every decision, not just at load: no bundle, an expired bundle, a stale revocation list (when required) or any Cedar evaluation error denies. `/readyz` reports 503 until a usable bundle is active | `store.go` (`Current`), `engine.go` |
| Policy projection | `tools/list` only advertises tools for which `list_tool` is permitted; a `tools/call` to a tool the caller cannot see gets the same "unknown tool" answer as a nonexistent one, so hidden tools cannot be probed | `gateway.go` (`listTools`, `callTool`) |
| Decision binding | Arguments are canonicalized once; the decision carries `sha256(args)` and a binding hash over (bundle digest, subject, action, server, tool, args hash); **the gateway forwards those exact canonical bytes**, so what the upstream executes is what was evaluated | `engine.go` (`Decide`, `Bind`) |
| Credential mediation | Per-upstream credentials from env or a mounted secret file, injected on the upstream request only. Client `Authorization`, cookies and forwarded-identity headers are stripped (no token passthrough). Secrets and bearer tokens are scrubbed from tool results, upstream error messages and logs (an `slog` handler) | `internal/creds/` |
| Audit | Append-only JSONL, every `allow` / `deny` / `list` / `error` with subject, client id, tool, args hash (never values), policy version, binding and matched policy ids; each record hashes the previous one; `mcpgw audit-verify` reports the first edited, deleted or reordered record; the gateway refuses to append to a broken chain | `internal/audit/` |
| Operator CLI | `mcpgw serve | keygen | sign-bundle | sign-revocations | audit-verify | dev-issuer | version` (`sign-bundle` refuses to emit a bundle that would not verify) | `cmd/mcpgw/` |
| Deploy | Distroless, non-root Dockerfile (built in CI). Cloud Run service YAML and a guide that lists what breaks on Cloud Run. **Not deployed** | `Dockerfile`, `deploy/cloudrun/`, `docs/cloud-run.md` |

## Architecture

```
                     identity provider (OIDC/OAuth AS)            policy author (offline key)
                      |  JWKS            | SCIM push                    | mcpgw sign-bundle / sign-revocations
                      v                  v                              v
 MCP client  ---->  +------------------------------------------------------------------+
 (agent/IDE)  Bearer | mcp-policy-gateway                                               |
 POST /mcp    token  |  1 Origin + protocol version check                                |
                     |  2 JWT: sig (JWKS), iss, aud == resource, exp, scopes  -> 401/403 |
                     |  3 SCIM directory: provisioned + active? groups        -> 403     |
                     |  4 strict JSON-RPC parse (no dups / batches / case folding)       |
                     |  5 tools/list: Cedar list_tool per tool  -> projected list        |
                     |    tools/call: visible? then Cedar call_tool(args, scopes)        |
                     |       policy store: signature, freshness, revocation, rollback    |
                     |  6 forward canonical args + gateway-held credential               |
                     |  7 scrub credentials from the result                              |
                     |  8 audit: hash-chained JSONL (args hashed)                        |
                     +--------------+------------------------------+--------------------+
                                    | Authorization: <upstream cred>| (client token never forwarded)
                                    v                               v
                             MCP server "files"              MCP server "web"
```

## Threat model and trust boundaries

**Trusted:** the gateway process and host; the policy signing key (kept offline); the trusted-keys file shipped with the deployment; the identity provider's JWKS endpoint (fetched over the configured URL; use HTTPS); the SCIM provisioning token holder.

**Untrusted:** every MCP client and its token (until validated); request bodies; upstream MCP servers and everything they return (tool lists, results, errors, headers); policy and revocation files on disk until their signatures verify; the gateway's own state files, which are treated as tamper-evident at best.

| Threat | Mitigation here | Not covered |
|---|---|---|
| Token for another service replayed here (confused deputy) | `aud` must equal this gateway's resource URL | Sender-constrained tokens (DPoP/mTLS) |
| Forged tokens | Asymmetric algs only, alg must match the JWK, key from JWKS | JWKS fetched over plain HTTP in the local demo |
| Client token leaking to upstreams | Stripped; upstreams only ever see the gateway's credential | Upstreams that need per-user delegation (token exchange is not implemented) |
| Upstream credential leaking to the client/model | Injected per call, scrubbed from results, errors and logs | Secrets an upstream re-encodes (base64, split across fields, JSON-escaped) |
| Former employee keeps access via a long-lived token | SCIM `active:false` or delete denies on the next request | Tokens are not introspected or revoked at the IdP |
| Old, more permissive policy replayed | Monotonic version floor persisted to disk + operator floor; equivocation check | Floor is per instance; a wiped disk without `min_version` resets it (see Cloud Run notes) |
| Leaked signing key | Key revocation (sticky), bundle expiry bounds exposure | No threshold signatures; one key can sign |
| Stale policy kept forever (e.g. attacker blocks updates) | Every decision re-checks expiry; optional mandatory fresh revocation list | Clock manipulation on the gateway host |
| Parser differential smuggling a different call past policy | Strict parser + forwarding the re-encoded, evaluated arguments | Differentials inside upstream-specific argument formats |
| Probing for hidden tools | Hidden and missing tools give identical errors | Timing differences |
| Audit tampering | Hash chain detects edits, deletions and reordering | Truncating the tail: export the chain head (`mcpgw audit-verify` prints it) to an external system |
| DNS rebinding against a local gateway | `Origin` allowlist | |

## Try it

```bash
go test -race ./...           # 138 tests incl. subtests; e2e runs gateway -> 2 fake MCP servers over real HTTP
./scripts/demo.sh             # dev issuer + 2 fake upstreams + gateway on loopback, SCIM provisioning, 4 calls, audit verify

# fuzz (CI runs each for 30s)
go test -run='^$' -fuzz=FuzzParseRequest -fuzztime=30s ./internal/jsonrpc
go test -run='^$' -fuzz=FuzzDecide       -fuzztime=30s ./internal/policy
go test -run='^$' -fuzz=FuzzLoadBundle   -fuzztime=30s ./internal/policy

# operator flow
go run ./cmd/mcpgw keygen -out keys -keyid policy-1
go run ./cmd/mcpgw sign-bundle -key keys/policy-1.key -keyid policy-1 -version 2 -ttl 24h -policies policies -out bundle.json
go run ./cmd/mcpgw sign-revocations -key keys/policy-1.key -keyid policy-1 -seq 1 -versions 1 -out revocations.json
go run ./cmd/mcpgw audit-verify -log audit.jsonl
```

Demo output (abridged): alice (group `engineering`) sees `files__read_file`, `web__search_web`, `web__send_email`; reading `/srv/docs/readme.md` succeeds; `/etc/passwd` returns `-32003 denied by policy` with a decision binding; `files__write_file` returns "unknown tool" because she cannot see it; `audit-verify` reports 4 records and the chain head.

## How the guarantees are tested

- **Auth** (`internal/auth`): 18 table-driven negative cases: wrong audience, audience = issuer, expired, not yet valid, wrong issuer, unknown kid, missing sub/exp, signed by another key, `alg: none`, HS256 signed with the JWKS as the secret, tampered claims, malformed and oversized tokens, missing scope, no scopes. Also: RS256 path, alg/key mismatch, kid rotation, and 20 forged kids causing exactly one JWKS fetch.
- **Bundles** (`internal/policy`): bad signature, untrusted key, tampered payload, a revocation list replayed as a bundle, wrong payload type, expired, issued in the future, version 0, no policies, Cedar syntax error, malformed envelope; none of them become active. Rollback to an older version, equivocation, rollback after restart, operator floor, corrupt state file failing closed. Revocation by version, digest and key; revocation of the active bundle while loaded; revocation-list rollback; sticky key revocation across restarts; stale revocation list.
- **Decisions**: 15 table cases over the example policy (projection by group, argument prefixes, `..` traversal, missing and wrongly typed arguments → evaluation error → deny, scope-gated tool, internal-only email, `forbid` overriding an admin `permit`); binding changes with subject and arguments and is reproducible; expiry while loaded fails closed; over-deep arguments are refused.
- **Fuzz**: `FuzzParseRequest` (accepted messages round-trip with the same method and id; its first finding, the case-folding bug, is kept as a regression seed); `FuzzDecide` (deterministic, and `read_file`/`write_file` are never allowed outside their path prefixes or with `..`); `FuzzLoadBundle` (arbitrary bytes never activate unless they verify).
- **End to end** (`internal/gateway/e2e_test.go`, 20 subtests): 401 + metadata discovery, foreign `Origin` refused, foreign-audience token, insufficient scope, unprovisioned subject, initialize/notification, per-principal projection for three users, argument constraints, scope gating, hidden = missing, forbid over admin, credential echo scrubbed and the client token never seen upstream or in logs, forwarded bytes equal the canonical evaluated arguments, duplicate-key smuggling rejected, unmediated methods, upstream session loss recovery, SCIM deactivation, runtime rollback rejected while the previous bundle keeps serving, expiry → empty projection + denied calls + 503 readiness, audit verifies and holds no argument values or secrets. The credential test was checked by removing the scrub step and watching it fail.
- **Audit**: edit, delete, swap and garbage-line tampering each reported at the right line; reopen continues the chain; a broken chain refuses appends.

## Design decisions

- **Cedar, not OPA.** Tool authorization is a principal/action/resource question with group membership, which is Cedar's native model; policies are analyzable and `forbid` always wins. cedar-go is the only non-stdlib dependency.
- **Two actions, `list_tool` and `call_tool`.** Projection needs a question that does not depend on arguments. Requiring both for a call keeps the advertised list and what is callable from drifting apart.
- **Evaluation errors deny.** Cedar skips a policy whose condition errors; for a `forbid` that would fail open. The cost is that policies must guard optional arguments with `has`, which the example policy does.
- **DSSE-style envelopes over raw payload bytes.** Signing re-serialized JSON invites canonicalization bugs; signing the exact bytes plus the payload type does not.
- **Rollback floor persisted before activation.** If writing the floor fails, the new bundle is not served.
- **Forward what was evaluated.** Rather than trying to prove two parsers agree, the gateway parses once, decides on the parsed value, and sends its own encoding of that value.
- **Gateway answers `initialize` itself.** It advertises only `tools`, since that is all it mediates.

## Limits, stated plainly

- **Not deployed, no users.** The Cloud Run config and guide are untested; `docs/cloud-run.md` lists what would break (in-memory SCIM directory, instance-local rollback state and audit file).
- **No prompt-injection or tool-poisoning detection.** This gateway enforces identity and policy; it does not inspect tool descriptions or results for injected instructions, and there is no detection eval.
- **No SAML, no OIDC login, no token exchange.** The gateway is an OAuth resource server only. `dev-issuer` is a local key + JWKS + mint endpoint for tests and the demo, not an authorization server (no `/authorize`, PKCE or client registration). It has not been run against a real IdP (Keycloak, Okta, Entra). Upstream calls use a static per-upstream credential, not an on-behalf-of token.
- **SCIM is a subset.** No bulk, sort, ETags, `/Schemas` or `/ResourceTypes`, only `eq` filters, and state is in memory. It has not been tested against a real IdP's SCIM client.
- **No OpenTelemetry.** Logs are structured JSON via `slog`; there is no tracing.
- **Credential scrubbing is string matching.** It catches the secret verbatim and bearer-token patterns, not encoded or fragmented copies.
- **Single instance.** Policy state, the SCIM directory and the audit log are local to the process.
- **The fake upstreams are fakes.** No real MCP server (filesystem, GitHub, etc.) has been put behind the gateway.
