#!/usr/bin/env bash
# Local demo: dev issuer + two fake upstreams + the gateway, then a few calls.
# Everything binds to 127.0.0.1 and lives in a temp directory.
set -euo pipefail
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$work"' EXIT
go build -o "$work/mcpgw" ./cmd/mcpgw
go build -o "$work/fakemcp" ./cmd/fakemcp

export FILES_TOKEN="files-$(openssl rand -hex 8)" WEB_TOKEN="web-$(openssl rand -hex 8)" SCIM_TOKEN="scim-$(openssl rand -hex 8)"
"$work/mcpgw" keygen -out "$work/keys" -keyid policy-1 >/dev/null
"$work/mcpgw" sign-bundle -key "$work/keys/policy-1.key" -keyid policy-1 -version 1 -policies policies -out "$work/bundle.json"

sed -e "s#__WORK__#$work#g" examples/gateway.json > "$work/gateway.json"
UPSTREAM_TOKEN=$FILES_TOKEN "$work/fakemcp" -tools files -addr 127.0.0.1:9100 2>/dev/null &
UPSTREAM_TOKEN=$WEB_TOKEN "$work/fakemcp" -tools web -addr 127.0.0.1:9101 2>/dev/null &
"$work/mcpgw" dev-issuer 2>/dev/null &
"$work/mcpgw" serve -config "$work/gateway.json" 2>"$work/gateway.log" &
up() { [ "$(curl -s -o /dev/null -w '%{http_code}' "$1")" != 000 ]; }
for _ in $(seq 1 100); do
  up 127.0.0.1:9100/mcp && up 127.0.0.1:9101/mcp && up 127.0.0.1:9000/.well-known/jwks.json && curl -sf localhost:8080/readyz >/dev/null && break
  sleep 0.1
done

scim() { curl -sf -X "$1" "localhost:8080/scim/v2$2" -H "Authorization: Bearer $SCIM_TOKEN" -H 'content-type: application/scim+json' -d "${3:-}"; }
alice=$(scim POST /Users '{"userName":"alice"}' | sed -E 's/.*"id":"([^"]+)".*/\1/')
scim POST /Groups "{\"displayName\":\"engineering\",\"members\":[{\"value\":\"$alice\"}]}" >/dev/null

TOKEN=$(curl -sf "127.0.0.1:9000/mint?sub=alice&aud=http://localhost:8080/mcp&scope=mcp:tools")
mcp() { curl -s localhost:8080/mcp -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' -d "$1"; echo; }

echo "== tools/list (projected for alice)";  mcp '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
echo "== allowed: read /srv/docs/readme.md"; mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"files__read_file","arguments":{"path":"/srv/docs/readme.md"}}}'
echo "== denied: read /etc/passwd";          mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files__read_file","arguments":{"path":"/etc/passwd"}}}'
echo "== hidden tool: write_file";           mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"files__write_file","arguments":{"path":"/srv/workspace/a"}}}'
echo "== audit";                             "$work/mcpgw" audit-verify -log "$work/audit.jsonl"
