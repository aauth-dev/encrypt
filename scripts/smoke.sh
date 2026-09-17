#!/usr/bin/env bash
# Live smoke for encrypt.aauth.dev: unauthenticated surface, the agent document, and the 401 shape.
# The signed flow (chain to the messaging service, encrypt, deliver) runs in vitest against the
# fake PS and a fake messaging service; live it needs a person at Hellō and is driven from an
# agent with the AAuth MCP.
#   bash scripts/smoke.sh [base_url]
set -uo pipefail
BASE="${1:-https://encrypt.aauth.dev}"
PASS=0; FAIL=0
check() { if [ "$2" = "true" ]; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; FAIL=$((FAIL+1)); fi; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
echo "Testing $BASE"
META=$(curl -sf "$BASE/.well-known/aauth-resource.json")
check "well-known issuer matches origin" "$(echo "$META" | jq -r .issuer | grep -qx "$BASE" && echo true || echo false)"
check "access_mode is person-token" "$(echo "$META" | jq -e '.access_mode == "person-token"' >/dev/null 2>&1 && echo true || echo false)"
AGENT=$(curl -sf "$BASE/.well-known/aauth-agent.json")
check "aauth-agent.json issuer matches origin and names the jwks" "$(echo "$AGENT" | jq -e --arg b "$BASE" '.issuer == $b and .jwks_uri == ($b + "/.well-known/jwks.json") and (.name | length > 0)' >/dev/null 2>&1 && echo true || echo false)"
JWKS=$(curl -sf "$BASE/.well-known/jwks.json")
check "jwks key is Ed25519 with a kid, no private material" "$(echo "$JWKS" | jq -e '.keys[0].crv == "Ed25519" and .keys[0].alg == "Ed25519" and .keys[0].d == null and (.keys[0].kid | length > 0)' >/dev/null 2>&1 && echo true || echo false)"
SPEC=$(curl -sf "$BASE/openapi.json")
check "openapi lists sendMessage: from, to, text required; resource optional (D27 6a)" "$(echo "$SPEC" | jq -e '.paths["/send"].post.operationId == "sendMessage" and (.paths["/send"].post.requestBody.content["application/json"].schema.required == ["from","to","text"])' >/dev/null 2>&1 && echo true || echo false)"
check "openapi.json has Cache-Control max-age=300 and an ETag (12c)" "$(curl -s -D - -o /dev/null "$BASE/openapi.json" | tr -d '\r' | tr 'A-Z' 'a-z' | awk '/^cache-control: public, max-age=300$/{c=1} /^etag: "/{e=1} END{print (c&&e)?"true":"false"}')"
for p in / /privacy /robots.txt /llms.txt /sitemap.xml /health; do check "GET $p is 200" "$([ "$(code "$BASE$p")" = "200" ] && echo true || echo false)"; done
H=$(curl -s -D - -o /dev/null -X POST -H 'content-type: application/json' -d '{}' "$BASE/send")
check "unsigned POST /send is 401 requirement=person-token" "$(echo "$H" | grep -q '^HTTP/[0-9.]* 401' && echo "$H" | grep -qi 'aauth-requirement: requirement=person-token' && echo true || echo false)"
echo; echo "$PASS passed, $FAIL failed"; [ "$FAIL" = 0 ]
