#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  echo 'Usage: ui/smoke.sh IMAGE' >&2
  exit 64
fi
image=$1
network="esignet-ui-smoke-${RANDOM}-$$"
backend=
frontend=
cleanup() {
  if [[ -n "$frontend" ]]; then docker rm -f "$frontend" >/dev/null 2>&1 || true; fi
  if [[ -n "$backend" ]]; then docker rm -f "$backend" >/dev/null 2>&1 || true; fi
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$network" >/dev/null
backend=$(docker run -d --rm --network "$network" --network-alias esignet \
  --entrypoint node \
  docker.io/library/node@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 \
  -e 'require("http").createServer((_request, response) => { response.writeHead(418); response.end("upstream"); }).listen(8080, "0.0.0.0")')
frontend=$(docker run -d --rm --network "$network" -p 127.0.0.1::3000 "$image")
port=$(docker port "$frontend" 3000/tcp | sed -n 's/.*://p')
[[ "$port" =~ ^[0-9]+$ ]] || { echo 'UI did not receive a loopback port' >&2; exit 1; }
origin="http://127.0.0.1:$port"
status() { curl -sS --max-time 3 -o /dev/null -w '%{http_code}' "$origin$1"; }

ready=false
for _attempt in {1..30}; do
  if [[ "$(status / 2>/dev/null || true)" == 200 ]]; then ready=true; break; fi
  sleep 0.2
done
[[ "$ready" == true ]] || { echo 'UI did not serve its static page' >&2; exit 1; }
[[ "$(status '/.well-known/openid-configuration')" == 418 ]] || { echo 'Public OIDC route did not proxy' >&2; exit 1; }
for path in /client-mgmt/client /system-info /v1/esignet/client-mgmt /admin; do
  [[ "$(status "$path")" == 404 ]] || { echo 'Private route was exposed' >&2; exit 1; }
done
headers=$(curl -sSI --max-time 3 "$origin/")
[[ "$headers" == *'Referrer-Policy: no-referrer'* && "$headers" == *'Content-Security-Policy:'* ]] || {
  echo 'Static response omitted privacy headers' >&2; exit 1;
}
canary="ui-query-canary-${RANDOM}"
[[ "$(status "/oauth2/authorize?probe=$canary")" == 418 ]] || { echo 'Authorization route did not proxy' >&2; exit 1; }
if docker logs "$frontend" 2>&1 | grep -q "$canary"; then
  echo 'UI access log disclosed the query string' >&2
  exit 1
fi
echo 'UI static serving, public proxy, private-route refusal, and log privacy passed'
