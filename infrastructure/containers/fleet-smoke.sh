#!/usr/bin/env bash
# Company-side synthetic Fleet packaging check; requires prebuilt Fleet images.
set -euo pipefail
name="sovereign-fleet-smoke-$$"
state="$name-state"
config="$(mktemp "$HOME/.sovereign-fleet-config.XXXXXX")"
cleanup() {
  if [[ "$?" -ne 0 ]]; then docker logs "$name-api" >&2 || true; fi
  docker rm -f "$name-portal" "$name-api" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
  docker volume rm "$state" >/dev/null 2>&1 || true
  rm -f "$config"
}
trap cleanup EXIT
printf '{"schema":1,"oidc_issuer":null}\n' > "$config"
chmod 644 "$config"
docker volume create "$state" >/dev/null
docker run --rm --user 0 --network none -v "$state:/state" \
  --entrypoint sh sovereign-fleet-api:synthetic -c \
  'printf "%s\n" "synthetic-fleet-admin-token-0123456789" > /state/token; chmod 600 /state/token; chown 10001:10001 /state /state/token; chmod 700 /state'
docker network create --internal "$name" >/dev/null
docker run -d --name "$name-api" --network "$name" --network-alias fleet-api \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$state:/state" \
  -e SOVEREIGN_FLEET_DB=/state/fleet.db \
  -e SOVEREIGN_FLEET_TOKEN_FILE=/state/token \
  sovereign-fleet-api:synthetic >/dev/null
docker run -d --name "$name-portal" --network "$name" --network-alias fleet-portal \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$config:/srv/fleet-config.json:ro" \
  sovereign-fleet-portal:synthetic >/dev/null
docker exec "$name-portal" nginx -t >/dev/null
for attempt in $(seq 1 30); do
  if docker exec "$name-api" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18800/health", timeout=2).status == 200' >/dev/null 2>&1; then break; fi
  sleep 1
done
for attempt in $(seq 1 30); do
  if docker exec "$name-api" python -c 'import urllib.request; assert urllib.request.urlopen("http://fleet-portal:8080/", timeout=2).status == 200' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name-api" python -c 'import json, urllib.error, urllib.request
base="http://fleet-portal:8080"
assert "root" in urllib.request.urlopen(base+"/").read().decode()
config=urllib.request.urlopen(base+"/fleet-config.json")
assert json.load(config)=={"schema":1,"oidc_issuer":None}
assert config.headers["Cache-Control"]=="no-store"
try:
    urllib.request.urlopen(base+"/api/fleet/me")
except urllib.error.HTTPError as exc:
    assert exc.code==401
else:
    raise AssertionError("unauthorised Fleet API passed")
request=urllib.request.Request(base+"/api/fleet/me", headers={"X-Fleet-Lab-Token":open("/state/token").read().strip()})
assert json.load(urllib.request.urlopen(request))["role"]=="fleet_admin"
try:
    urllib.request.urlopen(base+"/api/models")
except urllib.error.HTTPError as exc:
    assert exc.code==404
else:
    raise AssertionError("vessel API reached company portal")
import importlib.util
assert importlib.util.find_spec("apps.console") is None'
echo 'Synthetic Fleet containers: portal, config, role, denied API and service separation passed'
