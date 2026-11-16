#!/usr/bin/env bash
# Synthetic internal-network packaging check; requires Docker.
set -euo pipefail
name="sovereign-smoke-$$"
config="$(mktemp "$HOME/.sovereign-smoke-config.XXXXXX")"
cleanup() {
  docker rm -f "$name-console" "$name-core" >/dev/null 2>&1 || true
  docker network rm "$name" >/dev/null 2>&1 || true
  rm -f "$config"
}
trap cleanup EXIT
printf '{"schema":1,"oidc_issuer":null}\n' > "$config"
chmod 644 "$config"
docker network create --internal "$name" >/dev/null
docker run -d --name "$name-core" --network "$name" --network-alias core \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges --cap-drop ALL sovereign-core:synthetic >/dev/null
docker run -d --name "$name-console" --network "$name" --network-alias console \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$config:/srv/console-config.json:ro" \
  sovereign-console:synthetic >/dev/null
docker exec "$name-console" nginx -t >/dev/null
for attempt in $(seq 1 30); do
  if docker exec "$name-core" python -c 'import urllib.request; urllib.request.urlopen("http://console:8080/", timeout=2).close()' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name-core" python -c 'import urllib.request; assert "root" in urllib.request.urlopen("http://console:8080/").read().decode()'
docker exec "$name-core" python -c 'import json, urllib.request; r = urllib.request.urlopen("http://console:8080/console-config.json"); assert json.load(r) == {"schema": 1, "oidc_issuer": None}; assert r.headers["Cache-Control"] == "no-store"'
for attempt in $(seq 1 30); do
  if docker exec "$name-core" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health").status == 200' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name-core" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health").status == 200'
docker exec "$name-core" python -c 'import urllib.error, urllib.request
try:
    urllib.request.urlopen("http://console:8080/api/models")
except urllib.error.HTTPError as exc:
    assert exc.code == 401
else:
    raise AssertionError("unauthorised API passed")'
echo 'Synthetic containers: Console, runtime config, Core health and denied API passed'
