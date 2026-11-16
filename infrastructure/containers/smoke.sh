#!/usr/bin/env bash
# Synthetic loopback packaging check; requires Docker and curl.
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
docker run -d --name "$name-console" --network "$name" \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --security-opt no-new-privileges --cap-drop ALL \
  -v "$config:/srv/console-config.json:ro" \
  sovereign-console:synthetic >/dev/null
for attempt in $(seq 1 30); do
  if docker exec "$name-console" curl -fsS http://127.0.0.1:8080/ -o /dev/null 2>/dev/null; then break; fi
  sleep 1
done
docker exec "$name-console" curl -fsS http://127.0.0.1:8080/ | grep -q 'root'
docker exec "$name-console" curl -fsS http://127.0.0.1:8080/console-config.json | grep -q '"oidc_issuer":null'
for attempt in $(seq 1 30); do
  if docker exec "$name-core" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health").status == 200' >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$name-core" python -c 'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:18100/health").status == 200'
code="$(docker exec "$name-console" curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/models)"
test "$code" = 401
echo 'Synthetic containers: Console, runtime config, Core health and denied API passed'
