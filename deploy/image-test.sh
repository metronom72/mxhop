#!/usr/bin/env bash
set -euo pipefail

IMAGE="${IMAGE:-mxhop:test}"
NAME="mxhop-image-test-$$"
WORK="$(mktemp -d)"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/config" "$WORK/spool"
chmod 777 "$WORK/spool"

cat > "$WORK/config/mxhop.toml" <<'TOML'
hostname = "mx.image.test"
listen = "0.0.0.0:2525"
spool_dir = "/var/lib/mxhop/spool"

[observe]
listen = "0.0.0.0:9090"

[auth]
enabled = false

[domains."image.test".aliases]
hi = "someone@nowhere.invalid"
TOML

fail() { echo "FAIL: $*" >&2; docker logs "$NAME" >&2 || true; exit 1; }
ok() { echo "ok: $*"; }

echo "--- the image has no shell and no package manager"
docker run --rm --entrypoint /bin/sh "$IMAGE" -c true 2>/dev/null \
    && fail "a scratch image must not have a shell"
ok "nothing to exec but mxhop"

echo "--- it answers --version without a config"
docker run --rm "$IMAGE" --version >/dev/null || fail "--version"
ok "--version"

echo "--- a bad config fails instead of serving"
mkdir -p "$WORK/bad"
echo 'hostname = "only this"' > "$WORK/bad/mxhop.toml"
if docker run --rm -v "$WORK/bad:/etc/mxhop:ro" "$IMAGE" run >/dev/null 2>&1; then
    fail "a config missing listen and spool_dir must not start a mail server"
fi
ok "a bad config exits non-zero"

echo "--- starting the container"
docker run -d --name "$NAME" \
    -v "$WORK/config:/etc/mxhop:ro" \
    -v "$WORK/spool:/var/lib/mxhop/spool" \
    -p 12525:2525 -p 19090:9090 \
    "$IMAGE" >/dev/null

for _ in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:19090/healthz >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "--- it runs as the unprivileged user it says it does"
uid="$(docker inspect -f '{{.Config.User}}' "$NAME")"
[ "$uid" = "10001:10001" ] || fail "running as $uid"
ok "uid 10001"

echo "--- /healthz"
body="$(curl -fsS http://127.0.0.1:19090/healthz)" || fail "/healthz did not answer 200"
grep -q "^ok$" <<<"$body" || fail "/healthz body: $body"
grep -q "listener: ok" <<<"$body" || fail "/healthz body: $body"
ok "/healthz is 200 and the listener is up"

echo "--- /metrics"
metrics="$(curl -fsS http://127.0.0.1:19090/metrics)" || fail "/metrics did not answer 200"
grep -q "mxhop_sessions_total" <<<"$metrics" || fail "no counters"
grep -q "@" <<<"$metrics" && fail "an address leaked into /metrics"
ok "/metrics is the prometheus format with no addresses in it"

echo "--- the healthcheck subcommand the image uses"
docker exec "$NAME" /mxhop health >/dev/null || fail "mxhop health"
ok "mxhop health exits zero"

echo "--- an SMTP conversation"
reply="$(printf 'EHLO probe.test\r\nMAIL FROM:<sender@probe.test>\r\nRCPT TO:<nobody@elsewhere.test>\r\nRCPT TO:<hi@image.test>\r\nDATA\r\nSubject: hello\r\n\r\nbody\r\n.\r\nQUIT\r\n' \
    | timeout 60 python3 -c '
import socket, sys
data = sys.stdin.buffer.read()
s = socket.create_connection(("127.0.0.1", 12525), timeout=50)
s.sendall(data)
out = b""
while True:
    chunk = s.recv(65536)
    if not chunk:
        break
    out += chunk
sys.stdout.buffer.write(out)
')"

grep -q "^220 .*mxhop ready" <<<"$reply" || fail "no banner: $reply"
grep -q "^250-mx.image.test" <<<"$reply" || fail "no EHLO: $reply"
grep -q "550 5.7.1" <<<"$reply" || fail "a domain we do not serve must be refused: $reply"
grep -q "250 2.1.5 recipient accepted" <<<"$reply" || fail "the configured alias: $reply"
grep -q "^354 " <<<"$reply" || fail "no DATA: $reply"
grep -qE "^(250|451|550)" <<<"$reply" || fail "no final reply: $reply"
grep -q "^221 " <<<"$reply" || fail "no QUIT: $reply"
ok "banner, EHLO, relay refusal, alias accepted, DATA, final reply, QUIT"

echo "--- metrics moved"
after="$(curl -fsS http://127.0.0.1:19090/metrics)"
sessions="$(grep '^mxhop_sessions_total ' <<<"$after" | awk '{print $2}')"
[ "${sessions:-0}" -ge 1 ] || fail "mxhop_sessions_total is $sessions after a session"
ok "mxhop_sessions_total is $sessions"

echo "--- it stops gracefully inside the grace period"
start=$(date +%s)
docker stop -t 30 "$NAME" >/dev/null
took=$(( $(date +%s) - start ))
[ "$took" -lt 30 ] || fail "took ${took}s to stop, so it was killed rather than asked"
code="$(docker inspect -f '{{.State.ExitCode}}' "$NAME")"
[ "$code" = "0" ] || fail "exit code $code"
ok "stopped in ${took}s with exit code 0"

echo
echo "the image works"
