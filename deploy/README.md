# Deploying mxhop on a single-node Swarm

`mxhop.stack.yml` is an example, not a turnkey stack: edit the paths, the
hostname and the image tag before deploying it. Caddy (or whatever already
terminates TLS on the node) is untouched by it — mxhop binds port 25, which
nothing else on a web node wants.

## Before the first deploy: make the image pullable

A package published for the first time under a personal GitHub account is
**private**, and it does not inherit the repository's visibility. The node
has no GHCR credentials, so the task fails with `denied` and `stack deploy`
cannot even resolve the digest. Nothing in `.github/workflows/release.yml`
can change this — it is a setting on the package. After the first `v0.1.0`
tag has run, do one of:

- **Make the package public** (one-time, then never again): the package page
  → *Package settings* → *Danger Zone* → *Change visibility* → Public.
  `https://github.com/users/metronom72/packages/container/mxhop/settings`
- **Or keep it private and log the node in:** `docker login ghcr.io` with a
  personal access token that has `read:packages`, then deploy with
  `docker stack deploy --with-registry-auth -c …`. Without
  `--with-registry-auth` the credentials stay on your laptop and the manager
  never passes them to the task.

## On the host, first

```sh
# The spool must exist and be writable by the image's user (uid 10001).
install -d -o 10001 -g 10001 -m 0750 /srv/mxhop/spool

# The config. Start from mxhop.example.toml at the repository root.
# It must say:  listen = "0.0.0.0:2525"
install -m 0644 mxhop.example.toml /srv/mxhop/mxhop.toml
$EDITOR /srv/mxhop/mxhop.toml

# The SRS secret. Nothing reads it yet — SRS is not implemented — but
# creating it now keeps the stack file deployable as written.
openssl rand -base64 32 | docker secret create mxhop_srs_secret -
```

### The TLS pair: copy it, do not mount Caddy's store

Do **not** bind-mount Caddy's certificate directory. certmagic writes its
certificate directories `0700` and the keys `0600`, owned by the user Caddy
runs as; the task runs as uid 10001 and `mxhop check` refuses to start with
`… cannot be read: Permission denied`. The path is also not
`/var/lib/caddy/…` when Caddy runs in Docker — it is inside its volume, e.g.
`/var/lib/docker/volumes/<stack>_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/mx.example.com/`
— and Caddy only holds a certificate for `mx.example.com` at all if a
Caddyfile site block names that host.

Copy the pair into the config directory instead, owned by the task's uid:

```sh
CADDY=/var/lib/docker/volumes/web_caddy_data/_data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/mx.example.com
install -d -o 10001 -g 10001 -m 0750 /srv/mxhop/tls
install -o 10001 -g 10001 -m 0640 "$CADDY/mx.example.com.crt" /srv/mxhop/tls/
install -o 10001 -g 10001 -m 0600 "$CADDY/mx.example.com.key" /srv/mxhop/tls/
```

Put those install lines plus `docker kill -s HUP …` (see below) in the renewal
hook, or in a cron job that runs daily — a copy that is never refreshed
expires silently 60 days after the first deploy.

Then prove the files read **exactly as the task will read them** — same uid,
same mount, before anything binds port 25:

```sh
docker run --rm \
  -v /srv/mxhop:/etc/mxhop:ro \
  -v /srv/mxhop/spool:/var/lib/mxhop/spool \
  ghcr.io/metronom72/mxhop:0.1.0 check
```

If that exits 0 the first deploy will not restart-loop on the certificate.

## Deploy

```sh
docker stack config -c deploy/mxhop.stack.yml          # render and validate
docker stack deploy -c deploy/mxhop.stack.yml mxhop    # add --with-registry-auth if the package is private
docker service logs -f mxhop_mxhop
```

Then prove it from the node itself — a real delivery says more than the
healthcheck, which only checks that the listener still answers with a banner:

```sh
docker exec "$(docker ps -q -f name=mxhop_mxhop)" \
  mxhop send-test you@gmail.com "hello from the new box"
```

It prints the destination's reply word for word and exits non-zero if the
mail was refused or deferred, which is how a blocked outbound port 25 and a
missing PTR show themselves. **Accepted is not delivered:** Gmail returns
`250` and then files the message in Spam, which has already happened on this
project — open the message and read its headers.

## Why the three unusual choices

- **`mode: host` on the port.** Swarm's default ingress mesh rewrites the
  source address, so every sender would appear to come from an overlay
  address: wrong `Received` headers, useless logs, and SPF evaluated against
  the wrong host once SPF lands.
- **`order: stop-first`, `init: true`, `stop_grace_period: 30s`.** A
  host-mode port 25 cannot be held by two tasks at once, so the new task has
  to wait for the old one to let go.

  mxhop has no SIGTERM handler of its own — it registers SIGHUP only and the
  accept loop never returns, so there is no graceful shutdown yet (it is the
  0.2 row of the root README's status table). It still exits promptly:
  measured on this image, mxhop as pid 1 dies with 143 on the first SIGTERM,
  because tokio's signal driver installs a handler for it as a side effect of
  mxhop asking for SIGHUP, and a *caught* signal is delivered to pid 1. That
  is a runtime implementation detail and not a promise, so `init: true` makes
  it the stack's own: tini is pid 1, SIGTERM reaches mxhop as an ordinary
  process, and a deploy cannot start silently waiting out the grace period
  because something changed inside tokio. tini forwards SIGHUP as well, so
  the certificate reload below is unaffected.

  The abrupt exit costs nothing in the spool: it writes the body and the
  envelope into `tmp/`, fsyncs them and only then renames them into
  `queue/`, and delivery ignores an `.eml` whose `.json` rename never
  happened — so the worst case is a stray file, never half a message that
  gets delivered, and the sender that never saw its `250` retries. The grace
  period is 30s rather than 60s because nothing currently uses it; SMTP's own
  timeouts are 5 minutes per command and 10 inside `DATA`, which 60s never
  covered anyway. It starts to mean something once graceful shutdown lands.
- **The spool as a bind mount.** `docker system prune --volumes` removes
  named volumes. The spool holds mail that was accepted and not yet
  delivered, so that prune would delete mail the sender was already told had
  been taken.

## After a certificate renewal

Refresh the copy in `/srv/mxhop/tls` (above), then make mxhop reread it —
no restart needed:

```sh
docker kill --signal=HUP "$(docker ps -q -f name=mxhop_mxhop)"
```

A reload that cannot read the files logs a warning and keeps serving the
certificate already loaded. That is also why the healthcheck does not run
`mxhop check`: a probe that re-read the files would kill a task that is
still serving perfectly valid TLS.

## After a config change

A bind-mounted directory shows the edit immediately, but nothing rereads
`mxhop.toml` while the process runs — SIGHUP reloads the certificate only.
Restart the task:

```sh
docker service update --force mxhop_mxhop
```

## What is not here

No systemd unit, and no `docker-compose.yml` for a non-Swarm host. Both are
straightforward from the stack file; neither has been tried, so neither is
shipped as if it had.
