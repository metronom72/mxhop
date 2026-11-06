# Deploying mxhop on a single-node Swarm

`mxhop.stack.yml` is an example, not a turnkey stack: edit the paths, the
hostname and the image tag before deploying it. Caddy (or whatever already
terminates TLS on the node) is untouched by it — mxhop binds port 25, which
nothing else on a web node wants.

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

## Deploy

```sh
docker stack config -c deploy/mxhop.stack.yml          # render and validate
docker stack deploy -c deploy/mxhop.stack.yml mxhop
docker service logs -f mxhop_mxhop
```

Then prove it from the node itself — a real delivery says more than the
healthcheck, which only rereads the config:

```sh
docker exec "$(docker ps -q -f name=mxhop_mxhop)" \
  mxhop send-test you@gmail.com "hello from the new box"
```

It prints the destination's reply word for word and exits non-zero if the
mail was refused or deferred, which is how outbound port 25 being blocked
and a mismatched PTR show themselves.

## Why the three unusual choices

- **`mode: host` on the port.** Swarm's default ingress mesh rewrites the
  source address, so every sender would appear to come from an overlay
  address: wrong `Received` headers, useless logs, and SPF evaluated against
  the wrong host once SPF lands.
- **`order: stop-first` and `stop_grace_period: 60s`.** A host-mode port 25
  cannot be held by two tasks at once, so the new task has to wait for the
  old one to let go; and a session in the middle of `DATA` should be allowed
  to finish rather than be cut off into a retry.
- **The spool as a bind mount.** `docker system prune --volumes` removes
  named volumes. The spool holds mail that was accepted and not yet
  delivered, so that prune would delete mail the sender was already told had
  been taken.

## After a certificate renewal

mxhop rereads the certificate on `SIGHUP`, and does not need a restart:

```sh
docker kill --signal=HUP "$(docker ps -q -f name=mxhop_mxhop)"
```

A reload that cannot read the files logs a warning and keeps serving the
certificate already loaded.

## What is not here

No systemd unit, and no `docker-compose.yml` for a non-Swarm host. Both are
straightforward from the stack file; neither has been tried, so neither is
shipped as if it had.
