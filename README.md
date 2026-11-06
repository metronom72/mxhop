# mxhop

mxhop receives SMTP mail for your domains and forwards it to mailboxes you
already have — Gmail, Fastmail, anything with an address. It is one static
binary or one container image; configuration is a TOML file plus a few
environment variables, and administration is `SIGHUP`, logs and Prometheus
metrics. It rewrites the envelope sender (SRS) so forwarded mail still passes
SPF at the destination, evaluates SPF/DKIM/DMARC on what it accepts, and keeps
a small on-disk queue for destinations that defer.

It does **not** store mail, serve IMAP, send mail as your alias, or have a web
interface. If you need those, you need a mail server — [Stalwart][stalwart] is
a good one.

[stalwart]: https://stalw.art

## Status

**Not usable yet.** This repository is being built in the open, task by task;
the list below is the order of work, and nothing above the current line has
been proved end to end. Do not point an MX record at it.

| | |
|---|---|
| Config file, validation, `mxhop check` | done |
| Inbound SMTP session, spool to disk | done |
| STARTTLS and certificate reload | done |
| Outbound SMTP client | done |
| Synchronous relay, hop limit — **0.1** | planned |
| SRS and bounce decoding | planned |
| SPF/DKIM/DMARC and `Authentication-Results` | planned |
| Queue, retries, per-host backoff | planned |
| DSNs for queued failures | planned |
| Metrics, health, graceful shutdown — **0.2** | planned |
| ARC sealing | planned |
| Image and example Swarm stack | in progress |
| systemd unit, compose | planned |
| Docs and release — **1.0** | planned |

What works today: it accepts mail. It does not yet forward it, so a message
ends up in the spool directory and stays there. The queue is two files per
message — `queue/<id>.eml` is exactly what arrived, `queue/<id>.json` is its
envelope — so you can read what it took in with `cat`.

```sh
mxhop check --config mxhop.example.toml   # before anything else
mxhop run   --config mxhop.example.toml
```

## Running it

`run` still does not forward: the outbound client exists and can deliver a
message (see `send-test` below), but it is not yet wired into the inbound
session, so a message that arrives is written to the spool and stays there.
What follows is how to deploy that much.

### As a binary

```sh
cargo build --release --target x86_64-unknown-linux-musl   # one static binary
install -m 0755 target/x86_64-unknown-linux-musl/release/mxhop /usr/local/bin/

install -d -o mxhop -g mxhop -m 0750 /var/lib/mxhop/spool
install -D -m 0644 mxhop.example.toml /etc/mxhop/mxhop.toml
$EDITOR /etc/mxhop/mxhop.toml

mxhop check            # reads /etc/mxhop/mxhop.toml; exits non-zero if wrong
mxhop run
```

Port 25 is privileged, so `run` as an unprivileged user needs
`CAP_NET_BIND_SERVICE` (`AmbientCapabilities=CAP_NET_BIND_SERVICE` in a
systemd unit) or a socket handed to it. There is no systemd unit in this
repository yet. After a certificate renewal, `kill -HUP` makes mxhop reread
the certificate files; `systemctl reload` only works if the unit has
`ExecReload=/bin/kill -HUP $MAINPID`.

### As a container

```sh
docker build -t mxhop .
docker run --rm mxhop --version
```

The image listens on **2525**, not 25: the privileged port is published on
the host side, so the process needs no capability and the deployment can
drop all of them. Your config file must therefore say
`listen = "0.0.0.0:2525"`. The entrypoint runs `mxhop check` before
`mxhop run`, so a bad config fails the deploy instead of starting a mail
server that refuses every recipient.

The spool must be a mount point — a bind mount from a host path, not a named
volume and never a layer in the image. It holds mail that has been accepted
and not yet delivered.

```sh
docker run -d --name mxhop \
  -p 25:2525 \
  -v /srv/mxhop/mxhop.toml:/etc/mxhop/mxhop.toml:ro \
  -v /srv/mxhop/spool:/var/lib/mxhop/spool \
  --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/metronom72/mxhop:0.1.0
```

Images are published to `ghcr.io/metronom72/mxhop` on a version tag, with
the static binary attached to the GitHub release.

For a single-node Docker Swarm there is an example stack and the reasoning
behind its three unusual settings in [deploy/](deploy/README.md).

### Proving the deployment works

`mxhop check` only says the config and the certificate can be read. The thing
to run first on the server itself is a real delivery, which prints the
destination's reply verbatim:

```sh
mxhop send-test you@gmail.com "hello from the new box"
# in the container:
docker exec mxhop mxhop send-test you@gmail.com "hello from the new box"
```

It resolves the recipient's MX, connects out on port 25, delivers, and exits
non-zero if the destination refused or deferred — so the reply tells you
directly whether outbound port 25 is open, whether the HELO name and the
reverse DNS of the sending address satisfy the destination, and what it
dislikes if they do not. `--from` overrides the envelope sender, which
defaults to `postmaster@<hostname>`.

### DNS an operator has to publish

For a domain `example.com` forwarded by a host called `mx.example.com`:

| record | value |
|---|---|
| `example.com.` MX 10 | `mx.example.com.` |
| `mx.example.com.` A | the server's IPv4 address (and `AAAA` if it has IPv6) |

The MX target must be a name with an address record of its own — an MX
pointing at a CNAME is not allowed, and senders do reject it.

**Reverse DNS.** The PTR of the address mxhop sends *from* has to resolve to
the name it gives in HELO (`hostname` in the config), and that name has to
resolve back to the same address. Gmail and Outlook treat a mismatch as a
reason to distrust the mail, or to refuse it outright. The PTR is set where
the address comes from — your hosting provider's panel — not in your zone.

**SRS.** Once sender rewriting lands it will need a domain of its own for the
rewritten envelope senders, with an SPF record authorising this server to
send for it. That is not implemented yet, so there is nothing to publish for
it today.

## Why this exists

Stalwart is a full mail server — storage, JMAP, IMAP, a database, a web admin —
for what is a two-thousand-line job. Postfix set up to forward *correctly* is
four daemons (postfix, postsrsd, opendkim, opendmarc) and four configuration
languages. Cloudflare Email Routing works well but is not yours: no logs you
can grep, nothing you can self-host.

One sentence: a forwarder that fits in one binary and one TOML file, does SRS
and DMARC right by default, and can be read in an afternoon.

## Licence

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT licence ([LICENSE-MIT](LICENSE-MIT))

at your option. Contributions are accepted under the same terms.
