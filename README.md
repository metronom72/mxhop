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
| Synchronous relay, hop limit — **0.1** | done |
| SRS and bounce decoding | done |
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
`listen = "0.0.0.0:2525"`. For the `run` command — and only for it — the
entrypoint runs `mxhop check` first, so a bad config fails the deploy
instead of starting a mail server that refuses every recipient; other
commands (`--version`, `send-test`) run without needing a config at all.

The image's healthcheck opens an SMTP connection on the loopback and looks
for a `220` banner. That proves the listener is still answering; it does not
prove TLS, the spool or delivery work.

The spool must be a mount point — a bind mount from a host path, not a named
volume and never a layer in the image. It holds mail that has been accepted
and not yet delivered.

Mount the config *directory*, not `mxhop.toml` alone: a single-file bind
mount pins an inode, so an editor that saves by rename leaves the container
reading the old one. The directory is also where the TLS pair belongs,
copied there owned by uid 10001 — see [deploy/](deploy/README.md), which has
the one command that checks the files read as the container will read them.
A changed config needs a restart; nothing rereads it in place.

```sh
docker run -d --name mxhop \
  -p 25:2525 \
  -v /srv/mxhop:/etc/mxhop:ro \
  -v /srv/mxhop/spool:/var/lib/mxhop/spool \
  --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/metronom72/mxhop:0.1.0
```

Images *will be* published to `ghcr.io/metronom72/mxhop` on a version tag,
with the static binary attached to the GitHub release — the workflow exists
but no tag has been pushed yet, so nothing is there to pull. The first
publication also needs a one-time visibility change on the package;
[deploy/](deploy/README.md) says what and where.

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
non-zero if the destination refused or deferred. So it tells you two things:
that outbound port 25 is not blocked, and what the destination thinks of the
sending address — its verbatim reply names what it dislikes.

**Accepted is not delivered.** Gmail answers `250` and then files the
message in Spam; that has already happened once on this project. Open the
message in the destination mailbox and read its headers — that is the only
check that says the mail arrived where someone will see it. `--from`
overrides the envelope sender, which defaults to `postmaster@<hostname>`.

### DNS an operator has to publish

For a domain `example.com` forwarded by a host called `mx.example.com`:

| record | value |
|---|---|
| `example.com.` MX 10 | `mx.example.com.` |
| `mx.example.com.` A | the server's IPv4 address |

**A only — no `AAAA` yet.** If the host has IPv6 and you publish it, the
Docker daemon publishes port 25 on those addresses through `docker-proxy`
rather than host-mode, so the task sees the bridge gateway as the peer: the
exact wrong-`Received`-header problem host-mode publishing exists to avoid.
Those addresses also have no PTR. Add `AAAA` once an IPv6 connection has
shown up in the log with the real peer address in it.

The MX target must be a name with an address record of its own: an MX
pointing at a CNAME is forbidden ([RFC 2181 §10.3][rfc2181]), and some
senders refuse it — though Postfix and Exim follow the CNAME anyway, so it
can work for years before it does not.

[rfc2181]: https://www.rfc-editor.org/rfc/rfc2181#section-10.3

**Reverse DNS.** What Gmail enforces is *forward-confirmed* reverse DNS: the
address mxhop sends from must have a PTR, and the name that PTR gives must
resolve back to that same address. Without it Gmail refuses with
`550-5.7.25`, on IPv4 as well as IPv6. A HELO name (`hostname` in the
config) that does not match the PTR name is a reputation input rather than a
documented rejection, but there is no reason to have them differ. Outlook's
behaviour here is untested by this project. The PTR is set where the address
comes from — your hosting provider's panel — not in your zone.

**SRS.** Sender rewriting needs a subdomain of its own, and it has to be one
that is *not* listed in `[domains]` — `mxhop check` refuses a configuration
where it is both, because the alias table is consulted first and would answer
bounces instead of letting them be decoded. For an SRS domain
`srs.example.com`:

| record | value |
|---|---|
| `srs.example.com.` MX 10 | `mx.example.com.` |
| `srs.example.com.` TXT | `v=spf1 ip4:<the server's IPv4 address> -all` |

The MX record is what brings the bounces back: a destination that refuses a
forwarded message after accepting it sends its report to the rewritten
envelope sender, and that address has to be deliverable or the report is lost.
`-all` rather than `~all`, because mxhop is the only thing that ever sends
from this domain and there is no reason to ask a receiver to be lenient about
anything else.

The `ip4:` term alone is right for the default `outbound.ipv6 = false`. If you
turn `ipv6` on, add an `ip6:` term for the address mxhop sends from — with
`-all` and no `ip6:`, every message delivered over IPv6 hard-fails SPF, which
is worse than not rewriting the sender at all.

`example.com`'s own SPF record is untouched: mxhop never sends *as* your
domain, only as the SRS one.

The signing key is never in the config file. Generate it on the server and
point `srs.secret_file` at it:

```
head -c 32 /dev/urandom | base64 > /etc/mxhop/srs.key
chmod 600 /etc/mxhop/srs.key
```

To rotate it, put the new key on the **first** line and keep the old one below
it for at least `srs.max_age_days`: the first line signs and every line
verifies, so bounces already in flight — carrying addresses signed with the
retired key — still come home. Dropping the old key immediately destroys
every delivery report that has not arrived yet.

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
