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

**Every feature below is written and tested. None of it has yet carried a
real stranger's mail.** That is the honest line: the test suite covers each
piece end to end, including against the built container image, but this
project has not been an MX for a live domain. If you point a record at it,
you are the first.

| | what the tests prove |
|---|---|
| Config, validation, `mxhop check` | every problem reported with its line, as many at once as possible |
| Inbound session, spool to disk | body and envelope written to `tmp/`, fsynced, renamed into `queue/` |
| STARTTLS and certificate reload | a reload is seen by the next connection and not the current one |
| Outbound client | MX order, null MX, a dead exchanger deferred rather than bounced |
| Synchronous relay, hop limit — **0.1** | a loop is refused by the trace before any DNS is spent |
| SRS and bounce decoding | what a destination reads on the `MAIL FROM` line; a forged bounce refused |
| SPF/DKIM/DMARC, `Authentication-Results` | a real nameserver, a real RSA and Ed25519 signature, one changed byte breaking it |
| Queue, retries, per-host backoff | greylisting and `kill -9` mid-delivery, across two runners over one directory |
| Per-stage verification budgets | a forgery whose own SPF never answers still gets `550` |
| Delivery to a named server (`via`) | the MX lookup is skipped, and skipping it is what the test measures |
| Delivery reports (DSN) | a forged envelope gets none, and a bounce is never bounced |
| Metrics, health, graceful stop — **0.2** | `SIGTERM` in the middle of `DATA` finishes the message |
| `scratch` image, systemd units, compose | the image, end to end, in CI: no shell, uid 10001, a full SMTP conversation |
| Docs and release — **1.0** | you are reading it |
| ARC sealing | the seal verifies in a test; a receiver's `arc=pass` is a separate claim |
| Connection blocklists, rate limiting | not written |

What works today: it accepts mail, forwards it inside the session that
brought it, keeps whatever a destination deferred in a queue it retries, and
tells a sender whose identity it could prove when a copy finally failed. The
queue is two files per message — `queue/<id>.eml` is exactly what arrived,
`queue/<id>.json` is its envelope — so you can read what is stuck and why
with `cat`.

[ARCHITECTURE.md](ARCHITECTURE.md) is where the code is and why.
[SECURITY.md](SECURITY.md) is how to report something privately and what
counts. [CONTRIBUTING.md](CONTRIBUTING.md) is the DCO and what a change
needs.

```sh
mxhop check --config mxhop.example.toml   # before anything else
mxhop run   --config mxhop.example.toml
```

## Running it

`run` accepts a message, hands it on while the sending server is still
waiting, and queues what a destination deferred. What follows is how to
deploy it.

### As a binary

Every tag publishes a static binary for `x86_64` and `aarch64` with a
checksum beside it, and a multi-architecture image to `ghcr.io`. Or build it:

```sh
cargo build --release --target x86_64-unknown-linux-musl   # one static binary
install -m 0755 target/x86_64-unknown-linux-musl/release/mxhop /usr/local/bin/

install -d -o mxhop -g mxhop -m 0750 /var/lib/mxhop/spool
install -D -m 0644 mxhop.example.toml /etc/mxhop/mxhop.toml
$EDITOR /etc/mxhop/mxhop.toml

mxhop check            # reads /etc/mxhop/mxhop.toml; exits non-zero if wrong
mxhop run
```

Port 25 is privileged. There are two ways to have it without running as
root, and [`deploy/`](deploy/) has a unit for each:

```sh
install -D -m 0644 deploy/mxhop.service /etc/systemd/system/mxhop.service
install -D -m 0644 deploy/mxhop.socket  /etc/systemd/system/mxhop.socket
systemctl daemon-reload
systemctl enable --now mxhop.socket mxhop.service
```

**Socket activation** is the better one: `mxhop.socket` binds 25 as root
before the service starts and hands the listening socket over, so mxhop
never holds the capability at all. mxhop reads `LISTEN_FDS` and `LISTEN_PID`
and takes the socket if it is addressed to this process — a socket meant for
somebody else is left alone, which is what `LISTEN_PID` is for and what
`a_socket_meant_for_another_process_is_left_alone` pins.

**`AmbientCapabilities=CAP_NET_BIND_SERVICE`** is the fallback, and the unit
sets it too, so the service also starts without the socket unit. With no
socket handed over, mxhop binds `listen` from the config itself.

`ExecStartPre` runs `mxhop check`, so a bad config fails the start rather
than producing a mail server that refuses every recipient.

After a certificate renewal, `systemctl reload mxhop` rereads the
certificate files — the unit has the `ExecReload=/bin/kill -HUP $MAINPID`
that makes that work. A reload that fails keeps the pair already loaded and
does **not** make the service unhealthy.

### As a container

```sh
docker build -t mxhop .
docker run --rm mxhop --version
```

The image is **`scratch`** — the static binary, `/etc/passwd`, `/etc/group`
and an empty spool directory, and nothing else. No shell, no package
manager, no busybox, around 8 MB. The build asserts the binary has no
`NEEDED` entry before it is copied in, because a dynamically linked binary
on `scratch` fails at the first execve rather than at build time.

There is no entrypoint script, since there is nothing to run one with:
`ENTRYPOINT` is the binary. A bad config still fails the deploy — `run`
loads and validates the config, the certificate and the SRS secret before
it binds anything.

It listens on **2525**, not 25: the privileged port is published on the host
side, so the process needs no capability and the deployment can drop all of
them. Your config file must therefore say `listen = "0.0.0.0:2525"`.

The healthcheck is `mxhop health`, which asks the container's own
`/healthz` and exits non-zero on anything but `200`. That covers the
listener, the spool, the queue depth and the resolver — rather than only a
`220` banner, which is all the old `nc`-based check could prove and which a
shell-less image cannot run anyway. It needs an `[observe]` block in the
config; `127.0.0.1:9090` is enough, and keeps the endpoint inside the
container where nothing else can reach it.

[`deploy/compose.yml`](deploy/compose.yml) is a ready one-node file:
read-only root, all capabilities dropped, `no-new-privileges`, the spool and
the config bind-mounted. [`deploy/mxhop.stack.yml`](deploy/mxhop.stack.yml)
is the Swarm equivalent, with the port published in **`host` mode** — the
ingress mesh would NAT every connection through an overlay address, so
`Received` would name the wrong peer, the logs would be useless and SPF
would be evaluated against 10.0.x.x instead of the sender.

Neither publishes the metrics port. It is unauthenticated, and publishing it
from a host-mode service opens it to the internet; scrape it by adding the
mapping deliberately.

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

## Delivering to a named server instead of looking up MX

An alias normally sends mail to wherever the destination domain's MX says.
That breaks for one shape of forwarding: a domain whose MX is mxhop, with a
real mailbox *inside that same domain* as the destination.

```toml
[domains."example.com".aliases]
me = { to = "me@example.com", via = "aspmx.l.google.com" }
"*" = "me@example.com"
```

Mail for `example.com` arrives here. `me@` is handed straight to the named
server. Everything else is caught by the catch-all, lands on `me@`, and goes
to the same place. Each address gets exactly one copy: a `via` target is a
leaf, so the alias table is not consulted again for it, which is also why
this is not the loop that `check` would otherwise refuse.

Without `via` the same pair is a loop and `check` says so: the destination is
inside a domain mxhop serves, so the MX lookup finds mxhop, and the message
comes back to the alias it just left.

What this gives up is the one thing DNS was doing for you. A named server is
a fact nothing checks after you write it — if the name is wrong or the
provider changes it, mail piles up or bounces, and the MX record will not
say a word about it. So:

- `check` refuses a `via` that is not a fully qualified host name.
- `check` refuses a `via` that names this host: that is a loop made by hand.
- `check` resolves every `via` name and fails if it has no address. This is
  the one DNS lookup `mxhop check` makes.

A loop is still possible after all that. If the mailbox at the named server
forwards anything back to a domain mxhop serves, the circle closes outside
this configuration and nothing here can see it — only the hop counter in the
headers catches it. Test it with a real message before switching the MX
record over, not after.

One connection serves one destination server, so two addresses routed `via`
different hosts are two connections even when they share a domain.

Honestly: if your provider can do catch-all itself, it can do this without
mxhop and without moving the MX record. This exists for when you want the
mail to come through mxhop anyway.

## The queue, and what happens to mail that cannot be delivered

A message is forwarded inside the session that brought it: the sending server
waits, hears what the destination said, and keeps the message itself if the
answer was a deferral. That is the best place for mail to wait, because it is
somebody else's disk and somebody else's retry schedule.

What lands in `queue/` is what mxhop could not hand back: a message one of
whose destinations took it while another deferred. The sender has been told
`250` and will never send it again, so that copy is now the only one.

mxhop reads `queue/` every `sweep_seconds` and tries whatever is due:

| attempt | wait before it |
|---|---|
| 2nd | 1 minute |
| 3rd | 5 minutes |
| 4th | 15 minutes |
| 5th | 1 hour |
| 6th and after | 4 hours |

One minute first, because what is usually being waited out is a greylist and
a greylist clears in a minute; then longer, because what is left after the
first few attempts is a destination with something properly wrong with it.
The last interval repeats for as long as the message is queued.

Only the recipients still deferring are retried — one that has its copy comes
off the envelope, so nobody gets the message twice — and `last_reply` in the
sidecar is the destination's own sentence about why, which is the thing worth
reading:

```sh
cat /var/lib/mxhop/spool/queue/*.json | grep last_reply
```

After **48 hours** mxhop stops trying and moves both files to `frozen/`.
It has to fit inside the SRS window: the rewritten sender a destination
bounces to is only valid for `srs.max_age_days` (seven by default), so a last
attempt made after that provokes a report that comes back to an address mxhop
no longer recognises — `mxhop check` refuses a lifetime that does not fit.

Nothing is deleted. A frozen message is still somebody's mail. Its sender is
told, by a delivery report, if the envelope sender was proved — see
[when mail cannot be delivered](#when-mail-cannot-be-delivered-who-is-told)
for why that condition is there and what happens when it is not met. Either
way the files stay in `frozen/`, and an operator who has fixed whatever was
wrong can move them back:

```sh
mv /var/lib/mxhop/spool/frozen/<id>.* /var/lib/mxhop/spool/queue/
```

The next sweep picks them up. The same goes for editing a recipient in an
envelope by hand: the schedule lives in the file, nothing is cached, and
`queue/` is the whole administration interface.

### One failure stands in for the destination

A destination that defers everything it is handed is not connected to again
until its own wait is over, and every other message queued for it is skipped
in the meantime — without costing those messages an attempt, and without
touching their schedule. The wait doubles the same way a message's does, on
the destination's own count of consecutive failures, and is forgotten the
moment it answers for itself by taking a message or refusing one.

Without that, a hundred messages queued for one dead host were a hundred
connection attempts per sweep, every one of them waiting out the connect
timeout, and mail for the destinations that *were* up waited behind them.
With it, one connection per interval finds out whether the host is back, and
the backlog goes out in the sweep that finds it.

The count is in memory and lost on restart, which costs one connection per
destination after one and is the right trade: it is a fact about a host right
now, not about any message, and writing it into an envelope would put one
message in charge of a decision it shares with others.

A message whose recipients span two domains is skipped whole if either is
backed off. That costs the healthy domain a wait of at most one ceiling and
buys a rule with one clock in it; it is also nearly free in practice, since
the recipients that were delivered came off the envelope when the message was
first held.

### Changing any of it

The `[queue]` table, with these defaults:

```toml
[queue]
retry_minutes = [1, 5, 15, 60, 240]   # the last one repeats
lifetime_hours = 48
sweep_seconds = 60
```

`mxhop check` refuses a `lifetime_hours` longer than `srs.max_age_days`, an
empty `retry_minutes`, a zero or a value over a day inside it, and a zero
anywhere else — zero means something different for each of them and all three
meanings are a queue that has quietly stopped being one. It also prints the
schedule it would run with, so the file does not have to be read back.

One thing is still missing: a restart does not resume anything in flight. A
message killed mid-delivery is in `queue/` with its old schedule, so it is
tried again at once — and if the destination had already accepted it, that is
a second copy. The window is one message wide, and closing it means recording
an attempt before it is made rather than after, which is a change to what the
envelope holds and not to the runner.

## Watching it, and stopping it

### `/metrics` and `/healthz`

```toml
[observe]
listen = "127.0.0.1:9090"
```

Leave the block out and no HTTP listener is opened at all. Bind it to
loopback or to a private interface: it is unauthenticated, and `check`
refuses a port shared with SMTP.

`/metrics` is the Prometheus text format: counters for sessions, messages,
recipient outcomes, queue sweeps, freezes, reports and DMARC refusals; gauges
for queue depth and open sessions; histograms for session and delivery
duration. **No addresses, ever** — not in a value and not in a label. An
address in a label publishes the mail log to whoever can read the endpoint,
and blows the cardinality up besides. A test asserts the rendered output
contains no `@`.

`/healthz` is `200` or `503`, and says which part is unhappy:

```
ok
listener: ok
spool: ok
queue: 3/100000
resolver: ok
```

A `503` means one of: the SMTP listener is not accepting, the spool cannot be
read or written, the queue is at its limit, or the resolver stopped
answering.

**A failed certificate reload is not one of them.** `SIGHUP` with a broken or
unreadable certificate on disk logs a warning and keeps serving the pair
already loaded — so the process is still delivering mail, and telling an
orchestrator to kill it would turn a typo in a renewal hook into an outage.
`a_failed_certificate_reload_does_not_take_healthz_down` pins that.

### Stopping

`SIGTERM` (or `SIGINT`):

1. the listener stops accepting — a connection that arrives after this gets
   nothing;
2. a session **inside `DATA`** finishes: the message is taken, delivered or
   queued, and answered normally. Half a message is never a message;
3. a session waiting for its next command gets
   `421 4.3.2 this server is shutting down`, which a sending server reads as
   "come back", not as a failure;
4. the process waits up to **25 seconds** for the rest and then exits anyway.

Twenty-five rather than thirty so that the whole thing finishes inside a
default `stop_grace_period: 30s` with room to spare — a deploy that reaches
the `SIGKILL` is a deploy that cuts a session in half.

## ARC: sealing what this hop found out

Forwarding breaks SPF for the original sender — the message now arrives from
this host, not from theirs. DMARC then rests entirely on the original DKIM
signature surviving the hop. mxhop does not touch a message's bytes, so it
usually does. When it does not, the receiver has nothing left to check.

ARC (RFC 8617) is what the large receivers offer to fix that: this host
records what *it* found out, signs that record, and signs the chain. A
receiver that trusts the sealer can use it when its own checks fail.

```toml
[arc]
domain = "mx.example.com"
selector = "arc1"
key_file = "/etc/mxhop/arc.key"
```

No block, no seal — and no half-written header either. An RSA key:

```sh
openssl genrsa -out /etc/mxhop/arc.key 2048
chmod 600 /etc/mxhop/arc.key
```

**RSA, not Ed25519.** Ed25519 is in the specification; it is not validated by
every large receiver, and a seal nobody checks is worse than no seal, because
it looks like one. `check` refuses anything else and says so.

`mxhop check` prints the record to publish, and the public half comes from
the key:

```sh
openssl rsa -in /etc/mxhop/arc.key -pubout -outform DER 2>/dev/null | base64 -w0
```

as a TXT record at `arc1._domainkey.mx.example.com`:

```
v=DKIM1; k=rsa; p=<that base64>
```

Three headers go in front of the message, above mxhop's own `Received`:
`ARC-Seal`, `ARC-Message-Signature` and `ARC-Authentication-Results`. They
are kept on the envelope like the trace is, for the same reason — a seal
covers bytes, and a retry that sealed again would write a second seal for one
hop, which is exactly what a chain must not contain.

An arriving chain is verified first. A valid one is extended with `cv=pass`,
an empty one starts at `i=1` with `cv=none`, and a **broken one is left
alone**: mxhop adds nothing rather than sealing over a chain that already
failed.

**Honestly about what this buys.** A seal is worth exactly what the receiver
decides to give it. Google and Microsoft document that they consider ARC;
neither promises anything, and a new sealing domain carries no reputation at
all. ARC does not rescue a message that fails DMARC outright — it gives a
receiver a reason to believe the hop before this one, nothing more. The
honest reason to publish it is that without it a forwarder has nothing to say
for itself when DKIM breaks upstream.

## When mail cannot be delivered: who is told

A message that was accepted and then finally failed gets a delivery report
(RFC 3464) back to the envelope sender — but only when the envelope sender
was proved to be who it says it is.

| | |
|---|---|
| a copy permanently refused after mxhop answered `250` | report |
| a copy permanently refused on a retry from the queue | report |
| the queue's lifetime ran out and the message moved to `frozen/` | report |
| the envelope sender is null (`<>`) | no report |
| nothing proved the envelope sender | no report, a log line and a counter |

The second-to-last row is not an edge case; it is the whole design. A report
is a message mxhop sends, to an address somebody else chose, about a message
somebody else wrote. Send one for every failure and a spammer forging
`MAIL FROM:<victim@example.com>` has mxhop mailing the victim on his behalf.
That is backscatter, and it is spam with your name on it.

So the sender has to have been proved first, which means one of:

- **SPF passed for the envelope sender.** That is the identity the report
  would be sent to, so this is the test that actually answers the question.
- **A DKIM signature passed and its `d=` is the envelope sender's domain, or
  a parent of it.**

The alignment in the second one is deliberate and is stricter than it may
look. A DKIM pass proves the `From:` header's domain, which is routinely a
different domain from the envelope sender — forwarded mail and mailing lists
are nothing but that. An unaligned pass would say a newsletter's signature
vouches for a bounce address at a domain the signer has never heard of, and
a report sent on that basis is backscatter with extra steps. The issue this
came from says "SPF or DKIM"; without the alignment it would not meet its own
acceptance criterion.

The report itself goes into the same queue as any other message, with the
null sender, so it is retried and backed off like everything else — and when
it cannot be delivered, the first row of the table above stops the loop:
nothing is sent about a message sent from `<>`.

Reports carry the original's `Received` and `Authentication-Results` and
nothing else of the message. The body is not quoted back. A destination's
own refusal text is copied into `Diagnostic-Code:` with control characters
replaced, so a crafted reply cannot add a header to the report.

## What arriving mail is checked for

Every message is checked once, at the end of `DATA`, before anything leaves:
SPF for both the HELO name and the envelope sender **as it arrived**, DKIM
for every signature, and DMARC over the `From:` header. What was found goes
into an `Authentication-Results` header written directly under mxhop's own
`Received`, and the stored message is otherwise untouched.

Only one thing is ever refused:

| what DMARC says | what mxhop does |
|---|---|
| fails, and the domain publishes `p=reject` | `550 5.7.1`, naming the domain and the policy |
| `p=reject` is in hand but the check could not be finished | `451 4.7.1` — try again |
| fails under `p=reject`, but a signature on it was never checked | `451 4.7.1` — try again |
| could not be checked at all, so no policy is known | forwarded, with `dmarc=temperror` in the header |
| fails under `p=quarantine` | forwarded, with `policy.dmarc=quarantine` in the header |
| fails under `p=none`, or there is no record | forwarded |
| anything else, SPF failures included | forwarded |

The rule in one sentence: **defer only where a definite answer could have
refused.** A resolver that cannot answer never becomes a permanent refusal,
and never becomes an open door either.

The third row is the one worth arguing. An unreadable policy *could* have been
`p=reject`, so deferring looks like the cautious reading — but it is not the
sender's `_dmarc` record alone that produces it. `mail-auth` abandons the whole
DMARC tree walk on the first non-NXDOMAIN failure at any level, so a REFUSED
answer, a flaky authoritative server or a DNSSEC-bogus zone anywhere in a
domain's `_dmarc` ancestry arrives here as "no policy". A retry gets the same
answer, so a 451 there is a bounce after the sender's retry window, over DNS
that never affected delivery before. What it buys is small and not an
attacker's to arrange: a forgery of a `p=reject` domain gets through only while
*that domain's own* `_dmarc` is unanswerable, and the destination re-evaluates
DMARC with its own resolver regardless. Accepting and stamping on `temperror`
is what OpenDMARC, rspamd and Gmail all do. There is no setting for this; a
third knob nobody sets correctly is worse than one well-argued default.

That row is only safe because of how the twenty seconds all these lookups
share are divided. **The sender chooses two of the three names being looked
up** — the HELO name, the envelope sender and the `d=` of every signature are
all his, and `_dmarc.<the From domain>` is not. Under a single clock, a
handful of `include:`s in his own SPF record pointing at hosts that swallow
queries rather than refusing them spends the whole budget *before* the
victim's policy has been asked for. The verdict is then "policy unknown",
which the row above forwards — and the forged `From: service@paypal.com`
leaves here with mxhop's envelope on it, which is the one outcome this check
exists to prevent.

So each stage gets its own clock: **8 seconds for both SPF evaluations, 6 for
DKIM, and whatever is left — never less than 6 — for DMARC.** The sender may
spend both of his own stages down to the last millisecond and the policy is
still fetched, still in hand, and still enforced. An expired SPF stage only
reaches DMARC as a temporary error when the SPF identity is *aligned* with the
`From` domain, and forging somebody else's `From` is precisely what being
unaligned means — so the attacker's dead SPF earns a `550` while an honest
sender's dead SPF earns the `451` the deferral rule was written for. A session
with less than twenty seconds to spare shortens all three stages rather than
dropping the last one.

The new row in the table is the other half of that. An expired DKIM stage
hands DMARC an empty list of signatures, which is exactly what an unsigned
message hands it — and an unsigned message failing `p=reject` is refused. A
`550` is permanent, and the signature that would have cleared this message was
never fetched, so the two are told apart and that one is deferred instead. It
is still a refusal: a sender who hangs his own key lookup to earn the softer
code has bought a retry, not a delivery.

Why the one refusal matters here specifically: after SRS *every* message mxhop
forwards passes SPF at the destination, because the envelope sender is at a
domain whose SPF record is this host. So a forged `From: service@paypal.com`
would reach Gmail with a clean envelope and mxhop's address on it, Gmail would
refuse it, and the refusal would be counted against *your* reputation — every
time. With two destinations it is worse than a refusal: the lax one accepts,
mxhop answers `250`, and Gmail's refusal becomes a lost copy with nothing to
report it. The domain owner already asked every receiver to reject that
message; while the sending server still holds it, the refusal costs nobody
anything.

SPF alone decides nothing, which is why nothing is refused at `MAIL FROM`: an
SPF hard failure with an aligned DKIM pass is a DMARC *pass*, and that is
exactly what mail forwarded to you by somebody else looks like.

This is identity, not intent. It says nothing about a correctly signed message
from a throwaway domain, and content filtering stays out of a forwarder.

The whole thing is one table:

```toml
[auth]              # the whole table is optional; absent is this
enabled = true      # false: no lookups, no header, no refusals, no byte changed
enforce = "dmarc"   # or "off": evaluate, stamp and log, never refuse or defer
```

`enforce = "off"` logs each verdict it would have acted on, at info, with the
code, the domain and the policy — which is what makes it usable for watching
enforcement for a week before switching it on.

An `Authentication-Results` header that arrives already claiming mxhop's own
`hostname` is removed before the message is checked ([RFC 8601 §5][rfc8601]),
unless `enabled = false`, in which case mxhop has no finding of its own and
deletes nothing.
It is the one place mxhop changes the bytes of a message, and it is the
deletion of one header — another host's results are left alone. Without it a
sender writes the header itself, under your name, and nothing downstream can
tell the claim from the finding.

[rfc8601]: https://www.rfc-editor.org/rfc/rfc8601#section-5

## What mxhop writes down about your mail

A forwarder sees every message you receive. What it records is a decision, not
an implementation detail, so here it is in full.

### In the log

| | |
|---|---|
| the queue id | the one thread through every line about a message |
| the peer address and the `HELO` name | the connection's facts |
| `MAIL FROM` and the resolved recipients | the envelope |
| the `Message-ID` | so a line here can be matched to a line in the destination's log |
| the size in bytes, and the hop count from `Received` | counts, not content |
| the SPF, DKIM and DMARC verdicts | and the policy that was in hand |
| the destination's own reply, word for word | its text, not yours |

### Never, in any line

**The subject. The body. Any header the sender wrote**, apart from the
`Message-ID`, which is an identifier and is dropped if it contains anything
that could forge a log line.

This is not a promise in prose only. `tests/no_content_in_logs.rs` reads every
`tracing` call in the tree and fails the build if one of them would print a
message's content — a length or a count has to be bound to a name first, so
that what reaches the record is visible in the call itself.

The same rule holds for `/metrics`: counters and histograms, never a label
carrying an address. A test asserts the whole rendered output contains no `@`.

### On disk

`queue/<id>.eml` **is** the message, byte for byte as it arrived. That is the
point — an operator has to be able to read what is stuck. Its protection is
the directory's permissions and nothing else: `0750`, owned by the service
user.

| | |
|---|---|
| a message being delivered now | seconds |
| a message a destination deferred | up to `queue.lifetime_hours`, 48 by default |
| a message mxhop gave up on | **in `frozen/` until somebody removes it** |

mxhop never deletes a message it accepted. A frozen one is somebody's mail
and the only copy of it, so it stays readable and the disk it sits on is the
operator's to watch — `/metrics` reports the queue depth, and `/healthz`
turns `503` at the configured limit.

A delivered message is removed from `queue/` immediately. Nothing is archived,
nothing is copied anywhere, and there is no index of what passed through.

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
