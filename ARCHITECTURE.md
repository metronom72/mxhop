# Architecture

How mxhop is put together, and why. The README says what it does; this says
where the code is and which decisions it rests on.

## One message, end to end

```
TCP accept  ─► session::serve ──► policy::decide ──► client::deliver ──► 250
                   │                    │                 │
                   │                    │                 └─ per destination domain
                   │                    │                    (or per via host)
                   │                    └─ trace loop? DMARC? alias expansion?
                   │
                   ├─ auth::Verifier::check     (SPF, DKIM, DMARC, one clock per stage)
                   ├─ spool::Spool::store       (tmp/ → fsync → rename into queue/)
                   └─ dsn::send                 (only for a proved sender)

                                 queue::Runner::sweep  ─► retries, per-host backoff
                                        │
                                        └─ 48h ─► frozen/
```

Everything a delivery needs is on disk before the sending server is answered,
and nothing the runner does depends on state in memory. That is what makes
`kill -9` safe, and `tests/queue_restart.rs` is the proof: it drives two
runners over one spool directory with everything from the first dropped in
between.

## The modules

| file | what it owns |
|---|---|
| `config.rs` | the TOML, and `mxhop check`. Every problem is reported with its line, and as many as possible at once |
| `routing.rs` | `Mailbox`, the alias table, `Route` |
| `policy.rs` | the decision table. **No clock, no socket, no disk** |
| `auth.rs` | SPF, DKIM, DMARC, and the `Authentication-Results` header |
| `dns.rs` | MX and address lookups, and the null-MX rule |
| `smtp/session.rs` | the inbound conversation |
| `smtp/client.rs` | the outbound one, and the `Relay` trait |
| `smtp/wire.rs`, `smtp/command.rs` | lines and verbs, separately from either conversation |
| `spool.rs` | `queue/`, `tmp/`, `frozen/`, and the write-then-rename |
| `queue.rs` | the retry schedule and the per-host backoff |
| `srs.rs` | sender rewriting, and accepting the bounces that come back |
| `arc.rs` | the ARC signing key, and the record an operator publishes |
| `dsn.rs` | delivery reports, and the rule that keeps them from being spam |
| `observe.rs`, `metrics.rs` | `/healthz`, `/metrics` |
| `shutdown.rs`, `activation.rs` | stopping without cutting a session; taking a socket from systemd |
| `tls.rs` | the certificate, and reloading it without dropping connections |

## The decisions worth knowing

**`policy.rs` is a pure function.** `decide` takes an envelope, a router, a
header scan, limits and an auth verdict, and returns a plan or a refusal. It
has no resolver, no clock and no spool, so every rule in it can be tested with
a literal. Everything that can block lives behind the `Relay` trait in
`smtp/client.rs`, which is also the one place a test swaps the outside world
out.

**The envelope is the unit of durable state.** `Envelope` holds what the
session agreed to — sender, recipients, HELO, peer — plus the `Received` and
`Authentication-Results` mxhop built, the attempt count, the next attempt
time, and any `via` route. A retry therefore sends byte-identical headers
without repeating a single lookup, which is what keeps a DKIM signature over
our trace from breaking and what keeps two logs threadable by one id.

**Every refusal happens while the sending server still holds the message.**
That is the one moment a refusal costs nobody anything, and it is why SPF,
DKIM and DMARC are all evaluated at end of `DATA` rather than at `MAIL FROM`
or `RCPT TO`. An SPF hard failure with an aligned DKIM pass is a DMARC *pass*,
and that is exactly what forwarded mail looks like.

**Deferral is only for a question that a definite answer could have refused.**
`451` where the policy is in hand and the alignment lookup failed; `250` and a
stamped header where nothing could be found out at all. A resolver that cannot
answer never becomes a permanent refusal and never becomes an open door.

**Each verification stage has its own clock.** The sender picks two of the
three names being looked up — the HELO name, the envelope sender, and every
signature's `d=`. Under one clock he can spend the whole budget before the
victim's `_dmarc` is asked for, and "policy unknown" forwards. Eight seconds
for SPF, six for DKIM, and never less than six left for DMARC.

**Nothing a sender wrote reaches a log line or a metric label.**
`tests/no_content_in_logs.rs` scans every `tracing` call in the tree and fails
the build on anything that would break that.

**Duplicates beat losses.** A message delivered and then not removable from
the queue goes out again. Nothing on disk distinguishes that from an attempt
that never happened, and a forwarder that drops mail to avoid a duplicate has
chosen the worse of the two.

## Testing

Unit tests live beside the code; the ones that need two processes, two spools
or a real socket live in `tests/`:

| | |
|---|---|
| `queue_restart.rs` | greylisting and `kill -9`, through two runners over one directory |
| `graceful_stop.rs` | `SIGTERM` in the middle of `DATA` |
| `observe_http.rs` | `/healthz` and `/metrics` over a real socket, and a failed certificate reload |
| `starttls.rs` | a certificate reload seen by the next connection and not the current one |
| `srs_wire.rs` | what the destination actually reads on the `MAIL FROM` line |
| `no_content_in_logs.rs` | the logging promise, enforced against the source |
| `deploy/image-test.sh` | the built container image, end to end, in CI |

Two kinds of test double are used and no more: `dns::Table`, a scripted
resolver, and a scripted nameserver in `auth.rs` for the cases where the
mapping under test is made inside hickory by an rcode and a table of records
cannot express it.
