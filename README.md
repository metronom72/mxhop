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
| Config file, validation, `mxhop check` | in progress |
| Inbound SMTP session, spool to disk | planned |
| STARTTLS and certificate reload | planned |
| Outbound SMTP client | planned |
| Synchronous relay, hop limit — **0.1** | planned |
| SRS and bounce decoding | planned |
| SPF/DKIM/DMARC and `Authentication-Results` | planned |
| Queue, retries, per-host backoff | planned |
| DSNs for queued failures | planned |
| Metrics, health, graceful shutdown — **0.2** | planned |
| ARC sealing | planned |
| Image, systemd unit, compose | planned |
| Docs and release — **1.0** | planned |

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
