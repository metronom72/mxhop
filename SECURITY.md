# Security

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private advisory form:
<https://github.com/metronom72/mxhop/security/advisories/new>. It is enabled on
this repository and goes only to the maintainers.

Tell us what you can run, what you observed, and what you think it lets an
attacker do. A proof of concept helps and is not required.

This is a small project maintained by one person. Expect a first reply within
a week. If a week passes with nothing, open a public issue saying only *"I sent
a private report on <date> and have had no reply"* — with no details — and that
will be taken as the reminder.

There is no bounty.

## What counts

mxhop takes mail from strangers and hands it to mailboxes. Anything that lets
somebody who is not the operator do one of these is a vulnerability:

- read, change or lose a message mxhop accepted
- make mxhop deliver to a recipient the alias table does not name — an open
  relay, by any route
- make mxhop send mail on behalf of a domain it does not serve, including a
  delivery report sent to an address the sender did not prove it owns
- get a forged `From` from a `p=reject` domain forwarded, by exhausting a
  budget, a clock or a lookup
- forge or remove a trace header — `Received` or an
  `Authentication-Results` under this host's own name
- put a sender's own text into a log line, a metric label or a header in a
  position where it is read as structure rather than as data
- crash the process, exhaust its memory or its disk, or keep it from
  accepting mail, from an unauthenticated connection

## What does not count

- **Accepted mail being spam.** mxhop authenticates identity and does not
  filter content. A correctly signed message from a throwaway domain is
  delivered, by design.
- **A deferral.** `4xx` is the correct answer to anything mxhop could not
  decide, and making mxhop say `4xx` is not an escalation.
- **Backscatter mxhop declines to send.** Suppressing a delivery report for an
  unproved sender is the intended behaviour.
- **Anything reachable only with the operator's config file, spool directory
  or SRS secret.** Those are the trust base; an operator who can edit the
  alias table can already send mail wherever they like.
- **The metrics and health endpoint being unauthenticated.** It is documented
  as such and is meant for loopback or a private interface. Report it if it
  exposes something the documentation says it does not — an address, for
  instance.

## Things worth knowing before you look

- The **SRS secret** is the only key mxhop holds. Anyone who has it can forge
  a bounce address that mxhop will accept and relay. It belongs in a file
  readable by the service user alone, never in the config and never in an
  environment variable.
- **`queue/` is somebody's mail.** It is plain `.eml` on disk, by design, so an
  operator can read and repair it. Its permissions are the protection.
- **`frozen/` is never emptied by mxhop.** Messages given up on stay there
  until somebody removes them. That is deliberate, and it is a disk-space
  decision the operator owns.
- mxhop writes exactly one kind of header in somebody else's message and
  removes exactly one: it prepends its own `Received` and
  `Authentication-Results` on the wire, and it strips an arriving
  `Authentication-Results` that claims this host's name. Nothing else about
  a message is changed.

## Supported versions

Before 1.0, only the latest tag. There are no backports.
