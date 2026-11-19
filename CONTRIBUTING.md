# Contributing

## Sign-off, not a CLA

This project uses the [Developer Certificate of Origin](https://developercertificate.org/).
There is no CLA and nothing to sign in a browser. Add a `Signed-off-by` line to
every commit:

```sh
git commit -s
```

which appends

```
Signed-off-by: Your Name <you@example.com>
```

By doing that you state what the DCO says: you wrote the patch or have the
right to submit it, and you are contributing it under this project's licence
(MIT OR Apache-2.0). Use a real name and a real address.

## Before you open a pull request

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

All three run in CI and all three must pass. So does an end-to-end test
against the built container image:

```sh
docker build -t mxhop:test .
IMAGE=mxhop:test ./deploy/image-test.sh
```

## What a change needs

**A test that fails without it.** For a bug fix, write the test first and watch
it fail; for a behaviour change, change the test that asserted the old
behaviour rather than adding one beside it. A test that passes before and after
the change is documentation, not a test.

**A reason in the commit message, not in the code.** This tree carries no
comments. Explain in the commit message and the pull request why the change is
right and what else was considered — that is where the reasoning lives, and
`git log` keeps it next to the diff forever.

**Test names that are sentences.** `a_forged_envelope_gets_no_report`, not
`test_dsn_2`. The list of test names should read as a description of what the
program promises.

## What will be argued with

- A new dependency. This is a mail server; every crate is attack surface, and
  the tree already hand-rolls base64, date formatting, an HTTP responder and a
  metrics registry rather than pull four crates in. Bring a reason.
- A new configuration option. A knob nobody sets correctly is worse than one
  well-argued default. Several defaults here are documented at length for
  exactly that reason.
- Anything that makes mxhop drop mail to avoid an inconvenience. Delivering a
  message twice is bad; losing it is worse, and the queue's duplicate policy
  is deliberate.
- Putting anything a sender wrote into a log line or a metric label.
  `tests/no_content_in_logs.rs` enforces this and will fail the build.

## Scope

mxhop forwards mail. It does not store it, serve IMAP, send as an alias, filter
content, or have a web interface. A pull request that adds one of those is not
going to be merged no matter how good it is — see the README's first section.
