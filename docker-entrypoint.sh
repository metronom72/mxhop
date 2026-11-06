#!/bin/sh
set -e

# Validate only before serving. `mxhop check` needs a config file, so running
# it for every argument broke the one-liners that have no config at all —
# `--version`, `--help`, `send-test` — which exited 1 with "cannot be read"
# before printing anything. For `run` the check is still worth its
# millisecond: it turns a bad config into a failed deploy instead of a mail
# server that accepts a connection and then refuses every recipient, which
# senders see as a bounce rather than as an error anyone is paged for.
if [ "$1" = "run" ]; then
    mxhop check
fi

# exec, so the SMTP process keeps the pid the init gave it and receives
# SIGHUP directly — that is how a renewed TLS certificate is reloaded, and a
# shell in between would swallow it. Note that this process is NOT pid 1 in
# the stack: the service sets `init: true`, so tini is pid 1 and forwards
# signals here. See deploy/mxhop.stack.yml for why that matters.
exec mxhop "$@"
