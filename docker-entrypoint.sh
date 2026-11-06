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

# exec, so no shell is left between the signal and the SMTP process: SIGHUP
# is how a renewed TLS certificate is reloaded, and `sh` would swallow it
# while mxhop ran as its child. Note that mxhop is not necessarily pid 1 —
# the stack sets `init: true` so tini holds that slot and forwards signals
# here; see deploy/mxhop.stack.yml for why.
exec mxhop "$@"
