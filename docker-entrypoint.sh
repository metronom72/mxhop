#!/bin/sh
# Validate before serving. `mxhop check` exits non-zero on a bad config, and
# exiting here makes the deploy fail instead of starting a mail server that
# accepts a connection and then refuses every recipient — a failure senders
# see as a bounce, not as a deploy error.
set -e

mxhop check

# exec, so the SMTP process is pid 1 and gets SIGTERM and SIGHUP directly:
# SIGHUP is how the renewed TLS certificate is reloaded, and a shell in
# between would swallow both.
exec mxhop "$@"
