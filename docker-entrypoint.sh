#!/bin/sh
set -e

if [ "$1" = "run" ]; then
    mxhop check
fi

exec mxhop "$@"
