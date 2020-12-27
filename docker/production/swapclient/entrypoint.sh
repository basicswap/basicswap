#!/bin/bash
set -e

chown -R swap_user "$DATADIR"
exec gosu swap_user "$@"

