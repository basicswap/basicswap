#!/bin/bash
set -e

chown -R swap_user "$DATADIRS"
exec gosu swap_user "$@"

