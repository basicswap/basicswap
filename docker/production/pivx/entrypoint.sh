#!/bin/bash
set -e

if [[ "$1" == "pivx-cli" || "$1" == "pivx-tx" || "$1" == "pivxd" || "$1" == "test_pivx" ]]; then
	mkdir -p "$PIVX_DATA"

	chown -h pivx:pivx /home/pivx/.pivx
	exec gosu pivx "$@"
else
	exec "$@"
fi
