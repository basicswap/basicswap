#!/bin/bash
set -e

if [[ "$1" == "haven-wallet-rpc" ]]; then
	mkdir -p "$HAVEN_DATA"

	chown -h haven_wallet:haven_wallet /data
	exec gosu haven_wallet "$@"
else
	exec "$@"
fi
