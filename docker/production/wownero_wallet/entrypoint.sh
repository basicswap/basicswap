#!/bin/bash
set -e

if [[ "$1" == "wownero-wallet-rpc" ]]; then
	mkdir -p "$WOWNERO_DATA"

	chown -h wownero_wallet:wownero_wallet /data
	exec gosu wownero_wallet "$@"
else
	exec "$@"
fi
