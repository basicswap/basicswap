#!/bin/bash
set -e

if [[ "$1" == "monero-wallet-rpc" ]]; then
	mkdir -p "$MONERO_DATA"

	chown -h monero_wallet:monero_wallet /data
	exec gosu monero_wallet "$@"
else
	exec "$@"
fi
