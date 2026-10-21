#!/bin/bash
set -e

if [[ "${1##*/}" == "monero-wallet-rpc" ]]; then
	mkdir -p "$MONERO_DATA"
	find "$MONERO_DATA" ! -user monero -exec chown -h monero:monero {} +

	exec gosu monero "$@"
else
	exec "$@"
fi
