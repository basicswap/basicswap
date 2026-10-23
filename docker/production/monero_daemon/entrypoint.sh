#!/bin/bash
set -e

if [[ "${1##*/}" == "monerod" ]]; then
	mkdir -p "$MONERO_DATA"
	find "$MONERO_DATA" ! -user monero -exec chown -h monero:monero {} +

	chown -h monero:monero /home/monero/.monero
	exec gosu monero "$@"
else
	exec "$@"
fi
