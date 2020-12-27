#!/bin/bash
set -e

if [[ "$1" == "monerod" ]]; then
	mkdir -p "$MONERO_DATA"

	chown -h monero:monero /home/monero/.monero
	exec gosu monero "$@"
else
	exec "$@"
fi
