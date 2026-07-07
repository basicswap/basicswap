#!/bin/bash
set -e

if [[ "$1" == "zephyr-wallet-rpc" ]]; then
	mkdir -p "$ZEPHYR_DATA"

	chown -h zephyr_wallet:zephyr_wallet /data
	exec gosu zephyr_wallet "$@"
else
	exec "$@"
fi
