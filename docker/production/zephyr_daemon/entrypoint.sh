#!/bin/bash
set -e

if [[ "$1" == "zephyrd" ]]; then
	mkdir -p "$ZEPHYR_DATA"

	chown -h zephyr:zephyr /home/zephyr/.zephyr
	exec gosu zephyr "$@"
else
	exec "$@"
fi
