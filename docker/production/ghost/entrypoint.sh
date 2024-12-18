#!/bin/bash
set -e

if [[ "$1" == "ghost-cli" || "$1" == "ghost-tx" || "$1" == "ghostd" || "$1" == "test_ghost" ]]; then
	mkdir -p "$ghost_DATA"

	chown -h ghost:ghost /home/ghost/.ghost
	exec gosu ghost "$@"
else
	exec "$@"
fi
