#!/bin/bash
set -e

if [[ "$1" == "havend" ]]; then
	mkdir -p "$HAVEN_DATA"

	chown -h haven:haven /home/haven/.haven
	exec gosu haven "$@"
else
	exec "$@"
fi
