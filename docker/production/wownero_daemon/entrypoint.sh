#!/bin/bash
set -e

if [[ "$1" == "wownerod" ]]; then
	mkdir -p "$WOWNERO_DATA"

	chown -h wownero:wownero /home/wownero/.wownero
	exec gosu wownero "$@"
else
	exec "$@"
fi
