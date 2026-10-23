#!/bin/bash
set -e

if [[ "${1##*/}" == "wownerod" ]]; then
	mkdir -p "$WOWNERO_DATA"
	find "$WOWNERO_DATA" ! -user wownero -exec chown -h wownero:wownero {} +

	chown -h wownero:wownero /home/wownero/.wownero
	exec gosu wownero "$@"
else
	exec "$@"
fi
