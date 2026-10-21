#!/bin/bash
set -e

if [[ "${1##*/}" == "wownero-wallet-rpc" ]]; then
	mkdir -p "$WOWNERO_DATA"
	find "$WOWNERO_DATA" ! -user wownero -exec chown -h wownero:wownero {} +

	exec gosu wownero "$@"
else
	exec "$@"
fi
