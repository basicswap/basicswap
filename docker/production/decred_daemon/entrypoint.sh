#!/bin/bash
set -e

if [[ "${1##*/}" == "dcrctl" || "${1##*/}" == "dcrd" || "${1##*/}" == "dcrwallet"  ]]; then
	mkdir -p "$DCR_DATA"
	find "$DCR_DATA" ! -user decred -exec chown -h decred:decred {} +

	chown -h decred:decred /home/decred/decred
	exec gosu decred "$@"
else
	exec "$@"
fi