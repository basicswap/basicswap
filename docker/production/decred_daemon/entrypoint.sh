#!/bin/bash
set -e

if [[ "$1" == "dcrctl" || "$1" == "dcrd" || "$1" == "dcrwallet"  ]]; then
	mkdir -p "$DECRED_DATA"

	chown -h decred:decred /home/decred/decred
	exec gosu decred "$@"
else
	exec "$@"
fi