#!/bin/bash
set -e

if [[ "$1" == "particl-cli" || "$1" == "particl-tx" || "$1" == "particld" || "$1" == "test_particl" ]]; then
	mkdir -p "$PARTICL_DATA"

	chown -h particl:particl /home/particl/.particl
	exec gosu particl "$@"
else
	exec "$@"
fi
