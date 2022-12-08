#!/bin/bash
set -e

if [[ "$1" == "firo-cli" || "$1" == "firo-tx" || "$1" == "firod" || "$1" == "test_firo" ]]; then
	mkdir -p "$FIRO_DATA"

	chown -h firo:firo /home/firo/.firo
	exec gosu firo "$@"
else
	exec "$@"
fi
