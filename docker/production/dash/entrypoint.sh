#!/bin/bash
set -e

if [[ "$1" == "dash-cli" || "$1" == "dash-tx" || "$1" == "dashd" || "$1" == "test_dash" ]]; then
	mkdir -p "$DASH_DATA"

	chown -h dash:dash /home/dash/.dash
	exec gosu dash "$@"
else
	exec "$@"
fi
