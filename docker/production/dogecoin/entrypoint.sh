#!/bin/bash
set -e

if [[ "$1" == "dogecoin-cli" || "$1" == "dogecoin-tx" || "$1" == "dogecoind" || "$1" == "test_dogecoin" ]]; then
	mkdir -p "$DOGECOIN_DATA"

	chown -h dogecoin:dogecoin /home/dogecoin/.dogecoin
	exec gosu dogecoin "$@"
else
	exec "$@"
fi
