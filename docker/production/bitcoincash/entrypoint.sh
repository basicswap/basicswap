#!/bin/bash
set -e

if [[ "$1" == "bitcoin-cli" || "$1" == "bitcoin-tx" || "$1" == "bitcoind" || "$1" == "test_bitcoin" ]]; then
	mkdir -p "$BITCOIN_DATA"

	chown -h bitcoin:bitcoin /home/bitcoin/.bitcoin
	exec gosu bitcoin "$@"
else
	exec "$@"
fi
