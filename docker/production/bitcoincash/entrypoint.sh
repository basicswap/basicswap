#!/bin/bash
set -e

if [[ "$1" == "bitcoin-cli" || "$1" == "bitcoin-tx" || "$1" == "bitcoind" || "$1" == "test_bitcoin" ]]; then
	mkdir -p "$BITCOINCASH_DATA"

	chown -h bitcoincash:bitcoincash /home/bitcoincash/.bitcoincash
	exec gosu bitcoincash "$@"
else
	exec "$@"
fi
