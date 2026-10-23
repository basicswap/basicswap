#!/bin/bash
set -e

if [[ "${1##*/}" == "litecoin-cli" || "${1##*/}" == "litecoin-tx" || "${1##*/}" == "litecoind" || "${1##*/}" == "test_litecoin" ]]; then
	mkdir -p "$LITECOIN_DATA"
	find "$LITECOIN_DATA" ! -user litecoin -exec chown -h litecoin:litecoin {} +

	chown -h litecoin:litecoin /home/litecoin/.litecoin
	exec gosu litecoin "$@"
else
	exec "$@"
fi
