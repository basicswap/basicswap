#!/bin/sh
set -e

if [ "${1##*/}" = "tor" ]; then
	mkdir -p /var/lib/tor
	chown -R tor:tor /var/lib/tor
	exec su-exec tor "$@"
else
	exec "$@"
fi
