#!/bin/sh

if [ $# = 0 ]; then
  echo "error: no script path"
  echo "example: ./python.sh bin/basicswap_prepare.py"
  exit 1
fi

cd "$(dirname "$0")"

export PYTHONPATH="$PWD:$PYTHONPATH"

# nix-build . -A nur.repos.milahu.basicswap.bindir
export DEFAULT_TEST_BINDIR='/nix/store/3pnazf7d26wlk2w90mymqjpywck627p0-basicswap-bindir'

exec python "$@"
