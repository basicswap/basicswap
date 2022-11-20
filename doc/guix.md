## Guix

Start a development environment

    guix shell --pure -L. -D basicswap


Run tests

    export PYTHONPATH=$(pwd)

    # Prepare coin binaries - required once
    python ./bin/basicswap-prepare.py -preparebinonly --withcoins=monero,bitcoin,particl,litecoin

    pytest -vs tests/basicswap/test_run.py::Test::test_02_part_ltc


Install package

    guix package --install -L. basicswap


Create a guix pack

    guix pack -RR -S /opt/gnu/bin=bin -L. basicswap
