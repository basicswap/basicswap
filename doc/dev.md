
## Install dev dependencies

    pip install -e .[dev]


## Update requirements.txt

    pip-compile requirements.in --generate-hashes --output-file requirements.txt


## Run One Test

    pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx
