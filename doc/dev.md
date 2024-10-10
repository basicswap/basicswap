
## Install dev dependencies

    pip install -e .[dev]


## Update requirements.txt

    hashin --update-all -p3.9 -p3.10 -p3.11 -p3.12 -p3.13


## Run One Test

    pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx
