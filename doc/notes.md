
## Run One Test

```
pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx
```

## TODO
Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Manual method to set wallet seeds from particl mnemonic
    - prepare script tries to load seeds automatically, btc versions < 0.21 require a fully synced chain
