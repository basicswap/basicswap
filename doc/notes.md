
## Run One Test

```
pytest -v -s tests/basicswap/test_xmr.py::Test::test_02_leader_recover_a_lock_tx
```


## Private Offers

To send a private offer:
 1. Recipient creates a new address to receive offers on.
 2. Recipient sends the pubkey for the newly created address to the offerer.
 3. Offerer imports the recipient's pubkey.
 4. Offerer sends a new offer to the recipients key instead of the public network.

Nodes will ignore offers sent on keys other than the network key or keys created for offer-receiving.


## TODO

Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Manual method to set wallet seeds from particl mnemonic
    - prepare script tries to load seeds automatically, btc versions < 0.21 require a fully synced chain
