
## Run One Test

```
python setup.py test -s tests.basicswap.test_xmr.Test.test_02_leader_recover_a_lock_tx
```

## TODO
Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Manual method to set wallet seeds from particl mnemonic
    - prepare script tries to load seeds automatically, btc versions < 0.21 require a fully synced chain


## Seller first protocol:

Seller sends the 1st transaction.

1. Seller posts offer.
    - smsg from seller to network
        coin-from
        coin-to
        amount-from
        rate
        min-amount
        time-valid

2. Buyer posts bid:
    - smsg from buyer to seller
        offerid
        amount
        proof-of-funds
        address_to_buyer
        time-valid

3. Seller accepts bid:
    - verifies proof-of-funds
    - generates secret
    - submits initiate tx to coin-from network
    - smsg from seller to buyer
        txid
        initiatescript (includes pkhash_to_seller as the pkhash_refund)

4. Buyer participates:
    - inspects initiate tx in coin-from network
    - submits participate tx in coin-to network

5. Seller redeems:
    - constructs participatescript
    - inspects participate tx in coin-to network
    - redeems from participate tx revealing secret

6. Buyer redeems:
    - scans coin-to network for seller-redeem tx
    - redeems from initiate tx with revealed secret
