# Seller first protocol

Seller sends the first transaction.
Both coin types must support scripts.


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
