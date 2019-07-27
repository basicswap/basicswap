
# Simple Atomic Swap Network - Proof of Concept

[![Build Status](https://travis-ci.org/tecnovert/basicswap.svg?branch=master)](https://travis-ci.org/tecnovert/basicswap)

## Overview

Simple atomic swap experiment, doesn't have many interesting features yet.
Not ready for real world use.

Uses Particl secure messaging and Decred style atomic swaps.

The Particl node is used to hold the keys and sign for the swap transactions.
Other nodes can be run in pruned mode.
A node must be run for each coin type traded.
In the future it should be possible to use data from explorers instead of running a node.

## Currently a work in progress

Not ready for real-world use.

Features still required (of many):
 - Cached addresses must be regenerated after use.
 - Option to lookup data from public explorers / nodes.
 - Ability to swap coin-types without running nodes for all coin-types
 - More swap protocols
 - Method to load mnemonic into Particl.
    - Load seeds for other wallets from same mnemonic.
 - COIN must be defined per coin.


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
