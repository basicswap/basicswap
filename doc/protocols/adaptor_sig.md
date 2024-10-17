# Adaptor Signature Swap protocol


## WIP

Relies on a One-Time Verifiably Encrypted Signature (OtVES) to function
An OtVES:
 - Is a valid signature for key (a) encrypted with a public key (B)
 - Can be decrypted into a valid signature for key (a) with the private key (b) to the encrypting public key (B)
 - The encrypting private key (b) can be recovered using both the encrypted and decrypted signatures.


    Offerer     - Sends the offer
    Bidder      - Sends the bid
    Leader      - Sends the first lock tx (ITX)
    Follower    - Sends the second lock tx (PTX)


NOSCRIPT_COIN lock tx:
 - Sent second.
 - Is sent to a combined key using a private key from each participant.


SCRIPT_COIN lock tx:
 - Sent first
 - Requires two signatures to spend from.
 - Refund to sender txn is presigned for and can only be mined in the future.
   - Spending the refund tx reveals the leader's NOSCRIPT_COIN split private key.
 - Sender withholds signature until NOSCRIPT_COIN lock tx is confirmed.
 - spending the spend txn reveals the follower's NOSCRIPT_COIN split private key.


```
Offerer (Leader)                                                        | Bidder (Follower)                                                             |
------------------------------------------------------------------------|-------------------------------------------------------------------------------|
o1. Sends offer                                                         |                                                                               |
    - x SCRIPT_COIN for y NOSCRIPT_COIN                                 |                                                                               |
    - Sends smsg OfferMessage                                           |                                                                               |
                                                                        | b1. Receives offer                                                            |
                                                                        |     - Validates offer                                                         |
                                                                        | b2. Sends bid                                                                 |
                                                                        |     - Sends smsgs XmrBidMessage + 2x XmrSplitMessage                          |
                                                                        |                                                                               |
o2. Receives bid                                                        |                                                                               |
    - Validates bid                                                     |                                                                               |
o3. Accepts bid                                                         |                                                                               |
    - Sends smsgs XmrBidAcceptMessage + 2x XmrSplitMessage              |                                                                               |
                                                                        |                                                                               |
                                                                        | b3. Receives bid accept                                                       |
                                                                        |     - Validates                                                               |
                                                                        |     - Signs for lock tx refund                                                |
                                                                        |     - Sends smsg XmrBidLockTxSigsMessage                                      |
                                                                        |                                                                               |
o4. Receives bidder lock refund tx signatures                           |                                                                               |
    - Sends smsg XmrBidLockSpendTxMessage                               |                                                                               |
      - Full SCRIPT_COIN lock tx                                        |                                                                               |
      - Signature to prove leader can sign for split key                |                                                                               |
    - Submits SCRIPT_COIN lock tx to network                            |                                                                               |
                                                                        |                                                                               |
                                                                        | b4. Receives XmrBidLockSpendTxMessage                                         |
                                                                        |     - Validates SCRIPT_COIN lock tx and signature                             |
                                                                        |     - Waits for SCRIPT_COIN lock tx to confirm in chain                       |
                                                                        | b5. Sends NOSCRIPT_COIN lock tx                                               |
                                                                        |                                                                               |
o5. Waits for NOSCRIPT_COIN lock tx to confirm in chain                 |                                                                               |
o6. Sends SCRIPT_COIN lock release.                                     |                                                                               |
    - Sends smsg XmrBidLockReleaseMessage                               |                                                                               |
      - Includes OtVES ciphertext signature for the SCRIPT_COIN lock    |                                                                               |
        spend tx.                                                       |                                                                               |
                                                                        |                                                                               |
                                                                        | b6. Receives offerer OtVES for SCRIPT_COIN lock spend tx.                     |
                                                                        |     - Submits SCRIPT_COIN lock spend tx to network.                           |
                                                                        |                                                                               |
o7. Waits for SCRIPT_COIN lock spend tx.                                |                                                                               |
    - Extracts the NOSCRIPT_COIN bidders key using the signature        |                                                                               |
o8. Combines the keys to spend from the NOSCRIPT_COIN lock tx           |                                                                               |
    - Submits NOSCRIPT_COIN lock spend tx to network                    |                                                                               |
```

Per swap (including the offer smsg):
- Offerer sent 6 smsgs (2 extra from split messages)
- Bidder sent 4 smsgs (2 extra from split messages)

