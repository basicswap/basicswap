# Reverse Adaptor Signature Swap protocol



## WIP

    Offerer     - Sends the offer
    Bidder      - Sends the bid
    Leader      - Sends the first lock tx (ITX)
    Follower    - Sends the second lock tx (PTX)


The ITX must be sent from the script chain (coin A).
The side sending the ITX can be switched and the system can abstract to
users that the protocol is running in the opposite direction.


NOSCRIPT_COIN lock tx:
 - Sent second.
 - Is sent to a combined key using a private key from each participant.


SCRIPT_COIN lock tx:
 - Sent first.
 - Requires two signatures to spend from.
 - Refund to sender txn is presigned for and can only be mined in the future.
   - Spending the refund tx reveals the leader's NOSCRIPT_COIN split private key.
 - Sender withholds signature until NOSCRIPT_COIN lock tx is confirmed.
 - spending the spend txn reveals the follower's NOSCRIPT_COIN split private key.


```
Offerer (Follower)                                                      | Bidder (Leader)                                                               |
------------------------------------------------------------------------|-------------------------------------------------------------------------------|
o1. Sends offer                                                         |                                                                               |
    - x NOSCRIPT_COIN for y SCRIPT_COIN                                 |                                                                               |
    - Sends smsg OfferMessage                                           |                                                                               |
                                                                        | b1. Receives offer                                                            |
                                                                        |     - Validates offer                                                         |
                                                                        | b2. Sends bid intent message                                                  |
                                                                        |     - Sends smsg ADSBidIntentMessage                                          |
                                                                        |                                                                               |
o2. Receives bid intent message                                         |                                                                               |
    - Validates bid intent                                              |                                                                               |
o3. Accepts bid intent message                                          |                                                                               |
    - Sends smsgs ADSBidIntentAcceptMessage + 2x XmrSplitMessage        |                                                                               |
                                                                        |                                                                               |
                                                                        | b3. Receives bid intent message                                               |
                                                                        |     - Sends smsgs XmrBidAcceptMessage + 2x XmrSplitMessage                    |
                                                                        |                                                                               |
o4. Receives bid accept                                                 |                                                                               |
    - Validates                                                         |                                                                               |
    - Signs for lock tx refund                                          |                                                                               |
    - Sends smsg XmrBidLockTxSigsMessage                                |                                                                               |
                                                                        |                                                                               |
                                                                        | b4. Receives bidder lock refund tx signatures                                 |
                                                                        |     - Sends smsg XmrBidLockSpendTxMessage                                     |
                                                                        |       - Full SCRIPT_COIN lock tx                                              |
                                                                        |       - Signature to prove leader can sign for split key                      |
                                                                        |     - Submits SCRIPT_COIN lock tx to network                                  |
                                                                        |                                                                               |
o5. Receives XmrBidLockSpendTxMessage                                   |                                                                               |
    - Validates SCRIPT_COIN lock tx and signature                       |                                                                               |
    - Waits for SCRIPT_COIN lock tx to confirm in chain                 |                                                                               |
o6. Sends NOSCRIPT_COIN lock tx                                         |                                                                               |
                                                                        |                                                                               |
                                                                        | b5. Waits for NOSCRIPT_COIN lock tx to confirm in chain                       |
                                                                        | b6. Sends SCRIPT_COIN lock release.                                           |
                                                                        |     - Sends smsg XmrBidLockReleaseMessage                                     |
                                                                        |       - Includes OtVES ciphertext signature for the SCRIPT_COIN lock          |
                                                                        |         spend tx.                                                             |
                                                                        |                                                                               |
o7. Receives leader OtVES for SCRIPT_COIN lock spend tx.                |                                                                               |
    - Submits SCRIPT_COIN lock spend tx to network.                     |                                                                               |
                                                                        |                                                                               |
                                                                        | b7. Waits for SCRIPT_COIN lock spend tx.                                      |
                                                                        |     - Extracts the NOSCRIPT_COIN follower's key using the signature           |
                                                                        | b8. Combines the keys to spend from the NOSCRIPT_COIN lock tx                 |
                                                                        |     - Submits NOSCRIPT_COIN lock spend tx to network                          |
```

Per swap (including the offer smsg):
- Offerer sent 5 smsgs (2 extra from split messages)
- Bidder sent 6 smsgs (2 extra from split messages)

