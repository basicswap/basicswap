
0.0.x
==============


0.0.32
==============

- Experimental tor integration


0.0.31
==============

- XMR swaps: Coin to balance is checked before sending a bid.
- Use getblockhashafter command in getWalletRestoreHeight where possible.
  - Avoids rpc Errno 49 issue
  - Reuse rpc connection when getblockhashafter is not available.


0.0.30
==============

- Core launch log messages are written to disk.
- Fixed bug when manually redeeming noscript lock tx with invalid amount.


0.0.29
==============

- Use unique key path per key type.
  - Incompatible with previous versions.
- XMR swaps: Can manually spend chain B lock tx if both keys are known.


0.0.28
==============

- Set working dir to datadir for daemons.
- Remove requests module dependency by implementing HTTP digest authentication client.
  - Reduces log messages
- New 'debug_ui' mode, locktime can be specified in minutes.
  - Must also reduce the 'min_sequence_lock_seconds' setting.


0.0.27
==============

- Track failed and successful swaps by address.
- Added rate lookup helper when creating offer.
- Prevent old shutdown link from shutting down a new session.
- ui: Connected XMR wallet to rpc page.
- Separate chain to generate smsg addresses.
- ui: Display XMR subaddress on wallets page.


0.0.26
==============

- Added protocol version to order and bid messages.
- Moved chain start heights to bid.
- Avoid scantxoutset for decred style swaps.
- xmr: spend chain B lock tx will look for existing spends.
- xmrswaps:
  - Setting state to 'Script tx redeemed' will trigger an attempt to redeem the scriptless lock tx.
  - Node will wait for the chain B lock tx to reach a spendable depth before attempting to spend.
- ui: Sort settings page by coin name.
- ui, xmr: List of candidate remote XMR daemon urls can be set through the http ui.


0.0.25
==============

- Fix extra 33 bytes in lock spend fee calculation.
- XMR swaps use watchonly addresses to save the lock tx to the wallet
  - Instead of scantxoutset.
- Add missing check of leader's lock refund tx signature result.
- Blind part -> XMR swaps are possible:
  - The sha256 hash of the chain b view private key is used as the nonce for transactions requiring cooperation to sign.
  - Follower sends a public key in xmr_swap.dest_af.
  - Verify the rangeproofs and commitments of blinded pre-shared txns.
- Add explicit tests for all paths of:
  - PARTct -> XMR
  - BTC -> XMR
  - LTC -> XMR


0.0.24
==============

- Can swap Particl Anon outputs in place of XMR


0.0.23
==============

- Enables private offers.


0.0.22
==============

- Improved wallets page
  - Consistent wallet order.
  - Separated RPC calls into threads.


0.0.21
==============

- Raised Particl and Monero daemon versions.
- Display shared address on bid page if show more info is enabled.
- Added View Lock Wallet Transfers button to bid page.


0.0.6
==============

- Experimental support for XMR swaps
  - Single direction only, scriptless -> XMR.
