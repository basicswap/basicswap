0.12.2
==============

- Updated coincurve and libsecp256k1 versions.
  - Avoids needing secp256k1_generator_const_g as it's not accessible from a dll.
- Fix missing ripemd160 on some systems.


0.12.1
==============

- Firo and Navcoin send utxo outpoints with proof of funds address+sig.
  - Avoids missing scantxoutset command
  - Firo Bids will be incompatible with older versions.
  - Bids for other coins should still work between versions.
- Firo uses workarounds for missing getblock verbosity and rescanblockchain
- Coins without segwit can be used in reverse adaptor sig swaps.


0.11.68
==============

- Temporarily disabled Navcoin.
  - Untested on mainnet.
- Fixed bug where requesting a new XMR subaddress would return an old one.


0.11.67
==============

- Added support for p2sh-p2wsh coins
- Added Navcoin
- Fixed Particl fee estimation in secret hash swaps.
- Raised adaptor signature swap protocol version to 2
  - Not backwards compatible with previous versions.


0.11.66
==============

- Fixed bugs in getLinkedMessageId and validateSwapType.


0.11.65
==============

- smsg: Outbox messages are removed when expired.
- Fixed BTC witness size estimation.
- Added option to remove Offers and bids from the database automatically one week
  after they expire if they have no active bids.
  - Controlled by new settings: expire_db_records and expire_db_records_after
- ui: Show ITX and PTX status for adaptor sig type swaps.


0.11.64
==============

- protocol: Added reversed Adaptor sig protocol.
  - Runs the adaptor-sig protocol with leader and follower swapped to
    enable offers from no-script coins to script coins.

- Raised adaptor signature swap protocol version
  - Not backwards compatible with previous versions.


0.11.63
==============

- cores: Raised Particl and Monero daemon version.
- ui: Add debug option to remove expired offers, bids and transactions.
- ui: The abandon bid button is hidden if not in debug mode.
  - Abandoning a bid stops all processing.


0.11.62
==============

- ui: Persistent filters
- ui: Show only active bid and offer counts
- protocol: Require signature for chain B key half for same chain adaptor signature swaps.
  - Adaptor signature swaps are not backwards compatible with previous versions.


0.11.61
==============

- GUI 2.0


0.11.60
==============

- Accepted bids will timeout if the peer does not respond within an hour after the bid expires.
- Ensure messages are always sent from and to the expected addresses.
- ui: Add pagination and filters to smsgaddresses page.
- Removed dependency on particl-tx.
- Updated btcfastsync urls and signatures, added --skipbtcfastsyncchecks option to basicswap-prepare
  - If --skipbtcfastsyncchecks is set the script will use any file with a name matching the
    BITCOIN_FASTSYNC_FILE env var in the datadir without checking it's size or signature.


0.11.59
==============

- Added total_bids_value_multiplier option to automation strategies.
  - System won't automatically accept a bid for an offer if the sum of the values of all completed
    and in-porgress bids and the candidate bid exceeds total_bids_value_multiplier times the offer value.
  - default is 1.0.
- ui: The rpc page can send commands over http.
  - Must manually specify the argument types bsij for (bool, string, int, json).
- Removed error message for unprocessed revoke messages.
  - Some nodes won't have all messages.
- Started test framework for scripts.
- api: Can abandon bids.
- If wallets are encrypted the system will only load in-progress bids when unlocked rather than at startup.
- Can set overrides for automation strategies per identity.
- ui: Bids on expired offers won't show as available.
- api: getcoinseed shows seed id.
- ui: Can edit automation strategy data.
- ui: Fix pagination clearing filters
- Added restrict_unknown_seed_wallets option.
  - Set to false to disable unknown seed warnings.
- ui: Can edit offer automation strategy.


0.11.54
==============

- If the XMR daemon is busy the wallet can fail a transfer, later sending the tx unknown to bsx.
  - Check for existing transfers before trying to send the chain b lock tx.
  - Check for transfers in XMR_SWAP_SCRIPT_COIN_LOCKED state when bid is sent.
  - Continually try refund noscript lock tx in XMR_SWAP_FAILED state.
- showLockTransfers will attempt to create a wallet if none exists.
- tests:
  - Add B_LOCK_TX_MISSED_SEND debug event and test.
- Store the Dash wallet password in memory for use in upgradetohd
- Remove false positive warning.  Check for unlock_time transfer is not unlocked.
- ui:
  - Add 'Remote Key Half' to Show More Info section (with debug_ui on)
- api:
  - An unknown path will return an error instead of the default/index data.


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
