
0.17.4
==============

**Security / hardening**
- Particl blind swaps: verify the lock-tx-spend output pays the expected address.

**Electrum**
- Confirmations are now Merkle-verified against the block header.
- Watch-only (keyless) balances are no longer included in spendable wallet balances.

**Fixes**
- Config: a string `allowed_hosts` value is normalised to a single-element list rather than
  being iterated per character.
- Added an `unsafe_allow_any_host_without_auth` override to run with `"*"` in `allowed_hosts`
  without `client_auth_hash` set.
- AMM: fixed the AMM UI connection under Docker when `htmlhost` is set to `0.0.0.0`.
- Active-swap loops: snapshot `swaps_in_progress` before iterating.
- Queued swap actions now retry on transient daemon/RPC errors instead of failing the
  action outright.
- Particl blind swaps: attach the mercy output on the lock-refund swipe tx

**Tests / CI**
- CI runs the `test_coins` suite for Particl blind and Particl anon (in addition to plain
  Particl) when `interfaces/part` changes.
- CI pytest suites now exit early on the first failure.
- Added tests for Merkle proofs, Electrum median time, adversarial Electrum responses,
  transient-action retries and Electrum watch-only balances.


0.17.3
==============

**Security / hardening**
- Web UI: added a Host-header allowlist to defend against DNS-rebinding attacks.
  Requests whose `Host` header is not `localhost` / `127.0.0.1` / `::1` (or a
  configured host) are now rejected. A new `allowed_hosts` setting lists additional
  hostnames/origins for LAN, mDNS or reverse-proxy access; loopback access — including
  Docker with the port published to localhost — needs no configuration.
- Web UI: the cross-origin (CSRF) check now validates the request `Origin`/`Referer` as a
  full origin (scheme + host + port) against the allowed origins.
- Web UI: the WebSocket server now validates the handshake `Origin`, closing a cross-site
  WebSocket hijack. Browsers cannot spoof `Origin`.
- `allowed_hosts` entries may be a bare host (matches any scheme/port on that host) or a
  full `scheme://host[:port]` origin (exact match, for reverse proxies). `"*"` disables
  only the Host-header check and requires `client_auth_hash` to be set; the Origin/CSRF and
  WebSocket origin checks remain enforced.
- Adaptor-sig swaps: constrain which bid states accept the lock-release,
  coin-A-lock-signature and lock-spend P2P messages, and reject messages for
  revoked/inactive offers. Prevents a hostile or replayed peer message from mutating a
  finished/terminal bid or resurrecting it into an active swap.

**Fixes**
- GUI: the header "Bids" link navigates to the correct page.
- Electrum: use .onion servers only when Tor is enabled.

**AMM**
- Remove a redundant fixed-total offers check.
- Offers: correct the fixed-total budget calculation for reverse adaptor-sig swaps.

**Tests**
- Unit tests for the Host allowlist, same-origin and WebSocket origin checks.
- Added Particl blind/anon coverage to `test_coins.py`.


0.17.2
==============

**Security / hardening**
- Adaptor-sig swaps: track the coin A lock refund tx to `blocks_confirmed` depth before
  publishing the lock refund spend tx. The refund spend reveals the leader's key share
  to the counterparty; publishing it while the refund tx is still unconfirmed could let
  a released follower recover that share and race both legs of the swap.
- Adaptor-sig swaps: wait for the coin B lock tx to reach spendable depth before the
  follower broadcasts a chain B lock refund recovery spend (`recoverXmrBidCoinBLockTx`),
  matching the existing gate on the leader redeem path.
- Particl spent-index watcher: skip spends reported by `getspentinfo` until they have a
  known block height, matching the Electrum feeder's confirmed-only behaviour.

**Fixes**
- BCH adaptor-sig swaps: re-arm the mercy-tx watched script when reloading in-progress
  bids after a restart. The watch was only kept in memory and could be lost in the
  pre-refund state, so a mercy tx arriving after restart might go unnoticed.
- Create Offer: align manual single-offer contract-lock presets with AMM (quick-pick
  4/8/12/24 h, default 24 h, max 24 h; was 12/24/48/72 h with default 32 h).
- AMM edit UI: remove a stray lock-time option that did not belong on the template
  edit form.

**AMM**
- Send offer revoke messages as POST (was GET).
- Revoke standing offers when an in-flight or completed swap changes the offer's
  effective availability (fixed-total / standing logic).
- AMM tables: send a revoke when disabling an offer from the GUI, so the network copy
  is withdrawn immediately instead of waiting for the next automation cycle.

**GUI**
- Bid page: live updates over WebSocket (`bid_changed` events) so swap progress
  refreshes without manual reload.
- Bid page: clearer human-readable state descriptions for adaptor-sig and secret-hash
  swaps, including confirmation-depth context where relevant.
- Bid page: show a green status indicator while a bid is actively progressing.

**Tests**
- BTC→XMR: regression test that the leader does not publish the lock refund spend
  while the lock refund tx is unconfirmed.
- BCH→XMR: regression test that the mercy-tx watch is re-armed after reload.


0.17.1
==============

**Security / hardening**
- BTC/LTC adaptor-sig swaps no longer classify unrecognised spends of the chain A lock tx
  as refunds. Only exact matches against the precomputed spend/refund txids are accepted
  (the prevout fallback remains for BCH, where txids are malleable), preventing a malicious
  Electrum server from forcing a false pre-refund state.
- Electrum fee estimates exceeding the configured high_feerate are rejected at the source
  and fall back to the default rate. The fee-rate ceiling is also enforced when combining
  non-segwit prevouts. Prevents fee-inflation griefing by a malicious Electrum server.
- Act on Electrum-reported spends only once confirmed, matching full-node behaviour.
- Auto-migrate imported private keys still stored in the legacy XOR format to AEAD
  (ChaCha20-Poly1305) on first access.
- Validate and rate-limit Simplex connection request invitations before passing to /connect.
- Only dispatch route links belonging to the connected route on Simplex contact-connected events.

**Fixes**
- Fix crash in spendBLockTx when the Electrum backend fails to return the chain B lock tx
  or the expected output is missing; getBLockTxo now fails closed with a clear error
  instead of raising UnboundLocalError.
- Keep the BCH mercy tx watch alive when an unrelated tx pays the watched script.
- Don't attempt queued actions while the system is locked.

**AMM (v0.5.1)**
- Fix duplicate offers.
- Fix template save regression that blocked editing, disabling, deleting, and adding
  templates when any standing offer had min_coin_from_amt of 0.
- Restore min_coin_from_amt = 0 as a valid wallet floor for standing offers
  (0 = no reserve, sell until the wallet is empty). Only negative values are rejected.
- Saving the config from the form now validates the whole file first and reports all
  failing templates instead of only the first.
- The page keeps a backup of the config before add/edit/enable/disable/delete and
  restores it if the server rejects the save, keeping the screen in sync with what is
  actually saved.
- Edit form no longer drops a stored minimum balance of 0; editing a template preserves
  fields that are not shown in the form.
- AMM start wizard no longer requires a positive minimum balance on all enabled offers.
- Allow duplicate template names; restore the default offer name.
- Remove duplicate template name rejection from the AMM add/edit UI.
- Remove duplicate name checks when creating offer/bid templates via the API.
- Remove duplicate name validation from validate_amm_config() for offers and bids.
- Pre-fill new template modal with "Unnamed Offer" again instead of an empty name.
- Update test: duplicate names are allowed
  - aligned with createoffers.py, which renames name → name_2, etc. on load.

**GUI**
- Offer page: searchable send-from address dropdown (by label or address), limited to
  the 50 most recent addresses to prevent the browser hanging with large address lists.
  The currently selected address is always included.
- Wallet page: fix buttons and the type-to svg.

**Prepare**
- Uses a separate gpg homedir (DATADIR/gnupg) so imported PGP pubkeys stay isolated when not
  running in docker.
- PGP pubkeys are imported before verifying signatures
  - Avoids "Signature made by unknown key." warnings.

**Tests / CI**
- Run BCH/LTC CI tests only when coin-specific code changes
- Add test_amm_config_api to CI.


0.17.0
==============

- Updated DB (v37)
- GUI bumped to v4.0.0.
  - Live table updates via WebSocket (+ new_offer, offer_revoked, offer_expired, swaps, bids).
  - Template validation (client + server).
  - UI badges: offer mode, running offers/bids, exhausted, fixed-total progress, stale/revoked/expired.
  - Updated enable/disable toggle (green/red), save via API.
  - Update footer design.
  - Fix header counter desk/mobile.
  - GUI: Create Offer redesign
    - Market rate comparison and estimated network fee.
    - Added: Failed publishes keep your data so you can retry from review and correct your offer settings.
    - Better alerts (success/error/default).
    - Table of competing offers.
    - Offer modes:
      - One-time: fills once, then auto-closes (new default for manually created offers).
      - Fixed total: repeats until a cumulative total_to_sell is reached, then closes.
      - Standing: repeats continuously, skipping new offers while the wallet would drop below a reserve floor (min_coin_from_amt). Default for AMM templates.

- AMM updates:
  - Added version. (v0.5.0)
  - AMM/New offer page: per-offer budget and fill tracking so an offer can't be filled more times than intended.
  - JSON APIs: POST /amm/config, GET /amm/state (runtime + bid runtime).
  - Script persists fill progress across restarts / backend aggregates live fills across reposts.

- feat: set a destination address for reversed (adaptor-sig) swaps.New: 3-step flow: Trade → Terms → Review, plus a dedicated success page after published.

**Security**
This release hardens the local web UI against a malicious page in the user's
browser and against untrusted callers.
- Enable Jinja2 autoescape in templates.
- Add a CSRF token to forms.
- Block cross-origin POST requests.
- Require POST for state-changing JSON endpoints.
- Restrict the URL scheme allowed for js_readurl.
- Prevent path traversal in /static file serving.
- Harden the shutdown token, debug_ind, and session cookie.
- Restrict wallet seed export to local or authenticated callers.
- Encrypt imported Electrum-wallet private keys with AEAD (ChaCha20-Poly1305, per-record
  random nonce, domain-separated master-derived key). Decryption stays backward compatible
  with the legacy format.

**Fixes**
- interface/bch: use lock_time_1 for the lock-refund-tx input nSequence.
- fix: bind BCH covenant timelocks to the offer.
- fix: use the bip44 path for the wallet seedid in descriptor mode.
- fix: clamp the Electrum fee estimate for withdrawals.
- fix: ensure bid_rate is positive.
- fix: lock prefunded bid tx inputs, and add lock_unspent to _fundTxElectrum.
- http: use the correct application/json header.

**Startup / unlock robustness**
- Require all wallets to unlock before unlocking the system.
- Don't treat an RPC timeout as a missing seed during unlock; retry getWalletSeedID with
  exponential backoff and raise on persistent failure instead of wrongly running
  sethdseed/encryptwallet on an existing, still-locked wallet.
- Skip checkAndNotifyBalanceChange while the system is locked.
- Extend the getnetworkinfo timeout so slow daemons don't stop basicswap on startup.

**AMM**
- Skip templates with inactive coins instead of killing the AMM.
- Don't autostart the AMM while the system is locked.
- Add contract lock time to the GUI and script; remove a stray lock time option.

**Refactors**
- xmr: only open_wallet when a wallet change is expected.
- Keep coin specific code more contained to interface folders:
  - Move chainparams into each coin's folder and migrate interface/contrib into the coin dirs.
  - Untangle bin/prepare.py.
- Consolidate linter config and remove unused code.

**Tests**
- Add all coins to test_xmr_persistent.py.
- Add new test_coins.py which works for any coin pair.
- CI: split into a matrix and run jobs concurrently.
- test_offer.py (Selenium test).
- New tests covering AMM offer tracking, test_amm_config_api.py.


0.16.6
==============

- feat: ui add skip fee checks checkbox when placing bids
- build: add alternative dash release signer

**Fixes**
- fix: Improve Part anon and blind scriptless lock tx detection and spending
- fix: Add more limits to split messages
- fix: Check if offer matches reverse state for incoming messages
- fix: solve BCH regression not finding refund txns.
  - Add haveSignedLockRefundTx
- Firo spark withdraw fix
- Prevent reused receive addresses and fix the gap-limit calculation in the Electrum HD wallet.
  - Previously an address could be handed out again even after it had already been used,
    and the gap-limit check looked at the total derivation index instead of the run of
    trailing unused addresses, so address reuse could trigger at the wrong time.
  - This adds an ever_used flag to wallet addresses (with a DB migration for existing wallets),
    only recycles addresses that were never used, and bases the gap-limit decision on the number
    of unused addresses at the end of the chain. Addresses are marked used when they're handed out or first receive funds.
- amm: dialog fixes
  - amm: ensure swap type auto-updates
  - amm: dont silently change the coin_to when both coins are the same

**Refactors**
- swaps: only enforce secret hash if both coins are same type
- refactor: ease validateFeeRate limits
- refactor: use gettxout in getLockTxHeight() when possible
- refactor: log event for invalid ptx seen
- refactor: log event for invalid lock tx a
- refactor: check pending transfers before sending xmr lock tx
- refactor: reduce log clutter
  - Show xmr_b_half_privatekey_remote debug message only when it's expected to be there.

**Updates**
- dash: Bump to 23.1.4 mandatory
- particl: Bump to 27.2.4


0.16.5
==============

- Updated docker base images to Debian Trixie.
- By default reject secret hash type offers where the coin pair could use adaptor sig swap.
  - override with "strict_swap_type" setting.
- Verify follower's script chain lock refund tx sig.


0.16.4
==============

- Security: Always require the initiate tx output index and value for secret hash swaps.
  - Strengthens the 0.16.3 fix: the amount check can no longer be skipped when the output value is unavailable; the swap is now rejected (fails closed) instead of proceeding.
- Security: Also double check the participate tx output amount for secret hash swaps.
- Raise minimum Python version to 3.11.


0.16.3
==============

- Automatic fee validation.
  - Prevent sending bids to offers
  - Reject received offers, and
  - Prevent sending offers where the chain feerates are out of range.
  - Valid feerate range is the node's estimated feerate for confirmation in 24 blocks to 4x the estimated feerate.
    - The minimum feerate confirmation can be adjusted with the "low_fee_conf_target" setting.
    - If "low_feerate" is set above 0 it is used instead of the dynamic feerate with "low_fee_conf_target".
    - The maximum feerate multiplier can be adjusted with the "high_estimated_feerate_multiplier" setting.
    - If "high_estimated_feerate_multiplier" is set below 1.0 the max feerate can be set with the "high_feerate" setting.
- New setting "startup_delay":
  - Adjusts the time waited for coin daemons to start between "startup_tries".
  - Valid as a base setting and can be overridden per coin with chainclients settings.
- Add subfee bids.
  - Enables a user to create a bid specifying the amount before the lock tx fee.
    - Currently only works when the coin to is not XMR like.
- Set Adaptor sig bid type as default where possible.
- UI:
  - offer page:
    - Fixed feerate from other chain displayed for reversed swaps.
    - Added warning text for fee above 1.2 x local estimate.
    - Added subfee bid option.
- Increase DCR fee estimate by 1 byte.
- Waits for the refund and refund spend txn locks to expire before trying to submit them.
- Fixed bug where initiate tx amount was not checked for secret hash swaps.


0.14.5
==============

- ui: Fixed incorrect swap direction shown on active swaps page.
- ui: Fixed incorrect amounts shown on active swaps page for reverse swaps.
- cores: Firo  v0.14.14.1
  - Required for hardfork on 2025-05-28.
- Allow starting with a subset of configured coins.
  - New `--withcoin` and `--withoutcoin` options for basicswap-run.
- Timeout waiting for mutex on shutdown.
  - Waits a maximum of 5 seconds for any processing to complete.


0.14.2
==============

- BCH support.
- Mercy outputs on swipe txns of BTC descended coins.
  - Disable by setting 'altruistic' to false in basicswap.json
- Removed sqlalchemy.
- Incoming expired offers no longer raise an error.


0.13.2
==============

- Remove protobuf and protoc dependencies.
- Include mnemonic dependency directly.


0.13.1
==============

- coins: Add Decred.


0.13.0
==============

- GUI v3.0
- Bid and offer states change when expired.
- bid amounts are specified directly and not constructed from rate.
- Breaks compatibility with prior versions.
- Added enabled_chart_coins setting for which coins to show on the offers page.
  - Blank/unset for active coins.
  - All for all known coins.
  - Comma separated list of coin tickers to show.
- basicswap-run will rewrite litecoin.conf file to add config required to run Litecoin 0.21.3 in pruned mode.
- On new offers page a blank amount-from is auto-filled from amount-to and rate.


0.12.7
==============

- basicswap-prepare
  - Sets --usetorproxy automatically when tor is enabled on existing installs for commands that access the network.
    - Disable with --notorproxy
  - Switch the LTC download URL to github (works over Tor)
  - Sets `wshost` to match `htmlhost` by default
- doc: Simplify docker tor install notes.
- Basicswap will set monero-wallet-rpc proxy when Tor is enabled if the host ip setting (`rpchost`) for the monerod instance is not a private ip.
  - Works for automatically selected daemons too.
  - Override with a `use_tor` parameter in the Monero section of basicswap.json.
- Basicswap sets monero-wallet-rpc `--trusted-daemon` if the host ip setting for the monerod instance is a private ip.
  - Override with the `trusted_daemon` parameter in the Monero section of basicswap.json.
    - Defaults to auto.
      - Override in basicswap-prepare with `--trustremotenode`
- Add settings in basicswap.json to set Monero rpc timeouts
  - `rpctimeout`, `walletrpctimeout` and `walletrpctimeoutlong` in the Monero section of basicswap.json.
  - `wallet_update_timeout` in basicswap.json to set how long the wallet ui page waits for an rpc response.
- ui: Renamed unconfirmed balance to pending and include immature balance in pending.
- Fixed LTC create utxo.
- ui: Changed 'Subtract Fee' option to 'Sweep All' on XMR wallet page.
- ui: Added An Estimate Fee button on XMR wallet page.
- ui: Added a Force Refresh button on XMR wallet page.
  - get_balance (if called) at the end of withdrawCoin is correct, subsequent get_balance calls return old balance for a while.


0.12.6
==============

- ui: Display count of locked UTXOs on wallet page.
  - Only shows if locked UTXOs is > 0


0.12.5
==============

- Unlock wallets logs an error when failing to unlock a wallet.
- Fixed bug where failed unlock prevents processing incoming smsg messages.


0.12.4
==============

- LTC creates a new wallet to hold MWEB balance.
  - MWEB wallet should be be automatically created at startup or when unlocked if system is encrypted.


0.12.3
==============

- New basicswap-run parameter startonlycoin.
  - If set basicswap-run will only start the specified coin daemon/s.


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
