# Handshake (HNS) native swap integration

This branch routes fixed, manual HNS/BTC offers through BasicSwap's own bid and
state database, with HSRD as the Handshake full node and `hns-wallet-rs` as the
separate encrypted HNS signing wallet. Both HNS → BTC and BTC → HNS use the
same seller-first hashlock protocol. HNS is never passed through BasicSwap's
generic Bitcoin contract interface.

The [BasicSwap coin integration guide](https://github.com/basicswap/basicswap-docs/blob/master/docs/user-guides/integrate-coin.md)
lists UTXOs, timelocks, SegWit, and watch-only monitoring as standard
prerequisites. HNS has those chain features. Its transaction encoding, witness
rules, absolute-time lock encoding, and wallet RPC differ from Bitcoin Core,
so this integration uses a dedicated protocol and the existing Rust wallet
instead of treating HSRD as a Core-compatible wallet.

## Operator setup

1. Run a synced HSRD for the selected HNS network with `--wallet-index` and
   `--transaction-relay`. Enable its authenticated wallet RPC only on loopback.
   Keep the Authorization header in an owner-only regular file under an
   owner-controlled directory. HSRD never receives an HNS signing key.
2. Run Bitcoin Core in RPC mode. BasicSwap's Bitcoin setup uses `prune=2000`;
   this HNS/BTC path does not require `txindex=1` or an unpruned node. The
   contract observer checks retained confirmed blocks from a saved height and
   block hash. After an interrupted broadcast, the replay path can locate
   exact signed transaction bytes in retained blocks without a transaction
   index. Missing pruned blocks fail closed, so keep the node online until the
   trade completes or refunds. The Core wallet must be available for funding
   and receiving the Bitcoin contract output.
3. Build the separate `hns-wallet-basicswap-bridge` binary from the companion
   `hns-wallet-rs` branch. Create or restore a **dedicated** HNS wallet from a
   terminal. The recovery phrase is displayed only during creation; back it
   up before sending funds. Use the same passphrase that unlocks BasicSwap's
   wallets. An existing wallet database cannot be overwritten by the helper.

   ```text
   python -m bin.basicswap_hns_wallet create \
     --bridge /path/to/hns-wallet-basicswap-bridge \
     --database /private/path/hns-wallet.sqlite3 \
     --network mainnet --restore-height 0
   ```

   To restore, replace `create` with `restore` and provide the backed-up
   24-word phrase at the hidden terminal prompt. A restored wallet may have a
   different wallet ID. The printed seed fingerprint is stable and is the
   value BasicSwap binds to every active HNS/BTC trade.
4. Add a `handshake` entry to the existing BasicSwap `chainclients` settings.
   Use the actual absolute paths and the fingerprint printed above. Keep
   `manage_daemon` false; BasicSwap does not launch or manage HSRD.

   ```json
   {
     "chainclients": {
       "handshake": {
         "connection_type": "rpc",
         "manage_daemon": false,
         "rpchost": "127.0.0.1",
         "rpcport": 12037,
         "rpc_authorization_file": "/private/path/hsrd-wallet.auth",
         "bridge_executable": "/path/to/hns-wallet-basicswap-bridge",
         "wallet_database": "/private/path/hns-wallet.sqlite3",
         "wallet_seed_fingerprint": "64-lowercase-hex-characters",
         "maximum_htlc_fee": 100000,
         "maximum_send_fee": 100000
       }
     }
   }
   ```

   The example port is HSRD mainnet's wallet RPC default. Keep the existing
   Particl and Bitcoin entries in `chainclients`. Particl SMSG payload version
   2 must be active, since offers and the three HNS/BTC trade messages use
   exact SMSG message IDs. The Rust wallet database has single-process
   ownership; do not open it in another wallet process while trading.
   Ordinary HNS withdrawals use a separate two-step review in BasicSwap's
   wallet page. The Rust wallet binds the destination, amount, and maximum fee
   to a short-lived approval and rechecks the transaction before broadcast.
   The send fee cap is in HNS base units (one HNS is 1,000,000 units); the
   wallet chooses the actual fee below that cap.

## Trade and recovery rules

| Maker offers | First funded lock | Taker's second lock | Maker receives | Taker receives |
| --- | --- | --- | --- | --- |
| HNS | HNS native HTLC | Bitcoin P2WSH CLTV HTLC | BTC | HNS |
| BTC | Bitcoin P2WSH CLTV HTLC | HNS native HTLC | HNS | BTC |

The offer is one-time, fixed size, and manually accepted. The maker stores the
bid, both canonical contracts, preimage, and wallet fingerprint before it
funds the first lock. Its acceptance carries the exact first outpoint and
terms commitment. The taker stores those terms before checking the first
confirmed, unspent lock; it then funds its own lock. Only after the second
lock confirms does it queue the second-lock announcement. The maker verifies
that lock before redeeming it and revealing the preimage. The taker extracts
the preimage only from a confirmed spend of its own lock. Both parties wait
for confirmed redemption on both chains before marking the bid complete.

The first funded chain has the later refund deadline. The two deadlines are
at least two hours apart, and the second deadline must remain at least two
hours away when the contracts are negotiated. HNS absolute-time CLTV uses its
high-bit 512-second encoding; the refund threshold is rounded up. The worker
checks live HSRD and Bitcoin median times, HNS sync, contract outputs,
confirmation floors, unspent status, and the remaining refund margin before
value actions. Each side can refund only its own lock after its native
threshold. Bitcoin signed bytes are stored in SQLite before broadcast; the
Rust wallet stores and reconciles its signed HNS transactions in its own
encrypted workflow. The worker also stores bounded Bitcoin scan cursors and
rewinds them if their block hash anchor changes.

An exact encrypted SMSG message is stored before delivery. Retrying a
pending bid, acceptance, or second-lock message resubmits the same bytes and
message ID. A database unique index permits one accepted maker bid per
one-time offer, including if two acceptance requests race. Restarted workers
load the saved terms and the Rust wallet's submitted transaction IDs instead
of deriving new contract keys or funding a second lock.

## Verification

The focused Python HNS tests cover codec and HSD signature vectors, term and
message validation, SQLite replay, fee and time guards, reorganization
cursors, and the app bid/acceptance/second-lock handoff. An opt-in funded
regtest starts isolated HSD, HSRD, two encrypted Rust wallet processes, and
Bitcoin Core. It runs both directions through the value controller and then
through BasicSwap's bid handlers and scheduled worker. The latter test uses a
mock SMSG transport because the isolated harness has no Particl node; it
still stores and retries exact encrypted SMSG bytes and message IDs. It also
reopens both app databases during a trade and injects a crash after the maker
funds the first lock, before its acceptance is stored. A separate opt-in Linux
test advances only isolated regtest processes under a shared clock and verifies
a funded HNS timeout refund through confirmed `SWAP_TIMEDOUT`. Another opt-in
test starts two Particl Core regtest wallets: it delivers a native HNS/BTC offer
and bid into BasicSwap's actual handlers, and delivers all three trade-envelope
types with exact `smsgimport` message IDs over SMSG v2. When both Particl
binaries are supplied to the funded two-chain harness, the BasicSwap app test
also sends each bid, acceptance, and second-lock packet through those real
Particl nodes before completing both HNS/BTC trade directions. The Rust wallet's
isolated funded regtest also sends an ordinary HNS payment through the
prepare/review/approve pipe, rejects a wrong or reused approval token, cancels
a later prepared send without retaining its coin reservation, and then funds
the HNS lock.

```text
python -m unittest discover -s tests/basicswap -p 'test_hns*.py' -q

HNS_BRIDGE_BIN=/path/to/hns-wallet-basicswap-bridge \
BITCOIND_BIN=/path/to/bitcoind \
PARTICLD_BIN=/path/to/particld \
PARTICL_CLI_BIN=/path/to/particl-cli \
python -m tests.basicswap.run_hns_bridge_regtest \
  --hsd /path/to/hsd --hsrd /path/to/hsrd \
  --wallet-repo /path/to/hns-wallet-rs --two-chain-only

HNS_BRIDGE_BIN=/path/to/hns-wallet-basicswap-bridge \
python -m tests.basicswap.run_hns_bridge_regtest \
  --hsd /path/to/hsd --hsrd /path/to/hsrd \
  --wallet-repo /path/to/hns-wallet-rs --hns-refund-clock

PARTICLD_BIN=/path/to/particld \
PARTICL_CLI_BIN=/path/to/particl-cli \
python -m unittest tests.basicswap.test_hns_particl_smsg_regtest -q
```

## Remaining release work

The live app regtest covers normal redemption, confirmed completion,
interrupted maker acceptance in both directions, and a Bitcoin reorganization
before maker redemption. The HNS timeout refund passes with real HSD, HSRD,
and the Rust wallet under one isolated clock; the Bitcoin refund has a funded
Core regtest. A separate two-node Particl regtest covers real SMSG v2 offer and
bid handling. The combined app regtest runs funded trades in both directions
while Particl carries the three trade packets; the offer row is seeded after
the separate real offer-delivery check. Package and version the Rust bridge
and HSRD for BasicSwap's supported platforms. HNS now participates in
BasicSwap's password change: the Rust store re-encrypts all records and
key-derived private origin indexes in one transaction, checkpoints old
ciphertext, closes its runtime, and reopens under the new passphrase. If the
bridge reports `passphrase_changed_checkpoint_pending`, the database already
uses the new passphrase; retry a new unlock to finish the checkpoint. Release
qualification against the packaged binaries remains before HNS is presented
as a fully supported asset.

Companion source: [HSRD wallet RPC](https://github.com/handshake-rs/hns-node-rs/blob/main/docs/WALLET_RPC_V1.md)
and [hns-wallet-rs bridge contract](https://github.com/handshake-rs/hns-wallet-rs/blob/main/docs/BASICSWAP_BRIDGE.md).
