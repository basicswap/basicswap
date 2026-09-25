# Handshake (HNS) integration status

This branch starts a native HNS integration in BasicSwap. **HNS is not yet a
tradable or selectable asset.** The read-only HSRD adapter, transaction codec,
signature digest, canonical HTLC verifier, and client for the local
`hns-wallet-basicswap-bridge` are isolated under `basicswap/interface/hns/`.
No coin ID, offer path, or UI asset entry has been enabled.

Source snapshot: BasicSwap `5471e609b9fbcba1a528dac60e2e06fc2f1a8ca4`,
HSRD `c0785719db68a574a13fba224af5ff34ead13c3e`, and hns-wallet-rs
`f5a6a77841f34bf5a601df83de2900f76605df43`. Recheck these contracts
when updating either project.

## Compatibility result

BasicSwap's [coin integration guide](https://github.com/basicswap/basicswap-docs/blob/master/docs/user-guides/integrate-coin.md)
asks for a UTXO script chain, CLTV or CSV, SegWit, and watch-only monitoring.
Handshake has UTXOs, witness programs, both lock opcodes, and an indexed script
history and UTXO read path. HSRD does **not** provide a Bitcoin Core style
wallet, `importaddress`, `fundrawtransaction`, or wallet signing RPC. The
standard BasicSwap requirements script assumes a Core-like daemon and cannot
establish HSRD wallet compatibility by itself.

| Requirement | HNS / HSRD evidence | BasicSwap consequence |
| --- | --- | --- |
| UTXO scripts | HNS transaction outputs contain an address and covenant; HNS consensus executes witness scripts. | Implement a native HNS transaction and script interface. |
| CLTV / CSV | `hns-consensus` implements `OP_CHECKLOCKTIMEVERIFY` and `OP_CHECKSEQUENCEVERIFY`. | Use HNS's high-bit, 512-second absolute-time encoding and its sequence policy. |
| Witness | Every HNS input has a witness section after locktime. | Do not use Bitcoin's marker/flag serialization or txid calculation. |
| Watch-only | HSRD `--wallet-index` exposes `confirmed_scripts_page`, `mempool_scripts_page`, and ordered spender evidence over authenticated `/api/v1/wallet`. | BasicSwap must persist the scripts it owns and reconcile the index across restarts/reorgs; there is no `importaddress` equivalent. |
| Spend authorization | HSRD never holds keys or signs transactions. hns-wallet-rs already implements HNS funding, signing, native HTLC lock/redeem/refund, encrypted workflow state, and recovery over an HSRD adapter. | Reuse hns-wallet-rs through a BasicSwap-specific bridge; no new HNS wallet implementation is needed. |

HSRD's `tracked_contract_*` reads cannot currently be used as the only swap
watch: the public wallet RPC reports descriptor registration as
`unavailable_unpublished_protocol_boundary`. Script history and spender reads
are the available public evidence path. They still require BasicSwap to verify
the exact expected output address, amount, covenant, funding bytes, spend
branch, and witness/preimage locally.

## Implemented here

- `HnsNodeRpc` connects only to loopback and the authenticated wallet v1 route.
  It checks an exact network genesis under one chain epoch before script queries.
  Its confirmed-page collector splits script sets under HSRD's default 65,536
  byte request limit, rejects a changed epoch or tip, and discards partial
  results on a stale response. It is read-only.
- `HnsTransaction` encodes and decodes the HNS base/witness format and computes
  the native Blake2b-256 txid and witness hash. HSD-generated codec vectors
  verify the format.
- `signature_hash` computes the HNS BIP143-style Blake2b digest, including
  NOINPUT, ANYONECANPAY, SINGLE, and SINGLE_REVERSE. All 32 HSD oracle vectors
  from HSRD's pinned fixture pass.
- `HnsHtlc` parses the wallet's canonical `hns-swap` v1 descriptor under an
  expected network binding, reproduces its exact witness script and descriptor
  hash, and rejects a funding output with a different amount, script address,
  or covenant. The pinned `hns-rs` protocol fixture passes.
- `HnsWalletBridge` launches a separately named trusted-native wallet process
  over a versioned, bounded, sequential local pipe. It carries BasicSwap's
  offer/bid IDs, a pre-bid session nonce, and the exact HTLC descriptor, and validates returned transaction
  IDs, branch observations, and revealed preimages. The companion Rust binary
  is implemented in the local `hns-wallet-rs` `basicswap-bridge` branch. That
  binary opens one existing encrypted HNS account over its HSRD adapter and
  exposes key lookup, lock funding/verification, redeem/refund, spend
  observation, and durable rebroadcast without exporting signing keys.
- `HnsBtcSwapTerms` reconstructs the exact HNS and Bitcoin contracts from
  canonical, bounded bid and acceptance messages. It verifies a shared
  SHA-256 hashlock, both chains' recipient/refund roles, amounts, HNS network,
  minimum confirmations, and the commitment before exposing the announced
  first outpoint. It enforces a later refund on the first funded chain in
  either trade direction. This outpoint remains an untrusted hint until the
  applicable node verifies its funding output and confirmations.
- `BtcHtlcContract` prepares a Bitcoin Core wallet-funded P2WSH lock, verifies
  the exact confirmed unspent output, signs either native SegWit redeem or
  CLTV refund witnesses with a swap key, and scans confirmed blocks for the
  validated spend branch and revealed preimage. It returns signed raw bytes to
  the caller for durable persistence before broadcast. The isolated Bitcoin
  Core regtest test exercises both trade role mappings, redeem, and refund.
- `HnsBtcSwap` records the pre-bid session ID, nonce, exact accepted contracts,
  lock outpoints, Bitcoin prepared transaction bytes, and scan cursor in the
  BasicSwap database (schema version 39). The record helpers reject changed
  identities or terms and can reconstruct an accepted trade after the refund
  window closes. `trade_protocol.py` now constructs and binds the bid,
  acceptance, and second-lock messages to that row in both trade directions,
  including a maker restart between terms persistence and acceptance. The
  BasicSwap message handlers and periodic recovery worker do not yet call it.
- `HnsBtcSettlement` connects the two native value adapters to that persisted
  record. It gates the taker's funding on the maker's confirmed first lock,
  requires HSRD's sync scheduler to agree with its wallet chain tip, checks
  both nodes' median times and the live funding window, and persists
  Bitcoin signed bytes before broadcast. It supports redeem, refund, and a
  confirmed witness observation in either role mapping. Its bounded Bitcoin
  spend scanner persists a canonical block anchor, rewinds on a reorg, and
  leaves a found spend in the next scan range for rechecking after restart.
  BasicSwap's message dispatcher and bid worker still need to call it.

The focused Python tests pass. An isolated HSD and HSRD regtest pair, with
HSRD's `--wallet-index --mining-engine --transaction-relay`, exercised the
Rust bridge against an indexed live chain. A fresh encrypted HNS wallet
received an ordinary transfer, funded an HNS HTLC, verified its lock after
the account's two required confirmations, redeemed with the preimage, and
observed the spend. The bridge's ignored live test records this setup. It is
an HNS settlement test; a funded two-chain BasicSwap trade has not passed.

These Python components are independent evidence and encoding checks. The
spend-capable implementation is already in hns-wallet-rs; BasicSwap should use
its native wallet and `hns-swap` settlement code. A passing Python fixture does
not connect BasicSwap's offer protocol to that wallet.

## Reuse of hns-wallet-rs

The wallet repository already has `HnsNodeRpcBackend` for authenticated HSRD
wallet RPC, `HnsWalletRuntime` for HNS accounts and transaction workflows, and
`hns-swap::HnsHtlc` for a SHA-256 preimage/absolute-CLTV contract. Its market
module also has signed direct HNS/BTC and BTC/HNS offers, bilateral sessions,
funding watches, and evidence-driven redeem/refund recovery. The
`hns-wallet-service` library exposes trusted-native HTLC lock, verification,
redeem, refund, broadcast, and cancel methods. Its encrypted state and
reconciliation logic provide the HNS-side recovery machinery. These are the
components to adapt for BasicSwap; the HNS wallet and swap primitives do not
need to be rebuilt.

The default `hns-wallet-service` executable only processes the private ABI's
control operations. The new `hns-wallet-basicswap-bridge` is separately named
and uses trusted-native library APIs without adding value operations to that
browser/provider ABI. It opens a single existing encrypted account, accepts
only canonical HNS HTLC operations over a local process pipe, derives local
  settlement keys inside the wallet from the offer ID and nonce, and recovers the ID of a durably submitted
lock/redeem/refund after response loss. The Python HSRD client here can
cross-check chain observations; it is not a substitute for the wallet's node
adapter.

BasicSwap's existing seller-first contract uses an `OP_SIZE` check, a public-key
hash branch, and a CSV refund by default. The canonical `HnsHtlc` commits to
compressed receiver/refund public keys and an absolute CLTV refund. The
wallet's signed direct-offer/session envelopes are also a distinct protocol
from BasicSwap's offer and bid messages. The swap message and script
verification paths must agree on one exact HNS descriptor; the existing
Bitcoin contract cannot be sent to the HNS wallet unchanged.

## BTC ↔ HNS trade order

Both directions use seller-first funding and one 32-byte preimage selected by
the maker. The taker generates and persists a random 32-byte nonce before its
bid so its HNS settlement public key can be derived before BasicSwap assigns
the bid ID. The maker binds that bid, both exact contracts, and the first
funding outpoint in its acceptance message. The taker must verify the
acceptance commitment and first on-chain lock before funding the second lock.
The maker then redeems the second lock, revealing the preimage; the taker
redeems the first. Each party must resume observation and its own refund after
restart or a counterparty disconnect.

| Offered by maker | First lock | Second lock | Maker's receive branch | Taker's receive branch |
| --- | --- | --- | --- | --- |
| HNS | HNS HTLC | Bitcoin CLTV HTLC | Bitcoin | HNS |
| BTC | Bitcoin CLTV HTLC | HNS HTLC | HNS | Bitcoin |

The first refund becomes spendable at least two hours after the second, and
the second remains at least two hours from negotiation. HNS absolute time uses
its high-bit 512-second median-time encoding; the threshold is rounded up
when chosen. An implementation must also check live chain median times,
confirmation progress, fee policy, and remaining refund margin before every
funding action. The message and terms code does not yet run BasicSwap's bid
state machine or perform either chain's funding and spend actions.

## Work needed before an HNS asset can be enabled

1. Complete the native HNS coin interface around the address and transaction
   primitives already in this branch. Use HNS's six decimal places and its
   own money, dust, covenant, and policy rules, rather than BTC defaults.
2. Route the new bid and acceptance messages through a BasicSwap HNS/BTC
   protocol variant. Generate and persist the random nonce before sending the
   bid, derive the taker's HNS receive key, and retain the assigned bid ID.
   Persist the exact negotiated contracts and commitment on both peers before
   any value operation. The current message/terms classes have no network
   handlers or database mapping yet.
3. Complete bridge installation and wallet lifecycle: create/restore a
   dedicated HNS account, arrange protected unlock and HSRD Authorization
   delivery, supervise the sidecar, and reconcile BasicSwap's persisted bid
   identity with the wallet's persisted settlement identity after a restart.
   hns-wallet-rs now has a one-shot atomic create/restore mode and BasicSwap has
   a private-pipe client for it. The bridge exposes a stable seed fingerprint
   for comparing an unlocked account after restore; wallet IDs differ between
   create and restore. The UI and application startup do not yet
   call those paths. The HNS value path has passed funded regtest.
   HSRD remains its full-node backend.
4. Wire BasicSwap's offer and bid state machine to that bridge, including
   restart/reorg reconciliation and the correct mapping between BasicSwap
   states and the wallet's persisted settlement states. Verify the exact
   amount, plain covenant, script address, funding outpoint, spend branch,
   and preimage before crediting a lock or completion.
5. Wire the new coin ID, chain parameters, prepare/install configuration,
   daemon supervision, offer eligibility, UI/API display, and protocol routing
   only after the spend and recovery paths exist.
6. Exercise both swap directions on isolated HNS regtest against another
   BasicSwap asset: normal redeem, timeout refund, counterparty disconnect,
   restart, reorg, fee rejection, malformed witness, and stale index reads.
   Inspect exact raw transactions and on-chain outcomes before enabling
   mainnet offers.

HSRD requires active native sync, `--wallet-index`, and a private
`--rpc-authorization-header-file` for the wallet route. The BasicSwap side must
keep that authorization value private and use a dedicated local wallet/account
authority. The node's `broadcast_transaction` accepts already signed HNS
bytes; it never supplies signing authority.

## Reference source

- [BasicSwap's Bitcoin coin interface](https://github.com/basicswap/basicswap/blob/master/basicswap/interface/btc/btc.py)
  and [coin registration](https://github.com/basicswap/basicswap/blob/master/basicswap/chainparams.py).
- [HSRD wallet RPC contract](https://github.com/handshake-rs/hns-node-rs/blob/main/docs/WALLET_RPC_V1.md)
  and [consensus primitives](https://github.com/handshake-rs/hns-node-rs/tree/main/crates/hns-consensus).
- [hns-wallet-rs](https://github.com/handshake-rs/hns-wallet-rs) for the
  existing signing, HTLC, and recovery implementation, including its
  [native service APIs](https://github.com/handshake-rs/hns-wallet-rs/blob/main/crates/hns-wallet-service/src/native_value_runtime.rs).
