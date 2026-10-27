# Divi (DIVI)

Divi is a PIVX fork. Its integration follows `interface/pivx/` closely; this file records only
what is different.

## Capabilities

| | |
|---|---|
| UTXO scripts | yes |
| CLTV | yes |
| CSV | **no** |
| SegWit | **no** |
| Watch-only | yes |

`Coins.DIVI` is in `coins_without_segwit`, alongside PIVX and Dash. Offers must therefore use an
absolute lock type (`ABS_LOCK_BLOCKS` or `ABS_LOCK_TIME`) so the contract takes the
`OP_CHECKLOCKTIMEVERIFY` branch; a CSV-based offer cannot work on Divi.

Swap types:

- Secret hash: DIVI can be either side.
- Adaptor signature: DIVI can be coin B (the follower's lock) only, since coin A needs SegWit.
  To sell DIVI for a SegWit coin over an adaptor-signature swap, the offer is made as a reverse
  bid.

## Ports

divid defaults to RPC 51473 (mainnet) / 51475 (testnet) and P2P 51472 / 51474 -- the same
numbers PIVX uses, because Divi forked PIVX and never changed them. The BasicSwap entry
therefore assigns RPC 51873 / 51875 / 51877 and onion port 51872 instead.

## Wallet seeding

divid honours `mnemonic=` and `hdseed=` **only when creating a new wallet**, and has no
`sethdseed` or `upgradetohd` RPC. It reads the seed only from its command line or its conf file,
and the command line shows in the process list. `DIVIPrepare.getWalletInitDaemonArgs` therefore
writes the whole of `divi.conf` plus a `mnemonic=` line into a pipe, and `prepare.py` starts the
first daemon with `-conf=/dev/fd/N` on the read end. divid reads its conf once, at startup, so the
phrase never reaches disk or a command line; `DIVIPrepare.ensureWallet` closes the pipe once divid
answers RPC, with `getPostInitWarning` as a backstop. A platform without `/dev/fd` (Windows) is
refused rather than writing the phrase into `divi.conf`. `config_filename` is refused for Divi,
since a later `--conf` would replace the pipe.

The phrase encodes the key derived from the Particl master seed, so the same Particl mnemonic
restores the same Divi wallet; the wallet file itself holds that seed, as every core wallet does,
encrypted once a wallet password is set. Re-seeding an existing wallet is not possible over RPC --
the wallet file must be removed and the daemon restarted. `initialiseWallet` raises rather than
silently appearing to succeed.

## RPC credentials

Divi Core has no cookie auth and no `-rpcauth` option, so `prepare.py` always writes `rpcuser=` and
`rpcpassword=` into `divi.conf` and the same pair into `basicswap.json`. They come from
`DIVI_RPC_USER` / `DIVI_RPC_PWD` when set, and are generated at random otherwise.

## Node and release verification

`basicswap-prepare` installs [IronDivi](https://github.com/DiviDomains/IronDivi), a maintained
implementation of the Divi protocol, as the Divi node. Divi Core has had no commits since
2023-07-06 and no release since v3.0.0 (2023-07-14); IronDivi speaks the same P2P protocol and
the RPC calls listed below.

Each IronDivi release carries per-target archives (`irondivi-<target>.tar.gz`), a `SHA256SUMS`
file and `SHA256SUMS.asc`, a detached signature over it. `prepare.py` checks the signature
against `pgp/keys/irondivi_builder.pgp` (signer `irondivi_builder` in `interface/divi/core.py`)
and the archive's hash against `SHA256SUMS`, as it does for other coins. `irondivid` and
`irondivi-cli` are installed as `divid` and `divi-cli`. Releases exist for Linux (x86_64,
aarch64, armv7, i686, ppc64le, riscv64, s390x) and macOS (x86_64, arm64); there is no Windows
release.

## RPC quirks (differ from PIVX)

- Amounts must be JSON **numbers**; strings are rejected with
  `value is type str, expected real` by `createrawtransaction` and `sendtoaddress`.
- `getrawtransaction` wants an **int** verbose flag and rejects a JSON bool
  (`value is type bool, expected int`). `getblock` does accept a bool.
- `getblockheader` returns only `version, previousblockhash, merkleroot, time, bits, nonce` --
  no `height`, `confirmations` or `mediantime`. Use `getblock` for the first two; median time
  past is computed over the last 11 headers.
- `getblockchaininfo` has no `softforks` / `bip9_softforks` section at all.
- No multiwallet support, no `getaddressinfo`, no `rescanblockchain`, no `fundrawtransaction`,
  no `importpubkey` / `importmulti` / `importdescriptors`, no `signrawtransactionwithwallet`.
- `decoderawtransaction` has no `size` / `vsize`; fee checks fall back to the serialised length.
- Transactions are plain legacy Bitcoin (`int32 nVersion / vin / vout / uint32 nLockTime`),
  version 1. No `nType`, no Sapling -- unlike PIVX, so no `contrib/messages.py` is needed.

## Address index (required)

Divi must run with `addressindex=1`. `prepare.py` writes it into `divi.conf`, along with
`txindex=1`, before the daemon first starts.

**Why it is required.** Basicswap locates a swap output by importing the contract address as
watch-only and then asking the wallet what was paid to it. divid's watch-only support only
classifies addresses -- it does not track transactions. `importaddress` never creates a wallet
transaction, so a payment the node did not make itself is invisible to every wallet RPC.
Measured against a live participate transaction sent by another node, with the address confirmed
`iswatchonly: true`:

| Call | Result |
|---|---|
| `listunspent 0 9999999 ["<addr>"]` | `[]` |
| `listreceivedbyaddress 0 true true` | address absent, no `involvesWatchonly` entries |
| `gettransaction <txid> true` | `Invalid or non-wallet transaction id` |
| `gettxout <txid> <n>` | works, but needs the txid |

`gettxout` needs no index, but `getLockTxHeight` is a *discovery* call: it runs with `txid=None`
and learns the txid from the lookup, so it cannot be used there. The address index is the only
mechanism divid offers that answers "what is paid to this address" without wallet ownership, so
`DIVIInterface.getLockTxHeight` uses `getaddressutxos`.

**Reindex cost.**

| Case | Work required |
|---|---|
| Basicswap manages the daemon (the default) | **None.** The index is enabled before first start and builds during the initial sync. |
| An existing Divi node with `manage_daemon: false` | One `-reindex`, once. |

So a normal install needs no reindex. Only an operator reusing a node that was already synced
without the index pays that cost, and only once.

**Do not point the Divi backend at a third party's indexed node** (a block explorer's, for
example). The backend is not a read-only client -- it needs a wallet on that node for
`getnewaddress`, `getrawchangeaddress`, `dumphdinfo`, `importaddress`, `signrawtransaction` and
`sendtoaddress` -- so that would hand the swap keys to whoever runs it. Even limited to the
`getaddressutxos` query, it would mean trusting a remote operator about whether the
counterparty's HTLC exists, which is the fact the swap's safety rests on.

## Coin selection

divid has no `fundrawtransaction`, so `createRawFundedTransaction` and `fundTx` select inputs by
hand. A staking Divi wallet can spend any of its own outputs as a coinstake input at the next
block, so the selection is locked with `lockunspent` (divid honours it for coinstake), each input
is confirmed with `gettxout`, and any input lost in the window is reselected.

## Tests

- `tests/basicswap/test_prepare_divi.py`: prepare-time behaviour (RPC credentials, seed pipe, and the
  IronDivi download, hash and signature checks).
- `tests/basicswap/extended/test_divi.py`: regtest swaps against IronDivi, with PART, BTC and LTC as
  the other coin. Secret-hash and adaptor-signature swaps in both directions, refunds,
  coin B lock recovery, a private offer, a node stopped mid-swap, wallet withdraw, and the web UI.

There is no public Divi testnet faucet and testnet difficulty makes CPU mining impractical, so
funded tests use regtest, where `setgenerate <n>` mines immediately.
