# BasicSwap + Zephyr (ZEPH)

Adds **Zephyr (ZEPH)** - a Monero-derived privacy coin with a Djed-style stablecoin overlay -
as an atomic-swap coin. ZEPH rides the existing Monero adaptor-swap protocol (`xmr_swap_1`), so
it swaps against BasicSwap's UTXO coins (BTC / LTC / BCH / PART) with no new swap-protocol
code - the same shape as the Wownero coin-add.

## What this adds

- `basicswap/interface/zephyr/` - the per-coin module folder (matching the other coins):
  `zephyr.py` (the `XMRInterface` subclass), `chainparams.py` (ports, decimals, address
  prefixes), and `core.py` (the `XMRPrepare` subclass that downloads Zephyr's **official**
  `zephyr-cli` release and hash-verifies `zephyrd` + `zephyr-wallet-rpc`).
- `basicswap/chainparams.py`, `basicswap/basicswap.py`, `basicswap/bin/prepare.py` + the UI
  pages - the small central registrations (the `Coins.ZEPH` enum, the interface factory, the
  `xmr_based_coins` / `scriptless_coins` gates, the prepare dispatch, the wallet/offer/settings UI).
- `tests/basicswap/rct_distribution_proxy.py` - a small test-only localhost proxy that lets the
  stock wallet build RingCT on regtest (see note 1).
- `tests/basicswap/extended/test_zeph*.py` - ZEPH<>{BTC, LTC, BCH} adaptor-swap tests
  (happy + refund) on regtest. `test_dcr.py` gains a both-refund state-ordering tolerance that
  mirrors `test_xmr.py` (the shared `run_test_ads_*` helpers live there; the scriptless-coin
  checks already route through `xmr_based_coins`, which now includes ZEPH). ZEPH<>DASH is not
  supported (DASH has neither segwit nor a covenant, so `validateSwapType` correctly rejects an
  adaptor swap with a scriptless coin).
- `docker/production/zephyr_daemon` + `zephyr_wallet` + the two compose fragments - the
  optional containerised deployment, matching the other coins.

## Two Zephyr-specific notes for reviewers

**1. RingCT on regtest (test-only).** Stock `zephyr-wallet-rpc` hardcodes the RingCT
output-distribution query to start at the mainnet `AUDIT_FORK_HEIGHT` (block 481500), with no
per-network variant, so on a short regtest chain that height is past the tip, the daemon returns
"failed to get output distribution", and no RingCT transaction can build. Rather than patch the
binary, the ZEPH tests route the wallet's daemon RPC through
`tests/basicswap/rct_distribution_proxy.py`, which rewrites that request's `from_height` to 0 on
the wire - a strict mainnet no-op, needed only by the short-chain test. So **`prepare.py` uses
Zephyr's official, unmodified binary**; mainnet users hit none of this. (The equivalent one-line
wallet fix is also proposed upstream as
[ZephyrProtocol/zephyr#67](https://github.com/ZephyrProtocol/zephyr/pull/67), which would let the
test drop the proxy.)

**2. The Zephyr release is unsigned.** Zephyr publishes a prebuilt `zephyr-cli` but no
`SHA256SUMS` or signature, so `interface/zephyr/core.py` verifies the download against a maintained
hashes file (hash-only: `verifyCoreHash` runs, and `verifyCoreSignature` is a no-op override) - the
same model BasicSwap already uses for DOGE, which is pulled from a maintainer fork plus a hosted
`SHA256SUMS`. A signing request is open upstream as
[ZephyrProtocol/zephyr#68](https://github.com/ZephyrProtocol/zephyr/issues/68); if accepted, point
`getAssertUrl` at Zephyr's signed file and drop the no-op.

## Testing

`tests/basicswap/extended/test_zeph.py` (ZEPH<>BTC/PART) and the `test_zeph_{ltc,bch}.py`
variants exercise the happy, both-refund, and swipe-refund paths on regtest, reusing the shared
`run_test_ads_*` helpers.
