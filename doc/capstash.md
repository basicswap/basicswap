# CapStash integration status

CapStash support is experimental and local-binary-only. The BasicSwap identifier
`CAPS` is provisional because CapStash Core does not publish an authoritative
exchange ticker. Mainnet descriptor-wallet initialisation is disabled because no
authoritative SLIP-0044 assignment was found; the integration does not borrow
another project's registered coin type.

Automatic preparation and download are deliberately disabled. CapStash releases
do not currently provide a maintainer-controlled signed checksum chain suitable
for BasicSwap package verification. Users must supply locally built `CapStashd`
and `CapStash-cli` paths with `CAPS_BINDIR`.

## Tested source and binaries

The runtime binaries were built locally from the CapStash Core v27.1.0 tag target,
commit `892c5018f9d51c1a7f67bbdbb3b3945a663ed0b7`. The source commit is GitHub
web-flow verified; this is not a maintainer-signed release tag or binary checksum
attestation.

The extended mining and swap tests require a locally built, test-only regtest
easy-proof-of-work fixture. The hashes below identify the fixture used for the
reported validation; reviewers must set the expected hashes to the values of
their own locally built fixture.

| Executable | Tested SHA-256 |
| --- | --- |
| `CapStashd.exe` | `3701ca15eedd780644bd40a7d820bfc64b5bd321ca78986434597db259773872` |
| `CapStash-cli.exe` | `8f2704ab3314191a89860f7c444de04c8e141e69db54e64affb2f39db75c9e3b` |

Starting from CapStash Core commit
`892c5018f9d51c1a7f67bbdbb3b3945a663ed0b7`, the fixture applies exactly these
two source changes:

```diff
diff --git a/src/kernel/chainparams.cpp b/src/kernel/chainparams.cpp
@@
-        consensus.powLimit = uint256S("00000001fffe0000000000000000000000000000000000000000000000000000");
+        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
diff --git a/src/pow.cpp b/src/pow.cpp
@@
     if (params.fPowNoRetargeting) {
-        return pindexLast->nBits;
+        return bnPowLimit.GetCompact();
     }
```

These changes are test-only, unsuitable for mainnet and unsuitable for
production binaries. They are required because the unmodified v27.1.0 regtest
proof-of-work target makes maturity and swap testing impractical. Every node in
a multi-node test must use one consistently built fixture. The binaries and
patch are not used by BasicSwap production execution.

## Canonical reviewer suite

Run the explicit suite loader below from the repository root. Set the binary
paths to isolated local test artifacts; do not point them at production
installations or datadirs.

```powershell
$env:CAPS_BINDIR='C:\path\to\hash-pinned\capstash-regtest-easy-pow'
$env:CAPS_DAEMON_SHA256='<sha256-of-local-CapStashd>'
$env:CAPS_CLI_SHA256='<sha256-of-local-CapStash-cli>'
$env:PARTICL_BINDIR='C:\path\to\isolated\particl-test-binaries'
$env:BITCOIN_BINDIR='C:\path\to\isolated\bitcoin-test-binaries'
$env:PYTHONWARNINGS='default'
python -m unittest -v tests.basicswap.extended.test_capstash_suite
```

The loader names 15 tests explicitly, including the nine intended swap and
recovery methods, so inherited unrelated methods are not discovered. The suite
keeps both chains advancing during restart-during-refund coverage, uses a
30-block CapStash sequence lock, and asserts that the lock is still immature
immediately after restart.

The unmodified locally built v27.1.0 binaries had these hashes:

| Executable | SHA-256 |
| --- | --- |
| `CapStashd.exe` | `7200bd38361054a0cbd39f1a2ce50e245419641f6b5c83854fd5cd7e31e8580a` |
| `CapStash-cli.exe` | `1ce260d6f4f9eb3906cc6f250344730b4dbfe31a0edc575add959a281a5d2b78` |

The unmodified build confirmed startup, regtest selection, RPC identity,
descriptor wallet creation, private-key-disabled wallet creation, descriptor
inspection, and descriptor import. It was not used for maturity mining, funded
transaction tests, or swaps. The patched build exercised the complete standalone
probe and the BasicSwap tests below.

## Swap-critical compatibility

`CapStashInterface` subclasses the current `BTCInterface`. Source inspection
found no CapStash transaction or wallet encoding changes that require an
override. Runtime and swap tests provide the following evidence:

| Area | Implementation and evidence | Status |
| --- | --- | --- |
| Transaction version and serialization | Current BTC interface constructs standard version-2 Bitcoin-like transactions; funded and signed CapStash transactions were accepted. | Swap-confirmed |
| Locktime and sequence | Standard CLTV and CSV paths passed the standalone runtime probe; both refund-oriented swap tests reached their refund transaction. | Runtime- and swap-confirmed |
| Scripts and witness | Standard P2SH/P2WSH and SegWit handling is inherited; bidirectional lock and redeem transactions confirmed. | Swap-confirmed |
| Transaction IDs and sighash | Standard double-SHA256 transaction IDs and Bitcoin-like signature hashes are inherited; both directions signed, broadcast, and redeemed. | Swap-confirmed |
| Fee conversion | The shared interface converted the node's `0.00001000 CAPS/kB` relay fee to the BasicSwap integer fee rate. Fresh-regtest `estimatesmartfee` returned insufficient data and the interface selected `relayfee`. | BasicSwap-test-confirmed |
| Relay fee and dust | Runtime policy tests found minimum accepted outputs of 294 satoshis for P2WPKH and 330 satoshis for the tested P2WSH lock script; one satoshi less was rejected as dust. Low-fee rejection, multi-input funding, change creation and fee subtraction also passed. | BasicSwap-test-confirmed for tested scripts |
| Address encoding | Audited CapStash Base58 prefixes and `rcap` regtest HRP are in modular chain parameters. Bech32 receive and swap addresses worked. | Runtime- and swap-confirmed |
| Output lookup and raw decoding | Shared BTC RPC lookup and decoding found lock spends and redeems. Historical arbitrary lookup may still require node transaction visibility or `txindex`. | Swap-confirmed with stated constraint |
| Confirmations | Shared block-height and confirmation logic advanced both swap directions to completion. | Swap-confirmed |
| `lockunspent` | Exercised successfully by the standalone probe and normal swap wallet flows. | Runtime-confirmed |
| Wallet load/unload | CapStash did not auto-load the tested wallet after daemon restart; explicit `loadwallet` restored it and its balance. | Runtime-confirmed |
| Descriptor watch wallet | A blank private-key-disabled descriptor wallet imported the expected descriptor, recognized the script and UTXO, survived unload and daemon restart, and still could not sign. The recovered wallet was used through BasicSwap's known-vout output-discovery path. Legacy `iswatchonly` is not authoritative here. | Recovery-confirmed |
| Restart persistence | Both normal and watch wallets required explicit reload. Daemon-restart tests preserved the live CapStash lock transaction ID in both swap directions and completed with one spend. BasicSwap-process restart tests reloaded the existing database/configuration and completed both directions without changing lock transaction IDs. | Recovery-confirmed |
| Reorg recovery | A two-node controlled regtest invalidated a one-block-confirmed representative P2WSH lock output. BasicSwap reported confirmation depth dropping to zero, the transaction returned to the mempool, and a distinct replacement branch reconfirmed the same transaction. | Reorg-confirmed for a representative lock; no full active-swap reorg |
| Active-swap recovery | Live CapStash daemon restart and BasicSwap-process restart passed in PART → CAPS and CAPS → PART after lock broadcast/confirmation and before completion. A CAPS → PART refund test also restarted CapStash after the initiate lock confirmed and before maturity, then confirmed exactly one refund. | Recovery-confirmed |

## Test topology and results

`test_capstash_multinode.py` launches two hash-gated CapStash nodes with unique
temporary datadirs, loopback-only RPC and P2P ports, cookie authentication,
disabled discovery/DNS/onion connections, and independent descriptor wallets. It
confirmed peer connection, 102-block propagation, coinbase maturity, transaction
propagation and confirmation, balance visibility, daemon restart, explicit wallet
reload, and clean shutdown.

`test_capstash_swaps.py` follows the current upstream extended-test architecture.
It launches three isolated CapStash nodes alongside isolated Particl and Bitcoin
test nodes and separate BasicSwap instances. RPC credentials are generated at
runtime and are not stored in the repository.

The following secret-hash script-swap and recovery paths passed:

* PART to CAPS: initiate and participate locks confirmed, both redeem
  transactions confirmed, and the bid reached the completed state.
* CAPS to PART: initiate and participate locks confirmed, both redeem
  transactions confirmed, and the bid reached the completed state.
* PART to CAPS refund-oriented path: after deliberately preventing the normal
  initiate spend, the Particl initiate refund and CapStash participate spend
  were observed and the test completed.
* CAPS to PART refund-oriented path: the CapStash initiate refund was broadcast,
  found by chain scanning, and the test completed.
* PART to CAPS and CAPS to PART with the relevant CapStash daemon stopped after
  a live lock was confirmed, explicitly restarted, and required wallets loaded:
  the original lock transaction ID remained stable, one spend was observed,
  and each bid completed.
* PART to CAPS and CAPS to PART with the CapStash-wallet operator's BasicSwap
  instance cleanly finalized and reconstructed from its existing isolated
  configuration and database while chain daemons remained running: both lock
  transaction IDs remained stable and each bid completed.
* CAPS to PART with the CapStash daemon restarted after the initiate lock
  confirmed but before refund maturity: the original lock and preconstructed
  refund transaction IDs remained stable, the early refund was rejected as
  `non-BIP68-final`, both descriptor wallets were explicitly reloaded, exactly
  one mature refund confirmed, the counterchain spend appeared exactly once,
  terminal states were correct, and all watches cleared.

These are the current framework's secret-hash script-swap refund tests. Direct
pre-maturity rejection and later CLTV/CSV acceptance were independently exercised
by the standalone runtime probe. The controlled reorg test covers confirmation
loss and recovery for a representative swap-like P2WSH output, not a complete
active swap across a reorg.

`test_capstash_policy.py` records the v27.1.0 regtest node's policy rather than
assuming Bitcoin defaults. It confirmed a `0.00001000 CAPS/kB` relay and
incremental fee, insufficient fresh-chain smart-fee data, relay-fee fallback,
294-satoshi P2WPKH and 330-satoshi tested P2WSH dust boundaries, low-fee
rejection, two-input funding, change at output position zero, and fee
subtraction from a requested `0.02000000` output to `0.01996460`.

## Descriptor wallet semantics

For modern descriptor wallets, `private_keys_enabled=false`, descriptor
ownership/solvability, imported script recognition, UTXO observation, and signing
failure without private keys are the relevant assertions. The legacy
`iswatchonly` address field can remain false even when the private-key-disabled
wallet correctly observes the imported descriptor. This is expected behavior,
not evidence that the wallet holds private keys.

CapStash v27.1.0 did not automatically reload the test wallet after a daemon
restart. Test and production orchestration must call `loadwallet` for the named
normal and watch wallets when they are not listed by `listwallets`; it must not
silently recreate them.

## Remaining blockers

Distribution remains blocked by the absence of a maintainer-signed checksum
manifest, published signing-key fingerprint, signed release tag, and reproducible
build attestations. Mainnet wallet initialization also remains blocked pending an
authoritative SLIP-0044 assignment. Before production use, repeat all tests
against a production-suitable consensus build and add longer-running multi-peer,
deep/repeated reorg, full active-swap reorg, adverse process-termination, and
long-duration soak coverage. The present extended harness runs all BasicSwap
instances inside one Python process, so an abrupt kill cannot safely isolate one
instance; clean in-process reconstruction is proven, abrupt process death is
not. The test-only easy-PoW build is not a production artifact.
