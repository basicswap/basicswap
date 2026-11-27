# NORTH Notes

TrueNorth Core is a fork of Bitcoin Core v30 with RandomX proof of work and
120 second blocks, https://github.com/truenorth-project/truenorth.

## Confirmations and lock times

TrueNorth consensus refuses a reorg deeper than 72 blocks.  Shallower reorgs
are cheap on a small RandomX network, so TrueNorth's exchange guidance is to
wait for more than 72 confirmations, and to use 100.  `blocks_confirmed` is
100 for NORTH, about 3 hours 20 minutes.

BasicSwap allows `blocks_confirmed` × 120 s × 3, 10 hours, for a NORTH txn to
confirm.  What that changes:

- A bid waiting for the other side's coin A lock tx or initiate tx times out
  20 minutes (`sc_lock_tx_timeout`) after its last state change, or 12 hours
  (`sc_lock_tx_mempool_timeout`) once that tx is in a block or the coin A lock
  tx has been seen in the mempool.  This applies to every coin.
- The release and spend margins on the coin A refund lock are at least the
  coin A allowance, 10 hours for NORTH as coin A.
- A coin B lock tx is sent only with those margins plus the coin B allowance
  left on the coin A refund lock, 10 hours or more with NORTH on either side.
- In a secret hash swap the seller redeems the participate txn, which reveals
  the secret, only with the coin's allowance left on the participate txn
  refund lock, 10 hours for NORTH.
- The leader watches for a mercy tx for 200 blocks with NORTH as coin A, twice
  `blocks_confirmed`.  This assumes the follower also waits 100 blocks before
  sending it.
- An offer whose lock time could not meet these margins even if every txn
  confirmed at once is refused when it is made or received: under 10 hours
  plus the coin B allowance with NORTH as coin A (about 10.3 hours with XMR),
  under 11 hours with NORTH as coin B and BTC as coin A, and under about 20
  hours for a secret hash swap with NORTH on either side.

The lock time also has to leave room for the confirmations themselves:

- Adaptor signature swaps need about 14 hours with NORTH as coin A, or 20.5
  hours if its 100 confirmations take three times as long as expected, and
  about 11.5 hours with NORTH as coin B.  The default of 24 hours covers both.
- Secret hash swaps from or to NORTH need 30 hours or more, 32 to be safe.  The
  offer page allows 24 hours at most; set the lock time through the API
  (`lockseconds`), or swap with adaptor signatures.

A bid plan holds its ready legs at most an hour, counted from the first ready
leg, for a sibling's coin A lock tx to confirm.  With NORTH as coin A that
covers siblings mined within about an hour of the first.  A held leg stops
waiting while it can still send its coin B lock tx or participate txn.

Keep the node online until a swap completes.  Two late steps can't be covered
by a margin, they are what ends the swap: a participant redeeming the initiate
txn of a secret hash swap close to its refund, and a leader spending the coin A
lock refund tx close to `lock_time_2`.  On NORTH a reorg of up to 72 blocks
can undo either if it runs late.

## Wallet

TrueNorth Core has descriptor wallets only.  The wallet's default address type
is P2QRH (witness v2, `north1z...`); the node config sets `addresstype` and
`changetype` to `bech32`, and swap txns use P2WPKH and P2WSH outputs.  A swap
destination address must be a type BasicSwap builds, a P2QRH address is
refused there.  Withdrawals are sent by the node wallet and can pay a P2QRH
address.

## Releases

Releases are published for linux-x86_64, macos-arm64 (macOS 13 or later) and
windows-x86_64.  On other platforms, Docker on Apple silicon included, build
TrueNorth Core from source and point `bindir` at it, or run the node yourself.

The linux-x86_64 build needs glibc 2.38 and GLIBCXX_3.4.32 or later, and links
libevent, libnuma and SQLite dynamically.  On Ubuntu 24.04 install
`libevent-core-2.1-7t64`, `libevent-extra-2.1-7t64`,
`libevent-pthreads-2.1-7t64`, `libnuma1` and `libsqlite3-0`.  The BasicSwap
Docker image (Debian trixie-slim) doesn't include them.

`SHA256SUMS` is signed by subkey 895B7591E9701E99D87D58A9B932A2FBD92C626D of
the release key 3F0BAE0458615427B8CA935E3E242DF5E4478AE5.  The key signs every
release, so prepare also requires the archive's own line in `SHA256SUMS`.
Release candidates are published unsigned, prepare can't install them.

## Rates

NORTH is not listed on any of the rate sources, offers show no market rate.
