# RIN Notes

## Release

Rincoin Core is downloaded from https://github.com/Rin-coin/rincoin/releases.
`SHA256SUMS` is checked against `SHA256SUMS.asc`, signed by the subkey
`0ED99C46B2192E375381EF4AC5BEF8A9FA06C16F` of key
`ED20B6354EE4526D01F83B538B6E3BF45C714ECA`.

The x86_64 Linux build of 1.1.0 is linked dynamically and needs glibc
2.38 or later. On Ubuntu 24.04 rincoind needs libboost-filesystem1.83.0,
libboost-thread1.83.0, libevent-2.1-7t64, libevent-pthreads-2.1-7t64,
libfmt9, libminiupnpc17, libsqlite3-0 and libzmq5. The BasicSwap Docker
image is not covered.

## Transaction version

From block 840,000 every transaction other than the coinbase must have
version `0x52494e33` ("RIN3", RIP-0009). BasicSwap builds every swap
transaction with that version. A withdrawal is sent by the node wallet;
BasicSwap does not set its version.

Rincoin Core v1.1.0 or later is required, also for a node that BasicSwap
does not manage: v1.0.6 and earlier refuse transactions with this
version as non-standard.

## Not supported

- MWEB and Taproot are not active on Rincoin mainnet.
  `getDestForAddress` and `isValidAddress` refuse a witness version 1
  address for RIN. A withdrawal address is passed to the node wallet as
  it is.
- There is no Electrum mode for RIN.
