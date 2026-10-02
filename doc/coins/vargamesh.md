# VargaMesh (VMESH)

## Overview

VargaMesh is an independent Bitcoin-Core-derived UTXO blockchain.

- Ticker: `VMESH`
- Consensus: SHA-256d Proof of Work
- AuxPoW / merged mining supported
- Target block time: 120 seconds
- Native SegWit
- Mainnet Bech32 HRP: `vm`
- Testnet Bech32 HRP: `tvm`

Project website:

https://vargamesh.com/

Integration information:

https://vargamesh.com/listing/

Core source:

https://github.com/ati1993de/vargamesh-core

## Core version

The initial BasicSwap integration targets VargaMesh Core `v0.2.0`.

Mainnet and Public Testnet v1 are supported by the same Core binaries.

## Network

### Mainnet

- P2P: `29666`
- RPC: `29667`
- Bech32: `vm1...`

### Public Testnet v1

- P2P: `39666`
- RPC: `39667`
- Bech32: `tvm1...`

## BasicSwap

VargaMesh uses the Bitcoin-style UTXO and RPC model and is implemented as a
`BTCInterface` subclass.

The integration supports BasicSwap peer-to-peer, non-custodial atomic swaps.

VMESH currently has no automatic market-rate source in BasicSwap. Exchange
rates for VMESH offers are therefore entered manually.

## Core installation

Automatic VargaMesh Core downloading is intentionally not enabled in the
initial integration.

Use a verified VargaMesh Core `v0.2.0` installation and configure BasicSwap
to use the local Core binaries or an existing local VargaMesh node.

Relevant environment variables include:

- `VMESH_DATA_DIR`
- `VMESH_BINDIR`
- `VMESH_RPC_HOST`
- `VMESH_RPC_PORT`
- `VMESH_RPC_USER`
- `VMESH_RPC_PWD`

Do not expose the VargaMesh RPC port to the public Internet.
