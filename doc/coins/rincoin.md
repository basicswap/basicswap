# Rincoin Notes

## Overview

Rincoin is a Litecoin fork with the following features:
- **SegWit:** Enabled
- **Taproot:** Supported
- **MWEB (Mimblewimble Extension Block):** Supported (like Litecoin 0.21+)
- **Block Time:** 60 seconds (1 minute)
- **Halving Interval:** 210,000 blocks

## Network Ports

### Mainnet
- **P2P Port:** 9555
- **RPC Port:** 9556

### Testnet
- **P2P Port:** 19555
- **RPC Port:** 19556

### Regtest
- **P2P Port:** 29555
- **RPC Port:** 29556

## Address Formats

### Mainnet
- **Legacy (P2PKH):** Starts with "R" (base58 prefix: 60)
- **P2SH:** Starts with "r" (base58 prefix: 122)
- **Bech32 (SegWit):** Starts with "rin1..."
- **MWEB:** Starts with "rinmweb..."

### Testnet
- **Legacy (P2PKH):** Starts with "T" (base58 prefix: 65)
- **P2SH:** Starts with "t" (base58 prefix: 127)
- **Bech32 (SegWit):** Starts with "trin1..."

### Regtest
- Uses same format as Bitcoin regtest (starts with "m" or "bcrt")

## Installation

### Using Local Build

If you have Rincoin Core already built locally:

1. Set the `bindir` in your BasicSwap config to point to your Rincoin build:
   ```
   "rincoin": {
       "bindir": "/path/to/rincoin/src"
   }
   ```

2. BasicSwap will look for `rincoind`, `rincoin-cli`, and `rincoin-wallet` in that directory.

### Using Binary Downloads

When official Rincoin binaries are released:

```bash
basicswap-prepare --preparebinonly --withcoin=rincoin --bindir=~/basicswap/bin
```

## Configuration

Default configuration is automatically generated. You can customize in `rincoin.conf`:

```ini
# Network
rpcport=9556
rpcallowip=127.0.0.1
rpcbind=127.0.0.1

# Storage
prune=4000

# Addresses
changetype=bech32

# Authentication
rpcauth=user:salt$hash
```

## Wallet Features

### HD Wallet Support
Rincoin supports HD (Hierarchical Deterministic) wallets using the `sethdseed` RPC command.

### MWEB Wallet
Like Litecoin, Rincoin supports MWEB (Mimblewimble Extension Block) for enhanced privacy:
- Create MWEB addresses: `getnewaddress "label" "mweb"`
- MWEB addresses provide better privacy
- MWEB transactions are more compact

### Address Types
You can generate different address types:
- **Legacy:** `getnewaddress "label" "legacy"`
- **P2SH-SegWit:** `getnewaddress "label" "p2sh-segwit"`
- **Bech32:** `getnewaddress "label" "bech32"` (default)
- **MWEB:** `getnewaddress "label" "mweb"`

## BasicSwap Integration

### Initialization

Initialize BasicSwap with Rincoin:

```bash
basicswap-prepare --datadir=~/.basicswap --withcoins=rincoin --particl_mnemonic="your mnemonic"
```

### Running

Start BasicSwap with Rincoin enabled:

```bash
basicswap-run --datadir=~/.basicswap
```

### Testing on Regtest

For development and testing:

1. Start Rincoin in regtest mode
2. Mine some blocks: `rincoin-cli -regtest generatetoaddress 101 <address>`
3. Configure BasicSwap to use regtest chain

## Resources

- **Official Website:** https://www.rincoin.net/
- **GitHub Repository:** https://github.com/Rin-coin/rincoin
- **Block Explorer:** https://rinscan.net/
- **Whitepaper/Docs:** TBD

## Compatibility

- **Rincoin Core Version:** 0.21.4 or higher recommended
- **BasicSwap Version:** Requires version with Rincoin support
- **RPC Interface:** Compatible with Bitcoin/Litecoin RPC
- **MWEB:** Fully compatible with Litecoin MWEB implementation

## Known Issues

None currently. Please report issues to the BasicSwap or Rincoin repositories.

## Development

For developers integrating Rincoin:
- Inherits from `LTCInterface` in BasicSwap
- Supports all Litecoin features including MWEB
- Uses same atomic swap contracts as Litecoin
- Compatible with existing Litecoin-based swap protocols

## Support

For BasicSwap-specific Rincoin questions:
- Matrix: [#basicswap:matrix.org](https://matrix.to/#/#basicswap:matrix.org)

For Rincoin Core questions:
- Check the official Rincoin resources above
