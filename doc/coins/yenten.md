# Yenten Notes

## Overview

Yenten is a CPU-only cryptocurrency focused on fair mining accessibility. It uses the YespowerR16 algorithm, which is designed to be more efficient on CPUs than on GPUs or ASICs. Yenten is based on Bitcoin Core with SegWit support.

- **Algorithm:** YespowerR16 (CPU mining only — GPU is slower than CPU)
- **SegWit:** Enabled
- **Block Time:** 2 minutes (120 seconds)
- **Block Reward:** 50 YTN (initial coinbase reward)
- **Halving Interval:** 800,000 blocks
- **Max Supply:** 80,000,000 YTN
- **Difficulty Adjustment:** Every block (DarkGravityWave v3-1)
- **Premine:** None

## Network Ports

### Mainnet
- **P2P Port:** 9981
- **RPC Port:** 9982

### Testnet
- **P2P Port:** 19981
- **RPC Port:** 19982

## Address Formats

### Mainnet
- **Legacy (P2PKH):** Starts with "Y" (base58 prefix: 78)
- **P2SH:** Starts with "5" (base58 prefix: 10)
- **Bech32 (SegWit):** Starts with "ytn1..."

### Testnet
- **Legacy (P2PKH):** Starts with "m" or "n" (base58 prefix: 111)
- **P2SH:** Starts with "2" (base58 prefix: 196)
- **Bech32 (SegWit):** Starts with "tytn1..."

### Regtest
- **Legacy (P2PKH):** base58 prefix: 111
- **P2SH:** base58 prefix: 196
- **Bech32 (SegWit):** Starts with "rytn1..."

## Installation

### Using Binary Downloads

```bash
basicswap-prepare --preparebinonly --withcoin=yenten --bindir=~/basicswap/bin
```

### Using Local Build

If you have Yenten Core already built locally:

1. Set the `bindir` in your BasicSwap config to point to your Yenten build:
   ```
   "yenten": {
       "bindir": "/path/to/yenten/src"
   }
   ```

2. BasicSwap will look for `yentend`, `yenten-cli`, and `yenten-wallet` in that directory.

## Configuration

Default configuration is automatically generated. You can customize in `yenten.conf`:

```ini
# Network
rpcport=9982
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
Yenten supports HD (Hierarchical Deterministic) wallets using the `sethdseed` RPC command.

### Address Types
You can generate different address types:
- **Legacy:** `getnewaddress "label" "legacy"`
- **P2SH-SegWit:** `getnewaddress "label" "p2sh-segwit"`
- **Bech32:** `getnewaddress "label" "bech32"` (default)

## BasicSwap Integration

### Swap Protocol
Yenten uses P2PKH and P2SH scripts for atomic swaps via the `BTCInterface` base class. It does not support MWEB or other extension block features.

### Initialization

Initialize BasicSwap with Yenten:

```bash
basicswap-prepare --datadir=~/.basicswap --withcoins=yenten --particl_mnemonic="your mnemonic"
```

### Running

Start BasicSwap with Yenten enabled:

```bash
basicswap-run --datadir=~/.basicswap
```

## Resources

- **Official Website:** https://yentencoin.info/
- **GitHub Repository:** https://github.com/yentencoin/yenten
- **Core Version:** v6.0.4 (tested)

## Compatibility

- **Yenten Core Version:** 6.0.4 or higher recommended
- **BasicSwap Version:** Requires version with Yenten support
- **RPC Interface:** Compatible with Bitcoin RPC
- **BIP44 Coin Type:** 420

## Known Issues

None currently. Please report issues to the BasicSwap or Yenten repositories.

## Support

For BasicSwap-specific Yenten questions:
- Matrix: [#basicswap:matrix.org](https://matrix.to/#/#basicswap:matrix.org)

For Yenten Core questions:
- Discord: https://discord.gg/UnKHXvu
- Telegram: https://t.me/yenten
- Reddit: https://www.reddit.com/r/Yenten/
