# Adding a New Coin to BasicSwap

This guide describes the complete process for integrating a new cryptocurrency into BasicSwap. This document was created while adding Rincoin (a Litecoin fork) to the platform.

## Overview

Adding a new coin to BasicSwap requires changes across multiple layers:
1. Chain parameters definition
2. Coin interface implementation  
3. Binary download and preparation
4. Configuration file generation
5. UI/Frontend updates

## Prerequisites

- Understanding of the coin's blockchain parameters (ports, genesis, seeds, etc.)
- Access to the coin's core binaries or ability to build them
- GPG signing keys for binary verification (if available)
- Knowledge of which existing coin your new coin is forked from

## Step-by-Step Integration Guide

### 1. Add Coin to Chain Parameters

**File:** `basicswap/chainparams.py`

#### 1.1 Add to Coins Enum
```python
class Coins(IntEnum):
    PART = 1
    BTC = 2
    LTC = 3
    # ... existing coins ...
    RINCOIN = 19  # Add new entry with next available number
```

#### 1.2 Add Chain Parameters Dictionary Entry
Add a new entry to the `chainparams` dictionary. For a Litecoin fork like Rincoin:

```python
Coins.RINCOIN: {
    "name": "rincoin",
    "ticker": "RIN",
    "message_magic": "Rincoin Signed Message:\n",  # Or use Litecoin's if unchanged
    "blocks_target": 60 * 1,  # Block time in seconds (60 = 1 minute like LTC)
    "decimal_places": 8,
    "mainnet": {
        "rpcport": 9556,  # Your RPC port
        "pubkey_address": 48,  # Same as LTC if fork preserves address format
        "script_address": 5,
        "script_address2": 50,  # For segwit
        "key_prefix": 176,
        "hrp": "rin",  # Bech32 human-readable part
        "bip44": 2,  # Use LTC's or get your own
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
    "testnet": {
        "rpcport": 19556,  # Typically rpcport + 10000
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "trin",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
        "name": "testnet4",
    },
    "regtest": {
        "rpcport": 19557,
        "pubkey_address": 111,
        "script_address": 196,
        "script_address2": 58,
        "key_prefix": 239,
        "hrp": "rrin",
        "bip44": 1,
        "min_amount": 100000,
        "max_amount": 10000000 * COIN,
    },
},
```

**Important Parameters to Check:**
- `rpcport`: Default RPC port (9556 for Rincoin mainnet)
- `pubkey_address`, `script_address`: Address version bytes
- `hrp`: Bech32 prefix for segwit addresses
- `message_magic`: Used for message signing
- `blocks_target`: Average block time in seconds

### 2. Create Coin Interface

**File:** `basicswap/interface/rincoin.py` (new file)

For a simple Bitcoin/Litecoin fork, you can inherit from `BTCInterface` or `LTCInterface`:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2025 The Basicswap developers
# Distributed under the MIT software license, see the accompanying
# file LICENSE or http://www.opensource.org/licenses/mit-license.php.

from .ltc import LTCInterface  # Or .btc import BTCInterface
from basicswap.chainparams import Coins


class RINCOINInterface(LTCInterface):  # Inherit from parent coin
    @staticmethod
    def coin_type():
        return Coins.RINCOIN

    def __init__(self, coin_settings, network, swap_client=None):
        super(RINCOINInterface, self).__init__(coin_settings, network, swap_client)
        # Add any Rincoin-specific initialization here

    # Override any methods that differ from parent coin
    # For example:
    # def getNewAddress(self, ...):
    #     # Custom implementation
```

**If your coin has significant differences**, you may need to override more methods. Check the parent interface for available methods.

### 3. Register Interface in BasicSwap Core

**File:** `basicswap/basicswap.py`

#### 3.1 Add to createInterface method (around line 960-1020)

```python
def createInterface(self, coin):
    # ... existing coins ...
    elif coin == Coins.RINCOIN:
        from .interface.rincoin import RINCOINInterface
        
        return RINCOINInterface(self.coin_clients[coin], self.chain, self)
    # ... rest of method
```

### 4. Add Binary Download Support

**File:** `bin/basicswap-prepare.py`

#### 4.1 Add Version Constants (near top of file, around line 50-100)

```python
RINCOIN_VERSION = os.getenv("RINCOIN_VERSION", "0.21.4")  # Your version
RINCOIN_VERSION_TAG = os.getenv("RINCOIN_VERSION_TAG", "")
```

#### 4.2 Add to known_coins Dictionary (around line 103-115)

```python
known_coins = {
    # ... existing coins ...
    "rincoin": (RINCOIN_VERSION, RINCOIN_VERSION_TAG, ("your_signing_key",)),
}
```

#### 4.3 Add Expected GPG Key (if available, around line 145-165)

```python
expected_key_ids = {
    # ... existing keys ...
    "your_signing_key": ("GPG_KEY_ID_HERE",),
}
```

#### 4.4 Add Download URLs in prepareCore function (around line 900-1100)

```python
elif coin == "rincoin":
    release_url = "https://github.com/your-org/rincoin/releases/download/v{}/{}".format(
        version + version_tag, release_filename
    )
    assert_filename = "{}-{}-{}-build.assert".format(coin, os_name, version)
    assert_url = "https://raw.githubusercontent.com/your-org/gitian.sigs/master/{}-{}/{}/{}".format(
        version, os_dir_name, signing_key_name, assert_filename
    )
```

#### 4.5 Add Configuration Generation (around line 1350-1500 in prepareCore)

```python
elif coin == "rincoin":
    fp.write("prune=4000\n")
    fp.write("changetype=bech32\n")
    if RIN_RPC_USER != "":
        fp.write(
            "rpcauth={}:{}${}\n".format(
                RIN_RPC_USER, salt, password_to_hmac(salt, RIN_RPC_PWD)
            )
        )
```

#### 4.6 Add RPC User/Password Variables (near top of file, around line 250-300)

```python
RIN_RPC_HOST = os.getenv("RIN_RPC_HOST", "127.0.0.1")
RIN_RPC_PORT = os.getenv("RIN_RPC_PORT", "9556")
RIN_RPC_USER = os.getenv("RIN_RPC_USER", "")
RIN_RPC_PWD = os.getenv("RIN_RPC_PWD", "")
```

### 5. Add Daemon Management

**File:** `basicswap/bin/run.py` or `bin/basicswap-run.py`

Add coin name to the list of coins that need daemon management (around line 1050):

```python
pidfilename = cc["name"]
if cc["name"] in (
    "bitcoin",
    "litecoin", 
    "dogecoin",
    "namecoin",
    "dash",
    "firo",
    "bitcoincash",
    "rincoin",  # Add here
):
    pidfilename += "d"
```

### 6. Update UI/Frontend

#### 6.1 Add Coin Icon

**Location:** `basicswap/static/images/coins/`

Add the following files:
- `Rincoin.png` - Main icon (suggested size: 64x64 or 128x128)
- `Rincoin-20.png` - Small icon (20x20)

#### 6.2 Add to Coin Manager JavaScript

**File:** `basicswap/static/js/modules/coin-manager.js`

```javascript
{
    symbol: 'RIN',
    name: 'rincoin',
    displayName: 'Rincoin',
    aliases: ['rincoin'],
    coingeckoId: 'rincoin',  // If listed on CoinGecko
    cryptocompareId: 'RIN',   // If listed on CryptoCompare
    usesCryptoCompare: false,  // Set based on availability
    usesCoinGecko: false,
    historicalDays: 30,
    icon: 'Rincoin.png'
}
```

### 7. Optional: Add Coin-Specific Documentation

**Location:** `doc/coins/rincoin.md`

Create coin-specific documentation if needed (e.g., special wallet requirements, version compatibility notes).

Example:
```markdown
## Rincoin Notes

### P2P and RPC Ports
- Mainnet P2P: 9555
- Mainnet RPC: 9556
- Testnet P2P: 19555  
- Testnet RPC: 19556

### Wallet Compatibility
Rincoin core version 0.21.4 or higher is required for BasicSwap integration.

### Special Considerations
[Any Rincoin-specific notes]
```

## Testing Your Integration

### 1. Test Binary Download
```bash
cd ~/basicswap-rin
python3 bin/basicswap-prepare.py --preparebinonly --bindir=~/test_bins --withcoin=rincoin
```

### 2. Test Configuration Generation
```bash
python3 bin/basicswap-prepare.py --datadir=~/test_data --withcoins=rincoin --particl_mnemonic="your test mnemonic"
```

### 3. Test Daemon Startup
```bash
python3 bin/basicswap-run.py --datadir=~/test_data
```

### 4. Verify in UI
- Check coin appears in the interface
- Verify wallet can be created
- Test receiving an address
- Verify balance displays correctly

## Common Issues and Solutions

### Issue: Coin not appearing in UI
**Solution:** Check that coin is added to `chainparams`, interface is registered in `createInterface`, and JavaScript coin-manager has entry.

### Issue: Binary download fails
**Solution:** Verify URL in `prepareCore`, check version variables, ensure signing keys are correct.

### Issue: Daemon won't start
**Solution:** Check configuration file generation in `prepareCore`, verify ports aren't in use, check coin core version compatibility.

### Issue: RPC connection fails
**Solution:** Verify RPC port in `chainparams` matches daemon config, check `rpcauth` is being written correctly, ensure firewall allows connection.

## Checklist for New Coin Integration

- [ ] Added to `Coins` enum in `chainparams.py`
- [ ] Chain parameters added to `chainparams` dict
- [ ] Created interface file in `basicswap/interface/`
- [ ] Registered interface in `basicswap.py` `createInterface()`
- [ ] Added version constants in `basicswap-prepare.py`
- [ ] Added to `known_coins` dict
- [ ] Added GPG signing keys (if available)
- [ ] Added download URLs in `prepareCore()`
- [ ] Added config generation in `prepareCore()`
- [ ] Added RPC credentials variables
- [ ] Added to daemon management list
- [ ] Added coin icons (main and -20.png)
- [ ] Added to JavaScript coin-manager
- [ ] Created coin-specific documentation (optional)
- [ ] Tested binary download
- [ ] Tested configuration generation
- [ ] Tested daemon startup
- [ ] Tested in UI

## References

For examples, refer to existing coin integrations:
- **Simple Bitcoin fork:** See `basicswap/interface/btc.py` and Namecoin
- **Litecoin fork:** See `basicswap/interface/ltc.py` and Dogecoin  
- **With special features:** See DASH (`basicswap/interface/dash.py`) or FIRO
- **Monero-like:** See `basicswap/interface/xmr.py` and Wownero

## Additional Notes

- Always test on testnet/regtest before mainnet
- Ensure your coin daemon supports the required RPC calls
- Consider adding unit tests in `tests/basicswap/`
- Update README.md to list the new coin in "Available Assets"
