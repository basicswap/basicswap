# Rincoin Integration Plan for BasicSwap

This document outlines the specific changes required to integrate Rincoin into BasicSwap.

## Rincoin Specifications

- **Base:** Litecoin fork
- **Ticker:** RIN
- **Mainnet P2P Port:** 9555
- **Mainnet RPC Port:** 9556
- **Testnet P2P Port:** 19555 (assumed, typical +10000)
- **Testnet RPC Port:** 19556
- **Block Time:** ~1 minute (like Litecoin)
- **Features:** Likely includes SegWit, similar to Litecoin

## Required Information (Please Provide)

Before proceeding with implementation, please confirm the following Rincoin parameters:

### Critical Parameters
1. **Address Prefixes:**
   - Mainnet P2PKH address version byte (0x30 = '1' prefix like BTC, 0x30 = 'L' like LTC)?
   - Mainnet P2SH address version byte?
   - Does it use SegWit? If yes, what's the Bech32 HRP (human-readable part)?

2. **Binary Distribution:**
   - Official GitHub repository URL?
   - Latest stable version number?
   - Are binaries signed with GPG? If yes, what key?
   - Binary naming convention (e.g., `rincoind`, `rincoin-cli`)?

3. **Core Wallet:**
   - Compatible Rincoin Core version?
   - Does it support `sethdseed` RPC command?
   - Any special wallet features or limitations?

4. **Network:**
   - Default datadir name (.rincoin)?
   - Configuration file name (rincoin.conf)?
   - Any required special configuration parameters?

5. **Genesis/Chain:**
   - Message signing magic string ("Rincoin Signed Message:\n")?
   - BIP44 coin type (can use Litecoin's 2 if not registered)?

### Optional Information
- Block explorer URLs
- Seed nodes (if not in core binary)
- Any MWEB/privacy features like Litecoin?
- Any special consensus rules?
- Default fees/dust limits

## Implementation Steps Summary

Once the above information is provided, here are the changes needed:

### 1. Core Changes (Python)

**Files to modify:**
1. `basicswap/chainparams.py` - Add Rincoin entry with all network parameters
2. `basicswap/interface/rincoin.py` - Create new interface (inheriting from LTCInterface)
3. `basicswap/basicswap.py` - Register interface in createInterface()
4. `bin/basicswap-prepare.py` - Add version, download URLs, config generation
5. `basicswap/bin/run.py` - Add to daemon management

### 2. Frontend Changes

**Files to modify:**
1. `basicswap/static/images/coins/` - Add Rincoin.png and Rincoin-20.png
2. `basicswap/static/js/modules/coin-manager.js` - Add Rincoin entry

### 3. Documentation

**Files to create/modify:**
1. `doc/coins/rincoin.md` - Rincoin-specific notes
2. `README.md` - Add Rincoin to Available Assets list

## Estimated File Changes

Based on analysis of similar coin integrations (e.g., Dogecoin, Dash):

- **New Files:** 2-3 (interface, icon, docs)
- **Modified Files:** 5-7
- **Total Lines Changed:** ~200-300 lines
- **Development Time:** 2-4 hours (after information gathering)

## Testing Plan

1. **Binary Download Test:**
   - Verify binary can be downloaded and extracted
   - Verify GPG signature (if applicable)

2. **Configuration Test:**
   - Generate rincoin.conf with proper settings
   - Verify all required parameters present

3. **Daemon Test:**
   - Start rincoind daemon
   - Verify RPC connectivity
   - Check wallet creation

4. **Integration Test:**
   - Create new wallet from seed
   - Generate addresses
   - Check balance queries
   - Verify transaction creation (testnet)

5. **Swap Test (if possible):**
   - Attempt swap with another coin on testnet
   - Verify atomic swap contract creation
   - Test full swap lifecycle

## Risk Assessment

### Low Risk Items
- Chain parameters (straightforward for LTC fork)
- Interface creation (can inherit from LTCInterface)
- UI updates (standard additions)

### Medium Risk Items  
- Binary download/verification (depends on signing setup)
- Special wallet features (if any differ from LTC)

### High Risk Items (Unlikely for LTC fork)
- Non-standard consensus rules
- Custom transaction types
- Special address formats

## Dependencies

- Rincoin Core binaries (or ability to build from source)
- Working Rincoin node for testing
- Testnet coins for testing (if testnet exists)

## Next Steps

1. **Gather Information:** Provide the parameters requested above
2. **Setup Development Environment:** Ensure rincoin core is accessible
3. **Implement Changes:** Follow the manual in `doc/coins/adding-new-coin.md`
4. **Test Thoroughly:** Complete all tests on testnet/regtest
5. **Document:** Update all relevant documentation
6. **Submit:** Create pull request with changes

## Questions to Answer Before Implementation

Please provide answers to the following:

1. **Where can I download Rincoin Core binaries?**
   - URL: _______________

2. **What version should we use?**
   - Version: _______________

3. **Is the binary signing key available?**
   - Yes/No: _______________
   - Key ID: _______________

4. **What are the address version bytes?**
   - P2PKH (mainnet): _______________
   - P2SH (mainnet): _______________
   - Bech32 HRP: _______________

5. **Does Rincoin have any unique features not in Litecoin?**
   - Description: _______________

6. **Is there an active testnet?**
   - Yes/No: _______________
   - Testnet details: _______________

7. **Default datadir and config file names?**
   - Datadir: _______________
   - Config: _______________

8. **Are there any special configuration requirements?**
   - Details: _______________

9. **Block explorers for testing?**
   - Mainnet: _______________
   - Testnet: _______________

10. **Rincoin project contacts for questions?**
    - Contact: _______________

## Reference: Similar Coin Integration

For reference, Dogecoin (also a Litecoin fork) required these changes:
- Added to Coins enum with value 18
- ~40 lines in chainparams.py
- Interface inherits from BTCInterface (Rincoin will use LTCInterface)
- ~30 lines in basicswap-prepare.py for download
- ~20 lines for config generation
- Icon files added
- ~10 lines in JavaScript

Total: ~100-150 lines of actual code changes (excluding icons/docs)

---

**Status:** Information gathering phase
**Next Action:** Provide answers to questions above
**Blocked By:** Missing Rincoin-specific parameters
