# Rincoin Integration - Summary & Next Steps

## Completed Work

I've successfully analyzed the BasicSwap project structure and created comprehensive documentation for integrating Rincoin. All work is in the `rincoin` branch.

### Documents Created

1. **[doc/coins/adding-new-coin.md](doc/coins/adding-new-coin.md)**
   - Complete step-by-step manual for adding any new coin to BasicSwap
   - Detailed explanations of each file and change required
   - Testing procedures and troubleshooting guide
   - Checklist for implementation

2. **[doc/coins/rincoin-integration-plan.md](doc/coins/rincoin-integration-plan.md)**
   - Specific plan for Rincoin integration
   - Questions that need answers before implementation
   - Risk assessment and timeline estimates
   - Reference to similar coin integrations

3. **[doc/coins/rincoin-parameters.md](doc/coins/rincoin-parameters.md)**
   - **VERIFIED** Rincoin blockchain parameters from core source code
   - Complete address format specifications
   - Network ports and configuration details
   - Comparison with Litecoin

## Key Findings

### Rincoin Specifications (Verified)
- **Ports:** P2P 9555, RPC 9556 (mainnet) ✓
- **Addresses:** Start with 'R' (mainnet), 'T' (testnet) ✓
- **Bech32:** "rin" prefix for SegWit addresses ✓
- **Block Time:** 60 seconds (1 minute) ✓
- **Features:** SegWit, Taproot, MWEB (like Litecoin) ✓
- **Parent:** Litecoin fork with MWEB support ✓

### Integration Approach
Rincoin should inherit from `LTCInterface` because:
- It's a Litecoin fork
- Includes MWEB (Mimblewimble Extension Block)
- Similar RPC interface and features
- Same wallet capabilities

## Files That Need Changes

### Python Backend (7 files)
1. `basicswap/chainparams.py` - Add Rincoin to Coins enum and chainparams dict
2. `basicswap/interface/rincoin.py` - Create new interface (inherits LTCInterface)
3. `basicswap/basicswap.py` - Register interface in createInterface()
4. `bin/basicswap-prepare.py` - Add version, download URLs, config generation (4 sections)
5. `basicswap/bin/run.py` - Add to daemon management list

### Frontend/UI (2-3 files)
1. `basicswap/static/images/coins/` - Add Rincoin.png and Rincoin-20.png icons
2. `basicswap/static/js/modules/coin-manager.js` - Add coin entry

### Documentation (2 files)
1. `doc/coins/rincoin.md` - Coin-specific notes
2. `README.md` - Add to Available Assets table

**Total:** ~200-300 lines of code + icons

## Critical Information Still Needed

Before implementation can proceed, please provide:

### 1. Binary Distribution
- [ ] Where are Rincoin Core binaries published?
  - GitHub releases URL?
  - Official download site?
  - Or should we build from source?
  
- [ ] What version should we use?
  - Latest stable version number?
  - Recommend a tested version?

- [ ] GPG Signing
  - Are binaries GPG signed?
  - If yes, what's the signing key ID?
  - Who maintains the key?

### 2. Project Information
- [ ] Official Rincoin project repository?
- [ ] Official website (if any)?
- [ ] Is there a testnet for testing?
- [ ] Block explorer URLs?

### 3. Technical Clarifications
- [ ] Is MWEB fully working and compatible with Litecoin's implementation?
- [ ] Any Rincoin-specific RPC differences from Litecoin?
- [ ] Any special wallet requirements or limitations?
- [ ] Default configuration recommendations?

## Implementation Steps (Once Info is Provided)

### Step 1: Add Chain Parameters (~30 minutes)
```python
# In basicswap/chainparams.py
Coins.RINCOIN = 19

chainparams[Coins.RINCOIN] = {
    "name": "rincoin",
    "ticker": "RIN",
    # ... full parameters from rincoin-parameters.md
}
```

### Step 2: Create Interface (~45 minutes)
```python
# New file: basicswap/interface/rincoin.py
from .ltc import LTCInterface
from basicswap.chainparams import Coins

class RINCOINInterface(LTCInterface):
    @staticmethod
    def coin_type():
        return Coins.RINCOIN
```

### Step 3: Register Interface (~15 minutes)
```python
# In basicswap/basicswap.py, add to createInterface():
elif coin == Coins.RINCOIN:
    from .interface.rincoin import RINCOINInterface
    return RINCOINInterface(self.coin_clients[coin], self.chain, self)
```

### Step 4: Add Binary Support (~60-90 minutes)
- Add version constants
- Add to known_coins dict
- Add GPG keys (if available)
- Add download URLs in prepareCore()
- Add config generation
- Add RPC credentials

### Step 5: UI Updates (~30 minutes)
- Add coin icons
- Update JavaScript coin-manager
- Update README

### Step 6: Testing (~2-4 hours)
- Test binary download
- Test daemon startup
- Test wallet creation
- Test address generation
- Test swaps on testnet (if available)

**Total Time:** 5-12 hours (depending on binary setup complexity)

## Questions for You

1. **Where should we get Rincoin binaries?** 
   - Do you have a GitHub repository with releases?
   - Should BasicSwap build from the local ~/rincoin directory?
   - Is there an official release site?

2. **What Rincoin version is stable and tested?**
   - Current version number?
   - Which version has MWEB fully working?

3. **Testing environment:**
   - Do you have testnet coins available?
   - Can you provide testnet node access for testing?
   - Block explorer for verification?

4. **Binary signing:**
   - Are you signing releases with GPG?
   - If yes, what's your key ID for verification?

5. **Project maintenance:**
   - Who maintains the Rincoin project?
   - Where should users get support?
   - Documentation site?

6. **Special features:**
   - Any Rincoin-specific features beyond standard LTC fork?
   - Any custom RPC calls?
   - Any wallet migration needs from older versions?

## Recommendation

The most efficient path forward:

1. **Immediate:** Provide binary distribution details (Q1-Q2 above)
2. **Next:** Test that BasicSwap can download/run Rincoin daemon
3. **Then:** Implement the integration following the manual
4. **Finally:** Test thoroughly on testnet before mainnet

The technical work is straightforward since Rincoin is a clean Litecoin fork. The main blockers are:
- Binary distribution setup
- Testing infrastructure (testnet)
- Version selection

## What's Ready Now

✓ Complete integration manual created
✓ Rincoin blockchain parameters verified from source
✓ Branch created and ready for changes
✓ Project structure fully analyzed
✓ Implementation approach defined

## What's Needed

✗ Binary download URLs
✗ Version specification
✗ GPG signing setup (optional but recommended)
✗ Testnet access for testing
✗ Coin icons (Rincoin.png files)

**Once you provide the missing information, I can proceed with the implementation immediately.**

---

## Contact

Please provide answers to the questions above, and I'll:
1. Implement all the code changes
2. Test the integration
3. Create a pull request
4. Help troubleshoot any issues

The hardest part (analysis and documentation) is complete. Implementation is now straightforward!
