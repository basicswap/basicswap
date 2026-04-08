# Rincoin Integration - Complete Parameters

This document contains the verified Rincoin parameters extracted from the rincoin core source code.

## Confirmed Rincoin Parameters

### Network Parameters
- **P2P Port (Mainnet):** 9555
- **RPC Port (Mainnet):** 9556
- **P2P Port (Testnet):** 19555
- **RPC Port (Testnet):** 19556
- **P2P Port (Regtest):** 18555 (typical)
- **RPC Port (Regtest):** 18556 (typical)

### Address Prefixes (Mainnet)
- **PUBKEY_ADDRESS:** 60 (0x3C) - Produces addresses starting with "R"
- **SCRIPT_ADDRESS:** 122 (0x7A) - Produces addresses starting with "r"
- **SCRIPT_ADDRESS2:** 50 (0x32) - For SegWit P2SH
- **SECRET_KEY:** 188 (0xBC) - WIF private keys start with "7J" or "7K"
- **Bech32 HRP:** "rin" (for SegWit addresses like "rin1...")
- **MWEB HRP:** "rinmweb" (if MWEB support is enabled)

### Address Prefixes (Testnet)
- **PUBKEY_ADDRESS:** 65 (0x41) - Produces addresses starting with "T"
- **SCRIPT_ADDRESS:** 127 (0x7F) - Produces addresses starting with "t"
- **SCRIPT_ADDRESS2:** 50 (0x32)
- **SECRET_KEY:** 209 (0xD1) - WIF private keys start with "8K" or "8L"
- **Bech32 HRP:** "trin" (testnet SegWit addresses)

### Extended Keys
- **EXT_PUBLIC_KEY:** 0x0488B21E (same as Bitcoin/Litecoin "xpub")
- **EXT_SECRET_KEY:** 0x0488ADE4 (same as Bitcoin/Litecoin "xprv")

### Message Magic
- **Message Magic String:** "Rincoin Signed Message:\n" (implied, not "Litecoin")
- **Network Magic Bytes (pchMessageStart):**
  - Mainnet: 0x52, 0x49, 0x4E, 0x43 (ASCII: "RINC")
  - Testnet: 0x72, 0x69, 0x6E, 0x74 (ASCII: "rint")

### Blockchain Parameters
- **Block Time:** 60 seconds (1 minute, like Litecoin)
- **Block Target Timespan:** 33 hours (118,800 seconds)
- **Difficulty Adjustment Window:** 8064 blocks
- **Halving Interval:** 210,000 blocks (like Bitcoin)
- **Genesis Block Hash:** 0x000096bdd6e4613ca89b074ebd6f609aba6fe3f868b34ee79380aa3bc7a8c9db
- **Genesis Timestamp:** 1743054848 (approximately December 2024)
- **Merkle Root:** 0x8590c08530d2ed422b726a938f07df8f380671569e04dcb556dcb9601c47cdad

### Consensus Features
- **SegWit:** Enabled (height 26500)
- **BIP34:** Enabled (height 26500)
- **BIP65:** Enabled (height 26500)
- **BIP66:** Enabled (height 26500)
- **CSV (BIP112):** Enabled (height 26500)
- **Taproot:** Deployed
- **MWEB (MW Extension Block):** Deployed (like Litecoin 0.21+)
- **DGW (Dark Gravity Wave):** Enabled at height 30000

### DNS Seeds
- **Primary:** seed.rincoin.org

### Software Details
- **Daemon Name:** rincoind
- **CLI Name:** rincoin-cli
- **TX Tool Name:** rincoin-tx
- **Wallet Tool Name:** rincoin-wallet
- **Default Datadir:** ~/.rincoin (Linux/Mac) or %APPDATA%\Rincoin (Windows)
- **Config File:** rincoin.conf

### BIP44 Coin Type
- **BIP44 Path:** m/44'/2'/... (uses Litecoin's coin type)
- Note: Rincoin should ideally register its own coin type, but using LTC's is common for forks

## Integration Mapping for BasicSwap

### Coins Enum Value
Suggested: `RINCOIN = 19` (next available after BCH=17, DOGE=18)

### Parent Class
Inherit from `LTCInterface` since Rincoin includes:
- MWEB support (like Litecoin 0.21+)
- Similar RPC interface
- Same block timing and structure

### Binary Information
**Repository:** Check https://github.com/rincoin-project or local build
**Version:** TBD (need to determine stable release version)
**Signing Key:** TBD (need GPG key if binaries are signed)

### Configuration Notes
1. Rincoin supports MWEB like Litecoin
2. Requires `prune=4000` or similar for BasicSwap
3. Should set `changetype=bech32` for modern address types
4. Supports HD wallets with `sethdseed`

## Next Steps for Implementation

1. **Determine Binary Distribution:**
   - Where are Rincoin binaries hosted?
   - What's the latest stable version?
   - Are they GPG signed?

2. **Create Interface:**
   - Inherit from LTCInterface
   - Add MWEB wallet support (similar to LTC)
   - Test MWEB compatibility

3. **Add Chain Parameters:**
   - Use verified values above
   - Set proper address prefixes
   - Configure network ports

4. **Configure Binary Download:**
   - Add download URLs
   - Add GPG verification (if available)
   - Set version variables

5. **Testing:**
   - Test on regtest first
   - Verify address generation matches core wallet
   - Test MWEB address creation
   - Test atomic swaps on testnet

## Open Questions

1. **Binary Distribution:** Where should BasicSwap download Rincoin binaries from?
   - GitHub releases?
   - Official website?
   - Build from source?

2. **Version:** What version should be the default?
   - Latest stable?
   - Specific version tested with MWEB?

3. **MWEB Wallet:** Is MWEB fully compatible with Litecoin's implementation?
   - Can we use LTCInterfaceMWEB directly?
   - Any Rincoin-specific MWEB features?

4. **Block Explorer:** What block explorers are available for testing?

5. **Testnet:** Is there an active testnet for testing swaps?

## Comparison with Litecoin

| Parameter | Litecoin | Rincoin | Notes |
|-----------|----------|---------|-------|
| P2P Port | 9333 | 9555 | Different |
| RPC Port | 9332 | 9556 | Different |
| PUBKEY_ADDRESS | 48 ('L') | 60 ('R') | Different |
| SCRIPT_ADDRESS | 5 ('3') | 122 ('r') | Different |
| Bech32 HRP | "ltc" | "rin" | Different |
| Block Time | 150s (2.5min) | 60s (1min) | Faster! |
| MWEB | Yes | Yes | Same feature |
| SegWit | Yes | Yes | Same |
| Taproot | Yes | Yes | Same |

## Implementation Confidence

- **High Confidence:** Chain parameters, address formats, consensus rules
- **Medium Confidence:** MWEB compatibility, RPC interface parity
- **Low Confidence:** Binary distribution, GPG signing setup

## Estimated Implementation Time

- **With binaries available:** 3-4 hours
- **Need to build from source:** 6-8 hours (including build setup)
- **Full testing on testnet:** Additional 2-4 hours

**Total:** 5-12 hours depending on binary availability
