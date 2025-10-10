const CoinUtils = (function() {
    function buildAliasesFromCoinManager() {
        const aliases = {};
        const symbolMap = {};

        if (window.CoinManager) {
            const coins = window.CoinManager.getAllCoins();
            coins.forEach(coin => {
                const canonical = coin.name.toLowerCase();
                aliases[canonical] = coin.aliases || [coin.name.toLowerCase()];
                symbolMap[canonical] = coin.symbol;
            });
        }

        return { aliases, symbolMap };
    }

    let COIN_ALIASES = {};
    let CANONICAL_TO_SYMBOL = {};

    function initializeAliases() {
        const { aliases, symbolMap } = buildAliasesFromCoinManager();
        COIN_ALIASES = aliases;
        CANONICAL_TO_SYMBOL = symbolMap;
    }

    if (window.CoinManager) {
        initializeAliases();
    } else {
        document.addEventListener('DOMContentLoaded', () => {
            if (window.CoinManager) {
                initializeAliases();
            }
        });
    }

    function getCanonicalName(coin) {
        if (!coin) return null;
        const lower = coin.toString().toLowerCase().trim();
        
        for (const [canonical, aliases] of Object.entries(COIN_ALIASES)) {
            if (aliases.includes(lower)) {
                return canonical;
            }
        }
        return lower;
    }

    return {
        normalizeCoinName: function(coin, priceData = null) {
            const canonical = getCanonicalName(coin);
            if (!canonical) return null;

            if (priceData) {
                if (canonical === 'bitcoin-cash') {
                    if (priceData['bitcoin-cash']) return 'bitcoin-cash';
                    if (priceData['bch']) return 'bch';
                    if (priceData['bitcoincash']) return 'bitcoincash';
                    return 'bitcoin-cash';
                }
                
                if (canonical === 'particl') {
                    if (priceData['part']) return 'part';
                    if (priceData['particl']) return 'particl';
                    return 'part';
                }
            }

            return canonical;
        },

        isSameCoin: function(coin1, coin2) {
            if (!coin1 || !coin2) return false;

            if (window.CoinManager) {
                return window.CoinManager.coinMatches(coin1, coin2);
            }

            const canonical1 = getCanonicalName(coin1);
            const canonical2 = getCanonicalName(coin2);
            if (canonical1 === canonical2) return true;

            const lower1 = coin1.toString().toLowerCase().trim();
            const lower2 = coin2.toString().toLowerCase().trim();

            const particlVariants = ['particl', 'particl anon', 'particl blind', 'part', 'part_anon', 'part_blind'];
            if (particlVariants.includes(lower1) && particlVariants.includes(lower2)) {
                return true;
            }

            if (lower1.includes(' ') || lower2.includes(' ')) {
                const word1 = lower1.split(' ')[0];
                const word2 = lower2.split(' ')[0];
                if (word1 === word2 && word1.length > 4) {
                    return true;
                }
            }

            return false;
        },

        getCoinSymbol: function(identifier) {
            if (!identifier) return null;

            if (window.CoinManager) {
                const coin = window.CoinManager.getCoinByAnyIdentifier(identifier);
                if (coin) return coin.symbol;
            }

            const canonical = getCanonicalName(identifier);
            if (canonical && CANONICAL_TO_SYMBOL[canonical]) {
                return CANONICAL_TO_SYMBOL[canonical];
            }

            return identifier.toString().toUpperCase();
        },

        getDisplayName: function(identifier) {
            if (!identifier) return null;

            if (window.CoinManager) {
                const coin = window.CoinManager.getCoinByAnyIdentifier(identifier);
                if (coin) return coin.displayName || coin.name;
            }

            const symbol = this.getCoinSymbol(identifier);
            return symbol || identifier;
        },

        getCoinImage: function(coinName) {
            if (!coinName) return null;

            const canonical = getCanonicalName(coinName);
            const symbol = this.getCoinSymbol(canonical);
            
            if (!symbol) return null;

            const imagePath = `/static/images/coins/${symbol.toLowerCase()}.png`;
            return imagePath;
        },

        getPriceKey: function(coin, priceData = null) {
            return this.normalizeCoinName(coin, priceData);
        },

        getCoingeckoId: function(coinName) {
            if (!coinName) return null;

            if (window.CoinManager) {
                const coin = window.CoinManager.getCoinByAnyIdentifier(coinName);
                if (coin && coin.coingeckoId) {
                    return coin.coingeckoId;
                }
            }

            const canonical = getCanonicalName(coinName);
            return canonical;
        },

        formatCoinAmount: function(amount, decimals = 8) {
            if (amount === null || amount === undefined) return '0';

            const numAmount = parseFloat(amount);
            if (isNaN(numAmount)) return '0';

            return numAmount.toFixed(decimals).replace(/\.?0+$/, '');
        },

        getAllAliases: function(coin) {
            const canonical = getCanonicalName(coin);
            return COIN_ALIASES[canonical] || [canonical];
        },

        isValidCoin: function(coin) {
            if (!coin) return false;
            const canonical = getCanonicalName(coin);
            return canonical !== null && COIN_ALIASES.hasOwnProperty(canonical);
        },

        refreshAliases: function() {
            initializeAliases();
            return Object.keys(COIN_ALIASES).length;
        }
    };
})();

if (typeof window !== 'undefined') {
    window.CoinUtils = CoinUtils;
}

console.log('CoinUtils module loaded');
