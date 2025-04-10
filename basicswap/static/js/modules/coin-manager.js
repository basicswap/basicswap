const CoinManager = (function() {
    const coinRegistry = [
        {
            symbol: 'BTC',
            name: 'bitcoin',
            displayName: 'Bitcoin',
            aliases: ['btc', 'bitcoin'],
            coingeckoId: 'bitcoin',
            cryptocompareId: 'BTC',
            usesCryptoCompare: false,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Bitcoin.png'
        },
        {
            symbol: 'XMR',
            name: 'monero',
            displayName: 'Monero',
            aliases: ['xmr', 'monero'],
            coingeckoId: 'monero',
            cryptocompareId: 'XMR',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Monero.png'
        },
        {
            symbol: 'PART',
            name: 'particl',
            displayName: 'Particl',
            aliases: ['part', 'particl', 'particl anon', 'particl blind'],
            variants: ['Particl', 'Particl Blind', 'Particl Anon'],
            coingeckoId: 'particl',
            cryptocompareId: 'PART',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Particl.png'
        },
        {
            symbol: 'BCH',
            name: 'bitcoin-cash',
            displayName: 'Bitcoin Cash',
            aliases: ['bch', 'bitcoincash', 'bitcoin cash'],
            coingeckoId: 'bitcoin-cash',
            cryptocompareId: 'BCH',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Bitcoin-Cash.png'
        },
        {
            symbol: 'PIVX',
            name: 'pivx',
            displayName: 'PIVX',
            aliases: ['pivx'],
            coingeckoId: 'pivx',
            cryptocompareId: 'PIVX',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'PIVX.png'
        },
        {
            symbol: 'FIRO',
            name: 'firo',
            displayName: 'Firo',
            aliases: ['firo', 'zcoin'],
            coingeckoId: 'firo',
            cryptocompareId: 'FIRO',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Firo.png'
        },
        {
            symbol: 'DASH',
            name: 'dash',
            displayName: 'Dash',
            aliases: ['dash'],
            coingeckoId: 'dash',
            cryptocompareId: 'DASH',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Dash.png'
        },
        {
            symbol: 'LTC',
            name: 'litecoin',
            displayName: 'Litecoin',
            aliases: ['ltc', 'litecoin'],
            variants: ['Litecoin', 'Litecoin MWEB'],
            coingeckoId: 'litecoin',
            cryptocompareId: 'LTC',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Litecoin.png'
        },
        {
            symbol: 'DOGE',
            name: 'dogecoin',
            displayName: 'Dogecoin',
            aliases: ['doge', 'dogecoin'],
            coingeckoId: 'dogecoin',
            cryptocompareId: 'DOGE',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Dogecoin.png'
        },
        {
            symbol: 'DCR',
            name: 'decred',
            displayName: 'Decred',
            aliases: ['dcr', 'decred'],
            coingeckoId: 'decred',
            cryptocompareId: 'DCR',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Decred.png'
        },
        {
            symbol: 'NMC',
            name: 'namecoin',
            displayName: 'Namecoin',
            aliases: ['nmc', 'namecoin'],
            coingeckoId: 'namecoin',
            cryptocompareId: 'NMC',
            usesCryptoCompare: true,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Namecoin.png'
        },
        {
            symbol: 'WOW',
            name: 'wownero',
            displayName: 'Wownero',
            aliases: ['wow', 'wownero'],
            coingeckoId: 'wownero',
            cryptocompareId: 'WOW',
            usesCryptoCompare: false,
            usesCoinGecko: true,
            historicalDays: 30,
            icon: 'Wownero.png'
        }
    ];
    const symbolToInfo = {};
    const nameToInfo = {};
    const displayNameToInfo = {};
    const coinAliasesMap = {};

    function buildLookupMaps() {
        coinRegistry.forEach(coin => {
            symbolToInfo[coin.symbol.toLowerCase()] = coin;
            nameToInfo[coin.name.toLowerCase()] = coin;
            displayNameToInfo[coin.displayName.toLowerCase()] = coin;
            if (coin.aliases && Array.isArray(coin.aliases)) {
                coin.aliases.forEach(alias => {
                    coinAliasesMap[alias.toLowerCase()] = coin;
                });
            }
            coinAliasesMap[coin.symbol.toLowerCase()] = coin;
            coinAliasesMap[coin.name.toLowerCase()] = coin;
            coinAliasesMap[coin.displayName.toLowerCase()] = coin;
            if (coin.variants && Array.isArray(coin.variants)) {
                coin.variants.forEach(variant => {
                    coinAliasesMap[variant.toLowerCase()] = coin;
                });
            }
        });
    }

    buildLookupMaps();

    function getCoinByAnyIdentifier(identifier) {
        if (!identifier) return null;
        const normalizedId = identifier.toString().toLowerCase().trim();
        const coin = coinAliasesMap[normalizedId];
        if (coin) return coin;
        if (normalizedId.includes('bitcoin') && normalizedId.includes('cash') || 
            normalizedId === 'bch') {
            return symbolToInfo['bch'];
        }
        if (normalizedId === 'zcoin' || normalizedId.includes('firo')) {
            return symbolToInfo['firo'];
        }
        if (normalizedId.includes('particl')) {
            return symbolToInfo['part'];
        }
        return null;
    }

    return {
        getAllCoins: function() {
            return [...coinRegistry];
        },
        getCoinByAnyIdentifier: getCoinByAnyIdentifier,
        getSymbol: function(identifier) {
            const coin = getCoinByAnyIdentifier(identifier);
            return coin ? coin.symbol : null;
        },
        getDisplayName: function(identifier) {
            const coin = getCoinByAnyIdentifier(identifier);
            return coin ? coin.displayName : null;
        },
        getCoingeckoId: function(identifier) {
            const coin = getCoinByAnyIdentifier(identifier);
            return coin ? coin.coingeckoId : null;
        },
        coinMatches: function(coinId1, coinId2) {
            if (!coinId1 || !coinId2) return false;
            const coin1 = getCoinByAnyIdentifier(coinId1);
            const coin2 = getCoinByAnyIdentifier(coinId2);
            if (!coin1 || !coin2) return false;
            return coin1.symbol === coin2.symbol;
        },
        getPriceKey: function(coinIdentifier) {
            if (!coinIdentifier) return null;
            const coin = getCoinByAnyIdentifier(coinIdentifier);
            if (!coin) return coinIdentifier.toLowerCase();
            return coin.coingeckoId;
        }
    };
})();

window.CoinManager = CoinManager;
console.log('CoinManager initialized');
