const CoinManager = (function() {
    const coinRegistry = [
        {
            symbol: 'BTC',
            name: 'bitcoin',
            displayName: 'Bitcoin',
            aliases: ['btc', 'bitcoin'],
            priceKey: 'bitcoin',
            historicalDays: 30,
            icon: 'Bitcoin.png'
        },
        {
            symbol: 'XMR',
            name: 'monero',
            displayName: 'Monero',
            aliases: ['xmr', 'monero'],
            priceKey: 'monero',
            historicalDays: 30,
            icon: 'Monero.png'
        },
        {
            symbol: 'PART',
            name: 'particl',
            displayName: 'Particl',
            aliases: ['part', 'particl', 'particl anon', 'particl blind'],
            variants: ['Particl', 'Particl Blind', 'Particl Anon'],
            priceKey: 'particl',
            historicalDays: 30,
            icon: 'Particl.png'
        },
        {
            symbol: 'BCH',
            name: 'bitcoin-cash',
            displayName: 'Bitcoin Cash',
            aliases: ['bch', 'bitcoincash', 'bitcoin cash'],
            priceKey: 'bitcoin-cash',
            historicalDays: 30,
            icon: 'Bitcoin%20Cash.png'
        },
        {
            symbol: 'PIVX',
            name: 'pivx',
            displayName: 'PIVX',
            aliases: ['pivx'],
            priceKey: 'pivx',
            historicalDays: 30,
            icon: 'PIVX.png'
        },
        {
            symbol: 'FIRO',
            name: 'firo',
            displayName: 'Firo',
            aliases: ['firo', 'zcoin'],
            priceKey: 'firo',
            historicalDays: 30,
            icon: 'Firo.png'
        },
        {
            symbol: 'DASH',
            name: 'dash',
            displayName: 'Dash',
            aliases: ['dash'],
            priceKey: 'dash',
            historicalDays: 30,
            icon: 'Dash.png'
        },
        {
            symbol: 'LTC',
            name: 'litecoin',
            displayName: 'Litecoin',
            aliases: ['ltc', 'litecoin'],
            variants: ['Litecoin', 'Litecoin MWEB'],
            priceKey: 'litecoin',
            historicalDays: 30,
            icon: 'Litecoin.png'
        },
        {
            symbol: 'DOGE',
            name: 'dogecoin',
            displayName: 'Dogecoin',
            aliases: ['doge', 'dogecoin'],
            priceKey: 'dogecoin',
            historicalDays: 30,
            icon: 'Dogecoin.png'
        },
        {
            symbol: 'DCR',
            name: 'decred',
            displayName: 'Decred',
            aliases: ['dcr', 'decred'],
            priceKey: 'decred',
            historicalDays: 30,
            icon: 'Decred.png'
        },
        {
            symbol: 'NMC',
            name: 'namecoin',
            displayName: 'Namecoin',
            aliases: ['nmc', 'namecoin'],
            priceKey: 'namecoin',
            historicalDays: 30,
            icon: 'Namecoin.png'
        },
        {
            symbol: 'WOW',
            name: 'wownero',
            displayName: 'Wownero',
            aliases: ['wow', 'wownero'],
            priceKey: 'wownero',
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
        return coinAliasesMap[normalizedId] || null;
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
            if (!identifier) return null;

            const normalizedId = identifier.toString().toLowerCase().trim();
            if (normalizedId === 'particl anon' || normalizedId === 'part_anon' || normalizedId === 'particl_anon') {
                return 'Particl Anon';
            }
            if (normalizedId === 'particl blind' || normalizedId === 'part_blind' || normalizedId === 'particl_blind') {
                return 'Particl Blind';
            }
            if (normalizedId === 'litecoin mweb' || normalizedId === 'ltc_mweb' || normalizedId === 'litecoin_mweb') {
                return 'Litecoin MWEB';
            }

            const coin = getCoinByAnyIdentifier(identifier);
            return coin ? coin.displayName : null;
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
            return coin.priceKey;
        },
        getCoinIcon: function(identifier) {
            if (!identifier) return null;

            const normalizedId = identifier.toString().toLowerCase().trim();
            if (normalizedId === 'particl anon' || normalizedId === 'part_anon' || normalizedId === 'particl_anon') {
                return 'Particl.png';
            }
            if (normalizedId === 'particl blind' || normalizedId === 'part_blind' || normalizedId === 'particl_blind') {
                return 'Particl.png';
            }
            if (normalizedId === 'litecoin mweb' || normalizedId === 'ltc_mweb' || normalizedId === 'litecoin_mweb') {
                return 'Litecoin.png';
            }

            const coin = getCoinByAnyIdentifier(identifier);
            if (coin && coin.icon) {
                return coin.icon;
            }

            const capitalizedName = identifier.toString().split(' ')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
                .join('%20');

            return `${capitalizedName}.png`;
        }
    };
})();

window.CoinManager = CoinManager;
console.log('CoinManager initialized');
