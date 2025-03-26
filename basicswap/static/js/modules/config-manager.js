const ConfigManager = (function() {
    const state = {
        isInitialized: false
    };

    function determineWebSocketPort() {
        const wsPort = 
            window.ws_port || 
            (typeof getWebSocketConfig === 'function' ? getWebSocketConfig().port : null) || 
            '11700';
        return wsPort;
    }

    const selectedWsPort = determineWebSocketPort();

    const defaultConfig = {
        cacheDuration: 10 * 60 * 1000,
        requestTimeout: 60000,
        wsPort: selectedWsPort,
        
        cacheConfig: {
            defaultTTL: 10 * 60 * 1000,
            
            ttlSettings: {
                prices: 5 * 60 * 1000,
                chart: 5 * 60 * 1000,
                historical: 60 * 60 * 1000,
                volume: 30 * 60 * 1000,
                offers: 2 * 60 * 1000,
                identity: 15 * 60 * 1000
            },

            storage: {
                maxSizeBytes: 10 * 1024 * 1024,
                maxItems: 200
            },
            
            fallbackTTL: 24 * 60 * 60 * 1000
        },

        itemsPerPage: 50,

        apiEndpoints: {
            cryptoCompare: 'https://min-api.cryptocompare.com/data/pricemultifull',
            coinGecko: 'https://api.coingecko.com/api/v3',
            cryptoCompareHistorical: 'https://min-api.cryptocompare.com/data/v2/histoday',
            cryptoCompareHourly: 'https://min-api.cryptocompare.com/data/v2/histohour',
            volumeEndpoint: 'https://api.coingecko.com/api/v3/simple/price'
        },

        rateLimits: {
            coingecko: {
                requestsPerMinute: 50,
                minInterval: 1200
            },
            cryptocompare: {
                requestsPerMinute: 30,
                minInterval: 2000
            }
        },

        retryDelays: [5000, 15000, 30000],

        coins: [
            { symbol: 'BTC', name: 'bitcoin', usesCryptoCompare: false, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'XMR', name: 'monero', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'PART', name: 'particl', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'BCH', name: 'bitcoincash', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'PIVX', name: 'pivx', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'FIRO', name: 'firo', displayName: 'Firo', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'DASH', name: 'dash', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'LTC', name: 'litecoin', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'DOGE', name: 'dogecoin', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'DCR', name: 'decred', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
            { symbol: 'WOW', name: 'wownero', usesCryptoCompare: false, usesCoinGecko: true, historicalDays: 30 }
        ],

        coinMappings: {
            nameToSymbol: {
                'Bitcoin': 'BTC',
                'Litecoin': 'LTC',
                'Monero': 'XMR',
                'Particl': 'PART',
                'Particl Blind': 'PART',
                'Particl Anon': 'PART',
                'PIVX': 'PIVX',
                'Firo': 'FIRO',
                'Zcoin': 'FIRO',
                'Dash': 'DASH',
                'Decred': 'DCR',
                'Wownero': 'WOW',
                'Bitcoin Cash': 'BCH',
                'Dogecoin': 'DOGE'
            },
            
            nameToDisplayName: {
                'Bitcoin': 'Bitcoin',
                'Litecoin': 'Litecoin',
                'Monero': 'Monero',
                'Particl': 'Particl',
                'Particl Blind': 'Particl Blind',
                'Particl Anon': 'Particl Anon',
                'PIVX': 'PIVX',
                'Firo': 'Firo',
                'Zcoin': 'Firo',
                'Dash': 'Dash',
                'Decred': 'Decred',
                'Wownero': 'Wownero',
                'Bitcoin Cash': 'Bitcoin Cash',
                'Dogecoin': 'Dogecoin'
            },

            idToName: {
                1: 'particl', 2: 'bitcoin', 3: 'litecoin', 4: 'decred',
                6: 'monero', 7: 'particl blind', 8: 'particl anon',
                9: 'wownero', 11: 'pivx', 13: 'firo', 17: 'bitcoincash',
                18: 'dogecoin'
            },

            nameToCoinGecko: {
                'bitcoin': 'bitcoin',
                'monero': 'monero',
                'particl': 'particl',
                'bitcoin cash': 'bitcoin-cash',
                'bitcoincash': 'bitcoin-cash',
                'pivx': 'pivx',
                'firo': 'firo',
                'zcoin': 'firo',
                'dash': 'dash',
                'litecoin': 'litecoin',
                'dogecoin': 'dogecoin',
                'decred': 'decred',
                'wownero': 'wownero'
            }
        },

        chartConfig: {
            colors: {
                default: {
                    lineColor: 'rgba(77, 132, 240, 1)',
                    backgroundColor: 'rgba(77, 132, 240, 0.1)'
                }
            },
            showVolume: false,
            specialCoins: [''],
            resolutions: {
                year: { days: 365, interval: 'month' },
                sixMonths: { days: 180, interval: 'daily' },
                day: { days: 1, interval: 'hourly' }
            },
            currentResolution: 'year'
        }
    };

    const publicAPI = {
        ...defaultConfig,

        initialize: function(options = {}) {
            if (state.isInitialized) {
                console.warn('[ConfigManager] Already initialized');
                return this;
            }

            if (options) {
                Object.assign(this, options);
            }
            
            if (window.CleanupManager) {
                window.CleanupManager.registerResource('configManager', this, (mgr) => mgr.dispose());
            }

            this.utils = utils;
            
            state.isInitialized = true;
            console.log('ConfigManager initialized');
            return this;
        },

        getAPIKeys: function() {
            if (typeof window.getAPIKeys === 'function') {
                const apiKeys = window.getAPIKeys();
                return {
                    cryptoCompare: apiKeys.cryptoCompare || '',
                    coinGecko: apiKeys.coinGecko || ''
                };
            }

            return {
                cryptoCompare: '',
                coinGecko: ''
            };
        },

        getCoinBackendId: function(coinName) {
            if (!coinName) return null;

            const nameMap = {
                'bitcoin-cash': 'bitcoincash',
                'bitcoin cash': 'bitcoincash',
                'firo': 'firo',
                'zcoin': 'firo',
                'bitcoincash': 'bitcoin-cash'
            };

            const lowerCoinName = typeof coinName === 'string' ? coinName.toLowerCase() : '';
            return nameMap[lowerCoinName] || lowerCoinName;
        },
        
        coinMatches: function(offerCoin, filterCoin) {
            if (!offerCoin || !filterCoin) return false;

            offerCoin = offerCoin.toLowerCase();
            filterCoin = filterCoin.toLowerCase();

            if (offerCoin === filterCoin) return true;

            if ((offerCoin === 'firo' || offerCoin === 'zcoin') &&
                (filterCoin === 'firo' || filterCoin === 'zcoin')) {
                return true;
            }

            if ((offerCoin === 'bitcoincash' && filterCoin === 'bitcoin cash') ||
                (offerCoin === 'bitcoin cash' && filterCoin === 'bitcoincash')) {
                return true;
            }

            const particlVariants = ['particl', 'particl anon', 'particl blind'];
            if (filterCoin === 'particl' && particlVariants.includes(offerCoin)) {
                return true;
            }

            if (particlVariants.includes(filterCoin)) {
                return offerCoin === filterCoin;
            }

            return false;
        },

        update: function(path, value) {
            const parts = path.split('.');
            let current = this;

            for (let i = 0; i < parts.length - 1; i++) {
                if (!current[parts[i]]) {
                    current[parts[i]] = {};
                }
                current = current[parts[i]];
            }

            current[parts[parts.length - 1]] = value;
            return this;
        },

        get: function(path, defaultValue = null) {
            const parts = path.split('.');
            let current = this;
            
            for (let i = 0; i < parts.length; i++) {
                if (current === undefined || current === null) {
                    return defaultValue;
                }
                current = current[parts[i]];
            }

            return current !== undefined ? current : defaultValue;
        },

        dispose: function() {
            state.isInitialized = false;
            console.log('ConfigManager disposed');
        }
    };

    const utils = {
        formatNumber: function(number, decimals = 2) {
            if (typeof number !== 'number' || isNaN(number)) {
                console.warn('formatNumber received a non-number value:', number);
                return '0';
            }
            try {
                return new Intl.NumberFormat('en-US', {
                    minimumFractionDigits: decimals,
                    maximumFractionDigits: decimals
                }).format(number);
            } catch (e) {
                return '0';
            }
        },

        formatDate: function(timestamp, resolution) {
            const date = new Date(timestamp);
            const options = {
                day: { hour: '2-digit', minute: '2-digit', hour12: true },
                week: { month: 'short', day: 'numeric' },
                month: { year: 'numeric', month: 'short', day: 'numeric' }
            };
            return date.toLocaleString('en-US', { ...options[resolution], timeZone: 'UTC' });
        },

        debounce: function(func, delay) {
            let timeoutId;
            return function(...args) {
                clearTimeout(timeoutId);
                timeoutId = setTimeout(() => func(...args), delay);
            };
        },

        formatTimeLeft: function(timestamp) {
            const now = Math.floor(Date.now() / 1000);
            if (timestamp <= now) return "Expired";
            return this.formatTime(timestamp);
        },

        formatTime: function(timestamp, addAgoSuffix = false) {
            const now = Math.floor(Date.now() / 1000);
            const diff = Math.abs(now - timestamp);

            let timeString;
            if (diff < 60) {
                timeString = `${diff} seconds`;
            } else if (diff < 3600) {
                timeString = `${Math.floor(diff / 60)} minutes`;
            } else if (diff < 86400) {
                timeString = `${Math.floor(diff / 3600)} hours`;
            } else if (diff < 2592000) {
                timeString = `${Math.floor(diff / 86400)} days`;
            } else if (diff < 31536000) {
                timeString = `${Math.floor(diff / 2592000)} months`;
            } else {
                timeString = `${Math.floor(diff / 31536000)} years`;
            }

            return addAgoSuffix ? `${timeString} ago` : timeString;
        },

        escapeHtml: function(unsafe) {
            if (typeof unsafe !== 'string') {
                console.warn('escapeHtml received a non-string value:', unsafe);
                return '';
            }
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        },

        formatPrice: function(coin, price) {
            if (typeof price !== 'number' || isNaN(price)) {
                console.warn(`Invalid price for ${coin}:`, price);
                return 'N/A';
            }
            if (price < 0.000001) return price.toExponential(2);
            if (price < 0.001) return price.toFixed(8);
            if (price < 1) return price.toFixed(4);
            if (price < 10) return price.toFixed(3);
            if (price < 1000) return price.toFixed(2);
            if (price < 100000) return price.toFixed(1);
            return price.toFixed(0);
        },

        getEmptyPriceData: function() {
            return {
                'bitcoin': { usd: null, btc: null },
                'bitcoin-cash': { usd: null, btc: null },
                'dash': { usd: null, btc: null },
                'dogecoin': { usd: null, btc: null },
                'decred': { usd: null, btc: null },
                'litecoin': { usd: null, btc: null },
                'particl': { usd: null, btc: null },
                'pivx': { usd: null, btc: null },
                'monero': { usd: null, btc: null },
                'zano': { usd: null, btc: null },
                'wownero': { usd: null, btc: null },
                'firo': { usd: null, btc: null }
            };
        },
        
        getCoinSymbol: function(fullName) {
            return publicAPI.coinMappings?.nameToSymbol[fullName] || fullName;
        }
    };
    
    return publicAPI;
})();

window.logger = {
    log: function(message) {
        console.log(`[AppLog] ${new Date().toISOString()}: ${message}`);
    },
    warn: function(message) {
        console.warn(`[AppWarn] ${new Date().toISOString()}: ${message}`);
    },
    error: function(message) {
        console.error(`[AppError] ${new Date().toISOString()}: ${message}`);
    }
};

window.config = ConfigManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.configManagerInitialized) {
        ConfigManager.initialize();
        window.configManagerInitialized = true;
    }
});

if (typeof module !== 'undefined') {
    module.exports = ConfigManager;
}

//console.log('ConfigManager initialized with properties:', Object.keys(ConfigManager));
console.log('ConfigManager initialized');
