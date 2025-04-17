const PriceManager = (function() {
    const PRICES_CACHE_KEY = 'prices_unified';
    let fetchPromise = null;
    let lastFetchTime = 0;
    const MIN_FETCH_INTERVAL = 60000;
    let isInitialized = false;
    const eventListeners = {
        'priceUpdate': [],
        'error': []
    };

    return {
        addEventListener: function(event, callback) {
            if (eventListeners[event]) {
                eventListeners[event].push(callback);
            }
        },

        removeEventListener: function(event, callback) {
            if (eventListeners[event]) {
                eventListeners[event] = eventListeners[event].filter(cb => cb !== callback);
            }
        },

        triggerEvent: function(event, data) {
            if (eventListeners[event]) {
                eventListeners[event].forEach(callback => callback(data));
            }
        },

        initialize: function() {
            if (isInitialized) {
                console.warn('PriceManager: Already initialized');
                return this;
            }

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('priceManager', this, (mgr) => {
                    Object.keys(eventListeners).forEach(event => {
                        eventListeners[event] = [];
                    });
                });
            }

            setTimeout(() => this.getPrices(), 1500);
            isInitialized = true;
            return this;
        },

        getPrices: async function(forceRefresh = false) {
            if (!forceRefresh) {
                const cachedData = CacheManager.get(PRICES_CACHE_KEY);
                if (cachedData) {
                    return cachedData.value;
                }
            }

            if (fetchPromise && Date.now() - lastFetchTime < MIN_FETCH_INTERVAL) {
                return fetchPromise;
            }

            console.log('PriceManager: Fetching latest prices.');
            lastFetchTime = Date.now();
            fetchPromise = this.fetchPrices()
                .then(prices => {
                    this.triggerEvent('priceUpdate', prices);
                    return prices;
                })
                .catch(error => {
                    this.triggerEvent('error', error);
                    throw error;
                })
                .finally(() => {
                    fetchPromise = null;
                });

            return fetchPromise;
        },

        fetchPrices: async function() {
            try {
                if (!NetworkManager.isOnline()) {
                    throw new Error('Network is offline');
                }

                const coinSymbols = window.CoinManager
                    ? window.CoinManager.getAllCoins().map(c => c.symbol).filter(symbol => symbol && symbol.trim() !== '')
                    : (window.config.coins
                        ? window.config.coins.map(c => c.symbol).filter(symbol => symbol && symbol.trim() !== '')
                        : ['BTC', 'XMR', 'PART', 'BCH', 'PIVX', 'FIRO', 'DASH', 'LTC', 'DOGE', 'DCR', 'NMC', 'WOW']);

                console.log('PriceManager: lookupFiatRates ' + coinSymbols.join(', '));

                if (!coinSymbols.length) {
                    throw new Error('No valid coins configured');
                }

                let apiResponse;
                try {
                    apiResponse = await Api.fetchCoinPrices(
                        coinSymbols,
                        "coingecko.com",
                        300
                    );

                    if (!apiResponse) {
                        throw new Error('Empty response received from API');
                    }

                    if (apiResponse.error) {
                        throw new Error(`API error: ${apiResponse.error}`);
                    }

                    if (!apiResponse.rates) {
                        throw new Error('No rates found in API response');
                    }

                    if (typeof apiResponse.rates !== 'object' || Object.keys(apiResponse.rates).length === 0) {
                        throw new Error('Empty rates object in API response');
                    }
                } catch (apiError) {
                    console.error('API call error:', apiError);
                    throw new Error(`API error: ${apiError.message}`);
                }

                const processedData = {};

                Object.entries(apiResponse.rates).forEach(([coinId, price]) => {
                    let normalizedCoinId;

                    if (window.CoinManager) {
                        const coin = window.CoinManager.getCoinByAnyIdentifier(coinId);
                        if (coin) {
                            normalizedCoinId = window.CoinManager.getPriceKey(coin.name);
                        } else {
                            normalizedCoinId = coinId === 'bitcoincash' ? 'bitcoin-cash' : coinId.toLowerCase();
                        }
                    } else {
                        normalizedCoinId = coinId === 'bitcoincash' ? 'bitcoin-cash' : coinId.toLowerCase();
                    }

                    if (coinId.toLowerCase() === 'zcoin') {
                        normalizedCoinId = 'firo';
                    }

                    processedData[normalizedCoinId] = {
                        usd: price,
                        btc: normalizedCoinId === 'bitcoin' ? 1 : price / (apiResponse.rates.bitcoin || 1)
                    };
                });

                CacheManager.set(PRICES_CACHE_KEY, processedData, 'prices');

                Object.entries(processedData).forEach(([coin, prices]) => {
                    if (prices.usd) {
                        if (window.tableRateModule) {
                            window.tableRateModule.setFallbackValue(coin, prices.usd);
                        }
                    }
                });

                return processedData;
            } catch (error) {
                console.error('Error fetching prices:', error);
                NetworkManager.handleNetworkError(error);

                const cachedData = CacheManager.get(PRICES_CACHE_KEY);
                if (cachedData) {
                    console.log('Using cached price data');
                    return cachedData.value;
                }

                try {
                    const existingCache = localStorage.getItem(PRICES_CACHE_KEY);
                    if (existingCache) {
                        console.log('Using localStorage cached price data');
                        return JSON.parse(existingCache).value;
                    }
                } catch (e) {
                    console.warn('Failed to parse existing cache:', e);
                }

                const emptyData = {};

                const coinNames = window.CoinManager
                    ? window.CoinManager.getAllCoins().map(c => c.name.toLowerCase())
                    : ['bitcoin', 'bitcoin-cash', 'dash', 'dogecoin', 'decred', 'namecoin', 'litecoin', 'particl', 'pivx', 'monero', 'wownero', 'firo'];

                coinNames.forEach(coin => {
                    emptyData[coin] = { usd: null, btc: null };
                });

                return emptyData;
            }
        },

        getCoinPrice: function(coinSymbol) {
            if (!coinSymbol) return null;
            const prices = this.getPrices();
            if (!prices) return null;

            let normalizedSymbol;
            if (window.CoinManager) {
                normalizedSymbol = window.CoinManager.getPriceKey(coinSymbol);
            } else {
                normalizedSymbol = coinSymbol.toLowerCase();
            }

            return prices[normalizedSymbol] || null;
        },

        formatPrice: function(coin, price) {
            if (window.config && window.config.utils && window.config.utils.formatPrice) {
                return window.config.utils.formatPrice(coin, price);
            }
            if (typeof price !== 'number' || isNaN(price)) return 'N/A';
            if (price < 0.01) return price.toFixed(8);
            if (price < 1) return price.toFixed(4);
            if (price < 1000) return price.toFixed(2);
            return price.toFixed(0);
        }
    };
})();

window.PriceManager = PriceManager;
document.addEventListener('DOMContentLoaded', function() {
    if (!window.priceManagerInitialized) {
        window.PriceManager = PriceManager.initialize();
        window.priceManagerInitialized = true;
    }
});

console.log('PriceManager initialized');
