const ApiManager = (function() {

    const state = {
        isInitialized: false
    };

    function getConfig() {
        return window.config || window.ConfigManager || {
            requestTimeout: 60000,
            retryDelays: [5000, 15000, 30000],
            rateLimits: {
                coingecko: { requestsPerMinute: 50, minInterval: 1200 }
            }
        };
    }

    const rateLimiter = {
        lastRequestTime: {},
        requestQueue: {},

        getMinInterval: function(apiName) {
            const config = getConfig();
            return config.rateLimits?.[apiName]?.minInterval || 1200;
        },

        getRetryDelays: function() {
            const config = getConfig();
            return config.retryDelays || [5000, 15000, 30000];
        },

        canMakeRequest: function(apiName) {
            const now = Date.now();
            const lastRequest = this.lastRequestTime[apiName] || 0;
            return (now - lastRequest) >= this.getMinInterval(apiName);
        },

        updateLastRequestTime: function(apiName) {
            this.lastRequestTime[apiName] = Date.now();
        },

        getWaitTime: function(apiName) {
            const now = Date.now();
            const lastRequest = this.lastRequestTime[apiName] || 0;
            return Math.max(0, this.getMinInterval(apiName) - (now - lastRequest));
        },

        queueRequest: async function(apiName, requestFn, retryCount = 0) {
            if (!this.requestQueue[apiName]) {
                this.requestQueue[apiName] = Promise.resolve();
            }

            try {
                await this.requestQueue[apiName];

                const executeRequest = async () => {
                    const waitTime = this.getWaitTime(apiName);
                    if (waitTime > 0) {
                        await new Promise(resolve => CleanupManager.setTimeout(resolve, waitTime));
                    }

                    try {
                        this.updateLastRequestTime(apiName);
                        return await requestFn();
                    } catch (error) {
                        const retryDelays = this.getRetryDelays();
                        if (error.message.includes('429') && retryCount < retryDelays.length) {
                            const delay = retryDelays[retryCount];
                            console.log(`Rate limit hit, retrying in ${delay/1000} seconds...`);
                            await new Promise(resolve => CleanupManager.setTimeout(resolve, delay));
                            return publicAPI.rateLimiter.queueRequest(apiName, requestFn, retryCount + 1);
                        }

                        if ((error.message.includes('timeout') || error.name === 'NetworkError') &&
                            retryCount < retryDelays.length) {
                            const delay = retryDelays[retryCount];
                            console.warn(`Request failed, retrying in ${delay/1000} seconds...`, {
                                apiName,
                                retryCount,
                                error: error.message
                            });
                            await new Promise(resolve => CleanupManager.setTimeout(resolve, delay));
                            return publicAPI.rateLimiter.queueRequest(apiName, requestFn, retryCount + 1);
                        }

                        throw error;
                    }
                };

                this.requestQueue[apiName] = executeRequest();
                return await this.requestQueue[apiName];

            } catch (error) {
                if (error.message.includes('429') ||
                    error.message.includes('timeout') ||
                    error.name === 'NetworkError') {
                    const cacheKey = `coinData_${apiName}`;
                    try {
                        const cachedData = JSON.parse(localStorage.getItem(cacheKey));
                        if (cachedData && cachedData.value) {
                            return cachedData.value;
                        }
                    } catch (e) {
                        console.warn('Error accessing cached data:', e);
                    }
                }
                throw error;
            }
        }
    };

    const publicAPI = {
        config,
        rateLimiter,

        initialize: function(options = {}) {
            if (state.isInitialized) {
                console.warn('[ApiManager] Already initialized');
                return this;
            }

            if (options.config) {
                console.log('[ApiManager] Config options provided, but using ConfigManager instead');
            }

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('apiManager', this, (mgr) => mgr.dispose());
            }

            state.isInitialized = true;
            console.log('ApiManager initialized');
            return this;
        },

        makeRequest: async function(url, method = 'GET', headers = {}, body = null) {
            if (window.ErrorHandler) {
                return window.ErrorHandler.safeExecuteAsync(async () => {
                    const options = {
                        method: method,
                        headers: {
                            'Content-Type': 'application/json',
                            ...headers
                        },
                        signal: AbortSignal.timeout(getConfig().requestTimeout || 60000)
                    };

                    if (body) {
                        options.body = JSON.stringify(body);
                    }

                    const response = await fetch(url, options);

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    return await response.json();
                }, `ApiManager.makeRequest(${url})`, null);
            }

            try {
                const options = {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        ...headers
                    },
                    signal: AbortSignal.timeout(getConfig().requestTimeout || 60000)
                };

                if (body) {
                    options.body = JSON.stringify(body);
                }

                const response = await fetch(url, options);

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                return await response.json();
            } catch (error) {
                console.error(`Request failed for ${url}:`, error);
                throw error;
            }
        },

        makePostRequest: async function(url, headers = {}) {
            return new Promise((resolve, reject) => {
                fetch('/json/readurl', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        url: url,
                        headers: headers
                    })
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.Error) {
                        reject(new Error(data.Error));
                    } else {
                        resolve(data);
                    }
                })
                .catch(error => {
                    console.error(`Request failed for ${url}:`, error);
                    reject(error);
                });
            });
        },

        fetchCoinPrices: async function(coins, source = "coingecko.com", ttl = 300) {
            if (!coins) {
                throw new Error('No coins specified for price lookup');
            }
            let coinsParam;
            if (Array.isArray(coins)) {
                coinsParam = coins.filter(c => c && c.trim() !== '').join(',');
            } else if (typeof coins === 'object' && coins.coins) {
                coinsParam = coins.coins;
            } else {
                coinsParam = coins;
            }
            if (!coinsParam || coinsParam.trim() === '') {
                throw new Error('No valid coins to fetch prices for');
            }

            return this.makeRequest('/json/coinprices', 'POST', {}, {
                coins: coinsParam,
                source: source,
                ttl: ttl
            });
        },

        fetchCoinGeckoData: async function() {
            return this.rateLimiter.queueRequest('coingecko', async () => {
                try {
                    const coins = (window.config && window.config.coins) ?
                        window.config.coins
                            .filter(coin => coin.usesCoinGecko)
                            .map(coin => coin.name)
                            .join(',') :
                        'bitcoin,monero,particl,bitcoincash,pivx,firo,dash,litecoin,dogecoin,decred,namecoin';

                    const response = await this.fetchCoinPrices(coins);

                    if (!response || typeof response !== 'object') {
                        throw new Error('Invalid response type');
                    }

                    if (!response.rates || typeof response.rates !== 'object' || Object.keys(response.rates).length === 0) {
                        throw new Error('No valid rates found in response');
                    }

                    return response;
                } catch (error) {
                    console.error('Error in fetchCoinGeckoData:', {
                        message: error.message,
                        stack: error.stack
                    });
                    throw error;
                }
            });
        },

        fetchVolumeData: async function() {
            return this.rateLimiter.queueRequest('coingecko', async () => {
                try {
                    const coinSymbols = window.CoinManager
                        ? window.CoinManager.getAllCoins().map(c => c.symbol).filter(symbol => symbol && symbol.trim() !== '')
                        : (window.config.coins
                            ? window.config.coins.map(c => c.symbol).filter(symbol => symbol && symbol.trim() !== '')
                            : ['BTC', 'XMR', 'PART', 'BCH', 'PIVX', 'FIRO', 'DASH', 'LTC', 'DOGE', 'DCR', 'NMC', 'WOW']);

                    const response = await this.makeRequest('/json/coinvolume', 'POST', {}, {
                        coins: coinSymbols.join(','),
                        source: 'coingecko.com',
                        ttl: 300
                    });

                    if (!response) {
                        console.error('No response from backend');
                        throw new Error('Invalid response from backend');
                    }

                    if (!response.data) {
                        console.error('Response missing data field:', response);
                        throw new Error('Invalid response from backend');
                    }

                    const volumeData = {};

                    Object.entries(response.data).forEach(([coinSymbol, data]) => {
                        const coinKey = coinSymbol.toLowerCase();
                        volumeData[coinKey] = {
                            total_volume: (data.volume_24h !== undefined && data.volume_24h !== null) ? data.volume_24h : null,
                            price_change_percentage_24h: data.price_change_24h || 0
                        };
                    });

                    return volumeData;
                } catch (error) {
                    console.error("Error fetching volume data:", error);
                    throw error;
                }
            });
        },

        fetchHistoricalData: async function(coinSymbols, resolution = 'day') {
            if (!Array.isArray(coinSymbols)) {
                coinSymbols = [coinSymbols];
            }

            return this.rateLimiter.queueRequest('coingecko', async () => {
                try {
                    let days;
                    if (resolution === 'day') {
                        days = 1;
                    } else if (resolution === 'year') {
                        days = 365;
                    } else {
                        days = 180;
                    }

                    const response = await this.makeRequest('/json/coinhistory', 'POST', {}, {
                        coins: coinSymbols.join(','),
                        days: days,
                        source: 'coingecko.com',
                        ttl: 3600
                    });

                    if (!response) {
                        console.error('No response from backend');
                        throw new Error('Invalid response from backend');
                    }

                    if (!response.data) {
                        console.error('Response missing data field:', response);
                        throw new Error('Invalid response from backend');
                    }

                    return response.data;
                } catch (error) {
                    console.error('Error fetching historical data:', error);
                    throw error;
                }
            });
        },

        dispose: function() {
            rateLimiter.requestQueue = {};
            rateLimiter.lastRequestTime = {};
            state.isInitialized = false;
            console.log('ApiManager disposed');
        }
    };

    return publicAPI;
})();

window.Api = ApiManager;
window.ApiManager = ApiManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.apiManagerInitialized) {
        ApiManager.initialize();
        window.apiManagerInitialized = true;
    }
});

console.log('ApiManager initialized');
