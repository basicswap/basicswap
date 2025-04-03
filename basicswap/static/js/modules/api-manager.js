const ApiManager = (function() {

    const state = {
        isInitialized: false
    };

    const config = {
        requestTimeout: 60000,
        retryDelays: [5000, 15000, 30000],
        rateLimits: {
            coingecko: {
                requestsPerMinute: 50,
                minInterval: 1200
            },
            cryptocompare: {
                requestsPerMinute: 30,
                minInterval: 2000
            }
        }
    };

    const rateLimiter = {
        lastRequestTime: {},
        minRequestInterval: {
            coingecko: 1200,
            cryptocompare: 2000
        },
        requestQueue: {},
        retryDelays: [5000, 15000, 30000],

        canMakeRequest: function(apiName) {
            const now = Date.now();
            const lastRequest = this.lastRequestTime[apiName] || 0;
            return (now - lastRequest) >= this.minRequestInterval[apiName];
        },

        updateLastRequestTime: function(apiName) {
            this.lastRequestTime[apiName] = Date.now();
        },

        getWaitTime: function(apiName) {
            const now = Date.now();
            const lastRequest = this.lastRequestTime[apiName] || 0;
            return Math.max(0, this.minRequestInterval[apiName] - (now - lastRequest));
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
                        await new Promise(resolve => setTimeout(resolve, waitTime));
                    }

                    try {
                        this.updateLastRequestTime(apiName);
                        return await requestFn();
                    } catch (error) {
                        if (error.message.includes('429') && retryCount < this.retryDelays.length) {
                            const delay = this.retryDelays[retryCount];
                            console.log(`Rate limit hit, retrying in ${delay/1000} seconds...`);
                            await new Promise(resolve => setTimeout(resolve, delay));
                            return publicAPI.rateLimiter.queueRequest(apiName, requestFn, retryCount + 1);
                        }

                        if ((error.message.includes('timeout') || error.name === 'NetworkError') &&
                            retryCount < this.retryDelays.length) {
                            const delay = this.retryDelays[retryCount];
                            console.warn(`Request failed, retrying in ${delay/1000} seconds...`, {
                                apiName,
                                retryCount,
                                error: error.message
                            });
                            await new Promise(resolve => setTimeout(resolve, delay));
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
                Object.assign(config, options.config);
            }

            if (config.rateLimits) {
                Object.keys(config.rateLimits).forEach(api => {
                    if (config.rateLimits[api].minInterval) {
                        rateLimiter.minRequestInterval[api] = config.rateLimits[api].minInterval;
                    }
                });
            }

            if (config.retryDelays) {
                rateLimiter.retryDelays = [...config.retryDelays];
            }

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('apiManager', this, (mgr) => mgr.dispose());
            }

            state.isInitialized = true;
            console.log('ApiManager initialized');
            return this;
        },

        makeRequest: async function(url, method = 'GET', headers = {}, body = null) {
            try {
                const options = {
                    method: method,
                    headers: {
                        'Content-Type': 'application/json',
                        ...headers
                    },
                    signal: AbortSignal.timeout(config.requestTimeout)
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

                    //console.log('Fetching coin prices for:', coins);
                    const response = await this.fetchCoinPrices(coins);

                    //console.log('Full API response:', response);

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
                    const coins = (window.config && window.config.coins) ?
                        window.config.coins
                            .filter(coin => coin.usesCoinGecko)
                            .map(coin => getCoinBackendId ? getCoinBackendId(coin.name) : coin.name)
                            .join(',') :
                        'bitcoin,monero,particl,bitcoin-cash,pivx,firo,dash,litecoin,dogecoin,decred,namecoin';

                    const url = `https://api.coingecko.com/api/v3/simple/price?ids=${coins}&vs_currencies=usd&include_24hr_vol=true&include_24hr_change=true`;

                    const response = await this.makePostRequest(url, {
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'application/json'
                    });

                    const volumeData = {};
                    Object.entries(response).forEach(([coinId, data]) => {
                        if (data && data.usd_24h_vol) {
                            volumeData[coinId] = {
                                total_volume: data.usd_24h_vol,
                                price_change_percentage_24h: data.usd_24h_change || 0
                            };
                        }
                    });

                    return volumeData;
                } catch (error) {
                    console.error("Error fetching volume data:", error);
                    throw error;
                }
            });
        },

        fetchCryptoCompareData: function(coin) {
            return this.rateLimiter.queueRequest('cryptocompare', async () => {
                try {
                    const apiKey = window.config?.apiKeys?.cryptoCompare || '';
                    const url = `https://min-api.cryptocompare.com/data/pricemultifull?fsyms=${coin}&tsyms=USD,BTC&api_key=${apiKey}`;
                    const headers = {
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'application/json'
                    };

                    return await this.makePostRequest(url, headers);
                } catch (error) {
                    console.error(`CryptoCompare request failed for ${coin}:`, error);
                    throw error;
                }
            });
        },

        fetchHistoricalData: async function(coinSymbols, resolution = 'day') {
            if (!Array.isArray(coinSymbols)) {
                coinSymbols = [coinSymbols];
            }

            const results = {};
            const fetchPromises = coinSymbols.map(async coin => {
                if (coin === 'WOW') {
                    return this.rateLimiter.queueRequest('coingecko', async () => {
                        const url = `https://api.coingecko.com/api/v3/coins/wownero/market_chart?vs_currency=usd&days=1`;
                        try {
                            const response = await this.makePostRequest(url);
                            if (response && response.prices) {
                                results[coin] = response.prices;
                            }
                        } catch (error) {
                            console.error(`Error fetching CoinGecko data for WOW:`, error);
                            throw error;
                        }
                    });
                } else {
                    return this.rateLimiter.queueRequest('cryptocompare', async () => {
                        try {
                            const apiKey = window.config?.apiKeys?.cryptoCompare || '';
                            let url;

                            if (resolution === 'day') {
                                url = `https://min-api.cryptocompare.com/data/v2/histohour?fsym=${coin}&tsym=USD&limit=24&api_key=${apiKey}`;
                            } else if (resolution === 'year') {
                                url = `https://min-api.cryptocompare.com/data/v2/histoday?fsym=${coin}&tsym=USD&limit=365&api_key=${apiKey}`;
                            } else {
                                url = `https://min-api.cryptocompare.com/data/v2/histoday?fsym=${coin}&tsym=USD&limit=180&api_key=${apiKey}`;
                            }

                            const response = await this.makePostRequest(url);
                            if (response.Response === "Error") {
                                console.error(`API Error for ${coin}:`, response.Message);
                                throw new Error(response.Message);
                            } else if (response.Data && response.Data.Data) {
                                results[coin] = response.Data;
                            }
                        } catch (error) {
                            console.error(`Error fetching CryptoCompare data for ${coin}:`, error);
                            throw error;
                        }
                    });
                }
            });

            await Promise.all(fetchPromises);
            return results;
        },

        dispose: function() {
            // Clear any pending requests or resources
            rateLimiter.requestQueue = {};
            rateLimiter.lastRequestTime = {};
            state.isInitialized = false;
            console.log('ApiManager disposed');
        }
    };

    return publicAPI;
})();

function getCoinBackendId(coinName) {
    const nameMap = {
        'bitcoin-cash': 'bitcoincash',
        'bitcoin cash': 'bitcoincash',
        'firo': 'zcoin',
        'zcoin': 'zcoin',
        'bitcoincash': 'bitcoin-cash'
    };
    return nameMap[coinName.toLowerCase()] || coinName.toLowerCase();
}

window.Api = ApiManager;
window.ApiManager = ApiManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.apiManagerInitialized) {
        ApiManager.initialize();
        window.apiManagerInitialized = true;
    }
});

//console.log('ApiManager initialized with methods:', Object.keys(ApiManager));
console.log('ApiManager initialized');
