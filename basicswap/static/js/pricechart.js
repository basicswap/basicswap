// CONFIG
const config = {
  apiKeys: getAPIKeys(),
  coins: [
    { symbol: 'BTC', name: 'bitcoin', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'XMR', name: 'monero', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'PART', name: 'particl', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'BCH', name: 'bitcoin-cash', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'PIVX', name: 'pivx', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'FIRO', name: 'zcoin', displayName: 'Firo', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'DASH', name: 'dash', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'LTC', name: 'litecoin', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'DOGE', name: 'dogecoin', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'ETH', name: 'ethereum', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'DCR', name: 'decred', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'ZANO', name: 'zano', usesCryptoCompare: true, usesCoinGecko: true, historicalDays: 30 },
    { symbol: 'WOW', name: 'wownero', usesCryptoCompare: false, usesCoinGecko: true, historicalDays: 30 }
  ],
  apiEndpoints: {
    cryptoCompare: 'https://min-api.cryptocompare.com/data/pricemultifull',
    coinGecko: 'https://api.coingecko.com/api/v3',
    cryptoCompareHistorical: 'https://min-api.cryptocompare.com/data/v2/histoday'
  },
  chartColors: {
    default: {
      lineColor: 'rgba(77, 132, 240, 1)',
      backgroundColor: 'rgba(77, 132, 240, 0.1)'
    }
  },
  showVolume: false,
  cacheTTL: 10 * 60 * 1000,
  specialCoins: [''],
  resolutions: {
    year: { days: 365, interval: 'month' },
    sixMonths: { days: 180, interval: 'daily' },
    day: { days: 1, interval: 'hourly' }
  },
  currentResolution: 'year',
  requestTimeout: 60000,  // 60 sec
  retryDelays: [5000, 15000, 30000],
  rateLimits: {
    coingecko: {
      requestsPerMinute: 50,
      minInterval: 1200  // 1.2 sec
    },
    cryptocompare: {
      requestsPerMinute: 30,
      minInterval: 2000  // 2 sec
    }
  }
};

// UTILS
const utils = {
  formatNumber: (number, decimals = 2) =>
    number.toFixed(decimals).replace(/\B(?=(\d{3})+(?!\d))/g, ','),
  formatDate: (timestamp, resolution) => {
    const date = new Date(timestamp);
    const options = {
      day: { hour: '2-digit', minute: '2-digit', hour12: true },
      week: { month: 'short', day: 'numeric' },
      month: { year: 'numeric', month: 'short', day: 'numeric' }
    };
    return date.toLocaleString('en-US', { ...options[resolution], timeZone: 'UTC' });
  },

  debounce: (func, delay) => {
    let timeoutId;
    return (...args) => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func(...args), delay);
    };
  }
};

// ERROR
class AppError extends Error {
  constructor(message, type = 'AppError') {
    super(message);
    this.name = type;
  }
}

// LOG
const logger = {
  log: (message) => console.log(`[AppLog] ${new Date().toISOString()}: ${message}`),
  warn: (message) => console.warn(`[AppWarn] ${new Date().toISOString()}: ${message}`),
  error: (message) => console.error(`[AppError] ${new Date().toISOString()}: ${message}`)
};

const api = {
    makePostRequest: (url, headers = {}) => {
        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', '/json/readurl');
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.timeout = config.requestTimeout;
            
            xhr.ontimeout = () => {
                logger.warn(`Request timed out for ${url}`);
                reject(new AppError('Request timed out'));
            };
            
            xhr.onload = () => {
                logger.log(`Response for ${url}:`, xhr.responseText);
                if (xhr.status === 200) {
                    try {
                        const response = JSON.parse(xhr.responseText);
                        if (response.Error) {
                            logger.error(`API Error for ${url}:`, response.Error);
                            reject(new AppError(response.Error, 'APIError'));
                        } else {
                            resolve(response);
                        }
                    } catch (error) {
                        logger.error(`Invalid JSON response for ${url}:`, xhr.responseText);
                        reject(new AppError(`Invalid JSON response: ${error.message}`, 'ParseError'));
                    }
                } else {
                    logger.error(`HTTP Error for ${url}: ${xhr.status} ${xhr.statusText}`);
                    reject(new AppError(`HTTP Error: ${xhr.status} ${xhr.statusText}`, 'HTTPError'));
                }
            };
            
            xhr.onerror = () => {
                logger.error(`Network error occurred for ${url}`);
                reject(new AppError('Network error occurred', 'NetworkError'));
            };
            
            xhr.send(JSON.stringify({
                url: url,
                headers: headers
            }));
        });
    },

    fetchCryptoCompareDataXHR: (coin) => {
        return rateLimiter.queueRequest('cryptocompare', async () => {
            const url = `${config.apiEndpoints.cryptoCompare}?fsyms=${coin}&tsyms=USD,BTC&api_key=${config.apiKeys.cryptoCompare}`;
            const headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            };
            try {
                return await api.makePostRequest(url, headers);
            } catch (error) {
                logger.error(`CryptoCompare request failed for ${coin}:`, error);
                const cachedData = cache.get(`coinData_${coin}`);
                if (cachedData) {
                    logger.info(`Using cached data for ${coin}`);
                    return cachedData.value;
                }
                return { error: error.message };
            }
        });
    },

    fetchCoinGeckoDataXHR: async () => {
        const cacheKey = 'coinGeckoOneLiner';
        const cachedData = cache.get(cacheKey);

        if (cachedData) {
            console.log('Using cached CoinGecko data');
            return cachedData.value;
        }

        return rateLimiter.queueRequest('coingecko', async () => {
            try {
                const existingCache = localStorage.getItem(cacheKey);
                let fallbackData = null;

                if (existingCache) {
                    try {
                        const parsed = JSON.parse(existingCache);
                        fallbackData = parsed.value;
                    } catch (e) {
                        console.warn('Failed to parse existing cache:', e);
                    }
                }

                const coinIds = config.coins
                    .filter(coin => coin.usesCoinGecko)
                    .map(coin => coin.name)
                    .join(',');

                const url = `${config.apiEndpoints.coinGecko}/simple/price?ids=${coinIds}&vs_currencies=usd,btc&include_24hr_vol=true&include_24hr_change=true&api_key=${config.apiKeys.coinGecko}`;

                const response = await api.makePostRequest(url, {
                    'User-Agent': 'Mozilla/5.0',
                    'Accept': 'application/json',
                    'Accept-Language': 'en-US,en;q=0.5'
                });

                if (typeof response !== 'object' || response === null) {
                    if (fallbackData) {
                        console.log('Using fallback data due to invalid response');
                        return fallbackData;
                    }
                    throw new AppError('Invalid data structure received from CoinGecko');
                }

                if (response.error || response.Error) {
                    if (fallbackData) {
                        console.log('Using fallback data due to API error');
                        return fallbackData;
                    }
                    throw new AppError(response.error || response.Error);
                }

                const transformedData = {};
                Object.entries(response).forEach(([id, values]) => {
                    const coinConfig = config.coins.find(coin => coin.name === id);
                    const symbol = coinConfig?.symbol.toLowerCase() || id;
                    transformedData[symbol] = {
                        current_price: values.usd,
                        price_btc: values.btc,
                        total_volume: values.usd_24h_vol,
                        price_change_percentage_24h: values.usd_24h_change,
                        displayName: coinConfig?.displayName || coinConfig?.symbol || id
                    };
                });

                cache.set(cacheKey, transformedData);
                return transformedData;

            } catch (error) {
                console.error('Error fetching CoinGecko data:', error);

                const cachedData = cache.get(cacheKey);
                if (cachedData) {
                    console.log('Using expired cache data due to error');
                    return cachedData.value;
                }

                throw error;
            }
        });
    },

    fetchHistoricalDataXHR: async (coinSymbols) => {
        if (!Array.isArray(coinSymbols)) {
            coinSymbols = [coinSymbols];
        }

        const results = {};
        const fetchPromises = coinSymbols.map(async coin => {
            const coinConfig = config.coins.find(c => c.symbol === coin);
            if (!coinConfig) return;

            const cacheKey = `historical_${coin}_${config.currentResolution}`;
            const cachedData = cache.get(cacheKey);
            if (cachedData) {
                results[coin] = cachedData.value;
                return;
            }

            if (coin === 'WOW') {
                return rateLimiter.queueRequest('coingecko', async () => {
                    const url = `${config.apiEndpoints.coinGecko}/coins/wownero/market_chart?vs_currency=usd&days=1&api_key=${config.apiKeys.coinGecko}`;
                    try {
                        const response = await api.makePostRequest(url);
                        if (response && response.prices) {
                            results[coin] = response.prices;
                            cache.set(cacheKey, response.prices);
                        }
                    } catch (error) {
                        console.error(`Error fetching CoinGecko data for WOW:`, error);
                        if (cachedData) {
                            results[coin] = cachedData.value;
                        }
                    }
                });
            } else {
                return rateLimiter.queueRequest('cryptocompare', async () => {
                    const resolution = config.resolutions[config.currentResolution];
                    let url;
                    if (resolution.interval === 'hourly') {
                        url = `https://min-api.cryptocompare.com/data/v2/histohour?fsym=${coin}&tsym=USD&limit=${resolution.days * 24}&api_key=${config.apiKeys.cryptoCompare}`;
                    } else {
                        url = `${config.apiEndpoints.cryptoCompareHistorical}?fsym=${coin}&tsym=USD&limit=${resolution.days}&api_key=${config.apiKeys.cryptoCompare}`;
                    }

                    try {
                        const response = await api.makePostRequest(url);
                        if (response.Response === "Error") {
                            console.error(`API Error for ${coin}:`, response.Message);
                            if (cachedData) {
                                results[coin] = cachedData.value;
                            }
                        } else if (response.Data && response.Data.Data) {
                            results[coin] = response.Data;
                            cache.set(cacheKey, response.Data);
                        }
                    } catch (error) {
                        console.error(`Error fetching CryptoCompare data for ${coin}:`, error);
                        if (cachedData) {
                            results[coin] = cachedData.value;
                        }
                    }
                });
            }
        });

        await Promise.all(fetchPromises);
        return results;
    }
};

const rateLimiter = {
    lastRequestTime: {},
    minRequestInterval: {
        coingecko: config.rateLimits.coingecko.minInterval,
        cryptocompare: config.rateLimits.cryptocompare.minInterval
    },
    requestQueue: {},
    retryDelays: config.retryDelays,
    
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
                        return this.queueRequest(apiName, requestFn, retryCount + 1);
                    }

                    if ((error.message.includes('timeout') || error.name === 'NetworkError') && 
                        retryCount < this.retryDelays.length) {
                        const delay = this.retryDelays[retryCount];
                        logger.warn(`Request failed, retrying in ${delay/1000} seconds...`, {
                            apiName,
                            retryCount,
                            error: error.message
                        });
                        await new Promise(resolve => setTimeout(resolve, delay));
                        return this.queueRequest(apiName, requestFn, retryCount + 1);
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
                const cachedData = cache.get(`coinData_${apiName}`);
                if (cachedData) {
                    console.log('Using cached data due to request failure');
                    return cachedData.value;
                }
            }
            throw error;
        }
    }
};

// CACHE
const cache = {
  set: (key, value, customTtl = null) => {
    const item = {
      value: value,
      timestamp: Date.now(),
      expiresAt: Date.now() + (customTtl || app.cacheTTL)
    };
    localStorage.setItem(key, JSON.stringify(item));
    //console.log(`Cache set for ${key}, expires in ${(customTtl || app.cacheTTL) / 1000} seconds`);
  },
  get: (key) => {
    const itemStr = localStorage.getItem(key);
    if (!itemStr) {
      return null;
    }
    try {
      const item = JSON.parse(itemStr);
      const now = Date.now();
      if (now < item.expiresAt) {
        //console.log(`Cache hit for ${key}, ${(item.expiresAt - now) / 1000} seconds remaining`);
        return {
          value: item.value,
          remainingTime: item.expiresAt - now
        };
      } else {
        //console.log(`Cache expired for ${key}`);
        localStorage.removeItem(key);
      }
    } catch (error) {
      console.error('Error parsing cache item:', error.message);
      localStorage.removeItem(key);
    }
    return null;
  },
  isValid: (key) => {
    return cache.get(key) !== null;
  },
  clear: () => {
    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('coinData_') || key.startsWith('chartData_') || key === 'coinGeckoOneLiner') {
        localStorage.removeItem(key);
      }
    });
    //console.log('Cache cleared');
  }
};

// UI
const ui = {
displayCoinData: (coin, data) => {
    let priceUSD, priceBTC, priceChange1d, volume24h;
    const updateUI = (isError = false) => {
        const priceUsdElement = document.querySelector(`#${coin.toLowerCase()}-price-usd`);
        const volumeDiv = document.querySelector(`#${coin.toLowerCase()}-volume-div`);
        const volumeElement = document.querySelector(`#${coin.toLowerCase()}-volume-24h`);
        const btcPriceDiv = document.querySelector(`#${coin.toLowerCase()}-btc-price-div`);
        const priceBtcElement = document.querySelector(`#${coin.toLowerCase()}-price-btc`);
        if (priceUsdElement) {
            priceUsdElement.textContent = isError ? 'N/A' : `$ ${ui.formatPrice(coin, priceUSD)}`;
        }
        if (volumeDiv && volumeElement) {
            volumeElement.textContent = isError ? 'N/A' : `${utils.formatNumber(volume24h, 0)} USD`;
            volumeDiv.style.display = volumeToggle.isVisible ? 'flex' : 'none';
        }
        if (btcPriceDiv && priceBtcElement) {
            if (coin === 'BTC') {
                btcPriceDiv.style.display = 'none';
            } else {
                priceBtcElement.textContent = isError ? 'N/A' : `${priceBTC.toFixed(8)}`;
                btcPriceDiv.style.display = 'flex';
            }
        }
        ui.updatePriceChangeContainer(coin, isError ? null : priceChange1d);
    };
    try {
        if (data.error) {
            throw new Error(data.error);
        }
        if (!data || !data.current_price) {
            throw new Error(`Invalid CoinGecko data structure for ${coin}`);
        }
        priceUSD = data.current_price;
        priceBTC = coin === 'BTC' ? 1 : data.price_btc || (data.current_price / app.btcPriceUSD);
        priceChange1d = data.price_change_percentage_24h;
        volume24h = data.total_volume;
        if (isNaN(priceUSD) || isNaN(priceBTC) || isNaN(volume24h)) {
            throw new Error(`Invalid numeric values in data for ${coin}`);
        }
        updateUI(false);
    } catch (error) {
    logger.error(`Failed to display data for ${coin}:`, error.message);
    updateUI(true); // Show error state in UI
}
},

  showLoader: () => {
    const loader = document.getElementById('loader');
    if (loader) {
      loader.classList.remove('hidden');
    }
  },

  hideLoader: () => {
    const loader = document.getElementById('loader');
    if (loader) {
      loader.classList.add('hidden');
    }
  },

  showCoinLoader: (coinSymbol) => {
    const loader = document.getElementById(`${coinSymbol.toLowerCase()}-loader`);
    if (loader) {
      loader.classList.remove('hidden');
    }
  },

  hideCoinLoader: (coinSymbol) => {
    const loader = document.getElementById(`${coinSymbol.toLowerCase()}-loader`);
    if (loader) {
      loader.classList.add('hidden');
    }
  },

  updateCacheStatus: (isCached) => {
    const cacheStatusElement = document.getElementById('cache-status');
    if (cacheStatusElement) {
      cacheStatusElement.textContent = isCached ? 'Cached' : 'Live';
      cacheStatusElement.classList.toggle('text-green-500', isCached);
      cacheStatusElement.classList.toggle('text-blue-500', !isCached);
    }
  },

  updateLoadTimeAndCache: (loadTime, cachedData) => {
    const loadTimeElement = document.getElementById('load-time');
    const cacheStatusElement = document.getElementById('cache-status');
    if (loadTimeElement) {
      loadTimeElement.textContent = `Load time: ${loadTime}ms`;
    }
    if (cacheStatusElement) {
      if (cachedData && cachedData.remainingTime) {
        const remainingMinutes = Math.ceil(cachedData.remainingTime / 60000);
        cacheStatusElement.textContent = `Cached: ${remainingMinutes} min left`;
        cacheStatusElement.classList.add('text-green-500');
        cacheStatusElement.classList.remove('text-blue-500');
      } else {
        cacheStatusElement.textContent = 'Live';
        cacheStatusElement.classList.add('text-blue-500');
        cacheStatusElement.classList.remove('text-green-500');
      }
    }
    ui.updateLastRefreshedTime();
  },

  updatePriceChangeContainer: (coin, priceChange) => {
    const container = document.querySelector(`#${coin.toLowerCase()}-price-change-container`);
    if (container) {
      container.innerHTML = priceChange !== null ?
        (priceChange >= 0 ? ui.positivePriceChangeHTML(priceChange) : ui.negativePriceChangeHTML(priceChange)) :
        'N/A';
    }
  },

  updateLastRefreshedTime: () => {
    const lastRefreshedElement = document.getElementById('last-refreshed-time');
    if (lastRefreshedElement && app.lastRefreshedTime) {
      const formattedTime = app.lastRefreshedTime.toLocaleTimeString();
      lastRefreshedElement.textContent = `Last Refreshed: ${formattedTime}`;
    }
  },

  positivePriceChangeHTML: (value) => `
    <div class="flex flex-wrap items-center py-px px-1 border border-green-500 rounded-full">
      <svg class="mr-0.5" width="15" height="10" viewBox="0 0 15 10" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M8.16667 0.916748C7.75245 0.916748 7.41667 1.25253 7.41667 1.66675C7.41667 2.08096 7.75245 2.41675 8.16667 2.41675V0.916748ZM13.5 1.66675H14.25C14.25 1.25253 13.9142 0.916748 13.5 0.916748V1.66675ZM12.75 7.00008C12.75 7.41429 13.0858 7.75008 13.5 7.75008C13.9142 7.75008 14.25 7.41429 14.25 7.00008H12.75ZM0.96967 7.80308C0.676777 8.09598 0.676777 8.57085 0.96967 8.86374C1.26256 9.15664 1.73744 9.15664 2.03033 8.86374L0.96967 7.80308ZM5.5 4.33341L6.03033 3.80308C5.73744 3.51019 5.26256 3.51019 4.96967 3.80308L5.5 4.33341ZM8.16667 7.00008L7.63634 7.53041C7.92923 7.8233 8.4041 7.8233 8.697 7.53041L8.16667 7.00008ZM8.16667 2.41675H13.5V0.916748H8.16667V2.41675ZM12.75 1.66675V7.00008H14.25V1.66675H12.75ZM2.03033 8.86374L6.03033 4.86374L4.96967 3.80308L0.96967 7.80308L2.03033 8.86374ZM4.96967 4.86374L7.63634 7.53041L8.697 6.46975L6.03033 3.80308L4.96967 4.86374ZM8.697 7.53041L14.0303 2.19708L12.9697 1.13642L7.63634 6.46975L8.697 7.53041Z" fill="#20C43A"></path>
      </svg>
      <span class="text-xs text-green-500 font-medium">${value.toFixed(2)}%</span>
    </div>
  `,

  negativePriceChangeHTML: (value) => `
    <div class="flex flex-wrap items-center py-px px-1 border border-red-500 rounded-full">
      <svg class="mr-0.5" width="14" height="10" viewBox="0 0 14 10" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M7.66667 7.58341C7.25245 7.58341 6.91667 7.9192 6.91667 8.33341C6.91667 8.74763 7.25245 9.08341 7.66667 9.08341V7.58341ZM13 8.33341V9.08341C13.4142 9.08341 13.75 8.74763 13.75 8.33341H13ZM13.75 3.00008C13.75 2.58587 13.4142 2.25008 13 2.25008C12.5858 2.25008 12.25 2.58587 12.25 3.00008H13.75ZM1.53033 1.13642C1.23744 0.843525 0.762563 0.843525 0.46967 1.13642C0.176777 1.42931 0.176777 1.90418 0.46967 2.19708L1.53033 1.13642ZM5 5.66675L4.46967 6.19708C4.76256 6.48997 5.23744 6.48997 5.53033 6.19708L5 5.66675ZM7.66667 3.00008L8.197 2.46975C7.9041 2.17686 7.42923 2.17686 7.13634 2.46975L7.66667 3.00008ZM7.66667 9.08341H13V7.58341H7.66667V9.08341ZM13.75 8.33341V3.00008H12.25V8.33341H13.75ZM0.46967 2.19708L4.46967 6.19708L5.53033 5.13642L1.53033 1.13642L0.46967 2.19708ZM5.53033 6.19708L8.197 3.53041L7.13634 2.46975L4.46967 5.13642L5.53033 6.19708ZM7.13634 3.53041L12.4697 8.86374L13.5303 7.80308L8.197 2.46975L7.13634 3.53041Z" fill="#FF3131"></path>
      </svg>
      <span class="text-xs text-red-500 font-medium">${Math.abs(value).toFixed(2)}%</span>
    </div>
  `,

  formatPrice: (coin, price) => {
    if (typeof price !== 'number' || isNaN(price)) {
      logger.error(`Invalid price for ${coin}:`, price);
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

  setActiveContainer: (containerId) => {
    const containerIds = ['btc', 'xmr', 'part', 'pivx', 'firo', 'dash', 'ltc', 'doge', 'eth', 'dcr', 'zano', 'wow', 'bch'].map(id => `${id}-container`);
    containerIds.forEach(id => {
      const container = document.getElementById(id);
      if (container) {
        const innerDiv = container.querySelector('div');
        innerDiv.classList.toggle('active-container', id === containerId);
      }
    });
  },

  displayErrorMessage: (message) => {
    const errorOverlay = document.getElementById('error-overlay');
    const errorMessage = document.getElementById('error-message');
    const chartContainer = document.querySelector('.container-to-blur');
    if (errorOverlay && errorMessage && chartContainer) {
      errorOverlay.classList.remove('hidden');
      errorMessage.textContent = message;
      chartContainer.classList.add('blurred');
    }
  },

  hideErrorMessage: () => {
    const errorOverlay = document.getElementById('error-overlay');
    const containersToBlur = document.querySelectorAll('.container-to-blur');
    if (errorOverlay) {
      errorOverlay.classList.add('hidden');
      containersToBlur.forEach(container => container.classList.remove('blurred'));
    }
  }
};

// CHART
const chartModule = {
  chart: null,
  currentCoin: 'BTC',
  loadStartTime: 0,
  verticalLinePlugin: {
    id: 'verticalLine',
    beforeDraw: (chart, args, options) => {
      if (chart.tooltip._active && chart.tooltip._active.length) {
        const activePoint = chart.tooltip._active[0];
        const ctx = chart.ctx;
        const x = activePoint.element.x;
        const topY = chart.scales.y.top;
        const bottomY = chart.scales.y.bottom;
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(x, topY);
        ctx.lineTo(x, bottomY);
        ctx.lineWidth = options.lineWidth || 1;
        ctx.strokeStyle = options.lineColor || 'rgba(77, 132, 240, 0.5)';
        ctx.stroke();
        ctx.restore();
      }
    }
  },

  initChart: () => {
    const ctx = document.getElementById('coin-chart')?.getContext('2d');
    if (!ctx) {
      logger.error('Failed to get chart context. Make sure the canvas element exists.');
      return;
    }
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(77, 132, 240, 0.2)');
    gradient.addColorStop(1, 'rgba(77, 132, 240, 0)');
    chartModule.chart = new Chart(ctx, {
      type: 'line',
      data: {
        datasets: [{
          label: 'Price',
          data: [],
          borderColor: 'rgba(77, 132, 240, 1)',
          backgroundColor: gradient,
          tension: 0.4,
          fill: true,
          pointRadius: 2,
          pointHoverRadius: 4,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        scales: {
          x: {
            type: 'time',
            time: {
              unit: 'hour',
              displayFormats: {
                hour: 'h:mm a',
                day: 'MMM d',
                month: 'MMM yyyy'
              },
              tooltipFormat: 'MMM d, yyyy h:mm a'
            },
            adapters: {
              date: {
                zone: 'UTC'
              }
            },
            ticks: {
              source: 'data',
              maxTicksLimit: 12,
              font: {
                size: 12,
                family: "'Inter', sans-serif"
              },
              color: 'rgba(156, 163, 175, 1)',
              maxRotation: 0,
              minRotation: 0,
              callback: function(value) {
                const date = new Date(value);
                if (config.currentResolution === 'day') {
                  return date.toLocaleTimeString('en-US', {
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true,
                    timeZone: 'UTC'
                  });
                } else if (config.currentResolution === 'year') {
                  return date.toLocaleDateString('en-US', {
                    month: 'short',
                    year: 'numeric',
                    timeZone: 'UTC'
                  });
                } else {
                  return date.toLocaleDateString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    timeZone: 'UTC'
                  });
                }
              }
            },
            grid: {
              display: false
            }
          },
          y: {
            beginAtZero: false,
            ticks: {
              font: {
                size: 12,
                family: "'Inter', sans-serif"
              },
              color: 'rgba(156, 163, 175, 1)',
              callback: (value) => '$' + value.toLocaleString()
            },
            grid: {
              display: false
            }
          }
        },
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            mode: 'index',
            intersect: false,
            backgroundColor: 'rgba(255, 255, 255, 0.9)',
            titleColor: 'rgba(17, 24, 39, 1)',
            bodyColor: 'rgba(55, 65, 81, 1)',
            borderColor: 'rgba(226, 232, 240, 1)',
            borderWidth: 1,
            cornerRadius: 4,
            padding: 8,
            displayColors: false,
            callbacks: {
              title: (tooltipItems) => {
                const date = new Date(tooltipItems[0].parsed.x);
                if (config.currentResolution === 'day') {
                  return date.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true,
                    timeZone: 'UTC'
                  });
                } else if (config.currentResolution === 'year') {
                  return date.toLocaleString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    timeZone: 'UTC'
                  });
                } else {
                  return date.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    timeZone: 'UTC'
                  });
                }
              },
              label: (item) => {
                const value = item.parsed.y;
                return `${chartModule.currentCoin}: $${value.toLocaleString(undefined, {
                  minimumFractionDigits: 2,
                  maximumFractionDigits: 8
                })}`;
              }
            }
          },
          verticalLine: {
            lineWidth: 1,
            lineColor: 'rgba(77, 132, 240, 0.5)'
          }
        }
      },
      plugins: [chartModule.verticalLinePlugin]
    });
  },
  prepareChartData: (coinSymbol, data) => {
    if (!data) {
      return [];
    }
    try {
      let preparedData;

      if (coinSymbol === 'WOW' && Array.isArray(data)) {
        const endTime = new Date(data[data.length - 1][0]);
        endTime.setUTCMinutes(0, 0, 0);
        const endUnix = endTime.getTime();
        const startUnix = endUnix - (24 * 3600000);
        const hourlyPoints = [];
        for (let hourUnix = startUnix; hourUnix <= endUnix; hourUnix += 3600000) {
          const targetHour = new Date(hourUnix);
          targetHour.setUTCMinutes(0, 0, 0);
          const closestPoint = data.reduce((prev, curr) => {
            const prevTime = new Date(prev[0]);
            const currTime = new Date(curr[0]);
            const prevDiff = Math.abs(prevTime - targetHour);
            const currDiff = Math.abs(currTime - targetHour);
            return currDiff < prevDiff ? curr : prev;
          });

          hourlyPoints.push({
            x: targetHour,
            y: closestPoint[1]
          });
        }

        const lastTime = new Date(data[data.length - 1][0]);
        if (lastTime.getUTCMinutes() !== 0) {
          hourlyPoints.push({
            x: lastTime,
            y: data[data.length - 1][1]
          });
        }

        preparedData = hourlyPoints;

      } else if (data.Data && Array.isArray(data.Data)) {
        preparedData = data.Data.map(d => ({
          x: new Date(d.time * 1000),
          y: d.close
        }));
      } else if (data.Data && data.Data.Data && Array.isArray(data.Data.Data)) {
        preparedData = data.Data.Data.map(d => ({
          x: new Date(d.time * 1000),
          y: d.close
        }));
      } else if (Array.isArray(data)) {
        preparedData = data.map(([timestamp, price]) => ({
          x: new Date(timestamp),
          y: price
        }));
      } else {
        return [];
      }
      return preparedData.map(point => ({
        x: new Date(point.x).getTime(),
        y: point.y
      }));
    } catch (error) {
      console.error(`Error preparing chart data for ${coinSymbol}:`, error);
      return [];
    }
  },

  ensureHourlyData: (data) => {
    const now = new Date();
    now.setUTCMinutes(0, 0, 0);
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const hourlyData = [];

    for (let i = 0; i < 24; i++) {
      const targetTime = new Date(twentyFourHoursAgo.getTime() + i * 60 * 60 * 1000);
      const closestDataPoint = data.reduce((prev, curr) =>
        Math.abs(new Date(curr.x).getTime() - targetTime.getTime()) <
        Math.abs(new Date(prev.x).getTime() - targetTime.getTime()) ? curr : prev
      );
      hourlyData.push({
        x: targetTime.getTime(),
        y: closestDataPoint.y
      });
    }
    return hourlyData;
  },

    updateChart: async (coinSymbol, forceRefresh = false) => {
        try {
            const currentChartData = chartModule.chart?.data.datasets[0].data || [];
            if (currentChartData.length === 0) {
                chartModule.showChartLoader();
            }
            chartModule.loadStartTime = Date.now();
            const cacheKey = `chartData_${coinSymbol}_${config.currentResolution}`;
            let cachedData = !forceRefresh ? cache.get(cacheKey) : null;
            let data;
            if (cachedData && Object.keys(cachedData.value).length > 0) {
                data = cachedData.value;
                console.log(`Using cached data for ${coinSymbol}`);
            } else {
                try {
                    const allData = await api.fetchHistoricalDataXHR([coinSymbol]);
                    data = allData[coinSymbol];
                    if (!data || Object.keys(data).length === 0) {
                        throw new Error(`No data returned for ${coinSymbol}`);
                    }
                    cache.set(cacheKey, data, config.cacheTTL);
                } catch (error) {
                    if (error.message.includes('429') && currentChartData.length > 0) {
                        console.warn(`Rate limit hit for ${coinSymbol}, maintaining current chart`);
                        return;
                    }
                    const expiredCache = localStorage.getItem(cacheKey);
                    if (expiredCache) {
                        try {
                            const parsedCache = JSON.parse(expiredCache);
                            data = parsedCache.value;
                            console.log(`Using expired cache data for ${coinSymbol}`);
                        } catch (cacheError) {
                            throw error;
                        }
                    } else {
                        throw error;
                    }
                }
            }
            const chartData = chartModule.prepareChartData(coinSymbol, data);
            if (chartData.length > 0 && chartModule.chart) {
                chartModule.chart.data.datasets[0].data = chartData;
                chartModule.chart.data.datasets[0].label = `${coinSymbol} Price (USD)`;
                if (coinSymbol === 'WOW') {
                    chartModule.chart.options.scales.x.time.unit = 'hour';
                } else {
                    const resolution = config.resolutions[config.currentResolution];
                    chartModule.chart.options.scales.x.time.unit = 
                        resolution.interval === 'hourly' ? 'hour' : 
                        config.currentResolution === 'year' ? 'month' : 'day';
                }
                chartModule.chart.update('active');
                chartModule.currentCoin = coinSymbol;
                const loadTime = Date.now() - chartModule.loadStartTime;
                ui.updateLoadTimeAndCache(loadTime, cachedData);
            }
        } catch (error) {
            console.error(`Error updating chart for ${coinSymbol}:`, error);
            if (!(chartModule.chart?.data.datasets[0].data.length > 0)) {
                chartModule.chart.data.datasets[0].data = [];
                chartModule.chart.update('active');
            }
        } finally {
            chartModule.hideChartLoader();
        }
    },

  showChartLoader: () => {
    const loader = document.getElementById('chart-loader');
    const chart = document.getElementById('coin-chart');
    if (!loader || !chart) {
      //console.warn('Chart loader or chart container elements not found');
      return;
    }
    loader.classList.remove('hidden');
    chart.classList.add('hidden');
  },

  hideChartLoader: () => {
    const loader = document.getElementById('chart-loader');
    const chart = document.getElementById('coin-chart');
    if (!loader || !chart) {
      //console.warn('Chart loader or chart container elements not found');
      return;
    }
    loader.classList.add('hidden');
    chart.classList.remove('hidden');
  },
};

Chart.register(chartModule.verticalLinePlugin);

  const volumeToggle = {
    isVisible: localStorage.getItem('volumeToggleState') === 'true',
    init: () => {
      const toggleButton = document.getElementById('toggle-volume');
      if (toggleButton) {
        toggleButton.addEventListener('click', volumeToggle.toggle);
        volumeToggle.updateVolumeDisplay();
      }
    },
    toggle: () => {
      volumeToggle.isVisible = !volumeToggle.isVisible;
      localStorage.setItem('volumeToggleState', volumeToggle.isVisible.toString());
      volumeToggle.updateVolumeDisplay();
    },
    updateVolumeDisplay: () => {
      const volumeDivs = document.querySelectorAll('[id$="-volume-div"]');
      volumeDivs.forEach(div => {
        div.style.display = volumeToggle.isVisible ? 'flex' : 'none';
      });
      const toggleButton = document.getElementById('toggle-volume');
      if (toggleButton) {
        updateButtonStyles(toggleButton, volumeToggle.isVisible, 'green');
      }
    }
  };

  function updateButtonStyles(button, isActive, color) {
    button.classList.toggle('text-' + color + '-500', isActive);
    button.classList.toggle('text-gray-600', !isActive);
    button.classList.toggle('dark:text-' + color + '-400', isActive);
    button.classList.toggle('dark:text-gray-400', !isActive);
  }

const app = {
  btcPriceUSD: 0,
  autoRefreshInterval: null,
  nextRefreshTime: null,
  lastRefreshedTime: null,
  isRefreshing: false,
  isAutoRefreshEnabled: localStorage.getItem('autoRefreshEnabled') !== 'false',
  refreshTexts: {
    label: 'Auto-refresh in',
    disabled: 'Auto-refresh: disabled',
    justRefreshed: 'Just refreshed',
  },
  cacheTTL: 5 * 60 * 1000, // 5 min
  minimumRefreshInterval: 60 * 1000, // 1 min

  init: () => {
    console.log('Initializing app...');
    window.addEventListener('load', app.onLoad);
    app.loadLastRefreshedTime();
    app.updateAutoRefreshButton();
    console.log('App initialized');
  },

  onLoad: async () => {
    console.log('App onLoad event triggered');
    ui.showLoader();
    try {
        volumeToggle.init();
        await app.updateBTCPrice();
        const chartContainer = document.getElementById('coin-chart');
        if (chartContainer) {
            chartModule.initChart();
            chartModule.showChartLoader();
        }

        console.log('Loading all coin data...');
        await app.loadAllCoinData();

        if (chartModule.chart) {
            config.currentResolution = 'day';
            await chartModule.updateChart('BTC');
            app.updateResolutionButtons('BTC');

            const chartTitle = document.getElementById('chart-title');
            if (chartTitle) {
                chartTitle.textContent = 'Price Chart (BTC)';
            }
        }
        ui.setActiveContainer('btc-container');

        app.setupEventListeners();
        app.initializeSelectImages();
        app.initAutoRefresh();

    } catch (error) {
        ui.displayErrorMessage('Failed to initialize the dashboard. Please try refreshing the page.');
    } finally {
        ui.hideLoader();
        if (chartModule.chart) {
            chartModule.hideChartLoader();
        }
        console.log('App onLoad completed');
    }
},
    loadAllCoinData: async () => {
        //console.log('Loading data for all coins...');
        try {
            const allCoinData = await api.fetchCoinGeckoDataXHR();
            if (allCoinData.error) {
                throw new Error(allCoinData.error);
            }

            for (const coin of config.coins) {
                const coinData = allCoinData[coin.symbol.toLowerCase()];
                if (coinData) {
                    coinData.displayName = coin.displayName || coin.symbol;
                    ui.displayCoinData(coin.symbol, coinData);
                    const cacheKey = `coinData_${coin.symbol}`;
                    cache.set(cacheKey, coinData);
                } else {
                    //console.warn(`No data found for ${coin.symbol}`);
                }
            }
        } catch (error) {
            //console.error('Error loading all coin data:', error);
            ui.displayErrorMessage('Failed to load coin data. Please try refreshing the page.');
        } finally {
            //console.log('All coin data loaded');
        }
    },

  loadCoinData: async (coin) => {
    //console.log(`Loading data for ${coin.symbol}...`);
    const cacheKey = `coinData_${coin.symbol}`;
    let cachedData = cache.get(cacheKey);
    let data;
    if (cachedData) {
      //console.log(`Using cached data for ${coin.symbol}`);
      data = cachedData.value;
    } else {
      try {
        ui.showCoinLoader(coin.symbol);
        if (coin.usesCoinGecko) {
          data = await api.fetchCoinGeckoDataXHR(coin.symbol);
        } else {
          data = await api.fetchCryptoCompareDataXHR(coin.symbol);
        }
        if (data.error) {
          throw new Error(data.error);
        }
        //console.log(`Caching new data for ${coin.symbol}`);
        cache.set(cacheKey, data);
        cachedData = null;
      } catch (error) {
        //console.error(`Error fetching ${coin.symbol} data:`, error.message);
        data = {
          error: error.message
        };
      } finally {
        ui.hideCoinLoader(coin.symbol);
      }
    }
    ui.displayCoinData(coin.symbol, data);
    ui.updateLoadTimeAndCache(0, cachedData);
    //console.log(`Data loaded for ${coin.symbol}`);
  },

setupEventListeners: () => {
    config.coins.forEach(coin => {
        const container = document.getElementById(`${coin.symbol.toLowerCase()}-container`);
        if (container) {
            container.addEventListener('click', () => {
                const chartTitle = document.getElementById('chart-title');
                if (chartTitle) {
                    chartTitle.textContent = `Price Chart (${coin.symbol})`;
                }
                ui.setActiveContainer(`${coin.symbol.toLowerCase()}-container`);
                if (chartModule.chart) {
                    if (coin.symbol === 'WOW') {
                        config.currentResolution = 'day';
                    }
                    chartModule.updateChart(coin.symbol);
                    app.updateResolutionButtons(coin.symbol);
                }
            });
        }
    });

    const refreshAllButton = document.getElementById('refresh-all');
    if (refreshAllButton) {
      refreshAllButton.addEventListener('click', app.refreshAllData);
    }

    const headers = document.querySelectorAll('th');
    headers.forEach((header, index) => {
      header.addEventListener('click', () => app.sortTable(index, header.classList.contains('disabled')));
    });

    const closeErrorButton = document.getElementById('close-error');
    if (closeErrorButton) {
      closeErrorButton.addEventListener('click', ui.hideErrorMessage);
    }
    //console.log('Event listeners set up');
  },

  initAutoRefresh: () => {
    console.log('Initializing auto-refresh...');
    const toggleAutoRefreshButton = document.getElementById('toggle-auto-refresh');
    if (toggleAutoRefreshButton) {
      toggleAutoRefreshButton.addEventListener('click', app.toggleAutoRefresh);
      app.updateAutoRefreshButton();
    }

    if (app.isAutoRefreshEnabled) {
      console.log('Auto-refresh is enabled, scheduling next refresh');
      app.scheduleNextRefresh();
    } else {
      console.log('Auto-refresh is disabled');
    }
  },

  scheduleNextRefresh: () => {
    console.log('Scheduling next refresh...');
    if (app.autoRefreshInterval) {
      clearTimeout(app.autoRefreshInterval);
    }

    const now = Date.now();
    let earliestExpiration = Infinity;

    Object.keys(localStorage).forEach(key => {
      if (key.startsWith('coinData_') || key.startsWith('chartData_') || key === 'coinGeckoOneLiner') {
        try {
          const cachedItem = JSON.parse(localStorage.getItem(key));
          if (cachedItem && cachedItem.expiresAt) {
            earliestExpiration = Math.min(earliestExpiration, cachedItem.expiresAt);
          }
        } catch (error) {
          //console.error(`Error parsing cached item ${key}:`, error);
          localStorage.removeItem(key);
        }
      }
    });

    let nextRefreshTime;
    if (earliestExpiration !== Infinity) {
      nextRefreshTime = Math.max(earliestExpiration, now + app.minimumRefreshInterval);
    } else {
      nextRefreshTime = now + config.cacheTTL;
    }
    const timeUntilRefresh = nextRefreshTime - now;
    console.log(`Next refresh scheduled in ${timeUntilRefresh / 1000} seconds`);
    app.nextRefreshTime = nextRefreshTime;
    app.autoRefreshInterval = setTimeout(() => {
      console.log('Auto-refresh triggered');
      app.refreshAllData();
    }, timeUntilRefresh);
    localStorage.setItem('nextRefreshTime', app.nextRefreshTime.toString());
    app.updateNextRefreshTime();
  },
      refreshAllData: async () => {
    if (app.isRefreshing) {
        console.log('Refresh already in progress, skipping...');
        return;
    }

    const lastGeckoRequest = rateLimiter.lastRequestTime['coingecko'] || 0;
    const timeSinceLastRequest = Date.now() - lastGeckoRequest;
    const waitTime = Math.max(0, rateLimiter.minRequestInterval.coingecko - timeSinceLastRequest);
    
    if (waitTime > 0) {
        const seconds = Math.ceil(waitTime / 1000);
        ui.displayErrorMessage(`Rate limit: Please wait ${seconds} seconds before refreshing`);

        let remainingTime = seconds;
        const countdownInterval = setInterval(() => {
            remainingTime--;
            if (remainingTime > 0) {
                ui.displayErrorMessage(`Rate limit: Please wait ${remainingTime} seconds before refreshing`);
            } else {
                clearInterval(countdownInterval);
                ui.hideErrorMessage();
            }
        }, 1000);

        return;
    }

    console.log('Starting refresh of all data...');
    app.isRefreshing = true;
    ui.showLoader();
    chartModule.showChartLoader();

    try {
        ui.hideErrorMessage();
        cache.clear();

        const btcUpdateSuccess = await app.updateBTCPrice();
        if (!btcUpdateSuccess) {
            console.warn('BTC price update failed, continuing with cached or default value');
        }

        await new Promise(resolve => setTimeout(resolve, 1000));

        const allCoinData = await api.fetchCoinGeckoDataXHR();
        if (allCoinData.error) {
            throw new Error(`CoinGecko API Error: ${allCoinData.error}`);
        }

        const failedCoins = [];

        for (const coin of config.coins) {
            const symbol = coin.symbol.toLowerCase();
            const coinData = allCoinData[symbol];

            try {
                if (!coinData) {
                    throw new Error(`No data received`);
                }

                coinData.displayName = coin.displayName || coin.symbol;
                ui.displayCoinData(coin.symbol, coinData);

                const cacheKey = `coinData_${coin.symbol}`;
                cache.set(cacheKey, coinData);

            } catch (coinError) {
                console.warn(`Failed to update ${coin.symbol}: ${coinError.message}`);
                failedCoins.push(coin.symbol);
            }
        }

        await new Promise(resolve => setTimeout(resolve, 1000));

        if (chartModule.currentCoin) {
            try {
                await chartModule.updateChart(chartModule.currentCoin, true);
            } catch (chartError) {
                console.error('Chart update failed:', chartError);
            }
        }

        app.lastRefreshedTime = new Date();
        localStorage.setItem('lastRefreshedTime', app.lastRefreshedTime.getTime().toString());
        ui.updateLastRefreshedTime();

        if (failedCoins.length > 0) {
            const failureMessage = failedCoins.length === config.coins.length
                ? 'Failed to update any coin data'
                : `Failed to update some coins: ${failedCoins.join(', ')}`;

            let countdown = 5;
            ui.displayErrorMessage(`${failureMessage} (${countdown}s)`);

            const countdownInterval = setInterval(() => {
                countdown--;
                if (countdown > 0) {
                    ui.displayErrorMessage(`${failureMessage} (${countdown}s)`);
                } else {
                    clearInterval(countdownInterval);
                    ui.hideErrorMessage();
                }
            }, 1000);
        }

        console.log(`Refresh completed. Failed coins: ${failedCoins.length}`);

    } catch (error) {
        console.error('Critical error during refresh:', error);

        let countdown = 10;
        ui.displayErrorMessage(`Refresh failed: ${error.message}. Please try again later. (${countdown}s)`);
        
        const countdownInterval = setInterval(() => {
            countdown--;
            if (countdown > 0) {
                ui.displayErrorMessage(`Refresh failed: ${error.message}. Please try again later. (${countdown}s)`);
            } else {
                clearInterval(countdownInterval);
                ui.hideErrorMessage();
            }
        }, 1000);

    } finally {
        ui.hideLoader();
        chartModule.hideChartLoader();
        app.isRefreshing = false;

        if (app.isAutoRefreshEnabled) {
            app.scheduleNextRefresh();
        }
    }
},

  updateNextRefreshTime: () => {
    console.log('Updating next refresh time display');
    const nextRefreshSpan = document.getElementById('next-refresh-time');
    const labelElement = document.getElementById('next-refresh-label');
    const valueElement = document.getElementById('next-refresh-value');
    if (nextRefreshSpan && labelElement && valueElement) {
      if (app.nextRefreshTime) {
        if (app.updateNextRefreshTimeRAF) {
          cancelAnimationFrame(app.updateNextRefreshTimeRAF);
        }

        const updateDisplay = () => {
          const timeUntilRefresh = Math.max(0, Math.ceil((app.nextRefreshTime - Date.now()) / 1000));

          if (timeUntilRefresh === 0) {
            labelElement.textContent = '';
            valueElement.textContent = app.refreshTexts.justRefreshed;
          } else {
            const minutes = Math.floor(timeUntilRefresh / 60);
            const seconds = timeUntilRefresh % 60;
            labelElement.textContent = `${app.refreshTexts.label}: `;
            valueElement.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
          }

          if (timeUntilRefresh > 0) {
            app.updateNextRefreshTimeRAF = requestAnimationFrame(updateDisplay);
          }
        };
        updateDisplay();
      } else {
        labelElement.textContent = '';
        valueElement.textContent = app.refreshTexts.disabled;
      }
    }
  },

  updateAutoRefreshButton: () => {
    console.log('Updating auto-refresh button state');
    const button = document.getElementById('toggle-auto-refresh');
    if (button) {
      if (app.isAutoRefreshEnabled) {
        button.classList.remove('text-gray-600', 'dark:text-gray-400');
        button.classList.add('text-green-500', 'dark:text-green-400');
        app.startSpinAnimation();
      } else {
        button.classList.remove('text-green-500', 'dark:text-green-400');
        button.classList.add('text-gray-600', 'dark:text-gray-400');
        app.stopSpinAnimation();
      }
      button.title = app.isAutoRefreshEnabled ? 'Disable Auto-Refresh' : 'Enable Auto-Refresh';
    }
  },

  startSpinAnimation: () => {
    //console.log('Starting spin animation on auto-refresh button');
    const svg = document.querySelector('#toggle-auto-refresh svg');
    if (svg) {
      svg.classList.add('animate-spin');
      setTimeout(() => {
        svg.classList.remove('animate-spin');
      }, 2000);
    }
  },

  stopSpinAnimation: () => {
    //console.log('Stopping spin animation on auto-refresh button');
    const svg = document.querySelector('#toggle-auto-refresh svg');
    if (svg) {
      svg.classList.remove('animate-spin');
    }
  },

  updateLastRefreshedTime: () => {
    //console.log('Updating last refreshed time');
    const lastRefreshedElement = document.getElementById('last-refreshed-time');
    if (lastRefreshedElement && app.lastRefreshedTime) {
      const formattedTime = app.lastRefreshedTime.toLocaleTimeString();
      lastRefreshedElement.textContent = `Last Refreshed: ${formattedTime}`;
    }
  },

  loadLastRefreshedTime: () => {
    console.log('Loading last refreshed time from storage');
    const storedTime = localStorage.getItem('lastRefreshedTime');
    if (storedTime) {
      app.lastRefreshedTime = new Date(parseInt(storedTime));
      ui.updateLastRefreshedTime();
    }
  },

updateBTCPrice: async () => {
    console.log('Updating BTC price...');
    try {
        const priceData = await api.fetchCoinGeckoDataXHR();

        if (priceData.error) {
            console.warn('API error when fetching BTC price:', priceData.error);
            return false;
        }

        if (priceData.btc && typeof priceData.btc.current_price === 'number') {
            app.btcPriceUSD = priceData.btc.current_price;
            return true;
        } else if (priceData.bitcoin && typeof priceData.bitcoin.usd === 'number') {
            app.btcPriceUSD = priceData.bitcoin.usd;
            return true;
        }

        console.warn('Unexpected BTC price data structure:', priceData);
        return false;

    } catch (error) {
        console.error('Error fetching BTC price:', error);
        return false;
    }
},

sortTable: (columnIndex) => {
  //console.log(`Sorting column: ${columnIndex}`);
  const sortableColumns = [0, 5, 6, 7]; // 0: Time, 5: Rate, 6: Market +/-, 7: Trade
  if (!sortableColumns.includes(columnIndex)) {
    //console.log(`Column ${columnIndex} is not sortable`);
    return;
  }
  const table = document.querySelector('table');
  if (!table) {
    //console.error("Table not found for sorting.");
    return;
  }
  const rows = Array.from(table.querySelectorAll('tbody tr'));
  console.log(`Found ${rows.length} rows to sort`);
  const sortIcon = document.getElementById(`sort-icon-${columnIndex}`);
  if (!sortIcon) {
    //console.error("Sort icon not found.");
    return;
  }
  const sortOrder = sortIcon.textContent === '↓' ? 1 : -1;
  sortIcon.textContent = sortOrder === 1 ? '↑' : '↓';

  const getSafeTextContent = (element) => element ? element.textContent.trim() : '';

  rows.sort((a, b) => {
    let aValue, bValue;
    switch (columnIndex) {
      case 1: // Time column
        aValue = getSafeTextContent(a.querySelector('td:first-child .text-xs:first-child'));
        bValue = getSafeTextContent(b.querySelector('td:first-child .text-xs:first-child'));
        //console.log(`Comparing times: "${aValue}" vs "${bValue}"`);

        const parseTime = (timeStr) => {
          const [value, unit] = timeStr.split(' ');
          const numValue = parseFloat(value);
          switch(unit) {
            case 'seconds': return numValue;
            case 'minutes': return numValue * 60;
            case 'hours': return numValue * 3600;
            case 'days': return numValue * 86400;
            default: return 0;
          }
        };
        return (parseTime(bValue) - parseTime(aValue)) * sortOrder;

      case 5: // Rate
      case 6: // Market +/-
        aValue = getSafeTextContent(a.cells[columnIndex]);
        bValue = getSafeTextContent(b.cells[columnIndex]);
        //console.log(`Comparing values: "${aValue}" vs "${bValue}"`);

        aValue = parseFloat(aValue.replace(/[^\d.-]/g, '') || '0');
        bValue = parseFloat(bValue.replace(/[^\d.-]/g, '') || '0');
        return (aValue - bValue) * sortOrder;

      case 7: // Trade
        const aCell = a.cells[columnIndex];
        const bCell = b.cells[columnIndex];
        //console.log('aCell:', aCell ? aCell.outerHTML : 'null');
        //console.log('bCell:', bCell ? bCell.outerHTML : 'null');

        aValue = getSafeTextContent(aCell.querySelector('a')) || 
                 getSafeTextContent(aCell.querySelector('button')) || 
                 getSafeTextContent(aCell);
        bValue = getSafeTextContent(bCell.querySelector('a')) || 
                 getSafeTextContent(bCell.querySelector('button')) || 
                 getSafeTextContent(bCell);
        
        aValue = aValue.toLowerCase();
        bValue = bValue.toLowerCase();

        //console.log(`Comparing trade actions: "${aValue}" vs "${bValue}"`);

        if (aValue === bValue) return 0;
        if (aValue === "swap") return -1 * sortOrder;
        if (bValue === "swap") return 1 * sortOrder;
        return aValue.localeCompare(bValue) * sortOrder;

      default:
        aValue = getSafeTextContent(a.cells[columnIndex]);
        bValue = getSafeTextContent(b.cells[columnIndex]);
        //console.log(`Comparing default values: "${aValue}" vs "${bValue}"`);
        return aValue.localeCompare(bValue, undefined, {
          numeric: true,
          sensitivity: 'base'
        }) * sortOrder;
    }
  });

  const tbody = table.querySelector('tbody');
  if (tbody) {
    rows.forEach(row => tbody.appendChild(row));
  } else {
    //console.error("Table body not found.");
  }
  //console.log('Sorting completed');
},
  
  initializeSelectImages: () => {
    const updateSelectedImage = (selectId) => {
      const select = document.getElementById(selectId);
      const button = document.getElementById(`${selectId}_button`);
      if (!select || !button) {
        //console.error(`Elements not found for ${selectId}`);
        return;
      }
      const selectedOption = select.options[select.selectedIndex];
      const imageURL = selectedOption?.getAttribute('data-image');
      requestAnimationFrame(() => {
        if (imageURL) {
          button.style.backgroundImage = `url('${imageURL}')`;
          button.style.backgroundSize = '25px 25px';
          button.style.backgroundPosition = 'center';
          button.style.backgroundRepeat = 'no-repeat';
        } else {
          button.style.backgroundImage = 'none';
        }
        button.style.minWidth = '25px';
        button.style.minHeight = '25px';
      });
    };
    const handleSelectChange = (event) => {
      updateSelectedImage(event.target.id);
    };
    ['coin_to', 'coin_from'].forEach(selectId => {
      const select = document.getElementById(selectId);
      if (select) {
        select.addEventListener('change', handleSelectChange);
        updateSelectedImage(selectId);
      } else {
        //console.error(`Select element not found for ${selectId}`);
      }
    });
  },

updateResolutionButtons: (coinSymbol) => {
  const resolutionButtons = document.querySelectorAll('.resolution-button');
  resolutionButtons.forEach(button => {
    const resolution = button.id.split('-')[1];
    if (coinSymbol === 'WOW') {
      if (resolution === 'day') {
        button.classList.remove('text-gray-400', 'cursor-not-allowed', 'opacity-50', 'outline-none');
        button.classList.add('active');
        button.disabled = false;
      } else {
        button.classList.add('text-gray-400', 'cursor-not-allowed', 'opacity-50', 'outline-none');
        button.classList.remove('active');
        button.disabled = true;
      }
    } else {
      button.classList.remove('text-gray-400', 'cursor-not-allowed', 'opacity-50', 'outline-none');
      button.classList.toggle('active', resolution === config.currentResolution);
      button.disabled = false;
    }
  });
},
  
 toggleAutoRefresh: () => {
    console.log('Toggling auto-refresh');
    app.isAutoRefreshEnabled = !app.isAutoRefreshEnabled;
    localStorage.setItem('autoRefreshEnabled', app.isAutoRefreshEnabled.toString());
    if (app.isAutoRefreshEnabled) {
      console.log('Auto-refresh enabled, scheduling next refresh');
      app.scheduleNextRefresh();
    } else {
      console.log('Auto-refresh disabled, clearing interval');
      if (app.autoRefreshInterval) {
        clearTimeout(app.autoRefreshInterval);
        app.autoRefreshInterval = null;
      }
      app.nextRefreshTime = null;
      localStorage.removeItem('nextRefreshTime');
    }
    app.updateAutoRefreshButton();
    app.updateNextRefreshTime();
  }
};

const resolutionButtons = document.querySelectorAll('.resolution-button');
resolutionButtons.forEach(button => {
  button.addEventListener('click', () => {
    const resolution = button.id.split('-')[1];
    const currentCoin = chartModule.currentCoin;
    
    if (currentCoin !== 'WOW' || resolution === 'day') {
      config.currentResolution = resolution;
      chartModule.updateChart(currentCoin, true);
      app.updateResolutionButtons(currentCoin);
    }
  });
});

// LOAD
app.init();
