const chartConfig = window.config.chartConfig;
const coins = window.config.coins;
const apiKeys = window.config.getAPIKeys();

const utils = {
  formatNumber: (number, decimals = 2) => {
    if (typeof number !== 'number' || isNaN(number)) {
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

class AppError extends Error {
  constructor(message, type = 'AppError') {
    super(message);
    this.name = type;
  }
}

const logger = {
  log: (message) => console.log(`[AppLog] ${new Date().toISOString()}: ${message}`),
  warn: (message) => console.warn(`[AppWarn] ${new Date().toISOString()}: ${message}`),
  error: (message) => console.error(`[AppError] ${new Date().toISOString()}: ${message}`)
};

const api = {
    fetchVolumeDataXHR: async () => {
        const cacheKey = 'volumeData';
        const cachedData = CacheManager.get(cacheKey);

        if (cachedData) {
            console.log("Using cached volume data");
            return cachedData.value;
        }

        try {
            if (!NetworkManager.isOnline()) {
                throw new Error('Network is offline');
            }

            const volumeData = await Api.fetchVolumeData({
                cryptoCompare: apiKeys.cryptoCompare,
                coinGecko: apiKeys.coinGecko
            });

            if (Object.keys(volumeData).length > 0) {
                CacheManager.set(cacheKey, volumeData, 'volume');
                return volumeData;
            }

            throw new Error("No volume data found in the response");
        } catch (error) {
            console.error("Error fetching volume data:", error);

            NetworkManager.handleNetworkError(error);

            try {
                const existingCache = localStorage.getItem(cacheKey);
                if (existingCache) {
                    const fallbackData = JSON.parse(existingCache).value;
                    if (fallbackData && Object.keys(fallbackData).length > 0) {
                        return fallbackData;
                    }
                }
            } catch (e) {
                console.warn("Error accessing cached volume data:", e);
            }
            return {};
        }
    },

    fetchCryptoCompareDataXHR: (coin) => {
        try {
            if (!NetworkManager.isOnline()) {
                throw new Error('Network is offline');
            }

            return Api.fetchCryptoCompareData(coin, {
                cryptoCompare: apiKeys.cryptoCompare
            });
        } catch (error) {
            logger.error(`CryptoCompare request failed for ${coin}:`, error);

            NetworkManager.handleNetworkError(error);

            const cachedData = CacheManager.get(`coinData_${coin}`);
            if (cachedData) {
                logger.info(`Using cached data for ${coin}`);
                return cachedData.value;
            }
            return { error: error.message };
        }
    },

    fetchCoinGeckoDataXHR: async () => {
        try {
            const priceData = await window.PriceManager.getPrices();
            const transformedData = {};

            const btcPriceUSD = priceData.bitcoin?.usd || 0;
            if (btcPriceUSD > 0) {
                window.btcPriceUSD = btcPriceUSD;
            }

            window.config.coins.forEach(coin => {
                const symbol = coin.symbol.toLowerCase();
                const coinData = priceData[symbol] || priceData[coin.name.toLowerCase()];

                if (coinData && coinData.usd) {
                    let priceBtc;
                    if (symbol === 'btc') {
                        priceBtc = 1;
                    } else if (window.btcPriceUSD && window.btcPriceUSD > 0) {
                        priceBtc = coinData.usd / window.btcPriceUSD;
                    } else {
                        priceBtc = coinData.btc || 0;
                    }

                    transformedData[symbol] = {
                        current_price: coinData.usd,
                        price_btc: priceBtc,
                        displayName: coin.displayName || coin.symbol,
                        total_volume: coinData.total_volume,
                        price_change_percentage_24h: coinData.price_change_percentage_24h
                    };
                }
            });

            return transformedData;
        } catch (error) {
            console.error('Error in fetchCoinGeckoDataXHR:', error);
            return {};
        }
    },

    fetchHistoricalDataXHR: async (coinSymbols) => {
        if (!Array.isArray(coinSymbols)) {
            coinSymbols = [coinSymbols];
        }

        const results = {};

        try {
            if (!NetworkManager.isOnline()) {
                throw new Error('Network is offline');
            }

            const historicalData = await Api.fetchHistoricalData(
                coinSymbols,
                window.config.currentResolution,
                {
                    cryptoCompare: window.config.getAPIKeys().cryptoCompare
                }
            );

            Object.keys(historicalData).forEach(coin => {
                if (historicalData[coin]) {
                    results[coin] = historicalData[coin];

                    const cacheKey = `historical_${coin}_${window.config.currentResolution}`;
                    CacheManager.set(cacheKey, historicalData[coin], 'historical');
                }
            });

            return results;
        } catch (error) {
            console.error('Error fetching historical data:', error);

            NetworkManager.handleNetworkError(error);

            for (const coin of coinSymbols) {
                const cacheKey = `historical_${coin}_${window.config.currentResolution}`;
                const cachedData = CacheManager.get(cacheKey);
                if (cachedData) {
                    results[coin] = cachedData.value;
                }
            }

            return results;
        }
    },
};

const rateLimiter = {
    lastRequestTime: {},
    minRequestInterval: {
        coingecko: window.config.rateLimits.coingecko.minInterval,
        cryptocompare: window.config.rateLimits.cryptocompare.minInterval
    },
    requestQueue: {},
    retryDelays: window.config.retryDelays,

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
                        logger.warn(`Request failed, retrying in ${delay/1000} seconds...`);
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

                NetworkManager.handleNetworkError(error);

                const cachedData = CacheManager.get(`coinData_${apiName}`);
                if (cachedData) {
                    return cachedData.value;
                }
            }
            throw error;
        }
    }
};

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
      if (isError || volume24h === null || volume24h === undefined) {
        volumeElement.textContent = 'N/A';
      } else {
        volumeElement.textContent = `${utils.formatNumber(volume24h, 0)} USD`;
      }
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
      throw new Error(`Invalid data structure for ${coin}`);
    }
    priceUSD = data.current_price;

    if (coin === 'BTC') {
      priceBTC = 1;
    } else {

      if (data.price_btc !== undefined && data.price_btc !== null) {
        priceBTC = data.price_btc;
      }
      else if (window.btcPriceUSD && window.btcPriceUSD > 0) {
        priceBTC = priceUSD / window.btcPriceUSD;
      }
      else if (app && app.btcPriceUSD && app.btcPriceUSD > 0) {
        priceBTC = priceUSD / app.btcPriceUSD;
      }
      else {
        priceBTC = 0;
      }
    }

    priceChange1d = data.price_change_percentage_24h || 0;
    volume24h = data.total_volume || 0;
    if (isNaN(priceUSD) || isNaN(priceBTC)) {
      throw new Error(`Invalid numeric values in data for ${coin}`);
    }
    updateUI(false);
  } catch (error) {
    logger.error(`Failed to display data for ${coin}:`, error.message);
    updateUI(true);
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
      if (priceChange === null || priceChange === undefined) {
        container.innerHTML = 'N/A';
      } else {
        container.innerHTML = priceChange >= 0 ?
          ui.positivePriceChangeHTML(priceChange) :
          ui.negativePriceChangeHTML(priceChange);
      }
    }
  },

  updateLastRefreshedTime: () => {
    const lastRefreshedElement = document.getElementById('last-refreshed-time');
    if (lastRefreshedElement && app.lastRefreshedTime) {
      const formattedTime = app.lastRefreshedTime.toLocaleTimeString();
      lastRefreshedElement.textContent = `Last Refreshed: ${formattedTime}`;
    }
  },

  updateConnectionStatus: () => {
    const statusElement = document.getElementById('connection-status');
    if (statusElement) {
      const online = NetworkManager.isOnline();
      statusElement.textContent = online ? 'Connected' : 'Disconnected';
      statusElement.classList.toggle('text-green-500', online);
      statusElement.classList.toggle('text-red-500', !online);
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
    const containerIds = ['btc', 'xmr', 'part', 'pivx', 'firo', 'dash', 'ltc', 'doge', 'eth', 'dcr', 'nmc', 'zano', 'wow', 'bch'].map(id => `${id}-container`);
    containerIds.forEach(id => {
      const container = document.getElementById(id);
      if (container) {
        const innerDiv = container.querySelector('div');
        innerDiv.classList.toggle('active-container', id === containerId);
      }
    });
  },

  displayErrorMessage: (message, duration = 0) => {
    const errorOverlay = document.getElementById('error-overlay');
    const errorMessage = document.getElementById('error-message');
    const chartContainer = document.querySelector('.container-to-blur');
    if (errorOverlay && errorMessage && chartContainer) {
      errorOverlay.classList.remove('hidden');
      errorMessage.textContent = message;
      chartContainer.classList.add('blurred');

      if (duration > 0) {
        setTimeout(() => {
          ui.hideErrorMessage();
        }, duration);
      }
    }
  },

  hideErrorMessage: () => {
    const errorOverlay = document.getElementById('error-overlay');
    const containersToBlur = document.querySelectorAll('.container-to-blur');
    if (errorOverlay) {
      errorOverlay.classList.add('hidden');
      containersToBlur.forEach(container => container.classList.remove('blurred'));
    }
  },

  showNetworkErrorMessage: () => {
    ui.displayErrorMessage(
      "Network connection lost. Data shown may be outdated. We'll automatically refresh once connection is restored.",
      0
    );

    const errorOverlay = document.getElementById('error-overlay');
    if (errorOverlay) {
      const reconnectBtn = document.createElement('button');
      reconnectBtn.className = "mt-4 bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded";
      reconnectBtn.textContent = "Try to Reconnect";
      reconnectBtn.onclick = () => {
        NetworkManager.manualReconnect();
      };

      const buttonContainer = errorOverlay.querySelector('.button-container') ||
                              document.createElement('div');
      buttonContainer.className = "button-container mt-4";
      buttonContainer.innerHTML = '';
      buttonContainer.appendChild(reconnectBtn);

      if (!errorOverlay.querySelector('.button-container')) {
        errorOverlay.querySelector('div').appendChild(buttonContainer);
      }
    }
  }
};

const chartModule = {
  chart: null,
  currentCoin: 'BTC',
  loadStartTime: 0,
  chartRefs: new WeakMap(),
  pendingAnimationFrame: null,

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

  getChartByElement: function(element) {
    return this.chartRefs.get(element);
  },

  setChartReference: function(element, chart) {
    this.chartRefs.set(element, chart);
  },

destroyChart: function() {
  if (chartModule.chart) {
    try {
      const chartInstance = chartModule.chart;
      const canvas = document.getElementById('coin-chart');

      chartModule.chart = null;

      if (chartInstance && chartInstance.destroy && typeof chartInstance.destroy === 'function') {
        chartInstance.destroy();
      }

      if (canvas) {
        chartModule.chartRefs.delete(canvas);

        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
      }
    } catch (e) {
      console.error('Error destroying chart:', e);
    }
  }
},

  initChart: function() {
    this.destroyChart();

    const canvas = document.getElementById('coin-chart');
    if (!canvas) {
      console.error('Chart canvas element not found');
      return;
    }

    canvas.style.display = 'block';
    if (canvas.style.width === '1px' || canvas.style.height === '1px') {
      canvas.style.width = '100%';
      canvas.style.height = '100%';
    }

    const ctx = canvas.getContext('2d');
    if (!ctx) {
      console.error('Failed to get chart context. Make sure the canvas element exists.');
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
        animation: {
          duration: 750
        },
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
              source: 'auto',
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
                if (window.config.currentResolution === 'day') {
                  return date.toLocaleTimeString('en-US', {
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true,
                    timeZone: 'UTC'
                  });
                } else if (window.config.currentResolution === 'year') {
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
                if (window.config.currentResolution === 'day') {
                  return date.toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true,
                    timeZone: 'UTC'
                  });
                } else if (window.config.currentResolution === 'year') {
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

    this.setChartReference(canvas, chartModule.chart);

    if (window.CleanupManager) {
      window.CleanupManager.registerResource('chart', chartModule.chart, () => {
        chartModule.destroyChart();
      });
    }
  },

  prepareChartData: function(coinSymbol, data) {
    if (!data) {
      return [];
    }

    try {
      let rawDataPoints = [];

      if (Array.isArray(data)) {
        rawDataPoints = data.map(([timestamp, price]) => ({
          time: new Date(timestamp).getTime(),
          close: price
        }));
      } else if (data.Data && Array.isArray(data.Data)) {
        rawDataPoints = data.Data.map(d => ({
          time: d.time * 1000,
          close: d.close
        }));
      } else if (data.Data && data.Data.Data && Array.isArray(data.Data.Data)) {
        rawDataPoints = data.Data.Data.map(d => ({
          time: d.time * 1000,
          close: d.close
        }));
      } else {
        return [];
      }

      if (rawDataPoints.length === 0) {
        return [];
      }

      rawDataPoints.sort((a, b) => a.time - b.time);

      let preparedData = [];

      if (window.config.currentResolution === 'day') {
        const endTime = new Date(rawDataPoints[rawDataPoints.length - 1].time);
        endTime.setUTCMinutes(0, 0, 0);

        const endUnix = endTime.getTime();
        const startUnix = endUnix - (24 * 3600000);

        for (let hourUnix = startUnix; hourUnix <= endUnix; hourUnix += 3600000) {
          let closestPoint = null;
          let closestDiff = Infinity;

          for (const point of rawDataPoints) {
            const diff = Math.abs(point.time - hourUnix);
            if (diff < closestDiff) {
              closestDiff = diff;
              closestPoint = point;
            }
          }

          if (closestPoint) {
            preparedData.push({
              x: hourUnix,
              y: closestPoint.close
            });
          }
        }

        const lastTime = rawDataPoints[rawDataPoints.length - 1].time;
        if (lastTime > endUnix) {
          preparedData.push({
            x: lastTime,
            y: rawDataPoints[rawDataPoints.length - 1].close
          });
        }
      } else {
        preparedData = rawDataPoints.map(point => ({
          x: point.time,
          y: point.close
        }));
      }

      if (preparedData.length === 0 && rawDataPoints.length > 0) {
        preparedData = rawDataPoints.map(point => ({
          x: point.time,
          y: point.close
        }));
      }

      return preparedData;
    } catch (error) {
      return [];
    }
  },

  ensureHourlyData: function(data) {
    const now = new Date();
    now.setUTCMinutes(0, 0, 0);
    const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const hourlyData = [];

    for (let i = 0; i < 24; i++) {
      const targetTime = new Date(twentyFourHoursAgo.getTime() + i * 60 * 60 * 1000);

      if (data.length > 0) {
        const closestDataPoint = data.reduce((prev, curr) =>
          Math.abs(new Date(curr.x).getTime() - targetTime.getTime()) <
          Math.abs(new Date(prev.x).getTime() - targetTime.getTime()) ? curr : prev
        , data[0]);
        hourlyData.push({
          x: targetTime.getTime(),
          y: closestDataPoint.y
        });
      }
    }

    return hourlyData;
  },

  updateChart: async function(coinSymbol, forceRefresh = false) {
    try {
      if (!chartModule.chart) {
        chartModule.initChart();
      }
      const currentChartData = chartModule.chart?.data?.datasets[0]?.data || [];
      if (currentChartData.length === 0) {
        chartModule.showChartLoader();
      }
      chartModule.loadStartTime = Date.now();
      const cacheKey = `chartData_${coinSymbol}_${window.config.currentResolution}`;
      const cachedData = !forceRefresh ? CacheManager.get(cacheKey) : null;
      let data;
      if (cachedData && Object.keys(cachedData.value).length > 0) {
        data = cachedData.value;
      } else {
        try {
          if (!NetworkManager.isOnline()) {
            throw new Error('Network is offline');
          }

          const allData = await api.fetchHistoricalDataXHR([coinSymbol]);
          data = allData[coinSymbol];

          if (!data || Object.keys(data).length === 0) {
            throw new Error(`No data returned for ${coinSymbol}`);
          }

          CacheManager.set(cacheKey, data, 'chart');
        } catch (error) {
          NetworkManager.handleNetworkError(error);

          if (error.message.includes('429') && currentChartData.length > 0) {
            console.warn(`Rate limit hit for ${coinSymbol}, maintaining current chart`);
            chartModule.hideChartLoader();
            return;
          }
          const expiredCache = localStorage.getItem(cacheKey);
          if (expiredCache) {
            try {
              const parsedCache = JSON.parse(expiredCache);
              data = parsedCache.value;
            } catch (cacheError) {
              throw error;
            }
          } else {
            throw error;
          }
        }
      }
      if (chartModule.currentCoin !== coinSymbol) {
        chartModule.destroyChart();
        chartModule.initChart();
      }

      const chartData = chartModule.prepareChartData(coinSymbol, data);
      if (chartData.length > 0 && chartModule.chart) {
        chartModule.chart.data.datasets[0].data = chartData;
        chartModule.chart.data.datasets[0].label = `${coinSymbol} Price (USD)`;
        if (coinSymbol === 'WOW') {
          chartModule.chart.options.scales.x.time.unit = 'hour';
        } else {
          const resolution = window.config.chartConfig.resolutions[window.config.currentResolution];
          chartModule.chart.options.scales.x.time.unit =
            resolution && resolution.interval === 'hourly' ? 'hour' :
            window.config.currentResolution === 'year' ? 'month' : 'day';
        }
        chartModule.chart.update('active');
        chartModule.currentCoin = coinSymbol;
        const loadTime = Date.now() - chartModule.loadStartTime;
        ui.updateLoadTimeAndCache(loadTime, cachedData);
      }
    } catch (error) {
      console.error(`Error updating chart for ${coinSymbol}:`, error);

      if (!(chartModule.chart?.data?.datasets[0]?.data?.length > 0)) {
        if (!chartModule.chart) {
          chartModule.initChart();
        }
        if (chartModule.chart) {
          chartModule.chart.data.datasets[0].data = [];
          chartModule.chart.update('active');
        }
      }
    } finally {
      chartModule.hideChartLoader();
    }
  },

  showChartLoader: function() {
    const loader = document.getElementById('chart-loader');
    const chart = document.getElementById('coin-chart');
    if (!loader || !chart) {
      return;
    }
    loader.classList.remove('hidden');
    chart.classList.add('hidden');
  },

  hideChartLoader: function() {
    const loader = document.getElementById('chart-loader');
    const chart = document.getElementById('coin-chart');
    if (!loader || !chart) {
      return;
    }
    loader.classList.add('hidden');
    chart.classList.remove('hidden');
  },

  cleanup: function() {
  if (this.pendingAnimationFrame) {
    cancelAnimationFrame(this.pendingAnimationFrame);
    this.pendingAnimationFrame = null;
  }

  if (!document.hidden) {
    this.currentCoin = null;
  }

  this.loadStartTime = 0;
  this.chartRefs = new WeakMap();
}
};

Chart.register(chartModule.verticalLinePlugin);

const volumeToggle = {
  isVisible: localStorage.getItem('volumeToggleState') === 'true',
  init: function() {
    const toggleButton = document.getElementById('toggle-volume');
    if (toggleButton) {
      if (typeof CleanupManager !== 'undefined') {
        CleanupManager.addListener(toggleButton, 'click', volumeToggle.toggle);
      } else {
        toggleButton.addEventListener('click', volumeToggle.toggle);
      }
      volumeToggle.updateVolumeDisplay();
    }
  },

  toggle: function() {
    volumeToggle.isVisible = !volumeToggle.isVisible;
    localStorage.setItem('volumeToggleState', volumeToggle.isVisible.toString());
    volumeToggle.updateVolumeDisplay();
  },

  updateVolumeDisplay: function() {
    const volumeDivs = document.querySelectorAll('[id$="-volume-div"]');
    volumeDivs.forEach(div => {
      if (div) {
        div.style.display = volumeToggle.isVisible ? 'flex' : 'none';
      }
    });

    const toggleButton = document.getElementById('toggle-volume');
    if (toggleButton) {
      updateButtonStyles(toggleButton, volumeToggle.isVisible, 'green');
    }
  },

  cleanup: function() {
    const toggleButton = document.getElementById('toggle-volume');
    if (toggleButton) {
      toggleButton.removeEventListener('click', volumeToggle.toggle);
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
  isAutoRefreshEnabled: localStorage.getItem('autoRefreshEnabled') === 'true',
  updateNextRefreshTimeRAF: null,

  refreshTexts: {
    label: 'Auto-refresh in',
    disabled: 'Auto-refresh: disabled',
    justRefreshed: 'Just refreshed',
  },
  cacheTTL: window.config.cacheConfig.ttlSettings.prices,
  minimumRefreshInterval: 300 * 1000,

  init: function() {
    window.addEventListener('load', app.onLoad);
    app.loadLastRefreshedTime();
    app.updateAutoRefreshButton();

    NetworkManager.addHandler('offline', () => {
      ui.showNetworkErrorMessage();
    });

    NetworkManager.addHandler('reconnected', () => {
      ui.hideErrorMessage();
      app.refreshAllData();
    });

    NetworkManager.addHandler('maxAttemptsReached', () => {
      ui.displayErrorMessage(
        "Server connection lost. Please check your internet connection and try refreshing the page.",
        0
      );
    });

    return app;
  },

  onLoad: async function() {
    ui.showLoader();
    try {
      volumeToggle.init();
      await app.updateBTCPrice();
      const chartContainer = document.getElementById('coin-chart');
      if (chartContainer) {
        chartModule.initChart();
        chartModule.showChartLoader();
      }

      await app.loadAllCoinData();

      if (chartModule.chart) {
        window.config.currentResolution = 'day';

        let defaultCoin = null;
        if (window.config.coins && window.config.coins.length > 0) {
          for (const coin of window.config.coins) {
            const container = document.getElementById(`${coin.symbol.toLowerCase()}-container`);
            if (container) {
              defaultCoin = coin.symbol;
              break;
            }
          }
        }

        if (!defaultCoin) {
          defaultCoin = 'BTC';
        }

        await chartModule.updateChart(defaultCoin);
        app.updateResolutionButtons(defaultCoin);

        const chartTitle = document.getElementById('chart-title');
        if (chartTitle) {
          chartTitle.textContent = `Price Chart (${defaultCoin})`;
        }

        ui.setActiveContainer(`${defaultCoin.toLowerCase()}-container`);
      }

      app.setupEventListeners();
      app.initAutoRefresh();

    } catch (error) {
      ui.displayErrorMessage('Failed to initialize the dashboard. Please try refreshing the page.');
      NetworkManager.handleNetworkError(error);
    } finally {
      ui.hideLoader();
      if (chartModule.chart) {
        chartModule.hideChartLoader();
      }
    }
  },

  loadAllCoinData: async function() {
    try {
      if (!NetworkManager.isOnline()) {
        throw new Error('Network is offline');
      }

      const allCoinData = await api.fetchCoinGeckoDataXHR();
      if (allCoinData.error) {
        throw new Error(allCoinData.error);
      }

      let volumeData = {};
      try {
        volumeData = await api.fetchVolumeDataXHR();
      } catch (volumeError) {}

      for (const coin of window.config.coins) {
        const coinData = allCoinData[coin.symbol.toLowerCase()];

        if (coinData) {
          coinData.displayName = coin.displayName || coin.symbol;

          const backendId = getCoinBackendId ? getCoinBackendId(coin.name) : coin.name;
          if (volumeData[backendId]) {
            coinData.total_volume = volumeData[backendId].total_volume;
            if (!coinData.price_change_percentage_24h && volumeData[backendId].price_change_percentage_24h) {
              coinData.price_change_percentage_24h = volumeData[backendId].price_change_percentage_24h;
            }
          }

          ui.displayCoinData(coin.symbol, coinData);

          const cacheKey = `coinData_${coin.symbol}`;
          CacheManager.set(cacheKey, coinData);
        } else {
          console.warn(`No data found for ${coin.symbol}`);
        }
      }
    } catch (error) {
      console.error('Error loading all coin data:', error);
      NetworkManager.handleNetworkError(error);
      ui.displayErrorMessage('Failed to load coin data. Please try refreshing the page.');
    }
  },

  loadCoinData: async function(coin) {
    const cacheKey = `coinData_${coin.symbol}`;
    let cachedData = CacheManager.get(cacheKey);
    let data;
    if (cachedData) {
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
        CacheManager.set(cacheKey, data, 'prices');
        cachedData = null;
      } catch (error) {
        NetworkManager.handleNetworkError(error);
        data = {
          error: error.message
        };
      } finally {
        ui.hideCoinLoader(coin.symbol);
      }
    }
    ui.displayCoinData(coin.symbol, data);
    ui.updateLoadTimeAndCache(0, cachedData);
  },

  setupEventListeners: function() {
    window.config.coins.forEach(coin => {
      const container = document.getElementById(`${coin.symbol.toLowerCase()}-container`);
      if (container) {
        CleanupManager.addListener(container, 'click', () => {
          const chartTitle = document.getElementById('chart-title');
          if (chartTitle) {
            chartTitle.textContent = `Price Chart (${coin.symbol})`;
          }
          ui.setActiveContainer(`${coin.symbol.toLowerCase()}-container`);
          if (chartModule.chart) {
            if (coin.symbol === 'WOW') {
              window.config.currentResolution = 'day';
            }
            chartModule.updateChart(coin.symbol);
            app.updateResolutionButtons(coin.symbol);
          }
        });
      }
    });

    const refreshAllButton = document.getElementById('refresh-all');
    if (refreshAllButton) {
      CleanupManager.addListener(refreshAllButton, 'click', app.refreshAllData);
    }

    const headers = document.querySelectorAll('th');
    headers.forEach((header, index) => {
    });

    const closeErrorButton = document.getElementById('close-error');
    if (closeErrorButton) {
      CleanupManager.addListener(closeErrorButton, 'click', ui.hideErrorMessage);
    }

    const reconnectButton = document.getElementById('network-reconnect');
    if (reconnectButton) {
      CleanupManager.addListener(reconnectButton, 'click', NetworkManager.manualReconnect);
    }
  },

  initAutoRefresh: function() {
    const toggleAutoRefreshButton = document.getElementById('toggle-auto-refresh');
    if (toggleAutoRefreshButton) {
      toggleAutoRefreshButton.addEventListener('click', app.toggleAutoRefresh);
      app.updateAutoRefreshButton();
    }

    if (app.isAutoRefreshEnabled) {
      app.scheduleNextRefresh();
    }
  },

  updateNextRefreshTime: function() {
  const nextRefreshSpan = document.getElementById('next-refresh-time');
  const labelElement = document.getElementById('next-refresh-label');
  const valueElement = document.getElementById('next-refresh-value');

  if (nextRefreshSpan && labelElement && valueElement) {
    if (app.isRefreshing) {
      labelElement.textContent = '';
      valueElement.textContent = 'Refreshing...';
      valueElement.classList.add('text-blue-500');
      return;
    } else {
      valueElement.classList.remove('text-blue-500');
    }

    if (app.nextRefreshTime) {
      if (app.updateNextRefreshTimeRAF) {
        cancelAnimationFrame(app.updateNextRefreshTimeRAF);
        app.updateNextRefreshTimeRAF = null;
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

  scheduleNextRefresh: function() {
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
          localStorage.removeItem(key);
        }
      }
    });

    let nextRefreshTime = now + app.minimumRefreshInterval;
    if (earliestExpiration !== Infinity) {
      nextRefreshTime = Math.max(earliestExpiration, now + app.minimumRefreshInterval);
    } else {
      nextRefreshTime = now + window.config.cacheTTL;
    }
    const timeUntilRefresh = nextRefreshTime - now;
    app.nextRefreshTime = nextRefreshTime;
    app.autoRefreshInterval = setTimeout(() => {
      if (NetworkManager.isOnline()) {
        app.refreshAllData();
      } else {
        app.scheduleNextRefresh();
      }
    }, timeUntilRefresh);
    localStorage.setItem('nextRefreshTime', app.nextRefreshTime.toString());
    app.updateNextRefreshTime();
  },

refreshAllData: async function() {
  //console.log('Price refresh started at', new Date().toLocaleTimeString());

  if (app.isRefreshing) {
    console.log('Refresh already in progress, skipping...');
    return;
  }

  if (!NetworkManager.isOnline()) {
    ui.displayErrorMessage("Network connection unavailable. Please check your connection.");
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

  //console.log('Starting refresh of all data...');
  app.isRefreshing = true;
  app.updateNextRefreshTime();
  ui.showLoader();
  chartModule.showChartLoader();

  try {
    ui.hideErrorMessage();
    CacheManager.clear();

    const btcUpdateSuccess = await app.updateBTCPrice();
    if (!btcUpdateSuccess) {
      console.warn('BTC price update failed, continuing with cached or default value');
    }

    await new Promise(resolve => setTimeout(resolve, 1000));

    const allCoinData = await api.fetchCoinGeckoDataXHR();
    if (allCoinData.error) {
      throw new Error(`CoinGecko API Error: ${allCoinData.error}`);
    }

    let volumeData = {};
    try {
      volumeData = await api.fetchVolumeDataXHR();
    } catch (volumeError) {}

    const failedCoins = [];

    for (const coin of window.config.coins) {
      const symbol = coin.symbol.toLowerCase();
      const coinData = allCoinData[symbol];

      try {
        if (!coinData) {
          throw new Error(`No data received`);
        }

        coinData.displayName = coin.displayName || coin.symbol;

        const backendId = getCoinBackendId ? getCoinBackendId(coin.name) : coin.name;
        if (volumeData[backendId]) {
          coinData.total_volume = volumeData[backendId].total_volume;
          if (!coinData.price_change_percentage_24h && volumeData[backendId].price_change_percentage_24h) {
            coinData.price_change_percentage_24h = volumeData[backendId].price_change_percentage_24h;
          }
        } else {
          try {
            const cacheKey = `coinData_${coin.symbol}`;
            const cachedData = CacheManager.get(cacheKey);
            if (cachedData && cachedData.value && cachedData.value.total_volume) {
              coinData.total_volume = cachedData.value.total_volume;
            }
            if (cachedData && cachedData.value && cachedData.value.price_change_percentage_24h &&
                !coinData.price_change_percentage_24h) {
              coinData.price_change_percentage_24h = cachedData.value.price_change_percentage_24h;
            }
          } catch (e) {
            console.warn(`Failed to retrieve cached volume data for ${coin.symbol}:`, e);
          }
        }

        ui.displayCoinData(coin.symbol, coinData);

        const cacheKey = `coinData_${coin.symbol}`;
        CacheManager.set(cacheKey, coinData, 'prices');

      //console.log(`Updated price for ${coin.symbol}: $${coinData.current_price}`);

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
      const failureMessage = failedCoins.length === window.config.coins.length
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
   //console.log(`Price refresh completed at ${new Date().toLocaleTimeString()}. Updated ${window.config.coins.length - failedCoins.length}/${window.config.coins.length} coins.`);

  } catch (error) {
    console.error('Critical error during refresh:', error);
    NetworkManager.handleNetworkError(error);

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

    console.error(`Price refresh failed at ${new Date().toLocaleTimeString()}: ${error.message}`);

  } finally {
    ui.hideLoader();
    chartModule.hideChartLoader();
    app.isRefreshing = false;
    app.updateNextRefreshTime();

    if (app.isAutoRefreshEnabled) {
      app.scheduleNextRefresh();
    }

    //console.log(`Refresh process finished at ${new Date().toLocaleTimeString()}, next refresh scheduled: ${app.isAutoRefreshEnabled ? 'yes' : 'no'}`);
  }
},

  updateAutoRefreshButton: function() {
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

  startSpinAnimation: function() {
    const svg = document.querySelector('#toggle-auto-refresh svg');
    if (svg) {
      svg.classList.add('animate-spin');
      setTimeout(() => {
        svg.classList.remove('animate-spin');
      }, 2000);
    }
  },

  stopSpinAnimation: function() {
    const svg = document.querySelector('#toggle-auto-refresh svg');
    if (svg) {
      svg.classList.remove('animate-spin');
    }
  },

  updateLastRefreshedTime: function() {
    const lastRefreshedElement = document.getElementById('last-refreshed-time');
    if (lastRefreshedElement && app.lastRefreshedTime) {
      const formattedTime = app.lastRefreshedTime.toLocaleTimeString();
      lastRefreshedElement.textContent = `Last Refreshed: ${formattedTime}`;
    }
  },

  loadLastRefreshedTime: function() {
    const storedTime = localStorage.getItem('lastRefreshedTime');
    if (storedTime) {
      app.lastRefreshedTime = new Date(parseInt(storedTime));
      ui.updateLastRefreshedTime();
    }
  },

  updateBTCPrice: async function() {
    try {
      const priceData = await window.PriceManager.getPrices();

      if (priceData) {
        if (priceData.bitcoin && priceData.bitcoin.usd) {
          app.btcPriceUSD = priceData.bitcoin.usd;
          return true;
        } else if (priceData.btc && priceData.btc.usd) {
          app.btcPriceUSD = priceData.btc.usd;
          return true;
        }
      }

      if (app.btcPriceUSD > 0) {
        console.log('Using previously cached BTC price:', app.btcPriceUSD);
        return true;
      }

      console.warn('Could not find BTC price in current data');
      return false;
    } catch (error) {
      console.error('Error fetching BTC price:', error);

      if (app.btcPriceUSD > 0) {
        console.log('Using previously cached BTC price after error:', app.btcPriceUSD);
        return true;
      }

      return false;
    }
  },

  updateResolutionButtons: function(coinSymbol) {
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
        button.classList.toggle('active', resolution === window.config.currentResolution);
        button.disabled = false;
      }
    });
  },

  toggleAutoRefresh: function() {
    app.isAutoRefreshEnabled = !app.isAutoRefreshEnabled;
    localStorage.setItem('autoRefreshEnabled', app.isAutoRefreshEnabled.toString());
    if (app.isAutoRefreshEnabled) {
      app.scheduleNextRefresh();
    } else {
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
      window.config.currentResolution = resolution;
      chartModule.updateChart(currentCoin, true);
      app.updateResolutionButtons(currentCoin);
    }
  });
});

function cleanup() {
  console.log('Starting cleanup process');

  try {
    if (window.MemoryManager) {
      MemoryManager.forceCleanup();
    }

    if (chartModule) {
      CleanupManager.registerResource('chartModule', chartModule, (cm) => {
        cm.cleanup();
      });
    }

    if (volumeToggle) {
      CleanupManager.registerResource('volumeToggle', volumeToggle, (vt) => {
        vt.cleanup();
      });
    }

    ['chartModule', 'volumeToggle', 'app'].forEach(ref => {
      if (window[ref]) {
        window[ref] = null;
      }
    });

    const cleanupCounts = CleanupManager.clearAll();
    console.log('All resources cleaned up:', cleanupCounts);

  } catch (error) {
    console.error('Error during cleanup:', error);
    CleanupManager.clearAll();
  }
}

window.cleanup = cleanup;

const appCleanup = {
  init: function() {
    window.addEventListener('beforeunload', this.globalCleanup);
  },

  globalCleanup: function() {
    try {
      if (window.MemoryManager) {
        MemoryManager.forceCleanup();
      }

      if (app.autoRefreshInterval) {
        CleanupManager.clearTimeout(app.autoRefreshInterval);
      }
      if (chartModule) {
        CleanupManager.registerResource('chartModule', chartModule, (cm) => {
          cm.cleanup();
        });
      }
      if (volumeToggle) {
        CleanupManager.registerResource('volumeToggle', volumeToggle, (vt) => {
          vt.cleanup();
        });
      }
      CleanupManager.clearAll();
      CacheManager.clear();
    } catch (error) {}
  },

  manualCleanup: function() {
    this.globalCleanup();
    window.location.reload();
  }
};

document.addEventListener('DOMContentLoaded', () => {
    if (window.NetworkManager && !window.networkManagerInitialized) {
        NetworkManager.initialize({
            connectionTestEndpoint: '/json',
            connectionTestTimeout: 3000,
            reconnectDelay: 5000,
            maxReconnectAttempts: 5
        });
        window.networkManagerInitialized = true;
    }

    app.init();

    if (window.MemoryManager) {
    if (typeof MemoryManager.enableAutoCleanup === 'function') {
        MemoryManager.enableAutoCleanup();
    } else {
        MemoryManager.initialize({
            autoCleanup: true,
            debug: false
        });
     }
    }

    CleanupManager.setInterval(() => {
        CacheManager.cleanup();
    }, 300000);

    CleanupManager.setInterval(() => {
        if (chartModule && chartModule.currentCoin && NetworkManager.isOnline()) {
            chartModule.updateChart(chartModule.currentCoin);
        }
    }, 900000);

    CleanupManager.addListener(document, 'visibilitychange', () => {
        if (!document.hidden) {
            console.log('Page is now visible');

            if (NetworkManager.isOnline()) {
                if (chartModule && chartModule.currentCoin) {
                    chartModule.updateChart(chartModule.currentCoin);
                }
            } else {

                NetworkManager.attemptReconnect();
            }
        }
    });

    CleanupManager.addListener(window, 'beforeunload', () => {
        cleanup();
    });

    appCleanup.init();
});

app.init = function() {
  window.addEventListener('load', app.onLoad);
  app.loadLastRefreshedTime();
  app.updateAutoRefreshButton();

  if (window.NetworkManager) {
    NetworkManager.addHandler('offline', () => {
      ui.showNetworkErrorMessage();
    });

    NetworkManager.addHandler('reconnected', () => {
      ui.hideErrorMessage();
      app.refreshAllData();
    });

    NetworkManager.addHandler('maxAttemptsReached', () => {
      ui.displayErrorMessage(
        "Server connection lost. Please check your internet connection and try refreshing the page.",
        0
      );
    });
  }

  return app;
};

app.init();
