// Global
let jsonData = [];
let originalJsonData = [];
let isInitialLoad = true;
let tableRateModule;

let lastRefreshTime = null;
let newEntriesCount = 0;
let nextRefreshCountdown = 600;
let countdownToFullRefresh = 900;

const isSentOffers = window.offersTableConfig.isSentOffers;

let currentPage = 1;
const itemsPerPage = 15;
let offerCache = new Map();

const coinIdToName = {
  1: 'particl', 2: 'bitcoin', 3: 'litecoin', 4: 'decred',
  6: 'monero', 7: 'particl blind', 8: 'particl anon',
  9: 'wownero', 11: 'pivx', 13: 'firo'
};

// DOM elements
const toggleButton = document.getElementById('toggleView');
const tableView = document.getElementById('tableView');
const jsonView = document.getElementById('jsonView');
const jsonContent = document.getElementById('jsonContent');
const offersBody = document.getElementById('offers-body');
const filterForm = document.getElementById('filterForm');
const prevPageButton = document.getElementById('prevPage');
const nextPageButton = document.getElementById('nextPage');
const currentPageSpan = document.getElementById('currentPage');
const totalPagesSpan = document.getElementById('totalPages');
const lastRefreshTimeSpan = document.getElementById('lastRefreshTime');
const newEntriesCountSpan = document.getElementById('newEntriesCount');
const nextRefreshTimeSpan = document.getElementById('nextRefreshTime');

// Utility
function isOfferExpired(offer) {
  const currentTime = Math.floor(Date.now() / 1000);
  const isExpired = offer.expire_at <= currentTime;
  if (isExpired) {
    console.log(`Offer ${offer.offer_id} is expired. Expire time: ${offer.expire_at}, Current time: ${currentTime}`);
  }
  return isExpired;
}

function setRefreshButtonLoading(isLoading) {
  const refreshButton = document.getElementById('refreshOffers');
  const refreshIcon = document.getElementById('refreshIcon');
  const refreshText = document.getElementById('refreshText');

  refreshButton.disabled = isLoading;
  refreshIcon.classList.toggle('animate-spin', isLoading);
  refreshText.textContent = isLoading ? 'Refreshing...' : 'Refresh';
}

function escapeHtml(unsafe) {
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
}

function formatTimeDifference(timestamp) {
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - timestamp);
  
  if (diff < 60) return `${diff} seconds`;
  if (diff < 3600) return `${Math.floor(diff / 60)} minutes`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} hours`;
  if (diff < 2592000) return `${Math.floor(diff / 86400)} days`;
  if (diff < 31536000) return `${Math.floor(diff / 2592000)} months`;
  return `${Math.floor(diff / 31536000)} years`;
}

function formatTimeAgo(timestamp) {
  const timeDiff = formatTimeDifference(timestamp);
  return `${timeDiff} ago`;
}

function formatTimeLeft(timestamp) {
  const now = Math.floor(Date.now() / 1000);
  if (timestamp <= now) return "Expired";
  return formatTimeDifference(timestamp);
}

function formatTimestamp(timestamp, withAgo = true, isExpired = false) {
  console.log("Incoming timestamp:", timestamp, typeof timestamp);
  
  if (typeof timestamp === 'string' && isNaN(Date.parse(timestamp))) {
    return timestamp;
  }

  if (!timestamp || isNaN(timestamp)) {
    console.log("Returning N/A due to invalid input");
    return "N/A";
  }
  
  try {
    const date = new Date(typeof timestamp === 'number' ? timestamp * 1000 : timestamp);
    console.log("Parsed date:", date);
    
    if (isNaN(date.getTime())) {
      console.log("Invalid date after parsing");
      return "N/A";
    }

    const now = new Date();
    const diffTime = Math.abs(now - date);
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (isExpired) {
      if (date > now) {
        const hours = Math.floor(diffTime / (1000 * 60 * 60));
        const minutes = Math.floor((diffTime % (1000 * 60 * 60)) / (1000 * 60));
        return `${hours}h ${minutes}min`;
      } else {
        return "Expired";
      }
    }

    if (diffDays <= 1) {
      const hours = date.getHours().toString().padStart(2, '0');
      const minutes = date.getMinutes().toString().padStart(2, '0');
      return `${hours}:${minutes}${withAgo ? ' ago' : ''}`;
    } else if (diffDays <= 7) {
      const options = { weekday: 'short' };
      return date.toLocaleDateString(undefined, options);
    } else {
      const options = { month: 'short', day: 'numeric' };
      return date.toLocaleDateString(undefined, options);
    }
  } catch (error) {
    console.error("Error formatting timestamp:", error);
    return "N/A";
  }
}

function normalizeCoinName(name) {
  return name.toLowerCase().replace(/\s+/g, ' ').trim();
}

function getCoinSymbol(fullName) {
  const symbolMap = {
    'Bitcoin': 'BTC', 'Litecoin': 'LTC', 'Monero': 'XMR',
    'Particl': 'PART', 'Particl Blind': 'PART', 'Particl Anon': 'PART',
    'PIVX': 'PIVX', 'Firo': 'FIRO', 'Dash': 'DASH',
    'Decred': 'DCR', 'Wownero': 'WOW', 'Bitcoin Cash': 'BCH'
  };
  return symbolMap[fullName] || fullName;
}

function formatSmallNumber(num) {
  if (Math.abs(num) < 0.000001) {
    return num.toExponential(8);
  } else if (Math.abs(num) < 0.01) {
    return num.toFixed(8);
  } else {
    return num.toFixed(4);
  }
}

// Table Rate
window.tableRateModule = {
  coinNameToSymbol: {
    'Bitcoin': 'BTC',
    'Particl': 'PART',
    'Particl Blind': 'PART',
    'Particl Anon': 'PART',
    'Monero': 'XMR',
    'Wownero': 'WOW',
    'Litecoin': 'LTC',
    'Firo': 'FIRO',
    'Dash': 'DASH',
    'PIVX': 'PIVX',
    'Decred': 'DCR',
    'Zano': 'ZANO',
    'Bitcoin Cash': 'BCH'
  },
  
  cache: {},
  processedOffers: new Set(),

  getCachedValue(key) {
    const cachedItem = localStorage.getItem(key);
    if (cachedItem) {
      const parsedItem = JSON.parse(cachedItem);
      if (Date.now() < parsedItem.expiry) {
        return parsedItem.value;
      } else {
        localStorage.removeItem(key);
      }
    }
    return null;
  },

  setCachedValue(key, value, ttl = 900000) {
    const item = {
      value: value,
      expiry: Date.now() + ttl,
    };
    localStorage.setItem(key, JSON.stringify(item));
  },

  setFallbackValue(coinSymbol, value) {
    this.setCachedValue(`fallback_${coinSymbol}_usd`, value, 24 * 60 * 60 * 1000);
  },

  isNewOffer(offerId) {
    if (this.processedOffers.has(offerId)) {
      return false;
    }
    this.processedOffers.add(offerId);
    return true;
  },
  
  formatUSD(value) {
    if (Math.abs(value) < 0.000001) {
      return value.toExponential(8) + ' USD';
    } else if (Math.abs(value) < 0.01) {
      return value.toFixed(8) + ' USD';
    } else {
      return value.toFixed(2) + ' USD';
    }
  },

  formatNumber(value, decimals) {
    if (Math.abs(value) < 0.000001) {
      return value.toExponential(decimals);
    } else if (Math.abs(value) < 0.01) {
      return value.toFixed(decimals);
    } else {
      return value.toFixed(Math.min(2, decimals));
    }
  },

  async updateUsdValue(cryptoCell, coinFullNameOrSymbol, isRate = false) {
    console.log('updateUsdValue called with:', { coinFullNameOrSymbol, isRate });
    
    if (!coinFullNameOrSymbol) {
      console.error('No coin name or symbol provided');
      return;
    }
    
    let coinSymbol = this.coinNameToSymbol[coinFullNameOrSymbol] || coinFullNameOrSymbol;
    console.log('Resolved coin symbol:', coinSymbol);
    
    const cryptoValue = parseFloat(cryptoCell.textContent);
    console.log('Crypto value:', cryptoValue);
    
    if (isNaN(cryptoValue) || cryptoValue <= 0) {
      console.error('Invalid or non-positive crypto value');
      return;
    }
    
    const usdCell = cryptoCell.closest('td').querySelector('.usd-value');
    if (!usdCell) {
      console.error("USD cell not found.");
      return;
    }
    
    const o16Value = usdCell.getAttribute('data-o16') || 'N/A';
    console.log('o16 value:', o16Value);
    
    const isWownero = coinSymbol.toUpperCase() === 'WOW';
    
    try {
      const [fromRate, toRate] = await Promise.all([
        this.getExchangeRate(coinSymbol),
        this.getExchangeRate(o16Value)
      ]);
      console.log(`Exchange rates - ${coinSymbol}: ${fromRate}, ${o16Value}: ${toRate}`);
      
      let usdValue = null;
      let exchangeRate = null;

      if (fromRate !== null && fromRate > 0) {
        usdValue = cryptoValue * fromRate;
        console.log(`Calculated USD value for ${coinSymbol}:`, usdValue);
        
        this.setFallbackValue(coinSymbol, fromRate);
      }

      if (usdValue === null) {
        const fallbackValue = this.getFallbackValue(coinSymbol);
        if (fallbackValue !== null) {
          usdValue = cryptoValue * fallbackValue;
          console.log(`Using fallback value for ${coinSymbol} USD:`, fallbackValue);
        }
      }

      if (fromRate !== null && toRate !== null && fromRate > 0 && toRate > 0) {
        exchangeRate = fromRate / toRate;
        console.log(`Calculated exchange rate ${coinSymbol}/${o16Value}:`, exchangeRate);
      }

      if (usdValue !== null) {
        usdCell.textContent = `${this.formatUSD(usdValue)}/${o16Value}`;
        usdCell.removeAttribute('data-is-fallback');
      } else {
        usdCell.textContent = `N/A/${o16Value}`;
        usdCell.setAttribute('data-is-fallback', 'true');
        console.warn(`No valid price available for ${coinSymbol} USD`);
      }

      const rateKey = `rate_${coinSymbol}_${o16Value}`;
      let cachedRate = this.getCachedValue(rateKey);
      if (cachedRate === null && exchangeRate !== null) {
        cachedRate = exchangeRate;
        this.setCachedValue(rateKey, cachedRate);
      } else if (cachedRate === null && usdValue !== null && toRate !== null && toRate > 0) {
        cachedRate = usdValue / (cryptoValue * toRate);
        this.setCachedValue(rateKey, cachedRate);
      }

      const marketPercentageKey = `market_percentage_${coinSymbol}_${o16Value}`;
      let cachedMarketPercentage = this.getCachedValue(marketPercentageKey);
      if (cachedMarketPercentage === null && exchangeRate !== null) {
        const marketRate = await this.getExchangeRate(o16Value);
        if (marketRate !== null && marketRate > 0) {
          cachedMarketPercentage = ((exchangeRate - marketRate) / marketRate) * 100;
          this.setCachedValue(marketPercentageKey, cachedMarketPercentage);
        } else {
          console.warn(`Invalid market rate for ${o16Value}, unable to calculate market percentage`);
        }
      }

      const rateCell = cryptoCell.closest('tr').querySelector('.coinname-value[data-coinname]');
      if (rateCell && cachedRate !== null) {
        rateCell.textContent = this.formatNumber(cachedRate, 8);
        const cachedRateElement = rateCell.closest('td').querySelector('.cached-rate');
        if (cachedRateElement) {
          cachedRateElement.textContent = cachedRate;
        }
      }

      if (usdValue !== null || isWownero) {
        const row = cryptoCell.closest('tr');
        if (row) {
          this.updateProfitLoss(row, cachedMarketPercentage);
          this.updateProfitValue(row);
        } else {
          console.error("Row not found for updating profit/loss and value.");
        }
      }
    } catch (error) {
      console.error(`Error in updateUsdValue for ${coinSymbol}:`, error);

      const fallbackValue = this.getFallbackValue(coinSymbol);
      if (fallbackValue !== null) {
        const usdValue = cryptoValue * fallbackValue;
        usdCell.textContent = `${this.formatUSD(usdValue)}/${o16Value}`;
        usdCell.setAttribute('data-is-fallback', 'true');
        console.warn(`Using fallback value for ${coinSymbol} due to error:`, fallbackValue);
        
        const row = cryptoCell.closest('tr');
        if (row) {
          this.updateProfitLoss(row, null);
          this.updateProfitValue(row);
        }
      } else {
        usdCell.textContent = `N/A/${o16Value}`;
        usdCell.setAttribute('data-is-fallback', 'true');
        console.warn(`No valid fallback price for ${coinSymbol}. Using N/A.`);
      }
    }
  },

  setFallbackValue(coinSymbol, value) {
    localStorage.setItem(`fallback_${coinSymbol}_usd`, value.toString());
  },

  getFallbackValue(coinSymbol) {
    const value = localStorage.getItem(`fallback_${coinSymbol}_usd`);
    return value ? parseFloat(value) : null;
  },

  async getExchangeRate(coinSymbol) {
    console.log(`Fetching exchange rate for ${coinSymbol}`);
    const cacheKey = `coinData_${coinSymbol}`;
    let cachedData = cache.get(cacheKey);
    let data;

    if (cachedData) {
      console.log(`Using cached data for ${coinSymbol}`);
      data = cachedData.value;
    } else {
      console.log(`Fetching fresh data for ${coinSymbol}`);
      
      const coin = config.coins.find(c => c.symbol.toLowerCase() === coinSymbol.toLowerCase());

      if (!coin) {
        return null;
      }

      if (coin.usesCoinGecko) {
        data = await api.fetchCoinGeckoDataXHR(coinSymbol);
      } else if (coin.usesCryptoCompare) {
        data = await api.fetchCryptoCompareDataXHR(coinSymbol);
      } else {
        console.error(`No API source configured for ${coinSymbol}`);
        return null;
      }

      cache.set(cacheKey, data);
    }

    console.log(`Data received for ${coinSymbol}:`, data);
    return this.extractExchangeRate(data, coinSymbol);
  },

  extractExchangeRate(data, coinSymbol) {
    console.log(`Extracting exchange rate for ${coinSymbol}`);
    const coin = config.coins.find(c => c.symbol === coinSymbol);
    if (!coin) {
      console.error(`Configuration not found for coin: ${coinSymbol}`);
      return null;
    }
    
    if (data.error) {
      console.error(`Error in data for ${coinSymbol}:`, data.error);
      return null;
    }
    
    let rate;
    if (coin.usesCoinGecko) {
      if (!data.market_data || !data.market_data.current_price || !data.market_data.current_price.usd) {
        console.error(`Invalid CoinGecko data structure for ${coinSymbol}:`, data);
        return null;
      }
      rate = data.market_data.current_price.usd;
    } else {
      if (!data.RAW || !data.RAW[coinSymbol] || !data.RAW[coinSymbol].USD || typeof data.RAW[coinSymbol].USD.PRICE !== 'number') {
        console.error(`Invalid CryptoCompare data structure for ${coinSymbol}:`, data);
        return null;
      }
      rate = data.RAW[coinSymbol].USD.PRICE;
    }
    
    if (rate <= 0) {
      console.error(`Invalid rate for ${coinSymbol}: ${rate}`);
      return null;
    }
    
    return rate;
  },

  updateProfitLoss(row, cachedMarketPercentage = null) {
    const usdCells = row.querySelectorAll('.usd-value');
    if (usdCells.length < 2) {
      console.error("Not enough USD value cells found.");
      return;
    }
    const [buyingUSDString, sellingUSDString] = Array.from(usdCells).map(cell => cell.textContent.split('/')[0].trim());
    const buyingUSD = buyingUSDString === 'N/A' ? NaN : parseFloat(buyingUSDString);
    const sellingUSD = sellingUSDString === 'N/A' ? NaN : parseFloat(sellingUSDString);
    
    console.log('ProfitLoss calculation inputs:', { buyingUSD, sellingUSD });
    
    const profitLossCell = row.querySelector('.profit-loss');
    if (!profitLossCell) {
      console.error("Profit/loss cell not found.");
      return;
    }
    
    if ((!isNaN(sellingUSD) && !isNaN(buyingUSD) && buyingUSD > 0) || cachedMarketPercentage !== null) {
      let profitLossPercentage;
      if (cachedMarketPercentage !== null) {
        profitLossPercentage = cachedMarketPercentage;
      } else {
        profitLossPercentage = ((sellingUSD - buyingUSD) / buyingUSD) * 100;
      }
      console.log('Calculated profit/loss percentage:', profitLossPercentage);
      
      let formattedPercentage;
      if (Math.abs(profitLossPercentage) < 0.000001) {
        formattedPercentage = profitLossPercentage.toExponential(6);
      } else if (Math.abs(profitLossPercentage) < 0.01) {
        formattedPercentage = profitLossPercentage.toFixed(6);
      } else {
        formattedPercentage = profitLossPercentage.toFixed(2);
      }

      profitLossCell.textContent = `${profitLossPercentage >= 0 ? '+' : ''}${formattedPercentage}%`;
      profitLossCell.className = 'profit-loss ' + (profitLossPercentage > 0 ? 'text-green-500' :
        profitLossPercentage < 0 ? 'text-red-500' : 'text-yellow-500');
      
      const cachedMarketPercentageElement = profitLossCell.closest('td').querySelector('.cached-market-percentage');
      if (cachedMarketPercentageElement) {
        cachedMarketPercentageElement.textContent = profitLossPercentage;
      }
    } else {
      profitLossCell.textContent = 'N/A';
      profitLossCell.className = 'profit-loss text-yellow-500';
    }
  },

  updateProfitValue(row) {
    const usdCells = row.querySelectorAll('.usd-value');
    if (usdCells.length < 2) {
      console.error("Not enough USD value cells found.");
      return;
    }
    const [buyingUSDString, sellingUSDString] = Array.from(usdCells).map(cell => cell.textContent.split('/')[0].trim());
    const buyingUSD = parseFloat(buyingUSDString);
    const sellingUSD = parseFloat(sellingUSDString);
    
    const profitValueCell = row.querySelector('.profit-value');
    if (!profitValueCell) {
      console.error("Profit value cell not found.");
      return;
    }
    
    if (!isNaN(sellingUSD) && !isNaN(buyingUSD)) {
      const profitValue = sellingUSD - buyingUSD;
      profitValueCell.textContent = this.formatUSD(profitValue);
      profitValueCell.classList.remove('hidden');
    } else {
      profitValueCell.textContent = 'N/A';
      profitValueCell.classList.remove('hidden');
    }
  },

  initializeTable() {
    console.log('Initializing table');
    document.querySelectorAll('.coinname-value').forEach(coinNameValue => {
      const coinFullNameOrSymbol = coinNameValue.getAttribute('data-coinname');
      console.log('Processing coin:', coinFullNameOrSymbol);
      if (!coinFullNameOrSymbol || coinFullNameOrSymbol === 'Unknown') {
        console.warn('Missing or unknown coin name/symbol in data-coinname attribute');
        return;
      }
      const isRate = coinNameValue.closest('td').querySelector('.ratetype') !== null;
      coinNameValue.classList.remove('hidden');
      this.updateUsdValue(coinNameValue, coinFullNameOrSymbol, isRate);
    });
  },

  init() {
    console.log('Initializing TableRateModule');
    this.initializeTable();
  }
};

// Main
function fetchOffers(manualRefresh = false) {
    return new Promise((resolve, reject) => {
        const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
        console.log(`Fetching offers from: ${endpoint}`);
        
        const newEntriesCountSpan = document.getElementById('newEntriesCount');
        if (newEntriesCountSpan) {
            newEntriesCountSpan.textContent = 'Loading...';
        }
        
        if (manualRefresh) {
            offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">Refreshing offers...</td></tr>';
        }
        
        setRefreshButtonLoading(true);
        
        fetch(endpoint)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                console.log('Raw data received:', data.length, 'offers');
                
                let newData = Array.isArray(data) ? data : Object.values(data);
                console.log('Processed data length before filtering:', newData.length);
                
                newData = newData.map(offer => ({
                    ...offer,
                    offer_id: String(offer.offer_id || ''),
                    swap_type: String(offer.swap_type || 'N/A'),
                    addr_from: String(offer.addr_from || ''),
                    coin_from: String(offer.coin_from || ''),
                    coin_to: String(offer.coin_to || ''),
                    amount_from: String(offer.amount_from || '0'),
                    amount_to: String(offer.amount_to || '0'),
                    rate: String(offer.rate || '0'),
                    created_at: Number(offer.created_at || 0),
                    expire_at: Number(offer.expire_at || 0),
                    is_own_offer: Boolean(offer.is_own_offer),
                    amount_negotiable: Boolean(offer.amount_negotiable)
                }));
                
                if (!isSentOffers) {
                    const currentTime = Math.floor(Date.now() / 1000);
                    const beforeFilterCount = newData.length;
                    newData = newData.filter(offer => {
                        const keepOffer = !isOfferExpired(offer);
                        if (!keepOffer) {
                            console.log('Filtered out expired offer:', offer.offer_id);
                        }
                        return keepOffer;
                    });
                    console.log(`Filtered out ${beforeFilterCount - newData.length} expired offers`);
                }
                
                console.log('Processed data length after filtering:', newData.length);
                
                if (isInitialLoad || manualRefresh) {
                    console.log('Initial load or manual refresh - replacing all data');
                    jsonData = newData;
                    originalJsonData = [...newData];
                    isInitialLoad = false;
                } else {
                    console.log('Updating existing data');
                    console.log('Current jsonData length:', jsonData.length);
                    
                    const mergedData = [...jsonData];
                    newData.forEach(newOffer => {
                        const existingIndex = mergedData.findIndex(existing => existing.offer_id === newOffer.offer_id);
                        if (existingIndex !== -1) {
                            mergedData[existingIndex] = newOffer;
                        } else {
                            mergedData.push(newOffer);
                        }
                    });
                    
                    jsonData = isSentOffers ? mergedData : mergedData.filter(offer => !isOfferExpired(offer));
                }
                
                console.log('Final jsonData length:', jsonData.length);
                
                offerCache.clear();
                jsonData.forEach(offer => offerCache.set(offer.offer_id, offer));
                
                const validItemCount = isSentOffers ? jsonData.length : jsonData.filter(offer => !isOfferExpired(offer)).length;
                if (newEntriesCountSpan) {
                    newEntriesCountSpan.textContent = validItemCount;
                }
                console.log('Valid offers count:', validItemCount);
                
                lastRefreshTime = Date.now();
                nextRefreshCountdown = getTimeUntilNextExpiration();
                updateLastRefreshTime();
                updateNextRefreshTime();
                applyFilters();
                updateOffersTable();
                updateJsonView();
                updatePaginationInfo();
                
                if (manualRefresh) {
                    console.log('Offers refreshed successfully');
                }
                
                resolve();
            })
            .catch(error => {
                console.error(`Error fetching ${isSentOffers ? 'sent offers' : 'offers'}:`, error);
                
                let errorMessage = 'An error occurred while fetching offers. ';
                if (error.message.includes('HTTP error')) {
                    errorMessage += 'The server returned an error. ';
                } else if (error.message.includes('empty data')) {
                    errorMessage += 'No offer data was received. ';
                } else if (error.name === 'TypeError') {
                    errorMessage += 'There was a problem parsing the response. ';
                } else {
                    errorMessage += 'Please check your network connection. ';
                }
                errorMessage += 'Please try again later.';
                
                if (typeof ui !== 'undefined' && ui.displayErrorMessage) {
                    ui.displayErrorMessage(errorMessage);
                } else {
                    console.error(errorMessage);
                    offersBody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-red-500">${escapeHtml(errorMessage)}</td></tr>`;
                }
                
                isInitialLoad = false;
                updateOffersTable();
                updateJsonView();
                updatePaginationInfo();
                
                if (newEntriesCountSpan) {
                    newEntriesCountSpan.textContent = '0';
                }
                
                reject(error);
            })
            .finally(() => {
                setRefreshButtonLoading(false);
            });
    });
}

function applyFilters() {
  console.log('Applying filters');
  console.log('Is Sent Offers:', isSentOffers);
  
  const formData = new FormData(filterForm);
  const filters = Object.fromEntries(formData);
  console.log('Raw filters:', filters);

  if (filters.coin_to !== 'any') {
    filters.coin_to = coinIdToName[filters.coin_to] || filters.coin_to;
  }
  if (filters.coin_from !== 'any') {
    filters.coin_from = coinIdToName[filters.coin_from] || filters.coin_from;
  }

  console.log('Processed filters:', filters);

  const currentTime = Math.floor(Date.now() / 1000);

  jsonData = originalJsonData.filter(offer => {
    const coinFrom = (offer.coin_from || '').toLowerCase();
    const coinTo = (offer.coin_to || '').toLowerCase();
    const isExpired = offer.expire_at <= currentTime;

    console.log(`Offer - id: ${offer.offer_id}, coinFrom: ${coinFrom}, coinTo: ${coinTo}, isExpired: ${isExpired}`);

    if (!isSentOffers && isExpired) {
      console.log(`Filtered out: offer expired`);
      return false;
    }

    if (isSentOffers) {
      if (filters.coin_to !== 'any' && coinFrom.toLowerCase() !== filters.coin_to.toLowerCase()) {
        console.log(`Filtered out sent offer: coin to send mismatch - ${coinFrom} !== ${filters.coin_to}`);
        return false;
      }
      if (filters.coin_from !== 'any' && coinTo.toLowerCase() !== filters.coin_from.toLowerCase()) {
        console.log(`Filtered out sent offer: coin to receive mismatch - ${coinTo} !== ${filters.coin_from}`);
        return false;
      }
    } else {
      if (filters.coin_to !== 'any' && coinTo.toLowerCase() !== filters.coin_to.toLowerCase()) {
        console.log(`Filtered out offer: bid mismatch - ${coinTo} !== ${filters.coin_to}`);
        return false;
      }
      if (filters.coin_from !== 'any' && coinFrom.toLowerCase() !== filters.coin_from.toLowerCase()) {
        console.log(`Filtered out offer: offer mismatch - ${coinFrom} !== ${filters.coin_from}`);
        return false;
      }
    }

    if (isSentOffers && filters.active && filters.active !== 'any') {
      const offerState = isExpired ? 'expired' : 'active';
      if (filters.active !== offerState) {
        console.log(`Filtered out: state mismatch - ${offerState} !== ${filters.active}`);
        return false;
      }
    }

    console.log('Offer passed all filters');
    return true;
  });

  console.log('Filtered data length:', jsonData.length);

  if (filters.sort_by) {
    jsonData.sort((a, b) => {
      const aValue = a[filters.sort_by];
      const bValue = b[filters.sort_by];
      
      if (filters.sort_by === 'created_at') {
        return (filters.sort_dir === 'asc' ? 1 : -1) * (Number(aValue) - Number(bValue));
      } else {
        return (filters.sort_dir === 'asc' ? 1 : -1) * String(aValue).localeCompare(String(bValue));
      }
    });
  }

  currentPage = 1;
  updateOffersTable();
  updateJsonView();
  updatePaginationInfo();
}

function initializeFlowbiteTooltips() {
  if (typeof Tooltip === 'undefined') {
    console.warn('Tooltip is not defined. Make sure the required library is loaded.');
    return;
  }
  
  const tooltipElements = document.querySelectorAll('[data-tooltip-target]');
  tooltipElements.forEach((el) => {
    const tooltipId = el.getAttribute('data-tooltip-target');
    const tooltipElement = document.getElementById(tooltipId);
    if (tooltipElement) {
      new Tooltip(tooltipElement, el);
    }
  });
}

function updateOffersTable() {
  console.log('Updating offers table');
  console.log('Current jsonData length:', jsonData.length);
  console.log('Is Sent Offers:', isSentOffers);
  console.log('Current Page:', currentPage);
  
  if (isInitialLoad) {
    offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">Loading offers...</td></tr>';
    return;
  }
  
  if (typeof initializeFlowbiteTooltips === 'function') {
    initializeFlowbiteTooltips();
  } else {
    console.warn('initializeFlowbiteTooltips is not defined. Skipping tooltip initialization.');
  }
  
  const currentTime = Math.floor(Date.now() / 1000);
  const validOffers = jsonData.filter(offer => {
    if (isSentOffers) {
      offer.isExpired = offer.expire_at <= currentTime;
      return true;
    } else {
      return offer.expire_at > currentTime;
    }
  });
  console.log('Valid offers after filtering:', validOffers.length);

  const totalPages = Math.max(1, Math.ceil(validOffers.length / itemsPerPage));
  currentPage = Math.max(1, Math.min(currentPage, totalPages));

  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const itemsToDisplay = validOffers.slice(startIndex, endIndex);
  console.log('Items to display:', itemsToDisplay.length);
  
  offersBody.innerHTML = '';
  
  if (itemsToDisplay.length === 0) {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    let message = 'No offers available';
    if (filters.coin_to !== 'any') {
      const coinToName = coinIdToName[filters.coin_to] || filters.coin_to;
      message += ` for bids to ${coinToName}`;
    }
    if (filters.coin_from !== 'any') {
      const coinFromName = coinIdToName[filters.coin_from] || filters.coin_from;
      message += ` for offers from ${coinFromName}`;
    }
    if (isSentOffers && filters.active && filters.active !== 'any') {
      message += ` with status: ${filters.active}`;
    }
    offersBody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">${message}</td></tr>`;
    console.log(message);
    return;
  }
  
  itemsToDisplay.forEach(offer => {
    const row = createTableRow(offer, isSentOffers);
    if (row) {
      offersBody.appendChild(row);
    }
  });
  console.log('Rows added to table:', itemsToDisplay.length);
  
  updateRowTimes();
  initializeFlowbiteTooltips();
  updatePaginationInfo(validOffers.length);
  
  if (tableRateModule && typeof tableRateModule.initializeTable === 'function') {
    setTimeout(() => {
      tableRateModule.initializeTable();
    }, 0);
  } else {
    console.warn('tableRateModule not found or initializeTable method not available');
  }
}
function updateOffersTable() {
  console.log('Updating offers table');
  console.log('Current jsonData length:', jsonData.length);
  console.log('Is Sent Offers:', isSentOffers);
  console.log('Current Page:', currentPage);
  
  if (isInitialLoad) {
    offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">Loading offers...</td></tr>';
    return;
  }
  
  const currentTime = Math.floor(Date.now() / 1000);
  const validOffers = isSentOffers ? jsonData : jsonData.filter(offer => offer.expire_at > currentTime);
  console.log('Valid offers after filtering:', validOffers.length);

  const totalPages = Math.max(1, Math.ceil(validOffers.length / itemsPerPage));
  currentPage = Math.max(1, Math.min(currentPage, totalPages));

  const startIndex = (currentPage - 1) * itemsPerPage;
  const endIndex = startIndex + itemsPerPage;
  const itemsToDisplay = validOffers.slice(startIndex, endIndex);
  console.log('Items to display:', itemsToDisplay.length);
  
  offersBody.innerHTML = '';
  
  if (itemsToDisplay.length === 0) {
    const message = getNoOffersMessage();
    offersBody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">${message}</td></tr>`;
    console.log(message);
  } else {
    itemsToDisplay.forEach(offer => {
      const row = createTableRow(offer, isSentOffers);
      if (row) {
        offersBody.appendChild(row);
      }
    });
    console.log('Rows added to table:', itemsToDisplay.length);
  }
  
  updateRowTimes();
  initializeFlowbiteTooltips();
  updatePaginationInfo(validOffers.length);
  
  if (tableRateModule && typeof tableRateModule.initializeTable === 'function') {
    setTimeout(() => {
      tableRateModule.initializeTable();
    }, 0);
  } else {
    console.warn('tableRateModule not found or initializeTable method not available');
  }
}

function performFullRefresh() {
    console.log('Performing full refresh');
    const currentTime = Math.floor(Date.now() / 1000);
    
    fetchOffers(true)
        .then(() => {
            jsonData = jsonData.filter(offer => {
                if (isSentOffers) {
                    offer.isExpired = offer.expire_at <= currentTime;
                    return true;
                } else {
                    return offer.expire_at > currentTime;
                }
            });
            
            applyFilters();
            updateOffersTable();
            updateJsonView();
            updatePaginationInfo();
            
            countdownToFullRefresh = 900;
            updateNextFullRefreshTime();
            
            console.log('Full refresh completed');
        })
        .catch(error => {
            console.error('Error during full refresh:', error);
        });
}

function updateNextRefreshTime() {
  if (!nextRefreshTimeSpan) {
    console.warn('nextRefreshTime element not found');
    return;
  }
  
  const minutes = Math.floor(nextRefreshCountdown / 60);
  const seconds = nextRefreshCountdown % 60;
  
  nextRefreshTimeSpan.textContent = `${minutes}m ${seconds}s`;

  updateNextFullRefreshTime();
}


function refreshTableData() {
  console.log('Refreshing table data');
  setRefreshButtonLoading(true);

  const offersBody = document.getElementById('offers-body');
  if (offersBody) {
    offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">Refreshing offers...</td></tr>';
  }
  
  const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
  fetch(endpoint)
    .then(response => response.json())
    .then(newData => {
      console.log('Received raw data:', newData);
      console.log('Number of offers received:', Array.isArray(newData) ? newData.length : Object.keys(newData).length);
      
      let processedData = Array.isArray(newData) ? newData : Object.values(newData);
      
      if (!isSentOffers) {
        const currentTime = Math.floor(Date.now() / 1000);
        const beforeFilterCount = processedData.length;
        processedData = processedData.filter(offer => !isOfferExpired(offer));
        console.log(`Filtered out ${beforeFilterCount - processedData.length} expired offers`);
      }
      
      const existingOfferIds = new Set(jsonData.map(offer => offer.offer_id));
      const newOffers = processedData.filter(offer => !existingOfferIds.has(offer.offer_id));
      console.log(`Found ${newOffers.length} new offers`);
      
      jsonData = processedData;
      originalJsonData = [...processedData];
      
      console.log('Final number of offers in jsonData:', jsonData.length);
      
      lastRefreshTime = Date.now();
      localStorage.setItem('lastRefreshedTime', lastRefreshTime.toString());
      updateLastRefreshTime();
      
      newEntriesCount = newOffers.length;
      
      applyFilters();
      updateOffersTable();
      updateJsonView();
      updatePaginationInfo();    
      tableRateModule.initializeTable();
      
      console.log('Table data refreshed successfully');
      setRefreshButtonLoading(false);
    })
    .catch(error => {
      console.error('Error refreshing table data:', error);
      setRefreshButtonLoading(false);
      if (offersBody) {
        offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-red-500">Failed to refresh offers. Please try again.</td></tr>';
      }
    });
}

function updateRowTimes() {
  const currentTime = Math.floor(Date.now() / 1000);
  
  document.querySelectorAll('[data-offer-id]').forEach(row => {
    const offerId = row.getAttribute('data-offer-id');
    let offer = offerCache.get(offerId);
    
    if (!offer) {
      offer = jsonData.find(o => o.offer_id === offerId);
      if (offer) {
        offerCache.set(offerId, offer);
      } else {
        console.warn(`Offer not found for ID: ${offerId}`);
        return;
      }
    }

    const timeColumn = row.querySelector('td:first-child');
    if (!timeColumn) return;

    const timeDiv = timeColumn.querySelector('div.flex.flex-col');
    if (!timeDiv) return;

    const postedTime = formatTimeAgo(offer.created_at);
    const expiresIn = formatTimeLeft(offer.expire_at);

    timeDiv.innerHTML = `
      <div class="text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
      <div class="text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
    `;
    
    const tooltipElement = document.getElementById(`tooltip-active${offerId}`);
    if (tooltipElement) {
      const tooltipContent = tooltipElement.querySelector('.active-revoked-expired');
      if (tooltipContent) {
        tooltipContent.innerHTML = `
          <span class="bold">
            <div class="text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
            <div class="text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
          </span>
        `;
      }
    }
  });
}

function checkExpiredAndFetchNew() {
  const currentTime = Math.floor(Date.now() / 1000);
  const expiredOffers = jsonData.filter(offer => offer.expire_at <= currentTime);
  
  if (expiredOffers.length > 0) {
    console.log(`Found ${expiredOffers.length} expired offers. Removing and checking for new listings.`);
    
    jsonData = jsonData.filter(offer => offer.expire_at > currentTime);
    
    fetch('/json/offers')
      .then(response => response.json())
      .then(data => {
        let newListings = Array.isArray(data) ? data : Object.values(data);
        newListings = newListings.filter(offer => !isOfferExpired(offer));
        
        const brandNewListings = newListings.filter(newOffer => 
          !jsonData.some(existingOffer => existingOffer.offer_id === newOffer.offer_id)
        );
        
        if (brandNewListings.length > 0) {
          console.log(`Found ${brandNewListings.length} new listings to add.`);
          jsonData = [...jsonData, ...brandNewListings];
          newEntriesCount += brandNewListings.length;
        } else {
          console.log('No new listings found during expiry check.');
        }
        
        updateOffersTable();
        updateJsonView();
        updatePaginationInfo();
        
        nextRefreshCountdown = getTimeUntilNextExpiration();
        console.log(`Next expiration check in ${nextRefreshCountdown} seconds`);
      })
      .catch(error => {
        console.error('Error fetching new listings during expiry check:', error);
      });
  } else {
    console.log('No expired offers found during this check.');

    nextRefreshCountdown = getTimeUntilNextExpiration();
    console.log(`Next expiration check in ${nextRefreshCountdown} seconds`);
  }
}

function createTableRow(offer, isSentOffers) {
  const row = document.createElement('tr');
  row.className = `opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600`;
  row.setAttribute('data-offer-id', offer.offer_id);

  const {
    coinFrom, coinTo, coinFromSymbol, coinToSymbol,
    postedTime, expiresIn, isActuallyExpired, isTreatedAsSentOffer,
    formattedRate, buttonClass, buttonText, clockColor
  } = prepareOfferData(offer, isSentOffers);

  row.innerHTML = `
    ${createTimeColumn(offer, postedTime, expiresIn, clockColor)}
    ${createDetailsColumn(offer)}
    ${createTakerAmountColumn(offer, coinFrom, coinFromSymbol, coinTo)}
    ${createSwapColumn(offer, coinFrom, coinTo)}
    ${createOrderbookColumn(offer, coinTo, coinToSymbol, coinFrom)}
    ${createRateColumn(offer, coinFrom, coinTo, formattedRate)}
    ${createPercentageColumn(offer)}
    ${createActionColumn(offer, buttonClass, buttonText)}
    ${createTooltips(offer, isSentOffers, coinFrom, coinTo, postedTime, expiresIn, isActuallyExpired)}
  `;

  return row;
}

function prepareOfferData(offer, isSentOffers) {
  const coinFrom = offer.coin_from;
  const coinTo = offer.coin_to;
  const coinFromSymbol = getCoinSymbol(coinFrom);
  const coinToSymbol = getCoinSymbol(coinTo);
  
  const postedTime = formatTimeAgo(offer.created_at);
  const expiresIn = formatTimeLeft(offer.expire_at);
  
  const currentTime = Math.floor(Date.now() / 1000);
  const isActuallyExpired = currentTime > offer.expire_at;

  const rateValue = parseFloat(offer.rate);
  const formattedRate = formatSmallNumber(rateValue);

  const { buttonClass, buttonText } = getButtonProperties(isActuallyExpired, isSentOffers, offer.is_own_offer);
  
  const clockColor = isActuallyExpired ? "#9CA3AF" : "#3B82F6";

  return {
    coinFrom, coinTo, coinFromSymbol, coinToSymbol,
    postedTime, expiresIn, isActuallyExpired,
    formattedRate, buttonClass, buttonText, clockColor
  };
}

function getButtonProperties(isActuallyExpired, isSentOffers, isTreatedAsSentOffer) {
  if (isActuallyExpired && isSentOffers) {
    return {
      buttonClass: 'bg-gray-400 text-white dark:border-gray-300 text-white hover:bg-red-700 transition duration-200',
      buttonText: 'Expired'
    };
  } else if (isTreatedAsSentOffer) {
    return {
      buttonClass: 'bg-gray-300 bold text-white bold hover:bg-green-600 transition duration-200',
      buttonText: 'Edit'
    };
  } else {
    return {
      buttonClass: 'bg-blue-500 text-white hover:bg-green-600 transition duration-200',
      buttonText: 'Swap'
    };
  }
}

function createTimeColumn(offer, postedTime, expiresIn, clockColor) {
  return `
    <td class="py-3 pl-6 text-xs">
      <div class="flex items-center">
        <svg alt="" class="w-5 h-5 rounded-full mr-3" data-tooltip-target="tooltip-active${escapeHtml(offer.offer_id)}" xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 24 24">
          <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${escapeHtml(clockColor)}" stroke-linejoin="round">
            <circle cx="12" cy="12" r="11"></circle>
            <polyline points="12,6 12,12 18,12" stroke="${escapeHtml(clockColor)}"></polyline>
          </g>
        </svg>
        <div class="flex flex-col hidden xl:block">
          <div class="text-xs"><span class="bold">Posted:</span> ${escapeHtml(postedTime)}</div>
          <div class="text-xs"><span class="bold">Expires in:</span> ${escapeHtml(expiresIn)}</div>
        </div>
      </div>
    </td>
  `;
}

function createDetailsColumn(offer) {
  const addrFrom = offer.addr_from || '';
  const amountVariable = offer.amount_variable !== undefined ? offer.amount_variable : false;
  return `
    <td class="py-8 px-4 text-xs text-left hidden xl:block">
      <a data-tooltip-target="tooltip-recipient${escapeHtml(offer.offer_id)}" href="/identity/${escapeHtml(addrFrom)}">
        <span class="bold">Recipient:</span> ${escapeHtml(addrFrom.substring(0, 10))}...
      </a>
    </td>
  `;
}

function createTakerAmountColumn(offer, coinFrom, coinFromSymbol, coinTo) {
  return `
    <td class="py-0 px-4 text-left text-sm">
      <a data-tooltip-target="tooltip-wallet${offer.offer_id}" href="/wallet/${coinFromSymbol}" class="items-center monospace">
        <span class="coinname bold w-32" data-coinname="${coinFrom}">
          ${offer.amount_from.substring(0, 7)}
          <div class="text-gray-600 dark:text-gray-300 text-xs">${coinFrom}</div>
        </span>
      </a>
      <div class="ratetype hidden">
        <span class="exchange-rates" data-coinname="${coinFrom}">${offer.rate.substring(0, 6)} ${coinTo}/${coinFrom}</span>
        <div class="coinname-value hidden" data-coinname="${coinTo}">${offer.amount_to.substring(0, 100)}</div>
        <div class="usd-value hidden" data-o16="${coinTo}"></div>
        <div class="usd-value-in-coin-value"></div>
      </div>
    </td>
  `;
}

function createSwapColumn(offer, coinFrom, coinTo) {
  return `
    <td class="py-0 px-0 text-right text-sm">
      <a data-tooltip-target="tooltip-offer${offer.offer_id}" href="/offer/${offer.offer_id}">
        <div class="flex items-center justify-evenly monospace">
          <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
            <img class="h-12" src="/static/images/coins/${coinFrom.replace(" ", "-")}.png" alt="${coinFrom}">
          </span>
             <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg ">
             <path fill-rule="evenodd " d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z " clip-rule="evenodd"></path></svg>
          <span class="inline-flex ml-3 mr-3 align-middle items-center justify-center w-18 h-20 rounded">
            <img class="h-12" src="/static/images/coins/${coinTo.replace(" ", "-")}.png" alt="${coinTo}">
          </span>
        </div>
      </a>
    </td>
  `;
}

function createOrderbookColumn(offer, coinTo, coinToSymbol, coinFrom) {
  return `
    <td class="py-0 px-4 text-right text-sm">
      <a data-tooltip-target="tooltip-wallet-maker${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(coinToSymbol)}" class="items-center monospace">
        <span class="coinname bold w-32" data-coinname="${escapeHtml(coinTo)}">
          ${escapeHtml(offer.amount_to.substring(0, 7))}
          <div class="text-gray-600 dark:text-gray-300 text-xs">${escapeHtml(coinTo)}</div>
        </span>
      </a>
      <div class="ratetype italic hidden">
        <span class="exchange-rates" data-coinname="${escapeHtml(coinTo)}">${escapeHtml(offer.rate.substring(0, 6))} ${escapeHtml(coinFrom)}/${escapeHtml(coinTo)}</span>
        <div class="coinname-value hidden" data-coinname="${escapeHtml(coinFrom)}">${escapeHtml(offer.amount_from.substring(0, 7))}</div>
        <div class="usd-value hidden" data-o16="${escapeHtml(coinFrom)}"></div>
        <div class="usd-value-in-coin-value"></div>
      </div>
    </td>
  `;
}

function createRateColumn(offer, coinFrom, coinTo, formattedRate) {
  return `
    <td class="py-3 pl-6 bold monospace text-sm text-right items-center rate-table-info">
      <div class="relative" data-tooltip-target="tooltip-rate-${offer.offer_id}">
        <div class="profit-value text-sm font-bold" style="display:none">
          <span class="text-xs text-gray-500 dark:text-white" style="display:none">PROFIT:</span>
        </div>
        <div class="text-xs font-bold">
          <span class="text-xs text-gray-500 dark:text-white">RATE:</span>
          <span class="coinname-value" data-coinname="${coinFrom}">${formattedRate}</span>
        </div>
        <div class="text-xs">
          <span class="text-gray-500 dark:text-white" style="display:none">USD:</span>
          <span class="usd-value" style="display:none" data-o16="${coinTo}"></span>
        </div>
        <div class="ratetype text-xs text-gray-500 dark:text-white">
          <span class="exchange-rates" style="display:none" data-coinname="${coinTo}">
            ${formattedRate} ${coinFrom}/${coinTo}
          </span>
        </div>
        <div class="cached-rate hidden"></div>
      </div>
    </td>
  `;
}

function createPercentageColumn(offer) {
  return `
    <td class="py-3 px-2 bold text-sm text-center monospace items-center rate-table-info">
      <div class="relative" data-tooltip-target="percentage-tooltip-${offer.offer_id}">
        <div class="profittype">
          <span class="profit-loss text-lg font-bold"></span>
        </div>
        <div class="cached-market-percentage hidden"></div>
      </div>
    </td>
  `;
}

function createActionColumn(offer, buttonClass, buttonText) {
  return `
    <td class="py-6 px-2 text-center">
      <div class="flex justify-center items-center h-full">
        <a class="inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md ${buttonClass}"
           href="/offer/${offer.offer_id}">
          ${buttonText}
        </a>
      </div>
    </td>
  `;
}

function createTooltips(offer, isSentOffers, coinFrom, coinTo, postedTime, expiresIn, isActuallyExpired) {
  return `
    <div id="tooltip-active${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white ${isActuallyExpired ? 'bg-gray-400' : 'bg-green-600'} rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired">
        <span class="bold">
          <div class="${isActuallyExpired ? 'dark:text-white' : ''} text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
          <div class="${isActuallyExpired ? 'dark:text-white' : ''} text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
        </span>
      </div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-recipient${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold monospace">${offer.addr_from}</span></div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-wallet${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${isSentOffers ? 'My' : ''} ${coinFrom} Wallet</span></div>
      <div class="tooltip-arrow pl-1" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-offer${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white ${offer.is_own_offer ? 'bg-gray-300' : 'bg-green-700'} rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${offer.is_own_offer ? 'Edit Offer' : `Buy ${coinTo}`}</span></div>
      <div class="tooltip-arrow pr-6" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-wallet-maker${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${isSentOffers ? 'My' : ''} ${coinTo} Wallet</span></div>
      <div class="tooltip-arrow pl-1" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-rate-${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="tooltip-content">
        <p class="font-bold mb-1">Exchange Rate Explanation:</p>
        <p>This rate shows how much ${coinTo} you'll receive for each ${coinFrom} you exchange.</p>
        <p class="mt-1">Example: 1 ${coinFrom} = ${offer.rate.substring(0, 6)} ${coinTo}</p>
      </div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>

    <div id="percentage-tooltip-${offer.offer_id}" role="tooltip" class="inline-block absolute invisible z-10 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="tooltip-content">
        <p class="font-bold mb-1">Market Comparison:</p>
        <p>This percentage shows how this offer compares to the current market rate.</p>
        <p class="mt-1">Positive: Better than market rate</p>
        <p>Negative: Worse than market rate</p>
      </div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>
  `;
}

function updatePaginationInfo() {
    const currentTime = Math.floor(Date.now() / 1000);
    const validOffers = isSentOffers ? jsonData : jsonData.filter(offer => offer.expire_at > currentTime);
    const validItemCount = validOffers.length;
    const totalPages = Math.max(1, Math.ceil(validItemCount / itemsPerPage));
    
    currentPage = Math.max(1, Math.min(currentPage, totalPages));
    
    currentPageSpan.textContent = currentPage;
    totalPagesSpan.textContent = totalPages;
    
    prevPageButton.classList.toggle('invisible', currentPage === 1 || validItemCount === 0);
    nextPageButton.classList.toggle('invisible', currentPage === totalPages || validItemCount === 0 || validItemCount <= itemsPerPage);

    prevPageButton.style.display = currentPage === 1 ? 'none' : 'inline-flex';
    nextPageButton.style.display = currentPage === totalPages ? 'none' : 'inline-flex';

    if (lastRefreshTime) {
        lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
    }

    const newEntriesCountSpan = document.getElementById('newEntriesCount');
    if (newEntriesCountSpan) {
        newEntriesCountSpan.textContent = validItemCount;
    }

    console.log(`Pagination: Page ${currentPage} of ${totalPages}, Valid items: ${validItemCount}`);
}

function updateJsonView() {
  jsonContent.textContent = JSON.stringify(jsonData, null, 2);
}

function updateLastRefreshTime() {
  lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
}

function updateNextFullRefreshTime() {
    const nextFullRefreshTimeSpan = document.getElementById('nextFullRefreshTime');
    if (nextFullRefreshTimeSpan) {
        const minutes = Math.floor(Math.max(0, countdownToFullRefresh) / 60);
        const seconds = Math.max(0, countdownToFullRefresh) % 60;
        nextFullRefreshTimeSpan.textContent = `${minutes}m ${seconds}s`;
    }
}

function getTimeUntilNextExpiration() {
  const currentTime = Math.floor(Date.now() / 1000);
  const nextExpiration = jsonData.reduce((earliest, offer) => {
    const timeUntilExpiration = offer.expire_at - currentTime;
    return timeUntilExpiration > 0 && timeUntilExpiration < earliest ? timeUntilExpiration : earliest;
  }, Infinity);
  
  return nextExpiration === Infinity ? 600 : Math.min(nextExpiration, 600);
}

// Event listeners
toggleButton.addEventListener('click', () => {
  tableView.classList.toggle('hidden');
  jsonView.classList.toggle('hidden');
  toggleButton.textContent = tableView.classList.contains('hidden') ? 'Show Table View' : 'Show JSON View';
});

filterForm.addEventListener('submit', (e) => {
  e.preventDefault();
  applyFilters();
});

filterForm.addEventListener('change', applyFilters);

document.getElementById('coin_to').addEventListener('change', (event) => {
  console.log('Coin To filter changed:', event.target.value);
  applyFilters();
});

document.getElementById('coin_from').addEventListener('change', (event) => {
  console.log('Coin From filter changed:', event.target.value);
  applyFilters();
});

prevPageButton.addEventListener('click', () => {
  if (currentPage > 1) {
    currentPage--;
    updateOffersTable();
    updatePaginationInfo();
  }
});

nextPageButton.addEventListener('click', () => {
  const validOffers = isSentOffers ? jsonData : jsonData.filter(offer => !isOfferExpired(offer));
  const totalPages = Math.ceil(validOffers.length / itemsPerPage);
  if (currentPage < totalPages) {
    currentPage++;
    updateOffersTable();
    updatePaginationInfo();
  }
  console.log(`Moved to page ${currentPage} of ${totalPages}`);
});

document.getElementById('clearFilters').addEventListener('click', () => {
  filterForm.reset();
  jsonData = [...originalJsonData];
  currentPage = 1;
  updateOffersTable();
  updateJsonView();
  updateCoinFilterImages();
});

document.getElementById('refreshOffers').addEventListener('click', () => {
  console.log('Refresh button clicked');
  fetchOffers(true);
});

function updateCoinFilterImages() {
  const coinToSelect = document.getElementById('coin_to');
  const coinFromSelect = document.getElementById('coin_from');
  const coinToButton = document.getElementById('coin_to_button');
  const coinFromButton = document.getElementById('coin_from_button');

  function updateButtonImage(select, button) {
    const selectedOption = select.options[select.selectedIndex];
    const imagePath = selectedOption.getAttribute('data-image');
    if (imagePath && select.value !== 'any') {
      button.style.backgroundImage = `url(${imagePath})`;
      button.style.backgroundSize = 'contain';
      button.style.backgroundRepeat = 'no-repeat';
      button.style.backgroundPosition = 'center';
    } else {
      button.style.backgroundImage = 'none';
    }
  }

  updateButtonImage(coinToSelect, coinToButton);
  updateButtonImage(coinFromSelect, coinFromButton);
}

function startRefreshCountdown() {
    console.log('Starting refresh countdown');

    setInterval(() => {
        nextRefreshCountdown--;
        countdownToFullRefresh--;

        if (nextRefreshCountdown <= 0) {
            checkExpiredAndFetchNew();
            nextRefreshCountdown = getTimeUntilNextExpiration();
        }

        if (countdownToFullRefresh <= 0) {
            performFullRefresh();
            countdownToFullRefresh = 900;
        }

        updateNextRefreshTime();
        updateNextFullRefreshTime();
    }, 1000);
}

function initializeTableRateModule() {
  if (typeof window.tableRateModule !== 'undefined') {
    tableRateModule = window.tableRateModule;
    console.log('tableRateModule loaded successfully');
    return true;
  } else {
    console.warn('tableRateModule not found. Waiting for it to load...');
    return false;
  }
}

// Init
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM content loaded, initializing...');
  
  if (initializeTableRateModule()) {
    continueInitialization();
  } else {
    let retryCount = 0;
    const maxRetries = 5;
    const retryInterval = setInterval(() => {
      retryCount++;
      if (initializeTableRateModule()) {
        clearInterval(retryInterval);
        continueInitialization();
      } else if (retryCount >= maxRetries) {
        console.error('Failed to load tableRateModule after multiple attempts. Some functionality may be limited.');
        clearInterval(retryInterval);
        continueInitialization();
      }
    }, 1000);
  }
});

function continueInitialization() {
    if (typeof volumeToggle !== 'undefined' && volumeToggle.init) {
        volumeToggle.init();
    } else {
        console.warn('volumeToggle is not defined or does not have an init method');
    }
    updateOffersTable();
    updateJsonView();
    updateCoinFilterImages();
    fetchOffers();
    startRefreshCountdown();
    initializeTableWithCache();
    updateNextFullRefreshTime();
    
    jsonData.forEach(offer => offerCache.set(offer.offer_id, offer));
    
    function updateTimesLoop() {
        updateRowTimes();
        requestAnimationFrame(updateTimesLoop);
    }
    requestAnimationFrame(updateTimesLoop);
    
    setInterval(updateRowTimes, 900000);
    
    setInterval(performFullRefresh, 30 * 60 * 1000);
}

console.log('Offers Table Module fully initialized');
