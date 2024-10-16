// Config

const coinNameToSymbol = {
  'Bitcoin': 'bitcoin',
  'Particl': 'particl',
  'Particl Blind': 'particl',
  'Particl Anon': 'particl',
  'Monero': 'monero',
  'Wownero': 'wownero',
  'Litecoin': 'litecoin',
  'Firo': 'firo',
  'Zcoin': 'firo',
  'Dash': 'dash',
  'PIVX': 'pivx',
  'Decred': 'decred',
  'Zano': 'zano',
  'Dogecoin': 'dogecoin',
};

function makePostRequest(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/json/readurl');
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.timeout = 30000;
    xhr.ontimeout = () => reject(new Error('Request timed out'));
    xhr.onload = () => {
      console.log(`Response for ${url}:`, xhr.responseText);
      if (xhr.status === 200) {
        try {
          const response = JSON.parse(xhr.responseText);
          if (response.Error) {
            console.error(`API Error for ${url}:`, response.Error);
            reject(new Error(response.Error));
          } else {
            resolve(response);
          }
        } catch (error) {
          console.error(`Invalid JSON response for ${url}:`, xhr.responseText);
          reject(new Error(`Invalid JSON response: ${error.message}`));
        }
      } else {
        console.error(`HTTP Error for ${url}: ${xhr.status} ${xhr.statusText}`);
        reject(new Error(`HTTP Error: ${xhr.status} ${xhr.statusText}`));
      }
    };
    xhr.onerror = () => reject(new Error('Network error occurred'));
    xhr.send(JSON.stringify({
      url: url,
      headers: headers
    }));
  });
}

const symbolToCoinName = {
  ...Object.fromEntries(Object.entries(coinNameToSymbol).map(([key, value]) => [value, key])),
  'zcoin': 'Firo',
  'firo': 'Firo'
};

function getDisplayName(coinName) {
  return coinNameToDisplayName[coinName] || coinName;
}

const coinNameToDisplayName = {
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
  'Dogecoin': 'Dogecoin',
  'Zano': 'Zano'
};

let latestPrices = null;

const CACHE_KEY = 'latestPricesCache';
const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes in milliseconds

async function fetchLatestPrices() {
  console.log('Checking for cached prices...');
  const cachedData = getCachedPrices();
  
  if (cachedData) {
    console.log('Using cached price data');
    latestPrices = cachedData;
    return cachedData;
  }

  console.log('Fetching latest prices...');
  const url = 'https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,dash,dogecoin,decred,litecoin,particl,pivx,monero,zano,wownero,zcoin&vs_currencies=USD,BTC';
  
  try {
    const data = await makePostRequest(url);
    console.log('Fetched price data:', data);
    
    latestPrices = data;
    setCachedPrices(data);
    return data;
  } catch (error) {
    console.error('Error fetching price data:', error.message);
    return null;
  }
}

function getCachedPrices() {
  const cachedItem = localStorage.getItem(CACHE_KEY);
  if (cachedItem) {
    const { data, timestamp } = JSON.parse(cachedItem);
    if (Date.now() - timestamp < CACHE_DURATION) {
      return data;
    }
  }
  return null;
}

function setCachedPrices(data) {
  const cacheItem = {
    data: data,
    timestamp: Date.now()
  };
  localStorage.setItem(CACHE_KEY, JSON.stringify(cacheItem));
}

const getUsdValue = async (cryptoValue, coinSymbol) => {
  try {
    const prices = await fetchLatestPrices();
    const apiSymbol = coinNameToSymbol[coinSymbol] || coinSymbol.toLowerCase();
    const coinData = prices[apiSymbol];
    if (coinData && coinData.usd) {
      return cryptoValue * coinData.usd;
    } else {
      throw new Error(`Price data not available for ${coinSymbol}`);
    }
  } catch (error) {
    console.error(`Error getting USD value for ${coinSymbol}:`, error);
    throw error;
  }
};

// Global
let jsonData = [];
let originalJsonData = [];
let isInitialLoad = true;
let tableRateModule;

let lastRefreshTime = null;
let newEntriesCount = 0;

let nextRefreshCountdown = 60; // Default to 60 seconds
const MIN_REFRESH_INTERVAL = 30; // Minimum refresh interval in seconds

const isSentOffers = window.offersTableConfig.isSentOffers;

let currentPage = 1;
const itemsPerPage = 100;

const coinIdToName = {
  1: 'particl', 2: 'bitcoin', 3: 'litecoin', 4: 'decred',
  6: 'monero', 7: 'particl blind', 8: 'particl anon',
  9: 'wownero', 11: 'pivx', 13: 'firo'
};

// DOM
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
function getCoinSymbol(fullName) {
  const symbolMap = {
    'Bitcoin': 'BTC', 'Litecoin': 'LTC', 'Monero': 'XMR',
    'Particl': 'PART', 'Particl Blind': 'PART', 'Particl Anon': 'PART',
    'PIVX': 'PIVX', 'Firo': 'FIRO', 'Zcoin': 'FIRO',
    'Dash': 'DASH', 'Decred': 'DCR', 'Wownero': 'WOW',
    'Bitcoin Cash': 'BCH'
  };
  return symbolMap[fullName] || fullName;
}

function getDisplayName(coinName) {
  if (coinName.toLowerCase() === 'zcoin') {
    return 'Firo';
  }
  return coinNameToDisplayName[coinName] || coinName;
}

function getValidOffers() {
    if (isSentOffers) {
        return jsonData;
    } else {
        const currentTime = Math.floor(Date.now() / 1000);
        return jsonData.filter(offer => offer.expire_at > currentTime);
    }
}

function removeExpiredOffers() {
    if (isSentOffers) {
        return false;
    }
    const currentTime = Math.floor(Date.now() / 1000);
    const initialLength = jsonData.length;
    jsonData = jsonData.filter(offer => offer.expire_at > currentTime);
    
    if (jsonData.length < initialLength) {
        console.log(`Removed ${initialLength - jsonData.length} expired offers`);
        return true;
    }
    return false;
}

function handleNoOffersScenario() {
    offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">No active offers available. Refreshing data...</td></tr>';
    fetchOffers(true);
}

function logOfferStatus() {
    const validOffers = getValidOffers();
    console.log(`Total offers: ${jsonData.length}, Valid offers: ${validOffers.length}, Current page: ${currentPage}, Total pages: ${Math.ceil(validOffers.length / itemsPerPage)}`);
}

function isOfferExpired(offer) {
    if (isSentOffers) {
        return false;
    }
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
  refreshText.textContent = isLoading ? 'Refresh' : 'Refresh'; //to-do
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
  return `${formatTimeDifference(timestamp)} ago`;
}

function formatTimeLeft(timestamp) {
  const now = Math.floor(Date.now() / 1000);
  if (timestamp <= now) return "Expired";
  return formatTimeDifference(timestamp);
}

function getTimeUntilNextExpiration() {
    const currentTime = Math.floor(Date.now() / 1000);
    const nextExpiration = jsonData.reduce((earliest, offer) => {
        const timeUntilExpiration = offer.expire_at - currentTime;
        return timeUntilExpiration > 0 && timeUntilExpiration < earliest ? timeUntilExpiration : earliest;
    }, Infinity);
    
    return Math.max(MIN_REFRESH_INTERVAL, Math.min(nextExpiration, 300));
}

function getNoOffersMessage() {
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
    return message;
}

window.tableRateModule = {
  coinNameToSymbol: {
    'Bitcoin': 'BTC', 'Particl': 'PART', 'Particl Blind': 'PART',
    'Particl Anon': 'PART', 'Monero': 'XMR', 'Wownero': 'WOW',
    'Litecoin': 'LTC', 'Firo': 'FIRO', 'Dash': 'DASH',
    'PIVX': 'PIVX', 'Decred': 'DCR', 'Zano': 'ZANO',
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

  getFallbackValue(coinSymbol) {
    const value = localStorage.getItem(`fallback_${coinSymbol}_usd`);
    return value ? parseFloat(value) : null;
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
      coinNameValue.classList.remove('hidden');
      if (!coinNameValue.textContent.trim()) {
        coinNameValue.textContent = 'N/A';
      }
    });

    document.querySelectorAll('.usd-value').forEach(usdValue => {
      if (!usdValue.textContent.trim()) {
        usdValue.textContent = 'N/A';
      }
    });

    document.querySelectorAll('.profit-loss').forEach(profitLoss => {
      if (!profitLoss.textContent.trim() || profitLoss.textContent === 'Calculating...') {
        profitLoss.textContent = 'N/A';
      }
    });
  },

  init() {
    console.log('Initializing TableRateModule');
    this.initializeTable();
  }
};

function updateProfitLoss(row, fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
  const profitLossElement = row.querySelector('.profit-loss');
  if (!profitLossElement) {
    console.warn('Profit loss element not found in row');
    return;
  }

  calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer)
    .then(percentDiff => {
      if (percentDiff === null) {
        profitLossElement.textContent = 'N/A';
        profitLossElement.className = 'profit-loss text-lg font-bold text-gray-500';
        console.log(`Unable to calculate profit/loss for ${fromCoin} to ${toCoin}`);
        return;
      }

      const formattedPercentDiff = percentDiff.toFixed(2);
      const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" : 
                                 (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

      const colorClass = getProfitColorClass(percentDiff);
      profitLossElement.textContent = `${percentDiffDisplay}%`;
      profitLossElement.className = `profit-loss text-lg font-bold ${colorClass}`;
      
      const tooltipId = `percentage-tooltip-${row.getAttribute('data-offer-id')}`;
      const tooltipElement = document.getElementById(tooltipId);
      if (tooltipElement) {
        const tooltipContent = createTooltipContent(isOwnOffer, fromCoin, toCoin, fromAmount, toAmount);
        tooltipElement.innerHTML = `
          <div class="tooltip-content">
            ${tooltipContent}
          </div>
          <div class="tooltip-arrow" data-popper-arrow></div>
        `;
      }

      console.log(`Updated profit/loss display: ${profitLossElement.textContent}, isOwnOffer: ${isOwnOffer}`);
    })
    .catch(error => {
      console.error('Error in updateProfitLoss:', error);
      profitLossElement.textContent = 'Error';
      profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
    });
}

function fetchOffers(manualRefresh = false) {
    return new Promise((resolve, reject) => {
        const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
        console.log(`Fetching offers from: ${endpoint}`);
        
        if (newEntriesCountSpan) {
            newEntriesCountSpan.textContent = 'Loading...';
        }
        
        if (manualRefresh) {
            offersBody.innerHTML = '<tr><td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">Refreshing offers...</td></tr>';
        }
        
        setRefreshButtonLoading(true);
        
        const requestBody = {
            with_extra_info: true
        };
        
        fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        })
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
                    amount_negotiable: Boolean(offer.amount_negotiable),
                    unique_id: `${offer.offer_id}_${offer.created_at}_${offer.coin_from}_${offer.coin_to}`
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
                
                if (!isSentOffers) {
                    removeExpiredOffers();
                }
                
                const validOffers = getValidOffers();
                const validItemCount = validOffers.length;
                if (newEntriesCountSpan) {
                    newEntriesCountSpan.textContent = validItemCount;
                }
                console.log('Valid offers count:', validItemCount);
                
                lastRefreshTime = Date.now();
                nextRefreshCountdown = getTimeUntilNextExpiration();
                updateLastRefreshTime();
                updateNextRefreshTime();
                
                updateOffersTable();
                updateJsonView();
                updatePaginationInfo();
                
                if (validItemCount === 0) {
                    handleNoOffersScenario();
                }
                
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
    jsonData = filterAndSortData();
    updateOffersTable();
    updateJsonView();
    updatePaginationInfo();
    console.log('Filters applied, table updated');
}

function filterAndSortData() {
    console.log('Filtering and sorting data');
    
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    console.log('Processed filters:', filters);

    if (filters.coin_to !== 'any') {
        filters.coin_to = coinIdToName[filters.coin_to] || filters.coin_to;
    }
    if (filters.coin_from !== 'any') {
        filters.coin_from = coinIdToName[filters.coin_from] || filters.coin_from;
    }

    console.log('Processed filters:', filters);

    const currentTime = Math.floor(Date.now() / 1000);

    const uniqueOffersMap = new Map();

    const isFiroOrZcoin = (coin) => ['firo', 'zcoin'].includes(coin.toLowerCase());
    const isParticlVariant = (coin) => ['particl', 'particl anon', 'particl blind'].includes(coin.toLowerCase());

    const coinMatches = (offerCoin, filterCoin) => {
        offerCoin = offerCoin.toLowerCase();
        filterCoin = filterCoin.toLowerCase();
        
        if (offerCoin === filterCoin) return true;
        if (isFiroOrZcoin(offerCoin) && isFiroOrZcoin(filterCoin)) return true;
        
        if (isParticlVariant(filterCoin)) {
            return offerCoin === filterCoin;
        }
        
        if (filterCoin === 'particl' && isParticlVariant(offerCoin)) return true;
        
        return false;
    };

    originalJsonData.forEach(offer => {
        const coinFrom = (offer.coin_from || '');
        const coinTo = (offer.coin_to || '');
        const isExpired = offer.expire_at <= currentTime;

        if (!isSentOffers && isExpired) {
            return;
        }

        let passesFilter = true;

        if (filters.coin_to !== 'any' && !coinMatches(coinTo, filters.coin_to)) {
            passesFilter = false;
        }
        if (filters.coin_from !== 'any' && !coinMatches(coinFrom, filters.coin_from)) {
            passesFilter = false;
        }

        if (isSentOffers && filters.active && filters.active !== 'any') {
            const offerState = isExpired ? 'expired' : 'active';
            if (filters.active !== offerState) {
                passesFilter = false;
            }
        }

        if (passesFilter) {
            uniqueOffersMap.set(offer.unique_id, offer);
        }
    });

    let filteredData = Array.from(uniqueOffersMap.values());

    console.log('Filtered data length:', filteredData.length);

    const sortBy = filters.sort_by || 'created_at';
    const sortDir = filters.sort_dir || 'desc';

    filteredData.sort((a, b) => {
        let aValue, bValue;

        switch (sortBy) {
            case 'created_at':
                aValue = a.created_at;
                bValue = b.created_at;
                break;
            case 'rate':
                aValue = parseFloat(a.rate);
                bValue = parseFloat(b.rate);
                break;
            default:
                aValue = a.created_at;
                bValue = b.created_at;
        }

        if (sortDir === 'asc') {
            return aValue - bValue;
        } else {
            return bValue - aValue;
        }
    });

    console.log(`Sorted offers by ${sortBy} in ${sortDir} order`);

    return filteredData;
}

function updateProfitLoss(row, fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
  const profitLossElement = row.querySelector('.profit-loss');
  if (!profitLossElement) {
    console.warn('Profit loss element not found in row');
    return;
  }

  calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer)
    .then(percentDiff => {
      if (percentDiff === null) {
        profitLossElement.textContent = 'N/A';
        profitLossElement.className = 'profit-loss text-lg font-bold text-gray-500';
        console.log(`Unable to calculate profit/loss for ${fromCoin} to ${toCoin}`);
        return;
      }

      // Format the percentage to two decimal places
      const formattedPercentDiff = percentDiff.toFixed(2);
      const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" : 
                                 (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

      const colorClass = getProfitColorClass(percentDiff);
      profitLossElement.textContent = `${percentDiffDisplay}%`;
      profitLossElement.className = `profit-loss text-lg font-bold ${colorClass}`;
      
      const tooltipId = `percentage-tooltip-${row.getAttribute('data-offer-id')}`;
      const tooltipElement = document.getElementById(tooltipId);
      if (tooltipElement) {
        const tooltipContent = createTooltipContent(isOwnOffer, fromCoin, toCoin, fromAmount, toAmount);
        tooltipElement.innerHTML = `
          <div class="tooltip-content">
            ${tooltipContent}
          </div>
          <div class="tooltip-arrow" data-popper-arrow></div>
        `;
      }

      console.log(`Updated profit/loss display: ${profitLossElement.textContent}, isOwnOffer: ${isOwnOffer}`);
    })
    .catch(error => {
      console.error('Error in updateProfitLoss:', error);
      profitLossElement.textContent = 'Error';
      profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
    });
}

function createTableRow(offer, isSentOffers) {
  const row = document.createElement('tr');
  const uniqueId = `${offer.offer_id}_${offer.created_at}`;
  row.className = `opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600`;
  row.setAttribute('data-offer-id', uniqueId);

  const coinFrom = offer.coin_from;
  const coinTo = offer.coin_to;
  const coinFromSymbol = coinNameToSymbol[coinFrom] || coinFrom.toLowerCase();
  const coinToSymbol = coinNameToSymbol[coinTo] || coinTo.toLowerCase();
  const coinFromDisplay = getDisplayName(coinFrom);
  const coinToDisplay = getDisplayName(coinTo);

  const postedTime = formatTimeAgo(offer.created_at);
  const expiresIn = formatTimeLeft(offer.expire_at);
  
  const currentTime = Math.floor(Date.now() / 1000);
  const isActuallyExpired = currentTime > offer.expire_at;

  const isOwnOffer = offer.is_own_offer;

  const { buttonClass, buttonText } = getButtonProperties(isActuallyExpired, isSentOffers, isOwnOffer);

  const fromAmount = parseFloat(offer.amount_from) || 0;
  const toAmount = parseFloat(offer.amount_to) || 0;

  row.innerHTML = `
    ${createTimeColumn(offer, postedTime, expiresIn)}
    ${createDetailsColumn(offer)}
    ${createTakerAmountColumn(offer, coinTo, coinFrom)}
    ${createSwapColumn(offer, coinFromDisplay, coinToDisplay, coinFromSymbol, coinToSymbol)}
    ${createOrderbookColumn(offer, coinFrom, coinTo)}
    ${createRateColumn(offer, coinFrom, coinTo)}
    ${createPercentageColumn(offer)}
    ${createActionColumn(offer, buttonClass, buttonText)}
    ${createTooltips(offer, isOwnOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired)}
  `;

  updateTooltipTargets(row, uniqueId);

  updateProfitLoss(row, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer);

  return row;
}

function prepareOfferData(offer, isSentOffers) {
  const coinFrom = offer.coin_from;
  const coinTo = offer.coin_to;
  
  const postedTime = formatTimeAgo(offer.created_at);
  const expiresIn = formatTimeLeft(offer.expire_at);
  
  const currentTime = Math.floor(Date.now() / 1000);
  const isActuallyExpired = currentTime > offer.expire_at;

  const { buttonClass, buttonText } = getButtonProperties(isActuallyExpired, isSentOffers, offer.is_own_offer);
  
  const clockColor = isActuallyExpired ? "#9CA3AF" : "#3B82F6";

  return {
    coinFrom, coinTo,
    postedTime, expiresIn, isActuallyExpired,
    buttonClass, buttonText, clockColor
  };
}

// to-do revoked
function getButtonProperties(isActuallyExpired, isSentOffers, isTreatedAsSentOffer, isRevoked) {
  if (isRevoked) {
    return {
      buttonClass: 'bg-red-500 text-white hover:bg-red-600 transition duration-200',
      buttonText: 'Revoked'
    };
  } else if (isActuallyExpired && isSentOffers) {
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

async function updateOffersTable() {
    console.log('Starting updateOffersTable function');
    console.log(`Is Sent Offers page: ${isSentOffers}`);
    
    try {
        const priceData = await fetchLatestPrices();
        if (!priceData) {
            console.error('Failed to fetch latest prices. Using last known prices or proceeding without price data.');
        } else {
            console.log('Latest prices fetched successfully');
            latestPrices = priceData;
        }

        let validOffers = getValidOffers();
        console.log(`Valid offers: ${validOffers.length}`);

        if (validOffers.length === 0) {
            console.log('No valid offers found. Handling no offers scenario.');
            handleNoOffersScenario();
            return;
        }

        const totalPages = Math.max(1, Math.ceil(validOffers.length / itemsPerPage));
        currentPage = Math.min(currentPage, totalPages);

        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = startIndex + itemsPerPage;
        const itemsToDisplay = validOffers.slice(startIndex, endIndex);
        
        console.log(`Displaying offers ${startIndex + 1} to ${endIndex} of ${validOffers.length}`);
        
        offersBody.innerHTML = '';
        
        for (const offer of itemsToDisplay) {
            const row = createTableRow(offer, isSentOffers);
            if (row) {
                offersBody.appendChild(row);
                try {
                    const fromAmount = parseFloat(offer.amount_from);
                    const toAmount = parseFloat(offer.amount_to);
                    await updateProfitLoss(row, offer.coin_from, offer.coin_to, fromAmount, toAmount, offer.is_own_offer);
                } catch (error) {
                    console.error(`Error updating profit/loss for offer ${offer.offer_id}:`, error);
                }
            }
        }
        
        updateRowTimes();
        initializeFlowbiteTooltips();
        updatePaginationInfo();
        
        if (tableRateModule && typeof tableRateModule.initializeTable === 'function') {
            tableRateModule.initializeTable();
        }
        
        logOfferStatus();

        lastRefreshTime = Date.now();
        nextRefreshCountdown = getTimeUntilNextExpiration();
        updateLastRefreshTime();
        updateNextRefreshTime();

        if (newEntriesCountSpan) {
            newEntriesCountSpan.textContent = validOffers.length;
        }

    } catch (error) {
        console.error('Error updating offers table:', error);
        offersBody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-red-500">An error occurred while updating the offers table. Please try again later.</td></tr>`;
    } finally {
        setRefreshButtonLoading(false);
    }
}

function updateProfitLoss(row, fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
  const profitLossElement = row.querySelector('.profit-loss');
  if (!profitLossElement) {
    console.warn('Profit loss element not found in row');
    return;
  }

  if (!fromCoin || !toCoin) {
    console.error(`Invalid coin names: fromCoin=${fromCoin}, toCoin=${toCoin}`);
    profitLossElement.textContent = 'Error';
    profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
    return;
  }

  calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer)
    .then(percentDiff => {
      if (percentDiff === null) {
        profitLossElement.textContent = 'N/A';
        profitLossElement.className = 'profit-loss text-lg font-bold text-gray-500';
        console.log(`Unable to calculate profit/loss for ${fromCoin} to ${toCoin}`);
        return;
      }

      // Format the percentage to two decimal places
      const formattedPercentDiff = percentDiff.toFixed(2);
      const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" : 
                                 (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

      const colorClass = getProfitColorClass(percentDiff);
      profitLossElement.textContent = `${percentDiffDisplay}%`;
      profitLossElement.className = `profit-loss text-lg font-bold ${colorClass}`;
      
      const tooltipId = `percentage-tooltip-${row.getAttribute('data-offer-id')}`;
      const tooltipElement = document.getElementById(tooltipId);
      if (tooltipElement) {
        const tooltipContent = createTooltipContent(isSentOffers || isOwnOffer, fromCoin, toCoin, fromAmount, toAmount);
        tooltipElement.innerHTML = `
          <div class="tooltip-content">
            ${tooltipContent}
          </div>
          <div class="tooltip-arrow" data-popper-arrow></div>
        `;
      }

      console.log(`Updated profit/loss display: ${profitLossElement.textContent}, isSentOffers: ${isSentOffers}, isOwnOffer: ${isOwnOffer}`);
    })
    .catch(error => {
      console.error('Error in updateProfitLoss:', error);
      profitLossElement.textContent = 'Error';
      profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
    });
}

async function calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
  console.log(`Calculating profit/loss for ${fromAmount} ${fromCoin} to ${toAmount} ${toCoin}, isOwnOffer: ${isOwnOffer}`);

  if (!latestPrices) {
    console.error('Latest prices not available. Unable to calculate profit/loss.');
    return null;
  }

  const getPriceKey = (coin) => {
    const lowerCoin = coin.toLowerCase();
    if (lowerCoin === 'firo' || lowerCoin === 'zcoin') {
      return 'zcoin';
    }
    return coinNameToSymbol[coin] || lowerCoin;
  };

  const fromSymbol = getPriceKey(fromCoin);
  const toSymbol = getPriceKey(toCoin);

  const fromPriceUSD = latestPrices[fromSymbol]?.usd;
  const toPriceUSD = latestPrices[toSymbol]?.usd;

  if (!fromPriceUSD || !toPriceUSD) {
    console.error(`Price data missing for ${fromSymbol} or ${toSymbol}`);
    return null;
  }

  const fromValueUSD = fromAmount * fromPriceUSD;
  const toValueUSD = toAmount * toPriceUSD;

  let percentDiff;
  if (isOwnOffer) {
    // For sent offers or own offers, always calculate as if selling
    percentDiff = ((toValueUSD / fromValueUSD) - 1) * 100;
  } else {
    // For received offers, calculate savings percentage
    percentDiff = ((fromValueUSD / toValueUSD) - 1) * 100;
  }

  console.log(`Percent difference: ${percentDiff.toFixed(2)}%`);

  return percentDiff;
}
function getProfitColorClass(percentage) {
  const numericPercentage = parseFloat(percentage);
  if (numericPercentage > 0) return 'text-green-500';
  if (numericPercentage < 0) return 'text-red-500';
  if (numericPercentage === 0) return 'text-yellow-400';
  return 'text-white';
}

function getMarketRate(fromCoin, toCoin) {
    return new Promise((resolve) => {
        console.log(`Attempting to get market rate for ${fromCoin} to ${toCoin}`);
        if (!latestPrices) {
            console.warn('Latest prices object is not available');
            resolve(null);
            return;
        }

        const getPriceKey = (coin) => {
            const lowerCoin = coin.toLowerCase();
            if (lowerCoin === 'firo' || lowerCoin === 'zcoin') {
                return 'zcoin';
            }
            return coinNameToSymbol[coin] || lowerCoin;
        };

        const fromSymbol = getPriceKey(fromCoin);
        const toSymbol = getPriceKey(toCoin);

        const fromPrice = latestPrices[fromSymbol]?.usd;
        const toPrice = latestPrices[toSymbol]?.usd;
        if (!fromPrice || !toPrice) {
            console.warn(`Missing price data for ${!fromPrice ? fromCoin : toCoin}`);
            resolve(null);
            return;
        }
        const rate = toPrice / fromPrice;
        console.log(`Market rate calculated: ${rate} ${toCoin}/${fromCoin}`);
        resolve(rate);
    });
}

function getTimerColor(offer) {
  const now = Math.floor(Date.now() / 1000);
  const timeLeft = offer.expire_at - now;

  if (timeLeft <= 300) { // 5 minutes or less
    return "#9CA3AF"; // Grey
  } else if (timeLeft <= 1800) { // 5-30 minutes
    return "#3B82F6"; // Blue
  } else { // More than 30 minutes
    return "#10B981"; // Green/Turquoise
  }
}

function createTimeColumn(offer, postedTime, expiresIn) {
  const timerColor = getTimerColor(offer);
  
  return `
    <td class="py-3 pl-6 text-xs">
      <div class="flex items-center">
        <div class="relative" data-tooltip-target="tooltip-active${escapeHtml(offer.offer_id)}">
          <svg alt="" class="w-5 h-5 rounded-full mr-3 cursor-pointer" xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 24 24">
            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${escapeHtml(timerColor)}" stroke-linejoin="round">
              <circle cx="12" cy="12" r="11"></circle>
              <polyline points="12,6 12,12 18,12" stroke="${escapeHtml(timerColor)}"></polyline>
            </g>
          </svg>
        </div>
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
  return `
    <td class="py-8 px-4 text-xs text-left hidden xl:block">
      <a data-tooltip-target="tooltip-recipient${escapeHtml(offer.offer_id)}" href="/identity/${escapeHtml(addrFrom)}">
        <span class="bold">Recipient:</span> ${escapeHtml(addrFrom.substring(0, 10))}...
      </a>

    </td>
  `;
}

function createSwapColumn(offer, coinFromDisplay, coinToDisplay, coinFromSymbol, coinToSymbol) {
  const getImageFilename = (symbol, displayName) => {
    if (displayName.toLowerCase() === 'zcoin' || displayName.toLowerCase() === 'firo') {
      return 'Firo.png';
    }
    return `${displayName.replace(' ', '-')}.png`;
  };

  return `
    <td class="py-0 px-0 text-right text-sm">
      <a data-tooltip-target="tooltip-offer${offer.offer_id}" href="/offer/${offer.offer_id}">
        <div class="flex items-center justify-evenly monospace">
          <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
            <img class="h-12" src="/static/images/coins/${getImageFilename(coinToSymbol, coinToDisplay)}" alt="${coinToDisplay}">
          </span>
          <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
            <path fill-rule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clip-rule="evenodd"></path>
          </svg>
          <span class="inline-flex ml-3 mr-3 align-middle items-center justify-center w-18 h-20 rounded">
            <img class="h-12" src="/static/images/coins/${getImageFilename(coinFromSymbol, coinFromDisplay)}" alt="${coinFromDisplay}">
          </span>
        </div>
      </a>
    </td>
  `;
}

function createTakerAmountColumn(offer, coinFrom, coinTo) {
  const fromAmount = parseFloat(offer.amount_to);
  const fromSymbol = getCoinSymbol(coinFrom);
  return `
    <td class="py-0">
      <div class="py-3 px-4 text-left">
        <a data-tooltip-target="tooltip-wallet${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(fromSymbol)}" class="items-center monospace">
          <div class="pr-2">        
            <div class="text-sm font-semibold">${fromAmount.toFixed(4)}</div>          
            <div class="text-sm text-gray-500 dark:text-gray-400">${coinFrom}</div>
          </div>
        </a>
      </div>
    </td>
  `;
}

function createOrderbookColumn(offer, coinTo, coinFrom) {
  const toAmount = parseFloat(offer.amount_from);
  const toSymbol = getCoinSymbol(coinTo);
  return `
    <td class="p-0">
      <div class="py-3 px-4 text-right">
        <a data-tooltip-target="tooltip-wallet-maker${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(toSymbol)}" class="items-center monospace">
          <div class="pr-2">        
            <div class="text-sm font-semibold">${toAmount.toFixed(4)}</div>           
            <div class="text-sm text-gray-500 dark:text-gray-400">${coinTo}</div>
          </div>
        </a>
      </div>
    </td>
  `;
}

function calculateInverseRate(rate) {
    return (1 / parseFloat(rate)).toFixed(8);
}

function createRateColumn(offer, coinFrom, coinTo) {
  const rate = parseFloat(offer.rate);
  const inverseRate = 1 / rate;
  const fromSymbol = getCoinSymbol(coinFrom);
  const toSymbol = getCoinSymbol(coinTo);
  
  const getPriceKey = (coin) => {
    const lowerCoin = coin.toLowerCase();
    return lowerCoin === 'firo' || lowerCoin === 'zcoin' ? 'zcoin' : coinNameToSymbol[coin] || lowerCoin;
  };

  const fromPriceUSD = latestPrices[getPriceKey(coinFrom)]?.usd || 0;
  const toPriceUSD = latestPrices[getPriceKey(coinTo)]?.usd || 0;

  const rateInUSD = rate * toPriceUSD;

  console.log(`Rate calculation for ${fromSymbol} to ${toSymbol}:`);
  console.log(`Rate: ${rate} ${toSymbol}/${fromSymbol}`);
  console.log(`Inverse Rate: ${inverseRate} ${fromSymbol}/${toSymbol}`);
  console.log(`${fromSymbol} price: $${fromPriceUSD}`);
  console.log(`${toSymbol} price: $${toPriceUSD}`);
  console.log(`Rate in USD: $${rateInUSD.toFixed(2)}`);

  return `
    <td class="py-3 semibold monospace text-xs text-right items-center rate-table-info">
      <div class="relative">
        <div class="flex flex-col items-end pr-3" data-tooltip-target="tooltip-rate-${offer.offer_id}">
          <span class="text-sm bold text-gray-700 dark:text-white">
            $${rateInUSD.toFixed(2)} USD
          </span>
          <span class="bold text-gray-700 dark:text-white">
            ${rate.toFixed(8)} ${toSymbol}/${fromSymbol}
          </span>
          <span class="semibold text-gray-400 dark:text-gray-300">
            ${inverseRate.toFixed(8)} ${fromSymbol}/${toSymbol}
          </span>
        </div>
      </div>
    </td>
  `;
}

function createPercentageColumn(offer) {
  return `
    <td class="py-3 px-2 bold text-sm text-center monospace items-center rate-table-info">
      <div class="relative" data-tooltip-target="percentage-tooltip-${offer.offer_id}">
        <div class="profittype">
          <span class="profit-loss text-lg font-bold" data-offer-id="${offer.offer_id}">
            Calculating...
          </span>
        </div>
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

function createTooltips(offer, treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired) {
  const rate = parseFloat(offer.rate);
  const fromSymbol = getCoinSymbolLowercase(coinFrom);
  const toSymbol = getCoinSymbolLowercase(coinTo);
  
  const fromPriceUSD = latestPrices[fromSymbol]?.usd || 0;
  const toPriceUSD = latestPrices[toSymbol]?.usd || 0;
  const rateInUSD = rate * toPriceUSD;

  const combinedRateTooltip = createCombinedRateTooltip(offer, coinFrom, coinTo, treatAsSentOffer);

  const percentageTooltipContent = createTooltipContent(treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount);

  const uniqueId = `${offer.offer_id}_${offer.created_at}`;

  return `
<div id="tooltip-active-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
  <div class="active-revoked-expired">
    <span class="bold">
      <div class="text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
      <div class="text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
    </span>
  </div>
  <div class="mt-5 text-xs">
    <p class="font-bold mb-3">Time Indicator Colors:</p>
    <p class="flex items-center">
      <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#10B981" stroke-linejoin="round">
          <circle cx="12" cy="12" r="11"></circle>
          <polyline points="12,6 12,12 18,12" stroke="#10B981"></polyline>
        </g>
      </svg>
      Green: More than 30 minutes left
    </p>
    <p class="flex items-center mt-3 ">
      <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#3B82F6" stroke-linejoin="round">
          <circle cx="12" cy="12" r="11"></circle>
          <polyline points="12,6 12,12 18,12" stroke="#3B82F6"></polyline>
        </g>
      </svg>
      Blue: Between 5 and 30 minutes left
    </p>
    <p class="flex items-center mt-3 mb-3">
      <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#9CA3AF" stroke-linejoin="round">
          <circle cx="12" cy="12" r="11"></circle>
          <polyline points="12,6 12,12 18,12" stroke="#9CA3AF"></polyline>
        </g>
      </svg>
      Grey: Less than 5 minutes left or expired
    </p>
  </div>
  <div class="tooltip-arrow" data-popper-arrow></div>
</div>
    
    <div id="tooltip-recipient-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold monospace">${offer.addr_from}</span></div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>
   
    <div id="tooltip-wallet-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${isSentOffers ? 'My' : ''} ${coinTo} Wallet</span></div>
      <div class="tooltip-arrow pl-1" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-offer-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white ${offer.is_own_offer ? 'bg-gray-300' : 'bg-green-700'} rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${offer.is_own_offer ? 'Edit Offer' : `Buy ${coinFrom}`}</span></div>
      <div class="tooltip-arrow pr-6" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-wallet-maker-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="active-revoked-expired"><span class="bold">${isSentOffers ? 'My' : ''} ${coinFrom} Wallet</span></div>
      <div class="tooltip-arrow pl-1" data-popper-arrow></div>
    </div>
    
    <div id="tooltip-rate-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="tooltip-content">
        ${combinedRateTooltip}
      </div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>

    <div id="percentage-tooltip-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
      <div class="tooltip-content">
        ${percentageTooltipContent}
      </div>
      <div class="tooltip-arrow" data-popper-arrow></div>
    </div>
  `;
}

function updateTooltipTargets(row, uniqueId) {
  row.querySelector('[data-tooltip-target^="tooltip-active"]').setAttribute('data-tooltip-target', `tooltip-active-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="tooltip-recipient"]').setAttribute('data-tooltip-target', `tooltip-recipient-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="tooltip-wallet"]').setAttribute('data-tooltip-target', `tooltip-wallet-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="tooltip-offer"]').setAttribute('data-tooltip-target', `tooltip-offer-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="tooltip-wallet-maker"]').setAttribute('data-tooltip-target', `tooltip-wallet-maker-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="tooltip-rate"]').setAttribute('data-tooltip-target', `tooltip-rate-${uniqueId}`);
  row.querySelector('[data-tooltip-target^="percentage-tooltip"]').setAttribute('data-tooltip-target', `percentage-tooltip-${uniqueId}`);
}

function getCoinSymbolLowercase(coin) {
  if (typeof coin === 'string') {
    return (coinNameToSymbol[coin] || coin).toLowerCase();
  } else if (coin && typeof coin === 'object' && coin.symbol) {
    return coin.symbol.toLowerCase();
  } else {
    console.warn('Invalid coin input:', coin);
    return 'unknown';
  }
}

function createTooltipContent(isSentOffers, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer) {
  if (!coinFrom || !coinTo) {
    console.error(`Invalid coin names: coinFrom=${coinFrom}, coinTo=${coinTo}`);
    return `<p class="font-bold mb-1">Unable to calculate profit/loss</p>
            <p>Invalid coin data.</p>`;
  }

  fromAmount = parseFloat(fromAmount) || 0;
  toAmount = parseFloat(toAmount) || 0;

  const getPriceKey = (coin) => {
    const lowerCoin = coin.toLowerCase();
    return lowerCoin === 'firo' || lowerCoin === 'zcoin' ? 'zcoin' : coinNameToSymbol[coin] || lowerCoin;
  };

  const fromSymbol = getPriceKey(coinFrom);
  const toSymbol = getPriceKey(coinTo);
  const fromPriceUSD = latestPrices[fromSymbol]?.usd;
  const toPriceUSD = latestPrices[toSymbol]?.usd;

  if (!fromPriceUSD || !toPriceUSD) {
    return `<p class="font-bold mb-1">Unable to calculate profit/loss</p>
            <p>Price data is missing for one or both coins.</p>`;
  }

  const fromValueUSD = fromAmount * fromPriceUSD;
  const toValueUSD = toAmount * toPriceUSD;
  const profitUSD = toValueUSD - fromValueUSD;

  const marketRate = fromPriceUSD / toPriceUSD;
  const offerRate = toAmount / fromAmount;
  let percentDiff;
  
  if (isSentOffers || isOwnOffer) {
    percentDiff = ((toValueUSD / fromValueUSD) - 1) * 100;
  } else {
    percentDiff = ((fromValueUSD / toValueUSD) - 1) * 100;
  }

  const formattedPercentDiff = percentDiff.toFixed(2);
  const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" : 
                             (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

  const profitLabel = (isSentOffers || isOwnOffer) ? "Max Profit" : "Max Loss";
  const actionLabel = (isSentOffers || isOwnOffer) ? "selling" : "buying";
  const directionLabel = (isSentOffers || isOwnOffer) ? "receiving" : "paying";

  return `
    <p class="font-bold mb-1">Profit/Loss Calculation:</p>
    <p>You are ${actionLabel} ${fromAmount.toFixed(8)} ${coinFrom} ($${fromValueUSD.toFixed(2)} USD) <br/> and ${directionLabel} ${toAmount.toFixed(8)} ${coinTo} ($${toValueUSD.toFixed(2)} USD).</p>
    <p class="mt-1">Percentage difference: ${percentDiffDisplay}%</p>
    <p>${profitLabel}: ${profitUSD > 0 ? '' : '-'}$${profitUSD.toFixed(2)} USD</p>
    <p class="font-bold mt-2">Calculation:</p>
    <p>Percentage = ${(isSentOffers || isOwnOffer) ? 
      "((To Amount in USD / From Amount in USD) - 1) * 100" : 
      "((From Amount in USD / To Amount in USD) - 1) * 100"}</p>
    <p>USD ${profitLabel} = To Amount in USD - From Amount in USD</p>
    <p class="font-bold mt-1">Interpretation:</p>
    ${(isSentOffers || isOwnOffer) ? `
    <p><span class="text-green-500">Positive percentage:</span> You're selling above market rate (profitable)</p>
    <p><span class="text-red-500">Negative percentage:</span> You're selling below market rate (loss)</p>
    ` : `
    <p><span class="text-green-500">Positive percentage:</span> You're buying below market rate (savings)</p>
    <p><span class="text-red-500">Negative percentage:</span> You're buying above market rate (premium)</p>
    `}
    <p class="mt-1"><strong>Note:</strong> ${(isSentOffers || isOwnOffer) ? 
      "As a seller, a positive percentage means <br/> you're selling for more than the current market value." : 
      "As a buyer, a positive percentage indicates </br> potential savings compared to current market rates."}</p>
    <p class="mt-1"><strong>Market Rate:</strong> 1 ${coinFrom} = ${marketRate.toFixed(8)} ${coinTo}</p>
    <p><strong>Offer Rate:</strong> 1 ${coinFrom} = ${offerRate.toFixed(8)} ${coinTo}</p>
  `;
}

function createCombinedRateTooltip(offer, coinFrom, coinTo, isSentOffers, treatAsSentOffer) {
  const rate = parseFloat(offer.rate);
  const inverseRate = 1 / rate;
  
  const getPriceKey = (coin) => {
    const lowerCoin = coin.toLowerCase();
    return lowerCoin === 'firo' || lowerCoin === 'zcoin' ? 'zcoin' : getCoinSymbolLowercase(coin);
  };

  const fromSymbol = getPriceKey(coinFrom);
  const toSymbol = getPriceKey(coinTo);
  
  const fromPriceUSD = latestPrices[fromSymbol]?.usd || 0;
  const toPriceUSD = latestPrices[toSymbol]?.usd || 0;
  const rateInUSD = rate * toPriceUSD;

  const marketRate = fromPriceUSD / toPriceUSD;
  
  const percentDiff = ((rate - marketRate) / marketRate) * 100;
  const formattedPercentDiff = percentDiff.toFixed(2);
  const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" : 
                             (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);
  const aboveOrBelow = percentDiff > 0 ? "above" : percentDiff < 0 ? "below" : "at";

  const action = isSentOffers || treatAsSentOffer ? "selling" : "buying";

  return `
    <p class="font-bold mb-1">Exchange Rate Explanation:</p>
    <p>This offer is ${action} ${coinFrom} for ${coinTo} <br/>at a rate that is ${percentDiffDisplay}% ${aboveOrBelow} market price.</p>
    <p class="font-bold mt-1">Exchange Rates:</p>
    <p>1 ${coinFrom} = ${rate.toFixed(8)} ${coinTo}</p>
    <p>1 ${coinTo} = ${inverseRate.toFixed(8)} ${coinFrom}</p>
    <p class="font-bold mt-2">USD Equivalent:</p>
    <p>1 ${coinFrom} = $${rateInUSD.toFixed(2)} USD</p>
    <p class="font-bold mt-2">Current market prices:</p>
    <p>${coinFrom}: $${fromPriceUSD.toFixed(2)} USD</p>
    <p>${coinTo}: $${toPriceUSD.toFixed(2)} USD</p>
    <p class="mt-1">Market rate: 1 ${coinFrom} = ${marketRate.toFixed(8)} ${coinTo}</p>
  `;
}

function updatePaginationInfo() {
    const validOffers = getValidOffers();
    const validItemCount = validOffers.length;
    const totalPages = Math.max(1, Math.ceil(validItemCount / itemsPerPage));
    
    currentPage = Math.max(1, Math.min(currentPage, totalPages));
    
    currentPageSpan.textContent = currentPage;
    totalPagesSpan.textContent = totalPages;
    
    prevPageButton.classList.toggle('invisible', currentPage === 1 || validItemCount === 0);
    nextPageButton.classList.toggle('invisible', currentPage === totalPages || validItemCount === 0);

    prevPageButton.style.display = currentPage === 1 ? 'none' : 'inline-flex';
    nextPageButton.style.display = (currentPage === totalPages || validItemCount === 0) ? 'none' : 'inline-flex';

    if (lastRefreshTime) {
        lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
    }

    const newEntriesCountSpan = document.getElementById('newEntriesCount');
    if (newEntriesCountSpan) {
        newEntriesCountSpan.textContent = validItemCount;
    }

    logOfferStatus();
}

function updateJsonView() {
    jsonContent.textContent = JSON.stringify(jsonData, null, 2);
}

function updateLastRefreshTime() {
    lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
}

function updateNextRefreshTime() {
    if (isSentOffers) return;

    const nextRefreshTimeSpan = document.getElementById('nextRefreshTime');
    if (!nextRefreshTimeSpan) {
        console.warn('nextRefreshTime element not found');
        return;
    }
    
    const minutes = Math.floor(nextRefreshCountdown / 60);
    const seconds = nextRefreshCountdown % 60;
    
    nextRefreshTimeSpan.textContent = `${minutes}m ${seconds.toString().padStart(2, '0')}s`;
    // console.log(`Next refresh in: ${minutes}m ${seconds}s`);
}

function updateRowTimes() {
  const currentTime = Math.floor(Date.now() / 1000);
  const rows = document.querySelectorAll('[data-offer-id]');
  
  rows.forEach(row => {
    const offerId = row.getAttribute('data-offer-id');
    const offer = jsonData.find(o => o.offer_id === offerId);
    if (!offer) return;

    const timeColumn = row.querySelector('td:first-child');
    if (!timeColumn) return;

    const postedTime = formatTimeAgo(offer.created_at);
    const expiresIn = formatTimeLeft(offer.expire_at);
    const timerColor = getTimerColor(offer);

    const svg = timeColumn.querySelector('svg');
    if (svg) {
      svg.querySelector('g').setAttribute('stroke', timerColor);
      svg.querySelector('polyline').setAttribute('stroke', timerColor);
    }

    const textContainer = timeColumn.querySelector('.xl\\:block');
    if (textContainer) {
      const postedElement = textContainer.querySelector('.text-xs:first-child');
      const expiresElement = textContainer.querySelector('.text-xs:last-child');
      
      if (postedElement) postedElement.textContent = `Posted: ${postedTime}`;
      if (expiresElement) expiresElement.textContent = `Expires in: ${expiresIn}`;
    }

    const tooltipElement = document.getElementById(`tooltip-active${offerId}`);
    if (tooltipElement) {
      const tooltipContent = tooltipElement.querySelector('.active-revoked-expired');
      if (tooltipContent) {
        const postedElement = tooltipContent.querySelector('.text-xs:first-child');
        const expiresElement = tooltipContent.querySelector('.text-xs:last-child');
        
        if (postedElement) postedElement.textContent = `Posted: ${postedTime}`;
        if (expiresElement) expiresElement.textContent = `Expires in: ${expiresIn}`;
      }
    }
  });
}

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

function updateCoinFilterOptions() {
  const coinToSelect = document.getElementById('coin_to');
  const coinFromSelect = document.getElementById('coin_from');
  
  const updateOptions = (select) => {
    const options = select.options;
    for (let i = 0; i < options.length; i++) {
      const option = options[i];
      if (option.value !== 'any') {
        const displayName = symbolToCoinName[option.value] || option.value;
        option.textContent = displayName;
      }
    }
  };

  updateOptions(coinToSelect);
  updateOptions(coinFromSelect);
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

function startRefreshCountdown() {
    if (isSentOffers) return;

    console.log('Starting refresh countdown');

    let refreshTimeout;
    let countdownInterval;

    function refreshCycle() {
        console.log(`Refresh cycle started. Current countdown: ${nextRefreshCountdown}`);
        checkExpiredAndFetchNew().then(() => {
            console.log(`Refresh cycle completed. Next refresh in ${nextRefreshCountdown} seconds`);
            startCountdown();
        });
    }

    function startCountdown() {
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }
        if (refreshTimeout) {
            clearTimeout(refreshTimeout);
        }

        nextRefreshCountdown = getTimeUntilNextExpiration();
        updateNextRefreshTime();

        countdownInterval = setInterval(() => {
            if (nextRefreshCountdown > 0) {
                nextRefreshCountdown--;
                updateNextRefreshTime();
            } else {
                clearInterval(countdownInterval);
                refreshCycle();
            }
        }, 1000);

        refreshTimeout = setTimeout(refreshCycle, nextRefreshCountdown * 1000);
    }

    refreshCycle();

    window.addEventListener('beforeunload', () => {
        if (countdownInterval) clearInterval(countdownInterval);
        if (refreshTimeout) clearTimeout(refreshTimeout);
    });
}

function checkExpiredAndFetchNew() {
    if (isSentOffers) return Promise.resolve();
    console.log('Starting checkExpiredAndFetchNew');
    const currentTime = Math.floor(Date.now() / 1000);
    const expiredOffers = jsonData.filter(offer => offer.expire_at <= currentTime);
    
    console.log(`Checking for expired offers. Current time: ${currentTime}`);
    console.log(`Found ${expiredOffers.length} expired offers.`);

    jsonData = jsonData.filter(offer => offer.expire_at > currentTime);

    console.log('Fetching new offers...');
    
    return fetch('/json/offers')
        .then(response => response.json())
        .then(data => {
            let newListings = Array.isArray(data) ? data : Object.values(data);
            newListings = newListings.filter(offer => !isOfferExpired(offer));
            
            const brandNewListings = newListings.filter(newOffer => 
                !jsonData.some(existingOffer => existingOffer.offer_id === newOffer.offer_id)
            );
            
            console.log(`Found ${brandNewListings.length} new listings to add.`);
            jsonData = [...jsonData, ...brandNewListings];
            newEntriesCount += brandNewListings.length;
            
            updateOffersTable();
            updateJsonView();
            updatePaginationInfo();
            
            if (jsonData.length === 0) {
                console.log('No active offers. Displaying message to user.');
                handleNoOffersScenario();
            }

            const timeUntilNextExpiration = getTimeUntilNextExpiration();
            nextRefreshCountdown = Math.max(MIN_REFRESH_INTERVAL, Math.min(timeUntilNextExpiration, 300)); // Between 30 seconds and 5 minutes
            console.log(`Next check scheduled in ${nextRefreshCountdown} seconds`);
        })
        .catch(error => {
            console.error('Error fetching new listings:', error);
            nextRefreshCountdown = 60;
            console.log(`Error occurred. Next check scheduled in ${nextRefreshCountdown} seconds`);
        });
}

// Event
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
    const validOffers = getValidOffers();
    const totalPages = Math.ceil(validOffers.length / itemsPerPage);
    if (currentPage < totalPages && validOffers.length > 0) {
        currentPage++;
        updateOffersTable();
        updatePaginationInfo();
        console.log(`Moved to page ${currentPage} of ${totalPages}`);
    } else {
        console.log('No more pages or all offers have expired');
        nextPageButton.classList.add('invisible');
        nextPageButton.style.display = 'none';
        if (validOffers.length === 0) {
            handleNoOffersScenario();
        }
    }
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

// Init
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

function continueInitialization() {
    if (typeof volumeToggle !== 'undefined' && volumeToggle.init) {
        volumeToggle.init();
    } else {
        console.warn('volumeToggle is not defined or does not have an init method');
    }
    
    updateCoinFilterImages();
    fetchOffers().then(() => {
        applyFilters();
        startRefreshCountdown();
    });
    
    function updateTimesLoop() {
        updateRowTimes();
        requestAnimationFrame(updateTimesLoop);
    }
    requestAnimationFrame(updateTimesLoop);
    
    setInterval(updateRowTimes, 900000);

    console.log('Initialization completed');
}

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

    filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        applyFilters();
    });

    filterForm.addEventListener('change', applyFilters);

    document.getElementById('coin_to').addEventListener('change', applyFilters);
    document.getElementById('coin_from').addEventListener('change', applyFilters);

    document.getElementById('clearFilters').addEventListener('click', () => {
        filterForm.reset();
        jsonData = [...originalJsonData];
        currentPage = 1;
        applyFilters();
        updateCoinFilterImages();
    });
});

console.log('Offers Table Module fully initialized');
