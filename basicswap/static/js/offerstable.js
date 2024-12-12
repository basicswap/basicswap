let latestPrices = null;
let lastRefreshTime = null;
let newEntriesCount = 0;
let nextRefreshCountdown = 60;
let currentPage = 1;
const itemsPerPage = 50;
let lastAppliedFilters = {};

const CACHE_KEY = 'latestPricesCache';

const MIN_REFRESH_INTERVAL = 60; // 60 sec

const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes 
const FALLBACK_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

let jsonData = [];
let originalJsonData = [];
let isInitialLoad = true;
let tableRateModule;
const isSentOffers = window.offersTableConfig.isSentOffers;

let currentSortColumn = 0;
let currentSortDirection = 'desc';

const PRICE_INIT_RETRIES = 3;
const PRICE_INIT_RETRY_DELAY = 2000;

const CacheManager = {
    maxItems: 100,
    maxSize: 5 * 1024 * 1024,
    
    set: function(key, value, customTtl = null) {
        try {
            this.cleanup();
            
            const item = {
                value: value,
                timestamp: Date.now(),
                expiresAt: Date.now() + (customTtl || CACHE_DURATION)
            };

            const itemSize = new Blob([JSON.stringify(item)]).size;

            if (itemSize > this.maxSize) {
                console.warn(`Cache item too large (${(itemSize/1024/1024).toFixed(2)}MB), not caching`);
                return false;
            }

            localStorage.setItem(key, JSON.stringify(item));
            
            console.log(`🟢 Cache set for ${key}, expires in ${(customTtl || CACHE_DURATION) / 1000} seconds`);
            console.log('Cached data:', {
                key: key,
                expiresIn: (customTtl || CACHE_DURATION) / 1000,
                sizeKB: (itemSize / 1024).toFixed(2),
                dataSize: typeof value === 'object' ? Object.keys(value).length : 'not an object'
            });
            
            return true;
        } catch (error) {
            if (error.name === 'QuotaExceededError') {
                console.warn('Storage quota exceeded, clearing old items');
                this.cleanup(true);
                try {
                    localStorage.setItem(key, JSON.stringify(item));
                    return true;
                } catch (retryError) {
                    console.error('❌ Still unable to store item after cleanup:', retryError);
                    return false;
                }
            }
            console.error('❌ Error setting cache:', error);
            return false;
        }
    },
    
    get: function(key) {
        try {
            const itemStr = localStorage.getItem(key);
            if (!itemStr) {
                console.log(`🔴 No cache found for ${key}`);
                return null;
            }

            const item = JSON.parse(itemStr);
            const now = Date.now();
            
            if (now < item.expiresAt) {
                const remainingTime = (item.expiresAt - now) / 1000;
                console.log(`🟢 Cache hit for ${key}, ${remainingTime.toFixed(1)} seconds remaining`);
                return {
                    value: item.value,
                    remainingTime: item.expiresAt - now
                };
            } else {
                console.log(`🟡 Cache expired for ${key}`);
                localStorage.removeItem(key);
            }
        } catch (error) {
            console.error('❌ Error parsing cache item:', error);
            localStorage.removeItem(key);
        }
        return null;
    },
    
    cleanup: function(aggressive = false) {
        const now = Date.now();
        let totalSize = 0;
        let itemCount = 0;
        const items = [];

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('offers_') || key.startsWith('prices_')) {
                try {
                    const itemStr = localStorage.getItem(key);
                    const size = new Blob([itemStr]).size;
                    const item = JSON.parse(itemStr);
                    
                    items.push({
                        key,
                        size,
                        expiresAt: item.expiresAt,
                        timestamp: item.timestamp
                    });
                    
                    totalSize += size;
                    itemCount++;
                } catch (error) {
                    console.warn(`🔧 Removing invalid cache item: ${key}`);
                    localStorage.removeItem(key);
                }
            }
        }

        items.forEach(item => {
            if (now >= item.expiresAt) {
                localStorage.removeItem(item.key);
                totalSize -= item.size;
                itemCount--;
            }
        });

        if (aggressive || totalSize > this.maxSize || itemCount > this.maxItems) {

            items.sort((a, b) => b.timestamp - a.timestamp);
            
            while ((totalSize > this.maxSize || itemCount > this.maxItems) && items.length > 0) {
                const item = items.pop();
                localStorage.removeItem(item.key);
                totalSize -= item.size;
                itemCount--;
            }
        }

        console.log('🧹 Cache cleanup completed:', {
            itemCount,
            totalSizeMB: (totalSize / 1024 / 1024).toFixed(2),
            aggressive
        });
    },
    
    isValid: function(key) {
        const result = this.get(key) !== null;
        console.log(`🔍 Cache validity check for ${key}: ${result ? 'valid' : 'invalid'}`);
        return result;
    },
    
    clear: function() {
        let clearedItems = [];
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('offers_') || key.startsWith('prices_')) {
                clearedItems.push(key);
                localStorage.removeItem(key);
            }
        });
        console.log(`🧹 Cache cleared: ${clearedItems.length} items removed`);
        if (clearedItems.length > 0) {
            console.log('Cleared items:', clearedItems);
        }
    },

    debug: function() {
        const cacheItems = {};
        let totalSize = 0;
        
        Object.keys(localStorage).forEach(key => {
            if (key.startsWith('offers_') || key.startsWith('prices_')) {
                try {
                    const itemStr = localStorage.getItem(key);
                    const size = new Blob([itemStr]).size;
                    const item = JSON.parse(itemStr);
                    
                    cacheItems[key] = {
                        expiresIn: ((item.expiresAt - Date.now()) / 1000).toFixed(1) + ' seconds',
                        sizeKB: (size / 1024).toFixed(2) + ' KB',
                        dataSize: typeof item.value === 'object' ? Object.keys(item.value).length : 'not an object'
                    };
                    
                    totalSize += size;
                } catch (e) {
                    cacheItems[key] = 'invalid cache item';
                }
            }
        });
        
        console.log('📊 Current cache status:', {
            items: cacheItems,
            totalSizeMB: (totalSize / 1024 / 1024).toFixed(2),
            itemCount: Object.keys(cacheItems).length
        });
        
        return cacheItems;
    }
};
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
    'Bitcoin Cash': 'bitcoin-cash'
};

const symbolToCoinName = {
    ...Object.fromEntries(Object.entries(coinNameToSymbol).map(([key, value]) => [value, key])),
    'zcoin': 'Firo',
    'firo': 'Firo'
};

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

const coinIdToName = {
    1: 'particl', 2: 'bitcoin', 3: 'litecoin', 4: 'decred',
    6: 'monero', 7: 'particl blind', 8: 'particl anon',
    9: 'wownero', 11: 'pivx', 13: 'firo', 17: 'bitcoincash'
};

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

// Enhanced WebSocket Manager
const WebSocketManager = {
    ws: null,
    reconnectTimeout: null,
    maxReconnectAttempts: 5,
    reconnectAttempts: 0,
    reconnectDelay: 5000,
    isIntentionallyClosed: false,

    initialize() {
        console.log('🚀 Initializing WebSocket Manager');
        this.connect();
    },

    connect() {

        this.cleanup();

        const config = getWebSocketConfig();
        const wsPort = config.port || window.ws_port || '11700';

        if (!wsPort) {
            console.error('❌ WebSocket port not configured');
            return false;
        }

        try {
            this.isIntentionallyClosed = false;
            this.ws = new WebSocket(`ws://${window.location.hostname}:${wsPort}`);
            this.setupEventHandlers();
            return true;
        } catch (error) {
            console.error('❌ Error creating WebSocket:', error);
            this.handleReconnect();
            return false;
        }
    },

    setupEventHandlers() {
        if (!this.ws) return;

        this.ws.onopen = () => {
            console.log('🟢 WebSocket connected successfully');
            this.reconnectAttempts = 0;
            window.ws = this.ws;
            updateConnectionStatus('connected');
        };

        this.ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                console.log('WebSocket message received:', message);
                this.handleMessage(message);
            } catch (error) {
                console.error('❌ Error processing WebSocket message:', error);
            }
        };

        this.ws.onerror = (error) => {
            console.error('❌ WebSocket error:', error);
            updateConnectionStatus('error');
        };

        this.ws.onclose = (event) => {
            console.log('🔴 WebSocket closed:', event.code, event.reason);
            window.ws = null;
            updateConnectionStatus('disconnected');

            if (!this.isIntentionallyClosed) {
                this.handleReconnect();
            }
        };
    },

    handleMessage(message) {
        if (message.event === 'new_offer') {
            // Fetch latest data
            const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
            fetch(endpoint)
                .then(response => {
                    if (!response.ok) throw new Error('Network response was not ok');
                    return response.json();
                })
                .then(newData => {
                    const fetchedOffers = Array.isArray(newData) ? newData : Object.values(newData);
                    
                    // Update data arrays
                    jsonData = formatInitialData(fetchedOffers);
                    originalJsonData = [...jsonData];
                    
                    // Update UI
                    console.log('Updating table with new data');
                    updateOffersTable(true);
                    updateJsonView();
                    updatePaginationInfo();
                })
                .catch(error => {
                    console.error('❌ Error fetching updated offers:', error);
                });
        }
    },

    handleReconnect() {
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }

        this.reconnectAttempts++;
        if (this.reconnectAttempts <= this.maxReconnectAttempts) {
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            
            // Exponential backoff
            const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
            
            this.reconnectTimeout = setTimeout(() => {
                if (!this.isIntentionallyClosed) {
                    this.connect();
                }
            }, delay);
        } else {
            console.error('❌ Max reconnection attempts reached');
            updateConnectionStatus('error');
        }
    },

    cleanup() {
        console.log('Cleaning up WebSocket connection');

        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }

        if (this.ws) {
            this.isIntentionallyClosed = true;

            this.ws.onopen = null;
            this.ws.onmessage = null;
            this.ws.onerror = null;
            this.ws.onclose = null;

            if (this.ws.readyState === WebSocket.OPEN) {
                this.ws.close();
            }

            this.ws = null;
            window.ws = null;
        }

        this.reconnectAttempts = 0;
    },

    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    },

    disconnect() {
        this.isIntentionallyClosed = true;
        this.cleanup();
    }
};

function initializeWebSocket() {
    return WebSocketManager.initialize();
}

function cleanupWebSocketResources() {
    WebSocketManager.cleanup();
}

function checkWebSocketConnection() {
    if (!WebSocketManager.isConnected()) {
        console.warn('WebSocket is not connected');
        return false;
    }
    return true;
}

function formatInitialData(data) {
    return data.map(offer => ({
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
        is_revoked: Boolean(offer.is_revoked),
        unique_id: `${offer.offer_id}_${offer.created_at}_${offer.coin_from}_${offer.coin_to}`
    }));
}

function processWebSocketMessage(message) {
    console.log('Processing message:', message);

    if (message.event === 'new_offer') {
        Promise.all([
            fetch('/json/offers').then(r => r.json()),
            fetch('/json/sentoffers').then(r => r.json())
        ])
        .then(([receivedOffers, sentOffers]) => {
            console.log('📊 Fetched data:', {
                receivedCount: Object.keys(receivedOffers).length,
                sentCount: Object.keys(sentOffers).length
            });

            if (isSentOffers) {
                const formattedSentOffers = formatInitialData(sentOffers);
                console.log('Updating sent offers:', formattedSentOffers.length);
                
                jsonData = formattedSentOffers;
                originalJsonData = [...formattedSentOffers];
            } else {
                const formattedReceivedOffers = formatInitialData(receivedOffers);
                console.log('Updating received offers:', formattedReceivedOffers.length);
                
                jsonData = formattedReceivedOffers;
                originalJsonData = [...formattedReceivedOffers];
            }

            updateOffersTable(true);
            updateJsonView();
            updatePaginationInfo();

            console.log('✅ Table updated for', isSentOffers ? 'sent' : 'received', 'offers');
        })
        .catch(error => {
            console.error('❌ Error fetching offers:', error);
        });
    }
}

function mergeOffers(existingOffers, newOffers) {
    const offerMap = new Map();

    existingOffers.forEach(offer => {
        const key = `${offer.offer_id}_${offer.created_at}`;
        offerMap.set(key, offer);
    });

    newOffers.forEach(offer => {
        const key = `${offer.offer_id}_${offer.created_at}`;
        offerMap.set(key, offer);
    });

    const mergedOffers = Array.from(offerMap.values());

    console.log('🔄 Offer Merge Stats:', {
        existingOffersCount: existingOffers.length,
        newOffersCount: newOffers.length,
        mergedOffersCount: mergedOffers.length
    });

    return mergedOffers;
}

function updateConnectionStatus(status) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    
    if (!dot || !text) {
        console.warn('Status indicators not found in DOM');
        return;
    }
    
    switch(status) {
        case 'connected':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-green-500 mr-2';
            text.textContent = 'Connected';
            text.className = 'text-sm text-green-500';
            break;
        case 'disconnected':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-red-500 mr-2';
            text.textContent = 'Disconnected - Reconnecting...';
            text.className = 'text-sm text-red-500';
            break;
        case 'error':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-yellow-500 mr-2';
            text.textContent = 'Connection Error';
            text.className = 'text-sm text-yellow-500';
            break;
        default:
            dot.className = 'w-2.5 h-2.5 rounded-full bg-gray-500 mr-2';
            text.textContent = 'Connecting...';
            text.className = 'text-sm text-gray-500';
    }
}

function formatOffer(message) {
    try {
        console.log('🔄 Formatting offer:', message);
        return {
            offer_id: String(message.offer_id || ''),
            swap_type: String(message.swap_type || 'N/A'),
            addr_from: String(message.addr_from || ''),
            coin_from: String(message.coin_from || ''),
            coin_to: String(message.coin_to || ''),
            amount_from: String(message.amount_from || '0'),
            amount_to: String(message.amount_to || '0'),
            rate: String(message.rate || '0'),
            created_at: Number(message.created_at || 0),
            expire_at: Number(message.expire_at || 0),
            is_own_offer: Boolean(message.is_own_offer),
            amount_negotiable: Boolean(message.amount_negotiable),
            is_revoked: Boolean(message.is_revoked),
            unique_id: `${message.offer_id}_${message.created_at || Date.now()}_${message.coin_from || ''}_${message.coin_to || ''}`
        };
    } catch (error) {
        console.error('❌ Error formatting offer:', error);
        return null;
    }
}

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
        'Bitcoin Cash': 'BCH',
        'Dogecoin': 'DOGE'
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
        document.querySelectorAll('.coinname-value').forEach(coinNameValue => {
            const coinFullNameOrSymbol = coinNameValue.getAttribute('data-coinname');
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

document.querySelectorAll('th[data-sortable="true"]').forEach(header => {
    header.addEventListener('click', () => {
        const columnIndex = parseInt(header.getAttribute('data-column-index'));
        
        if (currentSortColumn === columnIndex) {
            currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
        } else {

            currentSortColumn = columnIndex;
            currentSortDirection = 'desc';
        }

        document.querySelectorAll('.sort-icon').forEach(icon => {
            icon.classList.remove('text-blue-500');
            icon.textContent = '↓';
        });

        const sortIcon = document.getElementById(`sort-icon-${columnIndex}`);
        if (sortIcon) {
            sortIcon.textContent = currentSortDirection === 'asc' ? '↑' : '↓';
            sortIcon.classList.add('text-blue-500');
        }

        document.querySelectorAll('th[data-sortable="true"]').forEach(th => {
            const thColumnIndex = parseInt(th.getAttribute('data-column-index'));
            if (thColumnIndex === columnIndex) {
                th.classList.add('text-blue-500');
            } else {
                th.classList.remove('text-blue-500');
            }
        });

        localStorage.setItem('tableSortColumn', currentSortColumn);
        localStorage.setItem('tableSortDirection', currentSortDirection);
        
        applyFilters();
    });

    header.classList.add('cursor-pointer', 'hover:bg-gray-100', 'dark:hover:bg-gray-700');
});

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

async function initializePriceData() {
    console.log('Initializing price data...');
    let retryCount = 0;
    let prices = null;

    while (retryCount < PRICE_INIT_RETRIES) {
        try {
            prices = await fetchLatestPrices();
            
            if (prices && Object.keys(prices).length > 0) {
                console.log('Successfully fetched initial price data:', prices);
                latestPrices = prices;

                const PRICES_CACHE_KEY = 'prices_coingecko';
                CacheManager.set(PRICES_CACHE_KEY, prices, CACHE_DURATION);
                
                return true;
            }
            
            console.warn(`Attempt ${retryCount + 1}: Price data incomplete, retrying...`);
            retryCount++;
            
            if (retryCount < PRICE_INIT_RETRIES) {
                await new Promise(resolve => setTimeout(resolve, PRICE_INIT_RETRY_DELAY));
            }
        } catch (error) {
            console.error(`Error fetching prices (attempt ${retryCount + 1}):`, error);
            retryCount++;
            
            if (retryCount < PRICE_INIT_RETRIES) {
                await new Promise(resolve => setTimeout(resolve, PRICE_INIT_RETRY_DELAY));
            }
        }
    }

    const fallbackPrices = getFallbackPrices();
    if (fallbackPrices && Object.keys(fallbackPrices).length > 0) {
        console.log('Using fallback prices:', fallbackPrices);
        latestPrices = fallbackPrices;
        return true;
    }

    return false;
}

function loadSortPreferences() {
    const savedColumn = localStorage.getItem('tableSortColumn');
    const savedDirection = localStorage.getItem('tableSortDirection');
    
    if (savedColumn !== null) {
        currentSortColumn = parseInt(savedColumn);
        currentSortDirection = savedDirection || 'desc';
    }
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

function getCoinSymbolLowercase(coin) {
    if (typeof coin === 'string') {
        if (coin.toLowerCase() === 'bitcoin cash') {
            return 'bitcoin-cash';
        }
        return (coinNameToSymbol[coin] || coin).toLowerCase();
    } else if (coin && typeof coin === 'object' && coin.symbol) {
        return coin.symbol.toLowerCase();
    } else {
        console.warn('Invalid coin input:', coin);
        return 'unknown';
    }
}

function coinMatches(offerCoin, filterCoin) {
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

function getTimerColor(offer) {
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = offer.expire_at - now;

    if (timeLeft <= 300) { // 5 min or less
        return "#9CA3AF"; // Grey
    } else if (timeLeft <= 1800) { // 5-30 min
        return "#3B82F6"; // Blue
    } else { // More than 30 min
        return "#10B981"; // Green
    }
}

function getProfitColorClass(percentage) {
    const numericPercentage = parseFloat(percentage);
    if (numericPercentage > 0) return 'text-green-500';
    if (numericPercentage < 0) return 'text-red-500';
    if (numericPercentage === 0) return 'text-yellow-400';
    return 'text-white';
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

function getTimeUntilNextExpiration() {
    const currentTime = Math.floor(Date.now() / 1000);
    const nextExpiration = jsonData.reduce((earliest, offer) => {
        const timeUntilExpiration = offer.expire_at - currentTime;
        return timeUntilExpiration > 0 && timeUntilExpiration < earliest ? timeUntilExpiration : earliest;
    }, Infinity);
    
    return Math.max(MIN_REFRESH_INTERVAL, Math.min(nextExpiration, 300));
}

function calculateInverseRate(rate) {
    return (1 / parseFloat(rate)).toFixed(8);
}

function hasActiveFilters() {
    const formData = new FormData(filterForm);
    const filters = {
        coin_to: formData.get('coin_to'),
        coin_from: formData.get('coin_from'),
        status: formData.get('status')
    };
    
    console.log('Current filters:', filters);

    const hasFilters = 
        filters.coin_to !== 'any' || 
        filters.coin_from !== 'any' || 
        (filters.status && filters.status !== 'any');
                      
    console.log('Has active filters:', hasFilters);
    
    return hasFilters;
}

function getActiveFilters() {
    const formData = new FormData(filterForm);
    return {
        coin_to: formData.get('coin_to'),
        coin_from: formData.get('coin_from'),
        status: formData.get('status')
    };
}

function checkOfferAgainstFilters(offer, filters) {
    if (filters.coin_to !== 'any' && !coinMatches(offer.coin_to, filters.coin_to)) {
        return false;
    }
    if (filters.coin_from !== 'any' && !coinMatches(offer.coin_from, filters.coin_from)) {
        return false;
    }
    if (filters.status && filters.status !== 'any') {
        const currentTime = Math.floor(Date.now() / 1000);
        const isExpired = offer.expire_at <= currentTime;
        const isRevoked = Boolean(offer.is_revoked);
        
        switch (filters.status) {
            case 'active':
                return !isExpired && !isRevoked;
            case 'expired':
                return isExpired && !isRevoked;
            case 'revoked':
                return isRevoked;
            default:
                return true;
        }
    }
    return true;
}

function updateClearFiltersButton() {
    const clearButton = document.getElementById('clearFilters');
    if (clearButton) {
        clearButton.classList.toggle('opacity-50', !hasActiveFilters());
        clearButton.disabled = !hasActiveFilters();
    }
}

function setRefreshButtonLoading(isLoading) {
    const refreshButton = document.getElementById('refreshOffers');
    const refreshIcon = document.getElementById('refreshIcon');
    const refreshText = document.getElementById('refreshText');

    refreshButton.disabled = isLoading;
    refreshIcon.classList.toggle('animate-spin', isLoading);
    refreshText.textContent = isLoading ? 'Refreshing...' : 'Refresh';

    if (isLoading) {
        refreshButton.classList.add('opacity-75');
        refreshButton.classList.add('cursor-wait');
    } else {
        refreshButton.classList.remove('opacity-75');
        refreshButton.classList.remove('cursor-wait');
    }
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

function initializeFooter() {
    if (isSentOffers) {
        const nextRefreshContainer = document.getElementById('nextRefreshContainer');
        if (nextRefreshContainer) {
            nextRefreshContainer.style.display = 'none';
        }

        if (typeof nextRefreshCountdown !== 'undefined') {
            clearInterval(nextRefreshCountdown);
        }
    }
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


function updateRowTimes() {
    requestAnimationFrame(() => {
        const rows = document.querySelectorAll('[data-offer-id]');
        rows.forEach(row => {
            const offerId = row.getAttribute('data-offer-id');
            const offer = jsonData.find(o => o.offer_id === offerId);
            if (!offer) return;

            // Only update what's changed
            const newPostedTime = formatTimeAgo(offer.created_at);
            const newExpiresIn = formatTimeLeft(offer.expire_at);
            
            const postedElement = row.querySelector('.text-xs:first-child');
            const expiresElement = row.querySelector('.text-xs:last-child');
            
            if (postedElement && postedElement.textContent !== `Posted: ${newPostedTime}`) {
                postedElement.textContent = `Posted: ${newPostedTime}`;
            }
            if (expiresElement && expiresElement.textContent !== `Expires in: ${newExpiresIn}`) {
                expiresElement.textContent = `Expires in: ${newExpiresIn}`;
            }
        });
    });
}

function updateJsonView() {
    jsonContent.textContent = JSON.stringify(jsonData, null, 2);
}

function updateLastRefreshTime() {
    if (lastRefreshTimeSpan) {
        lastRefreshTimeSpan.textContent = lastRefreshTime ? new Date(lastRefreshTime).toLocaleTimeString() : 'Never';
    }
}

function updatePaginationInfo() {
    const validOffers = getValidOffers();
    const totalItems = validOffers.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));

    currentPage = Math.max(1, Math.min(currentPage, totalPages));

    currentPageSpan.textContent = currentPage;
    totalPagesSpan.textContent = totalPages;

    const showPrev = currentPage > 1;
    const showNext = currentPage < totalPages && totalItems > 0;
    
    prevPageButton.style.display = showPrev ? 'inline-flex' : 'none';
    nextPageButton.style.display = showNext ? 'inline-flex' : 'none';

    if (lastRefreshTime) {
        lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
    }
    
    if (newEntriesCountSpan) {
        newEntriesCountSpan.textContent = totalItems;
    }
}

function updatePaginationControls(totalPages) {
    prevPageButton.style.display = currentPage > 1 ? 'inline-flex' : 'none';
    nextPageButton.style.display = currentPage < totalPages ? 'inline-flex' : 'none';
    currentPageSpan.textContent = currentPage;
    totalPagesSpan.textContent = totalPages;
}

async function checkExpiredAndFetchNew() {
    if (isSentOffers) return Promise.resolve();
    
    console.log('Starting checkExpiredAndFetchNew');
    const OFFERS_CACHE_KEY = 'offers_received';
    
    try {
        const response = await fetch('/json/offers');
        const data = await response.json();
        let newListings = Array.isArray(data) ? data : Object.values(data);

        newListings = newListings.map(offer => ({
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

        newListings = newListings.filter(offer => !isOfferExpired(offer));
        originalJsonData = newListings;

        CacheManager.set(OFFERS_CACHE_KEY, newListings, CACHE_DURATION);

        const currentFilters = new FormData(filterForm);
        const hasActiveFilters = currentFilters.get('coin_to') !== 'any' || 
                               currentFilters.get('coin_from') !== 'any';
        
        if (hasActiveFilters) {
            jsonData = filterAndSortData();
        } else {
            jsonData = [...newListings];
        }

        updateOffersTable();
        updateJsonView();
        updatePaginationInfo();
        
        if (jsonData.length === 0) {
            handleNoOffersScenario();
        }

        nextRefreshCountdown = getTimeUntilNextExpiration();
        console.log(`Next refresh in ${nextRefreshCountdown} seconds`);
        
        return jsonData.length;
    } catch (error) {
        console.error('Error fetching new listings:', error);
        nextRefreshCountdown = 60;
        return Promise.reject(error);
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

function createTakerAmountColumn(offer, coinTo, coinFrom) {
    const fromAmount = parseFloat(offer.amount_to);
    const toSymbol = getCoinSymbol(coinTo);
    return `
        <td class="py-0">
            <div class="py-3 px-4 text-left">
                <a data-tooltip-target="tooltip-wallet${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(toSymbol)}" class="items-center monospace">
                    <div class="pr-2">        
                        <div class="text-sm font-semibold">${fromAmount.toFixed(4)}</div>          
                        <div class="text-sm text-gray-500 dark:text-gray-400">${coinTo}</div>
                    </div>
                </a>
            </div>
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

function createOrderbookColumn(offer, coinFrom, coinTo) {
    const toAmount = parseFloat(offer.amount_from);
    const fromSymbol = getCoinSymbol(coinFrom);
    return `
        <td class="p-0">
            <div class="py-3 px-4 text-right">
                <a data-tooltip-target="tooltip-wallet-maker${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(fromSymbol)}" class="items-center monospace">
                    <div class="pr-2">        
                        <div class="text-sm font-semibold">${toAmount.toFixed(4)}</div>           
                        <div class="text-sm text-gray-500 dark:text-gray-400">${coinFrom}</div>
                    </div>
                </a>
            </div>
        </td>
    `;
}

function createRateColumn(offer, coinFrom, coinTo) {
    const rate = parseFloat(offer.rate);
    const inverseRate = 1 / rate;
    const fromSymbol = getCoinSymbol(coinFrom);
    const toSymbol = getCoinSymbol(coinTo);
    
    const getPriceKey = (coin) => {
        const lowerCoin = coin.toLowerCase();
        if (lowerCoin === 'firo' || lowerCoin === 'zcoin') {
            return 'zcoin';
        }
        if (lowerCoin === 'bitcoin cash') {
            return 'bitcoin-cash';
        }
        return coinNameToSymbol[coin] || lowerCoin;
    };

    const fromPriceUSD = latestPrices[getPriceKey(coinFrom)]?.usd || 0;
    const toPriceUSD = latestPrices[getPriceKey(coinTo)]?.usd || 0;
    const rateInUSD = rate * toPriceUSD;

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
                profitLossElement.className = 'profit-loss text-lg font-bold text-gray-400';
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
                const tooltipContent = createTooltipContent(isSentOffers || isOwnOffer, fromCoin, toCoin, fromAmount, toAmount);
                tooltipElement.innerHTML = `
                    <div class="tooltip-content">
                        ${tooltipContent}
                    </div>
                    <div class="tooltip-arrow" data-popper-arrow></div>
                `;
            }
        })
        .catch(error => {
            console.error('Error in updateProfitLoss:', error);
            profitLossElement.textContent = 'Error';
            profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
        });
}

function createTooltips(offer, treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired, isRevoked) {
    const rate = parseFloat(offer.rate);
    const fromSymbol = getCoinSymbolLowercase(coinFrom);
    const toSymbol = getCoinSymbolLowercase(coinTo);
    const uniqueId = `${offer.offer_id}_${offer.created_at}`;
    
    const fromPriceUSD = latestPrices[fromSymbol]?.usd || 0;
    const toPriceUSD = latestPrices[toSymbol]?.usd || 0;
    const rateInUSD = rate * toPriceUSD;

    const combinedRateTooltip = createCombinedRateTooltip(offer, coinFrom, coinTo, treatAsSentOffer);
    const percentageTooltipContent = createTooltipContent(treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount);

    return `
        <div id="tooltip-active-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">
                    <div class="text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
                    <div class="text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
                    ${isRevoked ? '<div class="text-xs text-red-300"><span class="bold">Status:</span> Revoked</div>' : ''}
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
                <p class="flex items-center mt-3">
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
            <div class="active-revoked-expired">
                <span class="bold">${treatAsSentOffer ? 'My' : ''} ${coinTo} Wallet</span>
            </div>
            <div class="tooltip-arrow pl-1" data-popper-arrow></div>
        </div>
        
        <div id="tooltip-offer-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white ${isRevoked ? 'bg-red-500' : (offer.is_own_offer ? 'bg-gray-300' : 'bg-green-700')} rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">
                    ${isRevoked ? 'Offer Revoked' : (offer.is_own_offer ? 'Edit Offer' : `Buy ${coinFrom}`)}
                </span>
            </div>
            <div class="tooltip-arrow pr-6" data-popper-arrow></div>
        </div>
        
        <div id="tooltip-wallet-maker-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-blue-500 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">${treatAsSentOffer ? 'My' : ''} ${coinFrom} Wallet</span>
            </div>
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
        <p>${profitLabel}: ${profitUSD > 0 ? '' : '-'}$${Math.abs(profitUSD).toFixed(2)} USD</p>
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
        if (lowerCoin === 'firo' || lowerCoin === 'zcoin') {
            return 'zcoin';
        }
        if (lowerCoin === 'bitcoin cash') {
            return 'bitcoin-cash';
        }
        return coinNameToSymbol[coin] || lowerCoin;
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

function updateTooltipTargets(row, uniqueId) {
    const tooltipElements = [
        { prefix: 'tooltip-active', selector: '[data-tooltip-target^="tooltip-active"]' },
        { prefix: 'tooltip-recipient', selector: '[data-tooltip-target^="tooltip-recipient"]' },
        { prefix: 'tooltip-wallet', selector: '[data-tooltip-target^="tooltip-wallet"]' },
        { prefix: 'tooltip-offer', selector: '[data-tooltip-target^="tooltip-offer"]' },
        { prefix: 'tooltip-wallet-maker', selector: '[data-tooltip-target^="tooltip-wallet-maker"]' },
        { prefix: 'tooltip-rate', selector: '[data-tooltip-target^="tooltip-rate"]' },
        { prefix: 'percentage-tooltip', selector: '[data-tooltip-target^="percentage-tooltip"]' }
    ];

    tooltipElements.forEach(({ prefix, selector }) => {
        const element = row.querySelector(selector);
        if (element) {
            element.setAttribute('data-tooltip-target', `${prefix}-${uniqueId}`);
        }
    });
}

function clearFilters() {
    filterForm.reset();
    const statusSelect = document.getElementById('status');
    if (statusSelect) {
        statusSelect.value = 'any';
    }
    jsonData = [...originalJsonData];
    currentPage = 1;
    updateOffersTable();
    updateJsonView();
    updateCoinFilterImages();
    updateClearFiltersButton();
}

async function fetchLatestPrices() {
    const PRICES_CACHE_KEY = 'prices_coingecko';
    
    // Try to get cached prices first
    const cachedData = CacheManager.get(PRICES_CACHE_KEY);
    if (cachedData && cachedData.remainingTime > 60000) {
        console.log('Using cached price data (valid for next minute)');
        latestPrices = cachedData.value;
        return cachedData.value;
    }

    const url = `${config.apiEndpoints.coinGecko}/simple/price?ids=bitcoin,bitcoin-cash,dash,dogecoin,decred,litecoin,particl,pivx,monero,zano,wownero,zcoin&vs_currencies=USD,BTC&api_key=${config.apiKeys.coinGecko}`;
    
    try {
        console.log('Fetching fresh price data...');
        const data = await makePostRequest(url);
        
        if (data && Object.keys(data).length > 0) {
            console.log('✅ Fresh price data received');
            
            // Update latest prices
            latestPrices = data;
            
            // Cache the new data
            CacheManager.set(PRICES_CACHE_KEY, data, CACHE_DURATION);
            
            // Update fallback values
            Object.entries(data).forEach(([coin, prices]) => {
                tableRateModule.setFallbackValue(coin, prices.usd);
            });
            
            return data;
        } else {
            console.warn('Received empty price data');
        }
    } catch (error) {
        console.error('❌ Error fetching prices:', error);
        
        // Try to get fallback prices
        const fallbackPrices = getFallbackPrices();
        if (fallbackPrices && Object.keys(fallbackPrices).length > 0) {
            console.log('Using fallback prices');
            latestPrices = fallbackPrices;
            return fallbackPrices;
        }
    }

    console.warn('Using existing prices or null');
    return latestPrices || null;
}

function getFallbackPrices() {
    const fallbacks = {};
    const coins = [
        'bitcoin', 'bitcoin-cash', 'dash', 'dogecoin', 'decred', 
        'litecoin', 'particl', 'pivx', 'monero', 'zano', 
        'wownero', 'zcoin'
    ];
    
    for (const coin of coins) {
        const fallbackValue = tableRateModule.getFallbackValue(coin);
        if (fallbackValue) {
            fallbacks[coin] = { 
                usd: fallbackValue,
                last_updated: Date.now()
            };
        }
    }
    
    return Object.keys(fallbacks).length > 0 ? fallbacks : null;
}

async function fetchOffers(manualRefresh = false) {
  setRefreshButtonLoading(true);
  
  try {
    const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
    const response = await fetch(endpoint);
    const data = await response.json();
    
    jsonData = formatInitialData(data);
    originalJsonData = [...jsonData];

    await updateOffersTable();
    updateJsonView();
    updatePaginationInfo();
    
  } catch (error) {
    console.error('[Debug] Error fetching offers:', error);
    ui.displayErrorMessage('Failed to fetch offers. Please try again later.');
  } finally {
    setRefreshButtonLoading(false);
  }
}

function mergeSentOffers(existingOffers, newOffers) {
    console.log('[Debug] Merging offers:', {
        existing: existingOffers.length,
        new: newOffers.length
    });

    const offerMap = new Map();
    existingOffers.forEach(offer => {
        offerMap.set(offer.offer_id, offer);
    });

    newOffers.forEach(offer => {
        offerMap.set(offer.offer_id, offer);
    });
    
    const mergedOffers = Array.from(offerMap.values());
    console.log('[Debug] After merge:', mergedOffers.length);
    
    return mergedOffers;
}

function getValidOffers() {
    if (!jsonData) {
        console.warn('jsonData is undefined or null');
        return [];
    }

    const filteredData = filterAndSortData();
    console.log(`getValidOffers: Found ${filteredData.length} valid offers`);
    return filteredData;
}

function filterAndSortData() {
    console.log('[Debug] Starting filter with data length:', originalJsonData.length);
    
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    console.log('[Debug] Active filters:', filters);

    if (filters.coin_to !== 'any') {
        filters.coin_to = coinIdToName[filters.coin_to] || filters.coin_to;
    }
    if (filters.coin_from !== 'any') {
        filters.coin_from = coinIdToName[filters.coin_from] || filters.coin_from;
    }

    let filteredData = [...originalJsonData];

    filteredData = filteredData.filter(offer => {
        if (!isSentOffers && isOfferExpired(offer)) {
            return false;
        }

        const coinFrom = (offer.coin_from || '').toLowerCase();
        const coinTo = (offer.coin_to || '').toLowerCase();
        
        if (filters.coin_to !== 'any') {
            if (!coinMatches(coinTo, filters.coin_to)) {
                return false;
            }
        }
        
        if (filters.coin_from !== 'any') {
            if (!coinMatches(coinFrom, filters.coin_from)) {
                return false;
            }
        }

        if (isSentOffers && filters.status && filters.status !== 'any') {
            const currentTime = Math.floor(Date.now() / 1000);
            const isExpired = offer.expire_at <= currentTime;
            const isRevoked = Boolean(offer.is_revoked);
            
            switch (filters.status) {
                case 'active':
                    return !isExpired && !isRevoked;
                case 'expired':
                    return isExpired && !isRevoked;
                case 'revoked':
                    return isRevoked;
                default:
                    return true;
            }
        }

        return true;
    });

    if (currentSortColumn !== null) {
        filteredData.sort((a, b) => {
            let comparison = 0;
            
            switch(currentSortColumn) {
                case 0: // Time
                    comparison = a.created_at - b.created_at;
                    break;
                case 5: // Rate
                    comparison = parseFloat(a.rate) - parseFloat(b.rate);
                    break;
                case 6: // Market +/-
                    const aFromSymbol = getCoinSymbolLowercase(a.coin_from);
                    const aToSymbol = getCoinSymbolLowercase(a.coin_to);
                    const bFromSymbol = getCoinSymbolLowercase(b.coin_from);
                    const bToSymbol = getCoinSymbolLowercase(b.coin_to);
                    
                    const aFromPrice = latestPrices[aFromSymbol]?.usd || 0;
                    const aToPrice = latestPrices[aToSymbol]?.usd || 0;
                    const bFromPrice = latestPrices[bFromSymbol]?.usd || 0;
                    const bToPrice = latestPrices[bToSymbol]?.usd || 0;
                    
                    const aMarketRate = aToPrice / aFromPrice;
                    const bMarketRate = bToPrice / bFromPrice;
                    
                    const aOfferedRate = parseFloat(a.rate);
                    const bOfferedRate = parseFloat(b.rate);
                    
                    const aPercentDiff = ((aOfferedRate - aMarketRate) / aMarketRate) * 100;
                    const bPercentDiff = ((bOfferedRate - bMarketRate) / bMarketRate) * 100;
                    
                    comparison = aPercentDiff - bPercentDiff;
                    break;
                case 7: // Trade
                    comparison = a.offer_id.localeCompare(b.offer_id);
                    break;
            }
            
            return currentSortDirection === 'desc' ? -comparison : comparison;
        });
    }
    
    console.log(`[Debug] Filtered data length: ${filteredData.length}`);
    return filteredData;
}

function calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
    return new Promise((resolve) => {
        console.log(`Calculating profit/loss for ${fromAmount} ${fromCoin} to ${toAmount} ${toCoin}, isOwnOffer: ${isOwnOffer}`);

        if (!latestPrices) {
            console.error('Latest prices not available. Unable to calculate profit/loss.');
            resolve(null);
            return;
        }

        const getPriceKey = (coin) => {
            const lowerCoin = coin.toLowerCase();
            if (lowerCoin === 'firo' || lowerCoin === 'zcoin') {
                return 'zcoin';
            }
            if (lowerCoin === 'bitcoin cash') {
                return 'bitcoin-cash';
            }
            if (lowerCoin === 'particl anon' || lowerCoin === 'particl blind') {
                return 'particl';
            }
            return coinNameToSymbol[coin] || lowerCoin;
        };

        const fromSymbol = getPriceKey(fromCoin);
        const toSymbol = getPriceKey(toCoin);

        const fromPriceUSD = latestPrices[fromSymbol]?.usd;
        const toPriceUSD = latestPrices[toSymbol]?.usd;

        if (!fromPriceUSD || !toPriceUSD) {
            console.warn(`Price data missing for ${fromSymbol} (${fromPriceUSD}) or ${toSymbol} (${toPriceUSD})`);
            resolve(null);
            return;
        }

        const fromValueUSD = fromAmount * fromPriceUSD;
        const toValueUSD = toAmount * toPriceUSD;

        let percentDiff;
        if (isOwnOffer) {
            percentDiff = ((toValueUSD / fromValueUSD) - 1) * 100;
        } else {
            percentDiff = ((fromValueUSD / toValueUSD) - 1) * 100;
        }

        console.log(`Percent difference: ${percentDiff.toFixed(2)}%`);
        resolve(percentDiff);
    });
}

async function getMarketRate(fromCoin, toCoin) {
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
            if (lowerCoin === 'bitcoin cash') {
                return 'bitcoin-cash';
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

function handleNoOffersScenario() {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    const hasActiveFilters = filters.coin_to !== 'any' || 
                            filters.coin_from !== 'any' ||
                            (filters.status && filters.status !== 'any');
    
    if (hasActiveFilters) {
        offersBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">
                    No offers match the selected filters. Try different filter options or 
                    <button onclick="clearFilters()" class="text-blue-500 hover:text-blue-700 bold">clear filters</button>
                </td>
            </tr>`;
    } else {
        offersBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">
                    No active offers available. ${!isSentOffers ? 'Refreshing data...' : ''}
                </td>
            </tr>`;
        if (!isSentOffers) {
            setTimeout(() => fetchOffers(true), 2000);
        }
    }
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
    const isRevoked = Boolean(offer.is_revoked);

    const { buttonClass, buttonText } = getButtonProperties(isActuallyExpired, isSentOffers, isOwnOffer, isRevoked);

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
        ${createTooltips(offer, isOwnOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired, isRevoked)}
    `;

    updateTooltipTargets(row, uniqueId);
    updateProfitLoss(row, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer);

    return row;
}

async function updateOffersTable(skipPriceRefresh = false) {
    console.log('[Debug] Starting updateOffersTable function');
    
    try {
        if (!skipPriceRefresh) {
            const PRICES_CACHE_KEY = 'prices_coingecko';
            const cachedPrices = CacheManager.get(PRICES_CACHE_KEY);
            
            if (!cachedPrices || !cachedPrices.remainingTime || cachedPrices.remainingTime < 60000) {
                console.log('Fetching fresh price data...');
                const priceData = await fetchLatestPrices();
                if (!priceData) {
                    console.error('Failed to fetch latest prices');
                } else {
                    console.log('Latest prices fetched successfully');
                    latestPrices = priceData;
                }
            } else {
                console.log('Using cached price data (still valid)');
                latestPrices = cachedPrices.value;
            }
        }

        const totalOffers = originalJsonData.filter(offer => !isOfferExpired(offer));

        const networkOffersCount = document.getElementById('network-offers-count');
        if (networkOffersCount && !isSentOffers) {
            networkOffersCount.textContent = totalOffers.length;
        }

        let validOffers = getValidOffers();
        console.log('[Debug] Valid offers:', validOffers.length);

        if (validOffers.length === 0) {
            handleNoOffersScenario();
            return;
        }

        const totalPages = Math.max(1, Math.ceil(validOffers.length / itemsPerPage));
        currentPage = Math.min(currentPage, totalPages);
        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, validOffers.length);
        const itemsToDisplay = validOffers.slice(startIndex, endIndex);

        const fragment = document.createDocumentFragment();

        const currentOffers = new Set();
        itemsToDisplay.forEach(offer => {
            currentOffers.add(offer.offer_id);
            const row = createTableRow(offer, isSentOffers);
            if (row) {
                fragment.appendChild(row);
            }
        });

        offersBody.innerHTML = '';
        offersBody.appendChild(fragment);

        requestAnimationFrame(() => {
            initializeFlowbiteTooltips();
            updateRowTimes();
            updatePaginationControls(totalPages);
            
            if (tableRateModule?.initializeTable) {
                tableRateModule.initializeTable();
            }
        });

        lastRefreshTime = Date.now();
        if (newEntriesCountSpan) {
            const displayCount = isSentOffers ? jsonData.length : validOffers.length;
            newEntriesCountSpan.textContent = displayCount;
        }
        if (lastRefreshTimeSpan) {
            lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
        }

        if (!isSentOffers) {
            const nextUpdateTime = getTimeUntilNextExpiration() * 1000;
            setTimeout(() => {
                updateRowTimes();
            }, nextUpdateTime);
        }

    } catch (error) {
        console.error('[Debug] Error in updateOffersTable:', error);
        offersBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-red-500">
                    An error occurred while updating the offers table. Please try again later.
                </td>
            </tr>`;
    } finally {
        setRefreshButtonLoading(false);
    }
}

function handleWebSocketMessage(message) {
    console.log('WebSocket message received:', message);

    if (message.event === 'new_offer' || message.event === 'offer_expiration') {
        // Fetch latest data
        const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
        
        fetch(endpoint)
            .then(response => response.json())
            .then(newData => {
                const fetchedOffers = Array.isArray(newData) ? newData : Object.values(newData);
                console.log('Fetched offers:', fetchedOffers.length);

                const networkOffersCount = document.getElementById('network-offers-count');
                if (networkOffersCount && !isSentOffers) {
                    networkOffersCount.textContent = fetchedOffers.length;
                }

                jsonData = formatInitialData(fetchedOffers);
                originalJsonData = [...jsonData];

                updateOffersTable(true);
                updateJsonView();
                updatePaginationInfo();

                if (newEntriesCountSpan) {
                    const filteredOffers = filterAndSortData();
                    const displayCount = isSentOffers ? jsonData.length : filteredOffers.length;
                    newEntriesCountSpan.textContent = displayCount;
                    console.log('Updated listings count:', displayCount);
                }

                if (lastRefreshTimeSpan) {
                    lastRefreshTime = Date.now();
                    lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
                }
            })
            .catch(error => {
                console.error('❌ Error processing WebSocket message:', error);
            });
    }
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

let filterTimeout = null;
function applyFilters() {
    if (filterTimeout) {
        clearTimeout(filterTimeout);
        filterTimeout = null;
    }

    try {
        filterTimeout = setTimeout(() => {
            jsonData = filterAndSortData();
            updateOffersTable(true);
            updateJsonView();
            updatePaginationInfo();
            updateClearFiltersButton();
            filterTimeout = null;
        }, 250);
    } catch (error) {
        console.error('Error in filter timeout:', error);
        filterTimeout = null;
    }
}

function continueInitialization() {
    if (typeof volumeToggle !== 'undefined' && volumeToggle.init) {
        volumeToggle.init();
    }
    
    updateCoinFilterImages();
    fetchOffers().then(() => {
        applyFilters();
        if (!isSentOffers) {
        }
    });

    const listingLabel = document.querySelector('span[data-listing-label]');
    if (listingLabel) {
        listingLabel.textContent = isSentOffers ? 'Total Listings: ' : 'Network Listings: ';
    }
    
    function updateTimesLoop() {
        updateRowTimes();
        requestAnimationFrame(updateTimesLoop);
    }
    requestAnimationFrame(updateTimesLoop);
    
    setInterval(updateRowTimes, 900000);
    console.log('Initialization completed');
}

const eventListeners = {
    listeners: [],
    
    add(element, eventType, handler, options = false) {
        element.addEventListener(eventType, handler, options);
        this.listeners.push({ element, eventType, handler, options });
        console.log(`Added ${eventType} listener to`, element);
    },
    
    addWindowListener(eventType, handler, options = false) {
        window.addEventListener(eventType, handler, options);
        this.listeners.push({ element: window, eventType, handler, options });
        console.log(`Added ${eventType} window listener`);
    },
    
    removeAll() {
        console.log('Removing all event listeners...');
        this.listeners.forEach(({ element, eventType, handler, options }) => {
            element.removeEventListener(eventType, handler, options);
            console.log(`Removed ${eventType} listener from`, element);
        });
        this.listeners = [];
    },
    
    removeByElement(element) {
        const remainingListeners = [];
        this.listeners = this.listeners.filter(listener => {
            if (listener.element === element) {
                listener.element.removeEventListener(
                    listener.eventType,
                    listener.handler,
                    listener.options
                );
                console.log(`✂️ Removed ${listener.eventType} listener from`, element);
                return false;
            }
            return true;
        });
    },
    
    debug() {
        console.log('📊 Current event listeners:', this.listeners.map(l => ({
            element: l.element.tagName || 'window',
            eventType: l.eventType
        })));
    }
};

const timerManager = {
    intervals: [],
    timeouts: [],
    
    addInterval(callback, delay) {
        const intervalId = setInterval(callback, delay);
        this.intervals.push(intervalId);
        return intervalId;
    },
    
    addTimeout(callback, delay) {
        const timeoutId = setTimeout(callback, delay);
        this.timeouts.push(timeoutId);
        return timeoutId;
    },
    
    clearAllIntervals() {
        this.intervals.forEach(clearInterval);
        this.intervals = [];
    },
    
    clearAllTimeouts() {
        this.timeouts.forEach(clearTimeout);
        this.timeouts = [];
    },
    
    clearAll() {
        this.clearAllIntervals();
        this.clearAllTimeouts();
    }
};

function cleanupAllResources() {
    eventListeners.removeAll();

    timerManager.clearAll();

    cleanupWebSocketResources();

    if (window.wsCheckInterval) {
        clearInterval(window.wsCheckInterval);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM content loaded, initializing...');
    console.log('View type:', isSentOffers ? 'sent offers' : 'received offers');

    initializeFooter();
    updateClearFiltersButton();

    setTimeout(() => {
        console.log('Starting WebSocket initialization...');
        WebSocketManager.initialize();
    }, 1000);

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
                console.error('❌ Failed to load tableRateModule after multiple attempts');
                clearInterval(retryInterval);
                continueInitialization();
            }
        }, 1000);
    }

    eventListeners.add(filterForm, 'submit', (e) => {
        e.preventDefault();
        applyFilters();
    });

    eventListeners.add(filterForm, 'change', applyFilters);

    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');

    eventListeners.add(coinToSelect, 'change', () => {
        applyFilters();
        updateCoinFilterImages();
    });

    eventListeners.add(coinFromSelect, 'change', () => {
        applyFilters();
        updateCoinFilterImages();
    });

    eventListeners.add(document.getElementById('clearFilters'), 'click', () => {
        filterForm.reset();
        const statusSelect = document.getElementById('status');
        if (statusSelect) {
            statusSelect.value = 'any';
        }
        jsonData = [...originalJsonData];
        currentPage = 1;
        applyFilters();
        updateCoinFilterImages();
    });

    eventListeners.add(document.getElementById('refreshOffers'), 'click', async () => {
        console.log('Manual refresh initiated');
        setRefreshButtonLoading(true);

        try {
            const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
            const response = await fetch(endpoint);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const newData = await response.json();

            const processedNewData = Array.isArray(newData) ? newData : Object.values(newData);
            console.log('Fetched offers:', processedNewData.length);

            jsonData = formatInitialData(processedNewData);
            originalJsonData = [...jsonData];
            
            await updateOffersTable();
            updateJsonView();
            updatePaginationInfo();
            
            console.log('✅ Manual refresh completed successfully');
            
        } catch (error) {
            console.error('❌ Error during manual refresh:', error);
            ui.displayErrorMessage('Failed to refresh offers. Please try again later.');
        } finally {
            setRefreshButtonLoading(false);
        }
    });

    eventListeners.add(toggleButton, 'click', () => {
        tableView.classList.toggle('hidden');
        jsonView.classList.toggle('hidden');
        toggleButton.textContent = tableView.classList.contains('hidden') 
            ? 'Show Table View' 
            : 'Show JSON View';
    });

    eventListeners.add(prevPageButton, 'click', () => {
        if (currentPage > 1) {
            currentPage--;
            const validOffers = getValidOffers();
            const totalPages = Math.ceil(validOffers.length / itemsPerPage);
            updateOffersTable(true);
            updatePaginationControls(totalPages);
        }
    });

    eventListeners.add(nextPageButton, 'click', () => {
        const validOffers = getValidOffers();
        const totalPages = Math.ceil(validOffers.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            updateOffersTable(true);
            updatePaginationControls(totalPages);
        }
    });

    timerManager.addInterval(() => {
        if (WebSocketManager.isConnected()) {
            console.log('WebSocket Status: Connected');
        }
    }, 30000);

    timerManager.addInterval(() => {
        CacheManager.cleanup();
    }, 300000);

    updateCoinFilterImages();
    fetchOffers().then(() => {
        console.log('Initial offers fetched');
        applyFilters();
    }).catch(error => {
        console.error('❌ Error fetching initial offers:', error);
    });

    const listingLabel = document.querySelector('span[data-listing-label]');
    if (listingLabel) {
        listingLabel.textContent = isSentOffers ? 'Total Listings: ' : 'Network Listings: ';
    }

    function updateTimesLoop() {
        updateRowTimes();
        requestAnimationFrame(updateTimesLoop);
    }
    requestAnimationFrame(updateTimesLoop);

    timerManager.addInterval(updateRowTimes, 900000);

function cleanupResources() {
    console.log('🧹 Starting resource cleanup...');

    eventListeners.removeAll();

    timerManager.clearAll();

    WebSocketManager.disconnect();

    toggleButton = null;
    tableView = null;
    jsonView = null;
    filterForm = null;
    prevPageButton = null;
    nextPageButton = null;
    currentPageSpan = null;
    totalPagesSpan = null;
    lastRefreshTimeSpan = null;
    newEntriesCountSpan = null;
    nextRefreshTimeSpan = null;
    offersBody = null;
    jsonContent = null;

    if (filterTimeout) {
        clearTimeout(filterTimeout);
        filterTimeout = null;
    }

    if (typeof rafId !== 'undefined' && rafId) {
        cancelAnimationFrame(rafId);
        rafId = null;
    }

    jsonData = null;
    originalJsonData = null;
    latestPrices = null;
    lastRefreshTime = null;

    currentPage = 1;
    newEntriesCount = 0;
    nextRefreshCountdown = 60;

    if (typeof CacheManager !== 'undefined') {
        CacheManager.cleanup(true);
    }

    console.log('✅ Resource cleanup completed');
}

    eventListeners.addWindowListener('beforeunload', cleanupResources);
    eventListeners.addWindowListener('unload', cleanupResources);

    console.log('✅ Initialization completed');
});

console.log('Offers Table Module fully initialized');
