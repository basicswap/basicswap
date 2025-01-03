// GLOBAL STATE VARIABLES
let latestPrices = null;
let lastRefreshTime = null;
let currentPage = 1;
let jsonData = [];
let originalJsonData = [];
let currentSortColumn = 0;
let currentSortDirection = 'desc';
let filterTimeout = null;

// CONFIGURATION CONSTANTS

// Time Constants
const MIN_REFRESH_INTERVAL = 60; // 60 sec
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
const FALLBACK_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

// Application Constants
const itemsPerPage = 50;
const PRICE_INIT_RETRIES = 3;
const PRICE_INIT_RETRY_DELAY = 2000;
const isSentOffers = window.offersTableConfig.isSentOffers;

// MAPPING OBJECTS
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
    9: 'wownero', 11: 'pivx', 13: 'firo', 17: 'bitcoincash',
    18: 'dogecoin'
};

// DOM ELEMENT REFERENCES
const offersBody = document.getElementById('offers-body');
const filterForm = document.getElementById('filterForm');
const prevPageButton = document.getElementById('prevPage');
const nextPageButton = document.getElementById('nextPage');
const currentPageSpan = document.getElementById('currentPage');
const totalPagesSpan = document.getElementById('totalPages');
const lastRefreshTimeSpan = document.getElementById('lastRefreshTime');
const newEntriesCountSpan = document.getElementById('newEntriesCount');

// MANAGER OBJECTS
const WebSocketManager = {
    ws: null,
    messageQueue: [],
    processingQueue: false,
    debounceTimeout: null,
    reconnectTimeout: null,
    maxReconnectAttempts: 5,
    reconnectAttempts: 0,
    reconnectDelay: 5000,
    maxQueueSize: 1000,
    isIntentionallyClosed: false,

    connectionState: {
        isConnecting: false,
        lastConnectAttempt: null,
        connectTimeout: null,
        lastHealthCheck: null,
        healthCheckInterval: null
    },

    initialize() {
        console.log('Initializing WebSocket Manager');
        this.setupPageVisibilityHandler();
        this.connect();
        this.startHealthCheck();
    },

    setupPageVisibilityHandler() {
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.handlePageHidden();
            } else {
                this.handlePageVisible();
            }
        });
    },

    handlePageHidden() {
        console.log('📱 Page hidden, suspending operations');
        this.stopHealthCheck();
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.isIntentionallyClosed = true;
            this.ws.close(1000, 'Page hidden');
        }
    },

    handlePageVisible() {
        console.log('📱 Page visible, resuming operations');
        this.isIntentionallyClosed = false;
        if (!this.isConnected()) {
            this.connect();
        }
        this.startHealthCheck();
    },

    startHealthCheck() {
        this.stopHealthCheck();
        this.connectionState.healthCheckInterval = setInterval(() => {
            this.performHealthCheck();
        }, 30000);
    },

    stopHealthCheck() {
        if (this.connectionState.healthCheckInterval) {
            clearInterval(this.connectionState.healthCheckInterval);
            this.connectionState.healthCheckInterval = null;
        }
    },

    performHealthCheck() {
        if (!this.isConnected()) {
            console.warn('Health check: Connection lost, attempting reconnect');
            this.handleReconnect();
            return;
        }

        const now = Date.now();
        const lastCheck = this.connectionState.lastHealthCheck;
        if (lastCheck && (now - lastCheck) > 60000) {
            console.warn('Health check: Connection stale, refreshing');
            this.handleReconnect();
            return;
        }

        this.connectionState.lastHealthCheck = now;
        console.log('Health check passed');
    },

    connect() {
        if (this.connectionState.isConnecting || this.isIntentionallyClosed) {
            return false;
        }

        this.cleanup();
        this.connectionState.isConnecting = true;
        this.connectionState.lastConnectAttempt = Date.now();

        try {
            const config = getWebSocketConfig();
            const wsPort = config.port || window.ws_port || '11700';

            if (!wsPort) {
                console.error('WebSocket port not configured');
                this.connectionState.isConnecting = false;
                return false;
            }

            this.ws = new WebSocket(`ws://${window.location.hostname}:${wsPort}`);
            this.setupEventHandlers();

            this.connectionState.connectTimeout = setTimeout(() => {
                if (this.connectionState.isConnecting) {
                    console.log('⏳ Connection attempt timed out');
                    this.cleanup();
                    this.handleReconnect();
                }
            }, 5000);

            return true;
        } catch (error) {
            console.error('Error creating WebSocket:', error);
            this.connectionState.isConnecting = false;
            this.handleReconnect();
            return false;
        }
    },

    setupEventHandlers() {
    if (!this.ws) return;

    this.ws.onopen = () => {
        console.log('🟢 WebSocket connected successfully');
        this.connectionState.isConnecting = false;
        this.reconnectAttempts = 0;
        clearTimeout(this.connectionState.connectTimeout);
        this.connectionState.lastHealthCheck = Date.now();
        window.ws = this.ws;
        updateConnectionStatus('connected');
    };

    this.ws.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            this.handleMessage(message);
        } catch (error) {
            console.error('Error processing WebSocket message:', error);
            updateConnectionStatus('error');
        }
    };

    this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('error');
    };

    this.ws.onclose = (event) => {
        console.log('🔴 WebSocket closed:', event.code, event.reason);
        this.connectionState.isConnecting = false;
        window.ws = null;
        updateConnectionStatus('disconnected');

        if (!this.isIntentionallyClosed) {
            this.handleReconnect();
        }
    };
},

    handleMessage(message) {
        if (this.messageQueue.length >= this.maxQueueSize) {
            console.warn('⚠Message queue full, dropping oldest message');
            this.messageQueue.shift();
        }

        clearTimeout(this.debounceTimeout);
        this.messageQueue.push(message);

        this.debounceTimeout = setTimeout(() => {
            this.processMessageQueue();
        }, 250);
    },

    async processMessageQueue() {
        if (this.processingQueue || this.messageQueue.length === 0) return;

        this.processingQueue = true;
        const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';

        try {
            const response = await fetch(endpoint);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

            const newData = await response.json();
            const fetchedOffers = Array.isArray(newData) ? newData : Object.values(newData);

            jsonData = formatInitialData(fetchedOffers);
            originalJsonData = [...jsonData];

            requestAnimationFrame(() => {
                updateOffersTable();
                updateJsonView();
                updatePaginationInfo();
            });

            this.messageQueue = [];
        } catch (error) {
            console.error('Error processing message queue:', error);
        } finally {
            this.processingQueue = false;
        }
    },

    handleReconnect() {
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
        }

        this.reconnectAttempts++;
        if (this.reconnectAttempts <= this.maxReconnectAttempts) {
            console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);

            const delay = Math.min(
                this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1),
                30000
            );

            this.reconnectTimeout = setTimeout(() => {
                if (!this.isIntentionallyClosed) {
                    this.connect();
                }
            }, delay);
        } else {
            console.error('Max reconnection attempts reached');
            updateConnectionStatus('error');

            setTimeout(() => {
                this.reconnectAttempts = 0;
                this.connect();
            }, 60000);
        }
    },

    cleanup() {
        console.log('Cleaning up WebSocket resources');

        clearTimeout(this.debounceTimeout);
        clearTimeout(this.reconnectTimeout);
        clearTimeout(this.connectionState.connectTimeout);

        this.messageQueue = [];
        this.processingQueue = false;
        this.connectionState.isConnecting = false;

        if (this.ws) {
            this.ws.onopen = null;
            this.ws.onmessage = null;
            this.ws.onerror = null;
            this.ws.onclose = null;

            if (this.ws.readyState === WebSocket.OPEN) {
                this.ws.close(1000, 'Cleanup');
            }
            this.ws = null;
            window.ws = null;
        }
    },

    isConnected() {
        return this.ws && this.ws.readyState === WebSocket.OPEN;
    },

    disconnect() {
        this.isIntentionallyClosed = true;
        this.cleanup();
        this.stopHealthCheck();
    }
};

const CacheManager = {
    maxItems: 100,
    maxSize: 5 * 1024 * 1024, // 5MB

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
                //console.error(`Cache item exceeds maximum size (${(itemSize/1024/1024).toFixed(2)}MB)`);
                return false;
            }

            localStorage.setItem(key, JSON.stringify(item));
            return true;

        } catch (error) {
            if (error.name === 'QuotaExceededError') {
                this.cleanup(true); // Aggressive cleanup
                try {
                    localStorage.setItem(key, JSON.stringify(item));
                    return true;
                } catch (retryError) {
                    //console.error('Storage quota exceeded even after cleanup');
                    return false;
                }
            }
            //console.error('Cache set error:', error);
            return false;
        }
    },

    get: function(key) {
        try {
            const itemStr = localStorage.getItem(key);
            if (!itemStr) return null;

            const item = JSON.parse(itemStr);
            const now = Date.now();

            if (now < item.expiresAt) {
                return {
                    value: item.value,
                    remainingTime: item.expiresAt - now
                };
            }

            localStorage.removeItem(key);
        } catch (error) {
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
            if (!key.startsWith('offers_') && !key.startsWith('prices_')) continue;

            try {
                const itemStr = localStorage.getItem(key);
                const size = new Blob([itemStr]).size;
                const item = JSON.parse(itemStr);

                if (now >= item.expiresAt) {
                    localStorage.removeItem(key);
                    continue;
                }

                items.push({
                    key,
                    size,
                    expiresAt: item.expiresAt,
                    timestamp: item.timestamp
                });

                totalSize += size;
                itemCount++;
            } catch (error) {
                localStorage.removeItem(key);
            }
        }

        if (aggressive || totalSize > this.maxSize || itemCount > this.maxItems) {
            items.sort((a, b) => b.timestamp - a.timestamp);

            while ((totalSize > this.maxSize || itemCount > this.maxItems) && items.length > 0) {
                const item = items.pop();
                localStorage.removeItem(item.key);
                totalSize -= item.size;
                itemCount--;
            }
        }
    },

    clear: function() {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('offers_') || key.startsWith('prices_')) {
                keys.push(key);
            }
        }

        keys.forEach(key => localStorage.removeItem(key));
    },

    getStats: function() {
        let totalSize = 0;
        let itemCount = 0;
        let expiredCount = 0;
        const now = Date.now();

        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (!key.startsWith('offers_') && !key.startsWith('prices_')) continue;

            try {
                const itemStr = localStorage.getItem(key);
                const size = new Blob([itemStr]).size;
                const item = JSON.parse(itemStr);

                totalSize += size;
                itemCount++;

                if (now >= item.expiresAt) {
                    expiredCount++;
                }
            } catch (error) {
            }
        }

        return {
            totalSizeMB: (totalSize / 1024 / 1024).toFixed(2),
            itemCount,
            expiredCount,
            utilization: ((totalSize / this.maxSize) * 100).toFixed(1) + '%'
        };
    }
};

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
                //console.warn('Missing or unknown coin name/symbol in data-coinname attribute');
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
        //console.log('Initializing TableRateModule');
        this.initializeTable();
    }
};

// CORE SYSTEM FUNCTIONS
function initializeWebSocket() {
    return WebSocketManager.initialize();
}

function initializeTableRateModule() {
    if (typeof window.tableRateModule !== 'undefined') {
        tableRateModule = window.tableRateModule;
        //console.log('tableRateModule loaded successfully');
        return true;
    } else {
        //console.warn('tableRateModule not found. Waiting for it to load...');
        return false;
    }
}

async function initializePriceData() {
    //console.log('Initializing price data...');
    let retryCount = 0;
    let prices = null;

    const PRICES_CACHE_KEY = 'prices_coingecko';
    const cachedPrices = CacheManager.get(PRICES_CACHE_KEY);
    if (cachedPrices && cachedPrices.value) {
        console.log('Using cached price data');
        latestPrices = cachedPrices.value;
        return true;
    }

    while (retryCount < PRICE_INIT_RETRIES) {
        try {
            prices = await fetchLatestPrices();

            if (prices && Object.keys(prices).length > 0) {
                console.log('Successfully fetched initial price data');
                latestPrices = prices;
                CacheManager.set(PRICES_CACHE_KEY, prices, CACHE_DURATION);
                return true;
            }

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

    return false;
}

function continueInitialization() {
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
    //console.log('Initialization completed');
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

// DATA PROCESSING FUNCTIONS
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

        return jsonData.length;
    } catch (error) {
        //console.error('Error fetching new listings:', error);
        nextRefreshCountdown = 60;
        return Promise.reject(error);
    }
}

function getValidOffers() {
    if (!jsonData) {
        //console.warn('jsonData is undefined or null');
        return [];
    }

    const filteredData = filterAndSortData();
    //console.log(`getValidOffers: Found ${filteredData.length} valid offers`);
    return filteredData;
}

function filterAndSortData() {
    //console.log('[Debug] Starting filter with data length:', originalJsonData.length);

    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    //console.log('[Debug] Active filters:', filters);

    if (filters.coin_to !== 'any') {
        filters.coin_to = coinIdToName[filters.coin_to] || filters.coin_to;
    }
    if (filters.coin_from !== 'any') {
        filters.coin_from = coinIdToName[filters.coin_from] || filters.coin_from;
    }

    let filteredData = [...originalJsonData];

    const sentFromFilter = filters.sent_from || 'any';

    filteredData = filteredData.filter(offer => {
        if (sentFromFilter === 'public') {
            return offer.is_public;
        } else if (sentFromFilter === 'private') {
            return !offer.is_public;
        }
        return true;
    });

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

    //console.log(`[Debug] Filtered data length: ${filteredData.length}`);
    return filteredData;
}

function calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
    return new Promise((resolve) => {
        // console.log(`Calculating profit/loss for ${fromAmount} ${fromCoin} to ${toAmount} ${toCoin}, isOwnOffer: ${isOwnOffer}`);

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
            //console.warn(`Price data missing for ${fromSymbol} (${fromPriceUSD}) or ${toSymbol} (${toPriceUSD})`);
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

        // console.log(`Percent difference: ${percentDiff.toFixed(2)}%`);
        resolve(percentDiff);
    });
}

async function getMarketRate(fromCoin, toCoin) {
    return new Promise((resolve) => {
        //console.log(`Attempting to get market rate for ${fromCoin} to ${toCoin}`);
        if (!latestPrices) {
            //console.warn('Latest prices object is not available');
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
            //console.warn(`Missing price data for ${!fromPrice ? fromCoin : toCoin}`);
            resolve(null);
            return;
        }
        const rate = toPrice / fromPrice;
        //console.log(`Market rate calculated: ${rate} ${toCoin}/${fromCoin}`);
        resolve(rate);
    });
}

async function fetchLatestPrices() {
    const PRICES_CACHE_KEY = 'prices_coingecko';

    const cachedData = CacheManager.get(PRICES_CACHE_KEY);
    if (cachedData && cachedData.remainingTime > 60000) {
        console.log('Using cached price data (valid for next minute)');
        latestPrices = cachedData.value;
        return cachedData.value;
    }

    const url = `${config.apiEndpoints.coinGecko}/simple/price?ids=bitcoin,bitcoin-cash,dash,dogecoin,decred,litecoin,particl,pivx,monero,zano,wownero,zcoin&vs_currencies=USD,BTC&api_key=${config.apiKeys.coinGecko}`;

    try {
        console.log('Fetching fresh price data...');
        const response = await fetch('/json/readurl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                url: url,
                headers: {}
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        if (data.Error) {
            throw new Error(data.Error);
        }

        if (data && Object.keys(data).length > 0) {
            console.log('Fresh price data received');

            latestPrices = data;

            CacheManager.set(PRICES_CACHE_KEY, data, CACHE_DURATION);

            Object.entries(data).forEach(([coin, prices]) => {
                tableRateModule.setFallbackValue(coin, prices.usd);
            });

            return data;
        } else {
            //console.warn('Received empty price data');
        }
    } catch (error) {
        //console.error('Error fetching prices:', error);
        throw error;
    }

    return latestPrices || null;
}

async function fetchOffers(manualRefresh = false) {
    const refreshButton = document.getElementById('refreshOffers');
    const refreshIcon = document.getElementById('refreshIcon');
    const refreshText = document.getElementById('refreshText');

    try {
        refreshButton.disabled = true;
        refreshIcon.classList.add('animate-spin');
        refreshText.textContent = 'Refreshing...';
        refreshButton.classList.add('opacity-75', 'cursor-wait');

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
        stopRefreshAnimation();
    }
}

function formatInitialData(data) {
    return data.map(offer => ({
        offer_id: String(offer.offer_id || ''),
        swap_type: String(offer.swap_type || 'N/A'),
        addr_from: String(offer.addr_from || ''),
        addr_to: String(offer.addr_to || ''),
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
        is_public: offer.is_public !== undefined ? Boolean(offer.is_public) : false,
        unique_id: `${offer.offer_id}_${offer.created_at}_${offer.coin_from}_${offer.coin_to}`
    }));
}

// UI COMPONENT FUNCTIONS
function updateConnectionStatus(status) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (!dot || !text) {
        //console.warn('Status indicators not found in DOM');
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

function updateRowTimes() {
    requestAnimationFrame(() => {
        const rows = document.querySelectorAll('[data-offer-id]');
        rows.forEach(row => {
            const offerId = row.getAttribute('data-offer-id');
            const offer = jsonData.find(o => o.offer_id === offerId);
            if (!offer) return;

            const newPostedTime = formatTime(offer.created_at, true);
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

function stopRefreshAnimation() {
    const refreshButton = document.getElementById('refreshOffers');
    const refreshIcon = document.getElementById('refreshIcon');
    const refreshText = document.getElementById('refreshText');

    if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.classList.remove('opacity-75', 'cursor-wait');
    }
    if (refreshIcon) {
        refreshIcon.classList.remove('animate-spin');
    }
    if (refreshText) {
        refreshText.textContent = 'Refresh';
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

function updateProfitLoss(row, fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
    const profitLossElement = row.querySelector('.profit-loss');
    if (!profitLossElement) {
        //console.warn('Profit loss element not found in row');
        return;
    }

    if (!fromCoin || !toCoin) {
        //console.error(`Invalid coin names: fromCoin=${fromCoin}, toCoin=${toCoin}`);
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
            //console.error('Error in updateProfitLoss:', error);
            profitLossElement.textContent = 'Error';
            profitLossElement.className = 'profit-loss text-lg font-bold text-red-500';
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

function updateClearFiltersButton() {
    const clearButton = document.getElementById('clearFilters');
    if (clearButton) {
        const hasFilters = hasActiveFilters();
        clearButton.classList.toggle('opacity-50', !hasFilters);
        clearButton.disabled = !hasFilters;

        // Update button styles based on state
        if (hasFilters) {
            clearButton.classList.add('hover:bg-green-600', 'hover:text-white');
            clearButton.classList.remove('cursor-not-allowed');
        } else {
            clearButton.classList.remove('hover:bg-green-600', 'hover:text-white');
            clearButton.classList.add('cursor-not-allowed');
        }
    }
}

function handleNoOffersScenario() {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    const hasActiveFilters = filters.coin_to !== 'any' ||
                            filters.coin_from !== 'any' ||
                            (filters.status && filters.status !== 'any');

    stopRefreshAnimation();

    if (hasActiveFilters) {
        offersBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-8">
                    <div class="flex items-center justify-center text-gray-500 dark:text-white">
                        No offers match the selected filters. Try different filter options or
                        <button onclick="clearFilters()" class="ml-1 text-blue-500 hover:text-blue-700 font-semibold">
                            clear filters
                        </button>
                    </div>
                </td>
            </tr>`;
    } else {
        offersBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-8 text-gray-500 dark:text-white">
                    No active offers available.
                </td>
            </tr>`;
    }
}

async function updateOffersTable() {
    try {
        const PRICES_CACHE_KEY = 'prices_coingecko';
        const cachedPrices = CacheManager.get(PRICES_CACHE_KEY);

        if (!cachedPrices || !cachedPrices.remainingTime || cachedPrices.remainingTime < 60000) {
            console.log('Fetching fresh price data...');
            const priceData = await fetchLatestPrices();
            if (priceData) {
                latestPrices = priceData;
            }
        } else {
            latestPrices = cachedPrices.value;
        }

        const validOffers = getValidOffers();

        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, validOffers.length);
        const itemsToDisplay = validOffers.slice(startIndex, endIndex);

        const identityPromises = itemsToDisplay.map(offer =>
            offer.addr_from ? getIdentityData(offer.addr_from) : Promise.resolve(null)
        );

        const identities = await Promise.all(identityPromises);

        if (validOffers.length === 0) {
            handleNoOffersScenario();
            return;
        }

        const totalPages = Math.max(1, Math.ceil(validOffers.length / itemsPerPage));
        currentPage = Math.min(currentPage, totalPages);

        const fragment = document.createDocumentFragment();

        itemsToDisplay.forEach((offer, index) => {
            const identity = identities[index];
            const row = createTableRow(offer, identity);
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
            newEntriesCountSpan.textContent = validOffers.length;
        }
        if (lastRefreshTimeSpan) {
            lastRefreshTimeSpan.textContent = new Date(lastRefreshTime).toLocaleTimeString();
        }

    } catch (error) {
        console.error('[Debug] Error in updateOffersTable:', error);
        offersBody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-red-500">
                    An error occurred while updating the offers table. Please try again later.
                </td>
            </tr>`;
    }
}

async function getIdentityData(address) {
    try {
        const response = await fetch(`/json/identities/${address}`);
        if (!response.ok) {
            return null;
        }
        return await response.json();
    } catch (error) {
        console.error('Error fetching identity:', error);
        return null;
    }
}

function getIdentityInfo(address, identity) {
    if (!identity) {
        return {
            displayAddr: address ? `${address.substring(0, 10)}...` : 'Unspecified',
            fullAddress: address || '',
            label: '',
            note: '',
            automationOverride: 0,
            stats: {
                sentBidsSuccessful: 0,
                recvBidsSuccessful: 0,
                sentBidsRejected: 0,
                recvBidsRejected: 0,
                sentBidsFailed: 0,
                recvBidsFailed: 0
            }
        };
    }

    return {
        displayAddr: address ? `${address.substring(0, 10)}...` : 'Unspecified',
        fullAddress: address || '',
        label: identity.label || '',
        note: identity.note || '',
        automationOverride: identity.automation_override || 0,
        stats: {
            sentBidsSuccessful: identity.num_sent_bids_successful || 0,
            recvBidsSuccessful: identity.num_recv_bids_successful || 0,
            sentBidsRejected: identity.num_sent_bids_rejected || 0,
            recvBidsRejected: identity.num_recv_bids_rejected || 0,
            sentBidsFailed: identity.num_sent_bids_failed || 0,
            recvBidsFailed: identity.num_recv_bids_failed || 0
        }
    };
}

function createTableRow(offer, identity = null) {
    const row = document.createElement('tr');
    const uniqueId = `${offer.offer_id}_${offer.created_at}`;

    row.className = 'relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600';
    row.setAttribute('data-offer-id', uniqueId);

    const {
        coin_from: coinFrom,
        coin_to: coinTo,
        created_at: createdAt,
        expire_at: expireAt,
        amount_from: amountFrom,
        amount_to: amountTo,
        is_own_offer: isOwnOffer,
        is_revoked: isRevoked,
        is_public: isPublic
    } = offer;

    const coinFromSymbol = coinNameToSymbol[coinFrom] || coinFrom.toLowerCase();
    const coinToSymbol = coinNameToSymbol[coinTo] || coinTo.toLowerCase();
    const coinFromDisplay = getDisplayName(coinFrom);
    const coinToDisplay = getDisplayName(coinTo);
    const postedTime = formatTime(createdAt, true);
    const expiresIn = formatTime(expireAt);

    const currentTime = Math.floor(Date.now() / 1000);
    const isActuallyExpired = currentTime > expireAt;
    const fromAmount = parseFloat(amountFrom) || 0;
    const toAmount = parseFloat(amountTo) || 0;

    // Build row content
    row.innerHTML = `
        ${!isPublic ? createPrivateIndicator() : '<td class="w-0 p-0 m-0"></td>'}
        ${createTimeColumn(offer, postedTime, expiresIn)}
        ${createDetailsColumn(offer, identity)}
        ${createTakerAmountColumn(offer, coinTo, coinFrom)}
        ${createSwapColumn(offer, coinFromDisplay, coinToDisplay, coinFromSymbol, coinToSymbol)}
        ${createOrderbookColumn(offer, coinFrom, coinTo)}
        ${createRateColumn(offer, coinFrom, coinTo)}
        ${createPercentageColumn(offer)}
        ${createActionColumn(offer, isActuallyExpired)}
        ${createTooltips(
            offer,
            isOwnOffer,
            coinFrom,
            coinTo,
            fromAmount,
            toAmount,
            postedTime,
            expiresIn,
            isActuallyExpired,
            Boolean(isRevoked),
            identity
        )}
    `;

    updateTooltipTargets(row, uniqueId);
    updateProfitLoss(row, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer);

    return row;
}

function createPrivateIndicator() {
    return `<td class="relative w-0 p-0 m-0">
        <div class="absolute top-0 bottom-0 left-0 w-1 bg-red-700" style="min-height: 100%;"></div>
    </td>`;
}

function createTimeColumn(offer, postedTime, expiresIn) {
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = offer.expire_at - now;

    let strokeColor = '#10B981'; // Default green for > 30 min
    if (timeLeft <= 300) {
        strokeColor = '#9CA3AF'; // Grey for 5 min or less
    } else if (timeLeft <= 1800) {
        strokeColor = '#3B82F6'; // Blue for 5-30 min
    }

    return `
        <td class="py-3 pl-1 pr-2 text-xs whitespace-nowrap">
            <div class="flex items-center">
                <div class="relative" data-tooltip-target="tooltip-active${escapeHtml(offer.offer_id)}">
                    <svg alt="" class="w-5 h-5 rounded-full mr-4 cursor-pointer" xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 24 24">
                        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${strokeColor}" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="11"></circle>
                            <polyline points="12,6 12,12 18,12" stroke="${strokeColor}"></polyline>
                        </g>
                    </svg>
                </div>
                <div class="flex flex-col hidden xl:block">
                    <div class="text-xs whitespace-nowrap"><span class="bold">Posted:</span> ${escapeHtml(postedTime)}</div>
                    <div class="text-xs whitespace-nowrap"><span class="bold">Expires in:</span> ${escapeHtml(expiresIn)}</div>
                </div>
            </div>
        </td>
    `;
}

function shouldShowPublicTag(offers) {
    return offers.some(offer => !offer.is_public);
}

function truncateText(text, maxLength = 15) {
    if (typeof text !== 'string') return '';
    return text.length > maxLength
        ? text.slice(0, maxLength) + '...'
        : text;
}

function createDetailsColumn(offer, identity = null) {
    const addrFrom = offer.addr_from || '';
    const identityInfo = getIdentityInfo(addrFrom, identity);

    const showPublicPrivateTags = originalJsonData.some(o => o.is_public !== offer.is_public);

    const tagClass = offer.is_public
        ? 'bg-green-600 dark:bg-green-600'
        : 'bg-red-500 dark:bg-red-500';
    const tagText = offer.is_public ? 'Public' : 'Private';

    const displayIdentifier = truncateText(
        identityInfo.label || addrFrom || 'Unspecified'
    );

    const identifierTextClass = identityInfo.label
        ? 'text-white dark:text-white'
        : 'monospace';

    return `
        <td class="py-8 px-4 text-xs text-left hidden xl:block">
            <div class="flex flex-col gap-2 relative">
                ${showPublicPrivateTags ? `<span class="inline-flex pl-6 pr-6 py-1 justify-center text-[10px] w-1/4 font-medium text-gray-100 rounded-md ${tagClass}">${tagText}</span>
                ` : ''}

                <a data-tooltip-target="tooltip-recipient-${escapeHtml(offer.offer_id)}" href="/identity/${escapeHtml(addrFrom)}" class="flex items-center">
                    <svg class="w-4 h-4 mr-2 text-gray-400 dark:text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                     <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="${identifierTextClass} font-semibold">
                        ${escapeHtml(displayIdentifier)}
                    </span>
                </a>
            </div>
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

function createActionColumn(offer, isActuallyExpired = false) {
    const isRevoked = Boolean(offer.is_revoked);
    const isTreatedAsSentOffer = offer.is_own_offer;

    let buttonClass, buttonText;

    if (isRevoked) {
        buttonClass = 'bg-red-500 text-white hover:bg-red-600 transition duration-200';
        buttonText = 'Revoked';
    } else if (isActuallyExpired && isSentOffers) {
        buttonClass = 'bg-gray-400 text-white dark:border-gray-300 text-white hover:bg-red-700 transition duration-200';
        buttonText = 'Expired';
    } else if (isTreatedAsSentOffer) {
        buttonClass = 'bg-gray-300 bold text-white bold hover:bg-green-600 transition duration-200';
        buttonText = 'Edit';
    } else {
        buttonClass = 'bg-blue-500 text-white hover:bg-green-600 transition duration-200';
        buttonText = 'Swap';
    }

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

// TOOLTIP FUNCTIONS
function createTooltips(offer, treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired, isRevoked, identity = null) {
    const rate = parseFloat(offer.rate);
    const fromSymbol = getCoinSymbolLowercase(coinFrom);
    const toSymbol = getCoinSymbolLowercase(coinTo);
    const uniqueId = `${offer.offer_id}_${offer.created_at}`;

    const addrFrom = offer.addr_from || '';
    const identityInfo = getIdentityInfo(addrFrom, identity);

    const totalBids = identity ? (
        identityInfo.stats.sentBidsSuccessful +
        identityInfo.stats.recvBidsSuccessful +
        identityInfo.stats.sentBidsFailed +
        identityInfo.stats.recvBidsFailed +
        identityInfo.stats.sentBidsRejected +
        identityInfo.stats.recvBidsRejected
    ) : 0;

    const successRate = totalBids ? (
        ((identityInfo.stats.sentBidsSuccessful + identityInfo.stats.recvBidsSuccessful) / totalBids) * 100
    ).toFixed(1) : 0;

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

        <div id="tooltip-wallet-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
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

        <div id="tooltip-wallet-maker-${uniqueId}" role="tooltip" class="inline-block absolute invisible z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
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

        ${createRecipientTooltip(uniqueId, identityInfo, identity, successRate, totalBids)}
    `;
}

function createRecipientTooltip(uniqueId, identityInfo, identity, successRate, totalBids) {

    const getSuccessRateColor = (rate) => {
        if (rate >= 80) return 'text-green-600';
        if (rate >= 60) return 'text-yellow-600';
        return 'text-red-600';
    };


    const truncateText = (text, maxLength) => {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    };

    return `
        <div id="tooltip-recipient-${uniqueId}" role="tooltip"
            class="fixed z-50 py-3 px-4 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip max-w-sm pointer-events-none">
            <div class="identity-info space-y-2">
                ${identityInfo.label ? `
                    <div class="border-b border-gray-400 pb-2">
                        <div class="text-white text-xs tracking-wide font-semibold">Label:</div>
                        <div class="text-white">${escapeHtml(identityInfo.label)}</div>
                    </div>
                ` : ''}

                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Recipient Address:</div>
                    <div class="monospace text-xs break-all bg-gray-500 p-2 rounded-md text-white">
                        ${escapeHtml(identityInfo.fullAddress)}
                    </div>
                </div>

                ${identityInfo.note ? `
                    <div class="space-y-1 hidden">
                        <div class="text-white text-xs tracking-wide font-semibold">Note:</div>
                        <div class="text-white text-sm italic" title="${escapeHtml(identityInfo.note)}">
                            ${escapeHtml(truncateText(identityInfo.note, 150))}
                        </div>
                    </div>
                ` : ''}

                ${identity ? `
                    <div class="border-t border-gray-400 pt-2 mt-2">
                        <div class="text-white text-xs tracking-wide font-semibold mb-2">Swap History:</div>
                        <div class="grid grid-cols-2 gap-2">
                            <div class="text-center p-2 bg-gray-500 rounded-md">
                                <div class="text-lg font-bold ${getSuccessRateColor(successRate)}">${successRate}%</div>
                                <div class="text-xs text-white">Success Rate</div>
                            </div>
                            <div class="text-center p-2 bg-gray-500 rounded-md">
                                <div class="text-lg font-bold text-blue-500">${totalBids}</div>
                                <div class="text-xs text-white">Total Trades</div>
                            </div>
                        </div>
                        <div class="grid grid-cols-3 gap-2 mt-2 text-center text-xs">
                            <div>
                                <div class="text-green-600 font-semibold">
                                    ${identityInfo.stats.sentBidsSuccessful + identityInfo.stats.recvBidsSuccessful}
                                </div>
                                <div class="text-white">Successful</div>
                            </div>
                            <div>
                                <div class="text-yellow-600 font-semibold">
                                    ${identityInfo.stats.sentBidsRejected + identityInfo.stats.recvBidsRejected}
                                </div>
                                <div class="text-white">Rejected</div>
                            </div>
                            <div>
                                <div class="text-red-600 font-semibold">
                                    ${identityInfo.stats.sentBidsFailed + identityInfo.stats.recvBidsFailed}
                                </div>
                                <div class="text-white">Failed</div>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
            <div class="tooltip-arrow" data-popper-arrow></div>
        </div>`;
}

function createTooltipContent(isSentOffers, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer) {
    if (!coinFrom || !coinTo) {
        //console.error(`Invalid coin names: coinFrom=${coinFrom}, coinTo=${coinTo}`);
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

// FILTER FUNCTIONS
function applyFilters() {
    if (filterTimeout) {
        clearTimeout(filterTimeout);
        filterTimeout = null;
    }

    try {
        filterTimeout = setTimeout(() => {
            jsonData = filterAndSortData();
            updateOffersTable();
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

function clearFilters() {

    filterForm.reset();

    const selectElements = filterForm.querySelectorAll('select');
    selectElements.forEach(select => {
        select.value = 'any';
        // Trigger change event
        const event = new Event('change', { bubbles: true });
        select.dispatchEvent(event);
    });

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

function hasActiveFilters() {
    const formData = new FormData(filterForm);
    const filters = {
        coin_to: formData.get('coin_to'),
        coin_from: formData.get('coin_from'),
        status: formData.get('status')
    };

    const selectElements = filterForm.querySelectorAll('select');
    let hasChangedFilters = false;

    selectElements.forEach(select => {
        if (select.value !== 'any') {
            hasChangedFilters = true;
        }
    });

    return hasChangedFilters;
}
// UTILITY FUNCTIONS
function formatTimeLeft(timestamp) {
    const now = Math.floor(Date.now() / 1000);
    if (timestamp <= now) return "Expired";
    return formatTime(timestamp);
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
        //console.warn('Invalid coin input:', coin);
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

function formatTime(timestamp, addAgoSuffix = false) {
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
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') {
        //console.warn('escapeHtml received a non-string value:', unsafe);
        return '';
    }
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function getCoinSymbol(fullName) {
    const symbolMap = {
        'Bitcoin': 'BTC', 'Litecoin': 'LTC', 'Monero': 'XMR',
        'Particl': 'PART', 'Particl Blind': 'PART', 'Particl Anon': 'PART',
        'PIVX': 'PIVX', 'Firo': 'FIRO', 'Zcoin': 'FIRO',
        'Dash': 'DASH', 'Decred': 'DCR', 'Wownero': 'WOW',
        'Bitcoin Cash': 'BCH', 'Dogecoin': 'DOGE'
    };
    return symbolMap[fullName] || fullName;
}

// EVENT LISTENERS
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

const eventListeners = {
    listeners: [],

    add(element, eventType, handler, options = false) {
        element.addEventListener(eventType, handler, options);
        this.listeners.push({ element, eventType, handler, options });
        // console.log(`Added ${eventType} listener to`, element);
    },

    addWindowListener(eventType, handler, options = false) {
        window.addEventListener(eventType, handler, options);
        this.listeners.push({ element: window, eventType, handler, options });
        // console.log(`Added ${eventType} window listener`);
    },

    removeAll() {
        console.log('Removing all event listeners...');
        this.listeners.forEach(({ element, eventType, handler, options }) => {
            element.removeEventListener(eventType, handler, options);
            //console.log(`Removed ${eventType} listener from`, element);
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
};

// TIMER MANAGEMENT
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

// INITIALIZATION AND EVENT BINDING
document.addEventListener('DOMContentLoaded', () => {
    //console.log('DOM content loaded, initializing...');
    console.log('View type:', isSentOffers ? 'sent offers' : 'received offers');

    updateClearFiltersButton();

    // Add event listeners for filter controls
    const selectElements = filterForm.querySelectorAll('select');
    selectElements.forEach(select => {
        select.addEventListener('change', () => {
            updateClearFiltersButton();
        });
    });

    filterForm.addEventListener('change', () => {
        applyFilters();
        updateClearFiltersButton();
    });

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
                //console.error('Failed to load tableRateModule after multiple attempts');
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

        const refreshButton = document.getElementById('refreshOffers');
        const refreshIcon = document.getElementById('refreshIcon');
        const refreshText = document.getElementById('refreshText');

        refreshButton.disabled = true;
        refreshIcon.classList.add('animate-spin');
        refreshText.textContent = 'Refreshing...';
        refreshButton.classList.add('opacity-75', 'cursor-wait');

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

            console.log(' Manual refresh completed successfully');

        } catch (error) {
            console.error('Error during manual refresh:', error);
            ui.displayErrorMessage('Failed to refresh offers. Please try again later.');
        } finally {
            refreshButton.disabled = false;
            refreshIcon.classList.remove('animate-spin');
            refreshText.textContent = 'Refresh';
            refreshButton.classList.remove('opacity-75', 'cursor-wait');
        }
    });

    eventListeners.add(prevPageButton, 'click', () => {
        if (currentPage > 1) {
            currentPage--;
            const validOffers = getValidOffers();
            const totalPages = Math.ceil(validOffers.length / itemsPerPage);
            updateOffersTable();
            updatePaginationControls(totalPages);
        }
    });

    eventListeners.add(nextPageButton, 'click', () => {
        const validOffers = getValidOffers();
        const totalPages = Math.ceil(validOffers.length / itemsPerPage);
        if (currentPage < totalPages) {
            currentPage++;
            updateOffersTable();
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
        //console.log('Initial offers fetched');
        applyFilters();
    }).catch(error => {
        console.error('Error fetching initial offers:', error);
    });

    const listingLabel = document.querySelector('span[data-listing-label]');
    if (listingLabel) {
        listingLabel.textContent = isSentOffers ? 'Total Listings: ' : 'Network Listings: ';
    }

    timerManager.addInterval(updateRowTimes, 900000);

    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            console.log('Page became visible, checking WebSocket connection');
            if (!WebSocketManager.isConnected()) {
                WebSocketManager.connect();
            }
        }
    });

    console.log('Initialization completed');
});

console.log('Offers Table Module fully initialized');
