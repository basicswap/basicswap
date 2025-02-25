// Constants and State
const PAGE_SIZE = 50;
const state = {
    currentPage: {
        sent: 1,
        received: 1
    },
    isLoading: false,
    isRefreshing: false,
    currentTab: 'sent',
    wsConnected: false,
    refreshPromise: null,
    data: {
        sent: [],
        received: []
    },
    filters: {
        state: -1,
        sort_by: 'created_at',
        sort_dir: 'desc',
        with_expired: true,
        searchQuery: '',
        coin_from: 'any',
        coin_to: 'any'
    }
};

const STATE_MAP = {
    1: ['Sent'],
    2: ['Receiving'],
    3: ['Received'],
    4: ['Receiving accept'],
    5: ['Accepted'],
    6: ['Initiated'],
    7: ['Participating'],
    8: ['Completed'],
    9: ['Script coin locked'],
    10: ['Script coin spend tx valid'],
    11: ['Scriptless coin locked'],
    12: ['Script coin lock released'],
    13: ['Script tx redeemed'],
    14: ['Script pre-refund tx in chain'],
    15: ['Scriptless tx redeemed'],
    16: ['Scriptless tx recovered'],
    17: ['Failed, refunded'],
    18: ['Failed, swiped'],
    19: ['Failed'],
    20: ['Delaying'],
    21: ['Timed-out', 'Expired'],
    22: ['Abandoned'],
    23: ['Error'],
    24: ['Stalled (debug)'],
    25: ['Rejected'],
    26: ['Unknown bid state'],
    27: ['Exchanged script lock tx sigs msg'],
    28: ['Exchanged script lock spend tx msg'],
    29: ['Request sent'],
    30: ['Request accepted'],
    31: ['Expired'],
    32: ['Auto accept delay'],
    33: ['Auto accept failed']
};

const elements = {
    sentBidsBody: document.querySelector('#sent tbody'),
    receivedBidsBody: document.querySelector('#received tbody'),
    filterForm: document.querySelector('form'),
    stateSelect: document.querySelector('select[name="state"]'),
    sortBySelect: document.querySelector('select[name="sort_by"]'),
    sortDirSelect: document.querySelector('select[name="sort_dir"]'),
    withExpiredSelect: document.querySelector('select[name="with_expired"]'),
    tabButtons: document.querySelectorAll('#myTab button'),
    sentContent: document.getElementById('sent'),
    receivedContent: document.getElementById('received'),

    sentPaginationControls: document.getElementById('pagination-controls-sent'),
    receivedPaginationControls: document.getElementById('pagination-controls-received'),
    prevPageSent: document.getElementById('prevPageSent'),
    nextPageSent: document.getElementById('nextPageSent'),
    prevPageReceived: document.getElementById('prevPageReceived'),
    nextPageReceived: document.getElementById('nextPageReceived'),
    currentPageSent: document.getElementById('currentPageSent'),
    currentPageReceived: document.getElementById('currentPageReceived'),
    sentBidsCount: document.getElementById('sentBidsCount'),
    receivedBidsCount: document.getElementById('receivedBidsCount'),

    statusDotSent: document.getElementById('status-dot-sent'),
    statusTextSent: document.getElementById('status-text-sent'),
    statusDotReceived: document.getElementById('status-dot-received'),
    statusTextReceived: document.getElementById('status-text-received'),

    refreshSentBids: document.getElementById('refreshSentBids'),
    refreshReceivedBids: document.getElementById('refreshReceivedBids')
};

const EventManager = {
    listeners: new Map(),

    add(element, type, handler, options = false) {
        if (!element) return null;
        
        if (!this.listeners.has(element)) {
            this.listeners.set(element, new Map());
        }

        const elementListeners = this.listeners.get(element);
        if (!elementListeners.has(type)) {
            elementListeners.set(type, new Set());
        }

        const handlerInfo = { handler, options };
        elementListeners.get(type).add(handlerInfo);
        element.addEventListener(type, handler, options);

        return handlerInfo;
    },

    remove(element, type, handler, options = false) {
        if (!element) return;
        
        const elementListeners = this.listeners.get(element);
        if (!elementListeners) return;

        const typeListeners = elementListeners.get(type);
        if (!typeListeners) return;

        typeListeners.forEach(info => {
            if (info.handler === handler) {
                element.removeEventListener(type, handler, options);
                typeListeners.delete(info);
            }
        });

        if (typeListeners.size === 0) {
            elementListeners.delete(type);
        }
        if (elementListeners.size === 0) {
            this.listeners.delete(element);
        }
    },

    removeAll(element) {
        if (!element) return;
        
        const elementListeners = this.listeners.get(element);
        if (!elementListeners) return;

        elementListeners.forEach((typeListeners, type) => {
            typeListeners.forEach(info => {
                try {
                    element.removeEventListener(type, info.handler, info.options);
                } catch (e) {
                    console.warn('Error removing event listener:', e);
                }
            });
        });

        this.listeners.delete(element);
    },

    clearAll() {
        this.listeners.forEach((elementListeners, element) => {
            this.removeAll(element);
        });
        this.listeners.clear();
    }
};

function cleanup() {
    console.log('Starting cleanup process');
    EventManager.clearAll();

    const exportSentButton = document.getElementById('exportSentBids');
    const exportReceivedButton = document.getElementById('exportReceivedBids');

    if (exportSentButton) {
        exportSentButton.remove();
    }

    if (exportReceivedButton) {
        exportReceivedButton.remove();
    }

    if (window.TooltipManager) {
    const originalCleanup = window.TooltipManager.cleanup;
    window.TooltipManager.cleanup = function() {
        originalCleanup.call(window.TooltipManager);

        setTimeout(() => {
            forceTooltipDOMCleanup();

            const detachedTooltips = document.querySelectorAll('[id^="tooltip-"]');
            detachedTooltips.forEach(tooltip => {
                const tooltipId = tooltip.id;
                const trigger = document.querySelector(`[data-tooltip-target="${tooltipId}"]`);
                if (!trigger || !document.body.contains(trigger)) {
                    tooltip.remove();
                }
            });
        }, 10);
    };
}

    WebSocketManager.cleanup();
    if (searchTimeout) {
        clearTimeout(searchTimeout);
        searchTimeout = null;
    }
    state.data = {
        sent: [],
        received: []
    };
    IdentityManager.clearCache();
    Object.keys(elements).forEach(key => {
        elements[key] = null;
    });
    
    console.log('Cleanup completed');
}

document.addEventListener('beforeunload', cleanup);
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        WebSocketManager.pause();
    } else {
        WebSocketManager.resume();
    }
});

// WebSocket Management
const WebSocketManager = {
    ws: null,
    processingQueue: false,
    reconnectTimeout: null,
    maxReconnectAttempts: 5,
    reconnectAttempts: 0,
    reconnectDelay: 5000,
    healthCheckInterval: null,
    isPaused: false,
    lastMessageTime: Date.now(),
    
    initialize() {
        this.connect();
        this.startHealthCheck();
    },

    isConnected() {
        return this.ws?.readyState === WebSocket.OPEN;
    },

    connect() {
        if (this.isConnected() || this.isPaused) return;

        if (this.ws) {
            this.cleanupConnection();
        }

        try {
            const wsPort = window.ws_port || '11700';
            this.ws = new WebSocket(`ws://${window.location.hostname}:${wsPort}`);
            this.setupEventHandlers();
        } catch (error) {
            console.error('WebSocket connection error:', error);
            this.handleReconnect();
        }
    },

    setupEventHandlers() {
        if (!this.ws) return;
        
        this.ws.onopen = () => {
            state.wsConnected = true;
            this.reconnectAttempts = 0;
            this.lastMessageTime = Date.now();
            updateConnectionStatus('connected');
            console.log('🟢  WebSocket connection established for Sent Bids / Received Bids');
            updateBidsTable();
        };

        this.ws.onmessage = () => {
            this.lastMessageTime = Date.now();
            if (this.isPaused) return;
            
            if (!this.processingQueue) {
                this.processingQueue = true;
                setTimeout(async () => {
                    try {
                        if (!state.isRefreshing) {
                            await updateBidsTable();
                        }
                    } finally {
                        this.processingQueue = false;
                    }
                }, 200);
            }
        };

        this.ws.onclose = () => {
            state.wsConnected = false;
            updateConnectionStatus('disconnected');
            if (!this.isPaused) {
                this.handleReconnect();
            }
        };

        this.ws.onerror = () => {
            updateConnectionStatus('error');
        };
    },

    startHealthCheck() {
        this.stopHealthCheck();
        
        this.healthCheckInterval = setInterval(() => {
            if (this.isPaused) return;

            const timeSinceLastMessage = Date.now() - this.lastMessageTime;
            if (timeSinceLastMessage > 120000) {
                console.log('WebSocket connection appears stale. Reconnecting...');
                this.cleanupConnection();
                this.connect();
                return;
            }
            
            if (!this.isConnected()) {
                this.handleReconnect();
            }
        }, 30000);
    },

    stopHealthCheck() {
        if (this.healthCheckInterval) {
            clearInterval(this.healthCheckInterval);
            this.healthCheckInterval = null;
        }
    },

    handleReconnect() {
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }

        if (this.isPaused) return;

        this.reconnectAttempts++;
        if (this.reconnectAttempts <= this.maxReconnectAttempts) {
            const delay = this.reconnectDelay * Math.pow(1.5, this.reconnectAttempts - 1);
            //console.log(`Attempting to reconnect in ${delay}ms (attempt ${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
            this.reconnectTimeout = setTimeout(() => this.connect(), delay);
        } else {
            updateConnectionStatus('error');
            //console.log('Maximum reconnection attempts reached. Will try again in 60 seconds.');
            setTimeout(() => {
                this.reconnectAttempts = 0;
                this.connect();
            }, 60000);
        }
    },

    cleanupConnection() {
        if (this.ws) {
            this.ws.onopen = null;
            this.ws.onmessage = null;
            this.ws.onclose = null;
            this.ws.onerror = null;
            if (this.ws.readyState === WebSocket.OPEN) {
                try {
                    this.ws.close(1000, 'Cleanup');
                } catch (e) {
                    console.warn('Error closing WebSocket:', e);
                }
            }
            this.ws = null;
        }
    },

    pause() {
        this.isPaused = true;
        //console.log('WebSocket operations paused');
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }
    },

    resume() {
        if (!this.isPaused) return;
        this.isPaused = false;
        //console.log('WebSocket operations resumed');
        this.lastMessageTime = Date.now();
        if (!this.isConnected()) {
            this.reconnectAttempts = 0;
            this.connect();
        }
    },

    cleanup() {
        this.isPaused = true;
        this.stopHealthCheck();
        if (this.reconnectTimeout) {
            clearTimeout(this.reconnectTimeout);
            this.reconnectTimeout = null;
        }
        this.cleanupConnection();
    }
};

// Core
const safeParseInt = (value) => {
    const parsed = parseInt(value);
    return isNaN(parsed) ? 0 : parsed;
};

const formatAddress = (address, displayLength = 20) => {
    if (!address) return '';
    if (address.length <= displayLength) return address;
    return `${address.slice(8, displayLength)}...`;
};

const formatAddressSMSG = (address, displayLength = 14) => {
    if (!address) return '';
    if (address.length <= displayLength) return address;
    return `${address.slice(0, displayLength)}...`;
};

const formatTime = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
};

const getTimeStrokeColor = (expireTime) => {
    const now = Math.floor(Date.now() / 1000);
    return expireTime > now ? '#10B981' : '#9CA3AF';
};

const getStatusClass = (status) => {
    switch (status) {
        case 'Completed':
            return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
        case 'Expired':
        case 'Timed-out':
            return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-white';
        case 'Error':
        case 'Failed':
            return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
        case 'Failed, swiped':
        case 'Failed, refunded':
            return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-red-500';
        case 'InProgress':
        case 'Script coin locked':
        case 'Scriptless coin locked':
        case 'Script coin lock released':
        case 'SendingInitialTx':
        case 'SendingPaymentTx':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Received':
        case 'Exchanged script lock tx sigs msg':
        case 'Exchanged script lock spend tx msg':
        case 'Script tx redeemed':
        case 'Scriptless tx redeemed':
        case 'Scriptless tx recovered':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Accepted':
        case 'Request accepted':
            return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
        case 'Delaying':
        case 'Auto accept delay':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Abandoned':
        case 'Rejected':
            return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
        default:
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
    }
};

function coinMatches(offerCoin, filterCoin) {
    if (!offerCoin || !filterCoin || filterCoin === 'any') return true;

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

// State
function hasActiveFilters() {
    const coinFromSelect = document.getElementById('coin_from');
    const coinToSelect = document.getElementById('coin_to');
    const withExpiredSelect = document.getElementById('with_expired');
    const stateSelect = document.getElementById('state');
    const hasNonDefaultState = stateSelect && stateSelect.value !== '-1';
    const hasSearchQuery = state.filters.searchQuery.trim() !== '';
    const hasNonDefaultCoinFrom = coinFromSelect && coinFromSelect.value !== 'any';
    const hasNonDefaultCoinTo = coinToSelect && coinToSelect.value !== 'any';
    const hasNonDefaultExpired = withExpiredSelect && withExpiredSelect.value !== 'true';

    return hasNonDefaultState ||
           hasSearchQuery ||
           hasNonDefaultCoinFrom ||
           hasNonDefaultCoinTo ||
           hasNonDefaultExpired;
}

function filterAndSortData(bids) {
    if (!Array.isArray(bids)) {
        return [];
    }

    const expiredStates = ['Expired', 'Timed-out'];

    return bids.filter(bid => {
        if (state.filters.state !== -1) {
            const allowedStates = STATE_MAP[state.filters.state] || [];
            if (allowedStates.length > 0 && !allowedStates.includes(bid.bid_state)) {
                return false;
            }
        }

        if (!state.filters.with_expired && expiredStates.includes(bid.bid_state)) {
            return false;
        }

        if (state.filters.coin_from !== 'any') {
            const coinFromSelect = document.getElementById('coin_from');
            const selectedOption = coinFromSelect?.querySelector(`option[value="${state.filters.coin_from}"]`);
            const coinName = selectedOption?.textContent.trim();

            if (coinName) {
                const coinToMatch = state.currentTab === 'sent' ? bid.coin_to : bid.coin_from;
                if (!coinMatches(coinToMatch, coinName)) {
                    return false;
                }
            }
        }

        if (state.filters.coin_to !== 'any') {
            const coinToSelect = document.getElementById('coin_to');
            const selectedOption = coinToSelect?.querySelector(`option[value="${state.filters.coin_to}"]`);
            const coinName = selectedOption?.textContent.trim();

            if (coinName) {
                const coinToMatch = state.currentTab === 'sent' ? bid.coin_from : bid.coin_to;
                if (!coinMatches(coinToMatch, coinName)) {
                    return false;
                }
            }
        }

        if (state.filters.searchQuery) {
            const searchStr = state.filters.searchQuery.toLowerCase();
            const matchesBidId = bid.bid_id.toLowerCase().includes(searchStr);
            const matchesIdentity = bid.addr_from?.toLowerCase().includes(searchStr);
            const identity = IdentityManager.cache.get(bid.addr_from);
            const label = identity?.data?.label || '';
            const matchesLabel = label.toLowerCase().includes(searchStr);

            if (!(matchesBidId || matchesIdentity || matchesLabel)) {
                return false;
            }
        }

        return true;
    }).sort((a, b) => {
        if (state.filters.sort_by === 'created_at') {
            const direction = state.filters.sort_dir === 'asc' ? 1 : -1;
            return direction * (a.created_at - b.created_at);
        }
        return 0;
    });
}

function updateCoinFilterImages() {
    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');
    const coinToButton = document.getElementById('coin_to_button');
    const coinFromButton = document.getElementById('coin_from_button');

    function updateButtonImage(select, button) {
        if (!select || !button) return;

        const selectedOption = select.options[select.selectedIndex];
        const imagePath = selectedOption.getAttribute('data-image');

        if (imagePath && select.value !== 'any') {
            button.style.backgroundImage = `url(${imagePath})`;
            button.style.backgroundSize = '25px';
            button.style.backgroundRepeat = 'no-repeat';
            button.style.backgroundPosition = 'center';

        } else {
            button.style.backgroundImage = 'none';
            button.style.opacity = '1';
        }
    }

    updateButtonImage(coinToSelect, coinToButton);
    updateButtonImage(coinFromSelect, coinFromButton);
}

const updateLoadingState = (isLoading) => {
    state.isLoading = isLoading;

    ['Sent', 'Received'].forEach(type => {
        const refreshButton = elements[`refresh${type}Bids`];
        const refreshText = refreshButton?.querySelector(`#refresh${type}Text`);
        const refreshIcon = refreshButton?.querySelector('svg');

        if (refreshButton) {
            refreshButton.disabled = isLoading;
            if (isLoading) {
                refreshButton.classList.add('opacity-75', 'cursor-wait');
            } else {
                refreshButton.classList.remove('opacity-75', 'cursor-wait');
            }
        }

        if (refreshIcon) {
            if (isLoading) {
                refreshIcon.classList.add('animate-spin');
                refreshIcon.style.transform = 'rotate(0deg)';
            } else {
                refreshIcon.classList.remove('animate-spin');
                refreshIcon.style.transform = '';
            }
        }

        if (refreshText) {
            refreshText.textContent = isLoading ? 'Refreshing...' : 'Refresh';
        }
    });
};

const updateConnectionStatus = (status) => {
    const statusConfig = {
        connected: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-green-500 mr-2',
            textClass: 'text-sm text-green-500',
            message: 'Connected'
        },
        disconnected: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-red-500 mr-2',
            textClass: 'text-sm text-red-500',
            message: 'Disconnected - Reconnecting...'
        },
        error: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-yellow-500 mr-2',
            textClass: 'text-sm text-yellow-500',
            message: 'Connection Error'
        }
    };

    const config = statusConfig[status] || statusConfig.connected;

    ['sent', 'received'].forEach(type => {
        const dot = elements[`statusDot${type.charAt(0).toUpperCase() + type.slice(1)}`];
        const text = elements[`statusText${type.charAt(0).toUpperCase() + type.slice(1)}`];

        if (dot && text) {
            dot.className = config.dotClass;
            text.className = config.textClass;
            text.textContent = config.message;
        }
    });
};

// Identity
const IdentityManager = {
    cache: new Map(),
    pendingRequests: new Map(),
    retryDelay: 2000,
    maxRetries: 3,
    cacheTimeout: 5 * 60 * 1000,
    maxCacheSize: 500,

    async getIdentityData(address) {
        if (!address) return { address: '' };

        const cachedData = this.getCachedIdentity(address);
        if (cachedData) return { ...cachedData, address };

        if (this.pendingRequests.has(address)) {
            try {
                const pendingData = await this.pendingRequests.get(address);
                return { ...pendingData, address };
            } catch (error) {
                this.pendingRequests.delete(address);
            }
        }

        const request = this.fetchWithRetry(address);
        this.pendingRequests.set(address, request);

        try {
            const data = await request;

            this.trimCacheIfNeeded();

            this.cache.set(address, {
                data,
                timestamp: Date.now()
            });

            return { ...data, address };
        } catch (error) {
            console.warn(`Error fetching identity for ${address}:`, error);
            return { address };
        } finally {
            this.pendingRequests.delete(address);
        }
    },

    getCachedIdentity(address) {
        const cached = this.cache.get(address);
        if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
            cached.timestamp = Date.now();
            return cached.data;
        }
        if (cached) {
            this.cache.delete(address);
        }
        return null;
    },

    trimCacheIfNeeded() {
        if (this.cache.size > this.maxCacheSize) {

            const entries = Array.from(this.cache.entries());
            const sortedByAge = entries.sort((a, b) => a[1].timestamp - b[1].timestamp);

            const toRemove = Math.ceil(this.maxCacheSize * 0.2);
            for (let i = 0; i < toRemove && i < sortedByAge.length; i++) {
                this.cache.delete(sortedByAge[i][0]);
            }
            console.log(`Trimmed identity cache: removed ${toRemove} oldest entries`);
        }
    },

    clearCache() {
        this.cache.clear();
        this.pendingRequests.clear();
    },

    async fetchWithRetry(address, attempt = 1) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);
            
            const response = await fetch(`/json/identities/${address}`, { 
                signal: controller.signal 
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (error) {
            if (attempt >= this.maxRetries) {
                console.warn(`Failed to fetch identity for ${address} after ${attempt} attempts`);
                return { address };
            }
            await new Promise(resolve => setTimeout(resolve, this.retryDelay * attempt));
            return this.fetchWithRetry(address, attempt + 1);
        }
    }
};

// Stats
const processIdentityStats = (identity) => {
    if (!identity) return null;

    const stats = {
        sentSuccessful: safeParseInt(identity.num_sent_bids_successful),
        recvSuccessful: safeParseInt(identity.num_recv_bids_successful),
        sentFailed: safeParseInt(identity.num_sent_bids_failed),
        recvFailed: safeParseInt(identity.num_recv_bids_failed),
        sentRejected: safeParseInt(identity.num_sent_bids_rejected),
        recvRejected: safeParseInt(identity.num_recv_bids_rejected)
    };

    stats.totalSuccessful = stats.sentSuccessful + stats.recvSuccessful;
    stats.totalFailed = stats.sentFailed + stats.recvFailed;
    stats.totalRejected = stats.sentRejected + stats.recvRejected;
    stats.totalBids = stats.totalSuccessful + stats.totalFailed + stats.totalRejected;

    stats.successRate = stats.totalBids > 0
        ? ((stats.totalSuccessful / stats.totalBids) * 100).toFixed(1)
        : '0.0';

    return stats;
};

const createIdentityTooltipContent = (identity) => {
    if (!identity) return '';

    const stats = processIdentityStats(identity);
    if (!stats) return '';

    const getSuccessRateColor = (rate) => {
        const numRate = parseFloat(rate);
        if (numRate >= 80) return 'text-green-600';
        if (numRate >= 60) return 'text-yellow-600';
        return 'text-red-600';
    };

    return `
        <div class="identity-info space-y-2">
            ${identity.label ? `
                <div class="border-b border-gray-400 pb-2">
                    <div class="text-white text-xs tracking-wide font-semibold">Label:</div>
                    <div class="text-white">${identity.label}</div>
                </div>
            ` : ''}

            <div class="space-y-1">
                <div class="text-white text-xs tracking-wide font-semibold">Bid From Address:</div>
                <div class="monospace text-xs break-all bg-gray-500 p-2 rounded-md text-white">
                    ${identity.address || ''}
                </div>
            </div>

            ${identity.note ? `
                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Note:</div>
                    <div class="text-white text-sm italic">${identity.note}</div>
                </div>
            ` : ''}

            <div class="pt-2 mt-2">
                <div class="text-white text-xs tracking-wide font-semibold mb-2">Swap History:</div>
                <div class="grid grid-cols-2 gap-2">
                    <div class="text-center p-2 bg-gray-500 rounded-md">
                        <div class="text-lg font-bold ${getSuccessRateColor(stats.successRate)}">
                            ${stats.successRate}%
                        </div>
                        <div class="text-xs text-white">Success Rate</div>
                    </div>
                    <div class="text-center p-2 bg-gray-500 rounded-md">
                        <div class="text-lg font-bold text-blue-500">${stats.totalBids}</div>
                        <div class="text-xs text-white">Total Trades</div>
                    </div>
                </div>
                <div class="grid grid-cols-3 gap-2 mt-2 text-center text-xs">
                    <div>
                        <div class="text-green-600 font-semibold">
                            ${stats.totalSuccessful}
                        </div>
                        <div class="text-white">Successful</div>
                    </div>
                    <div>
                        <div class="text-yellow-600 font-semibold">
                            ${stats.totalRejected}
                        </div>
                        <div class="text-white">Rejected</div>
                    </div>
                    <div>
                        <div class="text-red-600 font-semibold">
                            ${stats.totalFailed}
                        </div>
                        <div class="text-white">Failed</div>
                    </div>
                </div>
            </div>
        </div>
    `;
};

// Table
let tooltipIdsToCleanup = new Set();

const cleanupTooltips = () => {
    if (window.TooltipManager) {
        Array.from(tooltipIdsToCleanup).forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.remove();
            }
        });
        tooltipIdsToCleanup.clear();
    }
    forceTooltipDOMCleanup();
};

const forceTooltipDOMCleanup = () => {
    let foundCount = 0;
    let removedCount = 0;
    const allTooltipElements = document.querySelectorAll('[role="tooltip"], [id^="tooltip-"], .tippy-box, [data-tippy-root]');
    foundCount += allTooltipElements.length;

    allTooltipElements.forEach(element => {

        const isDetached = !document.body.contains(element) || 
                           element.classList.contains('hidden') ||
                           element.style.display === 'none';

        if (element.id && element.id.startsWith('tooltip-')) {
            const triggerId = element.id;
            const triggerElement = document.querySelector(`[data-tooltip-target="${triggerId}"]`);

            if (!triggerElement || 
                !document.body.contains(triggerElement) ||
                triggerElement.classList.contains('hidden')) {
                element.remove();
                removedCount++;
                return;
            }
        }

        if (isDetached) {
            try {
                element.remove();
                removedCount++;
            } catch (e) {
                console.warn('Error removing detached tooltip:', e);
            }
        }
    });

    const tippyRoots = document.querySelectorAll('[data-tippy-root]');
    foundCount += tippyRoots.length;
    
    tippyRoots.forEach(element => {
        const isOrphan = !element.children.length || 
                         element.children[0].classList.contains('hidden') ||
                         !document.body.contains(element);

        if (isOrphan) {
            try {
                element.remove();
                removedCount++;
            } catch (e) {
                console.warn('Error removing tippy root:', e);
            }
        }
    });

    const tippyBoxes = document.querySelectorAll('.tippy-box');
    foundCount += tippyBoxes.length;
    tippyBoxes.forEach(element => {
        if (!element.parentElement || !document.body.contains(element.parentElement)) {
            try {
                element.remove();
                removedCount++;
            } catch (e) {
                console.warn('Error removing tippy box:', e);
            }
        }
    });
    
    // Handle legacy tooltip elements
    document.querySelectorAll('.tooltip').forEach(element => {
        const isTrulyDetached = !element.parentElement || 
                               !document.body.contains(element.parentElement) ||
                               element.classList.contains('hidden');

        if (isTrulyDetached) {
            try {
                element.remove();
                removedCount++;
            } catch (e) {
                console.warn('Error removing legacy tooltip:', e);
            }
        }
    });

    if (window.TooltipManager && window.TooltipManager.activeTooltips) {
        window.TooltipManager.activeTooltips.forEach((instance, id) => {
            const tooltipElement = document.getElementById(id.split('tooltip-trigger-')[1]);
            const triggerElement = document.querySelector(`[data-tooltip-trigger-id="${id}"]`);

            if (!tooltipElement || !triggerElement || 
                !document.body.contains(tooltipElement) || 
                !document.body.contains(triggerElement)) {
                if (instance?.[0]) {
                    try {
                        instance[0].destroy();
                    } catch (e) {
                        console.warn('Error destroying tooltip instance:', e);
                    }
                }
                window.TooltipManager.activeTooltips.delete(id);
            }
        });
    }
    if (removedCount > 0) {
       // console.log(`Tooltip cleanup: found ${foundCount}, removed ${removedCount} detached tooltips`);
    }
};

const createTableRow = async (bid) => {
    const identity = await IdentityManager.getIdentityData(bid.addr_from);
    const uniqueId = `${bid.bid_id}_${Date.now()}`;
    tooltipIdsToCleanup.add(`tooltip-identity-${uniqueId}`);
    tooltipIdsToCleanup.add(`tooltip-status-${uniqueId}`);
    const timeColor = getTimeStrokeColor(bid.expire_at);

    return `
        <tr class="opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600">
            <!-- Time Column -->
            <td class="py-3 pl-6 pr-3">
                <div class="flex items-center min-w-max">
                    <svg class="w-5 h-5 mr-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${timeColor}" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="11"></circle>
                            <polyline points="12,6 12,12 18,12"></polyline>
                        </g>
                    </svg>
                    <div class="text-xs">${formatTime(bid.created_at)}</div>
                </div>
            </td>

            <!-- Details Column -->
            <td class="p-3 hidden lg:flex">
                <div class="flex flex-col">
                    <div class="flex items-center min-w-max">
                        <div class="relative" data-tooltip-target="tooltip-identity-${uniqueId}">
                            <a href="/identity/${bid.addr_from}" class="text-xs font-mono">
                                <span>
                                    ${state.currentTab === 'sent' ? 'Out:' : 'In:'}
                                </span>
                                ${identity?.label || formatAddressSMSG(bid.addr_from)}
                            </a>
                        </div>
                    </div>
                    <div class="font-mono text-xs opacity-75">
                        <a href="/offer/${bid.offer_id}">
                            Offer: ${formatAddress(bid.offer_id)}
                        </a>
                    </div>
                </div>
            </td>

            <!-- Send Coin Column -->
            <td class="p-3">
                <div class="flex items-center min-w-max">
                    <img class="w-8 h-8 mr-2"
                         src="/static/images/coins/${state.currentTab === 'sent' ? bid.coin_to.replace(' ', '-') : bid.coin_from.replace(' ', '-')}.png"
                         alt="${state.currentTab === 'sent' ? bid.coin_to : bid.coin_from}"
                         onerror="this.src='/static/images/coins/default.png'">
                    <div>
                        <div class="text-sm font-medium monospace">${state.currentTab === 'sent' ? bid.amount_to : bid.amount_from}</div>
                        <div class="text-xs opacity-75 monospace">${state.currentTab === 'sent' ? bid.coin_to : bid.coin_from}</div>
                    </div>
                </div>
            </td>

            <!-- Receive Coin Column -->
            <td class="p-3">
                <div class="flex items-center min-w-max">
                    <img class="w-8 h-8 mr-2"
                         src="/static/images/coins/${state.currentTab === 'sent' ? bid.coin_from.replace(' ', '-') : bid.coin_to.replace(' ', '-')}.png"
                         alt="${state.currentTab === 'sent' ? bid.coin_from : bid.coin_to}"
                         onerror="this.src='/static/images/coins/default.png'">
                    <div>
                        <div class="text-sm font-medium monospace">${state.currentTab === 'sent' ? bid.amount_from : bid.amount_to}</div>
                        <div class="text-xs opacity-75 monospace">${state.currentTab === 'sent' ? bid.coin_from : bid.coin_to}</div>
                    </div>
                </div>
            </td>

           <!-- Status Column -->
           <td class="py-3 px-6">
            <div class="relative flex justify-center" data-tooltip-target="tooltip-status-${uniqueId}">
                <span class="w-full lg:w-7/8 xl:w-2/3 px-2.5 py-1 inline-flex items-center justify-center rounded-full text-xs font-medium bold ${getStatusClass(bid.bid_state)}">
                ${bid.bid_state}
                </span>
              </div>
            </td>

            <!-- Actions Column -->
            <td class="py-3 pr-4 pl-3">
                <div class="flex justify-center">
                    <a href="/bid/${bid.bid_id}"
                        class="inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md bg-blue-500 text-white border border-blue-500 hover:bg-blue-600 transition duration-200">
                        View Bid
                    </a>
                </div>
            </td>
        </tr>
        
        
        <!-- Tooltips -->
        <div id="tooltip-identity-${uniqueId}" role="tooltip" class="fixed z-50 py-3 px-4 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600 max-w-sm pointer-events-none">
            ${createIdentityTooltipContent(identity)}
            <div class="tooltip-arrow" data-popper-arrow></div>
        </div>

        <div id="tooltip-status-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
            <div class="text-white">
                <p class="font-bold mb-2">Transaction Status</p>
                <div class="grid grid-cols-2 gap-2">
                    <div class="bg-gray-500 p-2 rounded">
                        <p class="text-xs font-bold">ITX:</p>
                        <p>${bid.tx_state_a || 'N/A'}</p>
                    </div>
                    <div class="bg-gray-500 p-2 rounded">
                        <p class="text-xs font-bold">PTX:</p>
                        <p>${bid.tx_state_b || 'N/A'}</p>
                    </div>
                </div>
            </div>
            <div class="tooltip-arrow" data-popper-arrow></div>
        </div>
    `;
};

const updateTableContent = async (type) => {
    const tbody = elements[`${type}BidsBody`];
    if (!tbody) return;

    if (window.TooltipManager) {
        window.TooltipManager.cleanup();
    }

    cleanupTooltips();
    forceTooltipDOMCleanup();

    tooltipIdsToCleanup.clear();

    const filteredData = state.data[type];

    const startIndex = (state.currentPage[type] - 1) * PAGE_SIZE;
    const endIndex = startIndex + PAGE_SIZE;

    const currentPageData = filteredData.slice(startIndex, endIndex);

    //console.log('Updating table content:', {
    //    type: type,
    //    totalFilteredBids: filteredData.length,
    //    currentPageBids: currentPageData.length,
    //    startIndex: startIndex,
    //    endIndex: endIndex
    //});

    try {
        if (currentPageData.length > 0) {
            const BATCH_SIZE = 10;
            let allRows = [];
            
            for (let i = 0; i < currentPageData.length; i += BATCH_SIZE) {
                const batch = currentPageData.slice(i, i + BATCH_SIZE);
                const rowPromises = batch.map(bid => createTableRow(bid));
                const rows = await Promise.all(rowPromises);
                allRows = allRows.concat(rows);

                if (i + BATCH_SIZE < currentPageData.length) {
                    await new Promise(resolve => setTimeout(resolve, 5));
                }
            }

            const scrollPosition = tbody.parentElement?.scrollTop || 0;

            tbody.innerHTML = allRows.join('');

            if (tbody.parentElement && scrollPosition > 0) {
                tbody.parentElement.scrollTop = scrollPosition;
            }

            if (document.visibilityState === 'visible') {

                setTimeout(() => {
                    initializeTooltips();

                    setTimeout(() => {
                        forceTooltipDOMCleanup();
                    }, 100);
                }, 10);
            }
        } else {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">
                        No ${type} bids found
                    </td>
                </tr>`;
        }
    } catch (error) {
        console.error('Error updating table content:', error);
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-red-500">
                    Error loading data. Please try refreshing.
                </td>
            </tr>`;
    }

    updatePaginationControls(type);
};

const initializeTooltips = () => {
    if (!window.TooltipManager || document.hidden) {
        return;
    }

    window.TooltipManager.cleanup();

    let selector = '#' + state.currentTab + ' [data-tooltip-target]';
    const tooltipTriggers = document.querySelectorAll(selector);
    const tooltipCount = tooltipTriggers.length;
    if (tooltipCount > 50) {
        //console.log(`Optimizing ${tooltipCount} tooltips`);
        const viewportMargin = 200;
        const viewportTooltips = Array.from(tooltipTriggers).filter(trigger => {
            const rect = trigger.getBoundingClientRect();
            return (
                rect.bottom >= -viewportMargin &&
                rect.top <= (window.innerHeight + viewportMargin) &&
                rect.right >= 0 &&
                rect.left <= window.innerWidth
            );
        });

        viewportTooltips.forEach(trigger => {
            createTooltipForTrigger(trigger);
        });

        const offscreenTooltips = Array.from(tooltipTriggers).filter(t => !viewportTooltips.includes(t));
        
        offscreenTooltips.forEach(trigger => {
            const createTooltipOnHover = () => {
                createTooltipForTrigger(trigger);
                trigger.removeEventListener('mouseenter', createTooltipOnHover);
            };

            trigger.addEventListener('mouseenter', createTooltipOnHover);
        });
    } else {

        tooltipTriggers.forEach(trigger => {
            createTooltipForTrigger(trigger);
        });
    }
};

const createTooltipForTrigger = (trigger) => {
    if (!trigger || !window.TooltipManager) return;
    
    const targetId = trigger.getAttribute('data-tooltip-target');
    const tooltipContent = document.getElementById(targetId);

    if (tooltipContent) {
        window.TooltipManager.create(trigger, tooltipContent.innerHTML, {
            placement: trigger.getAttribute('data-tooltip-placement') || 'top',
            interactive: true,
            animation: false,
            maxWidth: 400,
            allowHTML: true,
            offset: [0, 8],
            zIndex: 50,
            delay: [200, 0],
            appendTo: () => document.body
        });
    }
};

function optimizeForLargeDatasets() {
    if (state.data[state.currentTab]?.length > 50) {

        const simplifyTooltips = tooltipIdsToCleanup.size > 50;

        implementVirtualizedRows();

        let scrollTimeout;
        window.addEventListener('scroll', () => {
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(() => {
                cleanupOffscreenTooltips();
            }, 150);
        }, { passive: true });
    }
}

function cleanupOffscreenTooltips() {
    if (!window.TooltipManager) return;

    const selector = '#' + state.currentTab + ' [data-tooltip-target]';
    const tooltipTriggers = document.querySelectorAll(selector);

    const farOffscreenTriggers = Array.from(tooltipTriggers).filter(trigger => {
        const rect = trigger.getBoundingClientRect();
        return (rect.bottom < -window.innerHeight * 2 || 
                rect.top > window.innerHeight * 3);
    });

    farOffscreenTriggers.forEach(trigger => {
        const targetId = trigger.getAttribute('data-tooltip-target');
        if (targetId) {
            const tooltipElement = document.getElementById(targetId);
            if (tooltipElement) {
                window.TooltipManager.destroy(trigger);
                trigger.addEventListener('mouseenter', () => {
                    createTooltipForTrigger(trigger);
                }, { once: true });
            }
        }
    });
}

function implementVirtualizedRows() {
    const tbody = elements[`${state.currentTab}BidsBody`];
    if (!tbody) return;

    const tableRows = tbody.querySelectorAll('tr');
    if (tableRows.length < 30) return;

    Array.from(tableRows).forEach(row => {
        const rect = row.getBoundingClientRect();
        const isVisible = (
            rect.bottom >= 0 &&
            rect.top <= window.innerHeight
        );

        if (!isVisible && (rect.bottom < -window.innerHeight || rect.top > window.innerHeight * 2)) {
            const tooltipTriggers = row.querySelectorAll('[data-tooltip-target]');
            tooltipTriggers.forEach(trigger => {
                if (window.TooltipManager) {
                    window.TooltipManager.destroy(trigger);
                }
            });
        }
    });
}

// Fetching
let activeFetchController = null;

const fetchBids = async () => {
    try {
        if (activeFetchController) {
            activeFetchController.abort();
        }
        activeFetchController = new AbortController();
        const endpoint = state.currentTab === 'sent' ? '/json/sentbids' : '/json/bids';
        const withExpiredSelect = document.getElementById('with_expired');
        const includeExpired = withExpiredSelect ? withExpiredSelect.value === 'true' : true;

        //console.log('Fetching bids, include expired:', includeExpired);

        const timeoutId = setTimeout(() => {
            if (activeFetchController) {
                activeFetchController.abort();
            }
        }, 30000);
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                sort_by: state.filters.sort_by || 'created_at',
                sort_dir: state.filters.sort_dir || 'desc',
                with_expired: true,
                state: state.filters.state ?? -1,
                with_extra_info: true
            }),
            signal: activeFetchController.signal
        });
        
        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        let data = await response.json();
        //console.log('Received raw data:', data.length, 'bids');

        state.filters.with_expired = includeExpired;

        let processedData;
        if (data.length > 500) {
            processedData = await new Promise(resolve => {
                setTimeout(() => {
                    const filtered = filterAndSortData(data);
                    resolve(filtered);
                }, 10);
            });
        } else {
            processedData = filterAndSortData(data);
        }
        
        return processedData;
    } catch (error) {
        if (error.name === 'AbortError') {
            console.log('Fetch request was aborted');
        } else {
            console.error('Error in fetchBids:', error);
        }
        throw error;
    } finally {
        activeFetchController = null;
    }
};

const updateBidsTable = async () => {
    if (state.isLoading) {
        //console.log('Already loading, skipping update');
        return;
    }

    try {
        //console.log('Starting updateBidsTable for tab:', state.currentTab);
        //console.log('Current filters:', state.filters);

        state.isLoading = true;
        updateLoadingState(true);

        const bids = await fetchBids();

       //console.log('Fetched bids:', bids.length);

        state.data[state.currentTab] = bids;
        state.currentPage[state.currentTab] = 1;

        await updateTableContent(state.currentTab);
        updatePaginationControls(state.currentTab);

    } catch (error) {
        console.error('Error in updateBidsTable:', error);
        updateConnectionStatus('error');
    } finally {
        state.isLoading = false;
        updateLoadingState(false);
    }
};

const updatePaginationControls = (type) => {
    const data = state.data[type] || [];
    const totalPages = Math.ceil(data.length / PAGE_SIZE);
    const controls = elements[`${type}PaginationControls`];
    const prevButton = elements[`prevPage${type.charAt(0).toUpperCase() + type.slice(1)}`];
    const nextButton = elements[`nextPage${type.charAt(0).toUpperCase() + type.slice(1)}`];
    const currentPageSpan = elements[`currentPage${type.charAt(0).toUpperCase() + type.slice(1)}`];
    const bidsCount = elements[`${type}BidsCount`];

    //console.log('Pagination controls update:', {
    //    type: type,
    //    totalBids: data.length,
    //    totalPages: totalPages,
    //    currentPage: state.currentPage[type]
    //});

    if (state.currentPage[type] > totalPages) {
        state.currentPage[type] = totalPages > 0 ? totalPages : 1;
    }

    if (controls) {
        controls.style.display = totalPages > 1 ? 'flex' : 'none';
    }

    if (currentPageSpan) {
        currentPageSpan.textContent = totalPages > 0 ? state.currentPage[type] : 0;
    }

    if (prevButton) {
        prevButton.style.display = state.currentPage[type] > 1 ? 'inline-flex' : 'none';
    }

    if (nextButton) {
        nextButton.style.display = state.currentPage[type] < totalPages ? 'inline-flex' : 'none';
    }

    if (bidsCount) {
        bidsCount.textContent = data.length;
    }
};

// Filter
let searchTimeout;
function handleSearch(event) {
    if (searchTimeout) {
        clearTimeout(searchTimeout);
    }

    searchTimeout = setTimeout(() => {
        state.filters.searchQuery = event.target.value.toLowerCase();
        updateBidsTable();
        updateClearFiltersButton();
    }, 300);
}

function clearFilters() {
    if (!hasActiveFilters()) return;

    const filterElements = {
        stateSelect: document.getElementById('state'),
        withExpiredSelect: document.getElementById('with_expired'),
        coinFrom: document.getElementById('coin_from'),
        coinTo: document.getElementById('coin_to'),
        searchInput: document.getElementById('searchInput')
    };

    if (filterElements.stateSelect) filterElements.stateSelect.value = '-1';
    if (filterElements.withExpiredSelect) filterElements.withExpiredSelect.value = 'true';
    if (filterElements.coinFrom) filterElements.coinFrom.value = 'any';
    if (filterElements.coinTo) filterElements.coinTo.value = 'any';
    if (filterElements.searchInput) filterElements.searchInput.value = '';

    state.filters = {
        state: -1,
        sort_by: 'created_at',
        sort_dir: 'desc',
        with_expired: true,
        searchQuery: '',
        coin_from: 'any',
        coin_to: 'any'
    };

    localStorage.removeItem('bidsTableSettings');
    updateCoinFilterImages();
    updateBidsTable();
    updateClearFiltersButton();
}

function applyFilters() {
    const stateSelect = document.getElementById('state');
    const sortBySelect = document.getElementById('sort_by');
    const sortDirSelect = document.getElementById('sort_dir');
    const withExpiredSelect = document.getElementById('with_expired');
    const coinFromSelect = document.getElementById('coin_from');
    const coinToSelect = document.getElementById('coin_to');
    const searchInput = document.getElementById('searchInput');

    state.filters = {
        state: stateSelect ? parseInt(stateSelect.value) : -1,
        sort_by: sortBySelect ? sortBySelect.value : 'created_at',
        sort_dir: sortDirSelect ? sortDirSelect.value : 'desc',
        with_expired: withExpiredSelect ? withExpiredSelect.value === 'true' : true,
        searchQuery: searchInput ? searchInput.value.toLowerCase() : '',
        coin_from: coinFromSelect ? coinFromSelect.value : 'any',
        coin_to: coinToSelect ? coinToSelect.value : 'any'
    };

    updateBidsTable();
    updateClearFiltersButton();
}

function updateClearFiltersButton() {
    const clearButton = document.getElementById('clearFilters');
    if (clearButton) {
        const hasFilters = hasActiveFilters();

        clearButton.disabled = !hasFilters;

        if (hasFilters) {
            clearButton.classList.remove('opacity-50', 'cursor-not-allowed', 'bg-gray-300');
            clearButton.classList.add('hover:bg-green-600', 'hover:text-white', 'bg-coolGray-200');
        } else {
            clearButton.classList.add('opacity-50', 'cursor-not-allowed', 'bg-gray-300');
            clearButton.classList.remove('hover:bg-green-600', 'hover:text-white', 'bg-coolGray-200');
        }
    }
}

const handleFilterChange = (e) => {
    if (e) e.preventDefault();

    state.filters = {
        state: parseInt(elements.stateSelect.value),
        sort_by: elements.sortBySelect.value,
        sort_dir: elements.sortDirSelect.value,
        with_expired: elements.withExpiredSelect.value === 'true'
    };

    state.currentPage[state.currentTab] = 1;

    updateBidsTable();
};

function setupFilterEventListeners() {
    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');
    const withExpiredSelect = document.getElementById('with_expired');

    if (coinToSelect) {
        EventManager.add(coinToSelect, 'change', () => {
            state.filters.coin_to = coinToSelect.value;
            updateBidsTable();
            updateCoinFilterImages();
            updateClearFiltersButton();
        });
    }

    if (coinFromSelect) {
        EventManager.add(coinFromSelect, 'change', () => {
            state.filters.coin_from = coinFromSelect.value;
            updateBidsTable();
            updateCoinFilterImages();
            updateClearFiltersButton();
        });
    }

    if (withExpiredSelect) {
        EventManager.add(withExpiredSelect, 'change', () => {
            state.filters.with_expired = withExpiredSelect.value === 'true';
            updateBidsTable();
            updateClearFiltersButton();
        });
    }

    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        EventManager.add(searchInput, 'input', (event) => {
            if (searchTimeout) {
                clearTimeout(searchTimeout);
            }

            searchTimeout = setTimeout(() => {
                state.filters.searchQuery = event.target.value.toLowerCase();
                updateBidsTable();
                updateClearFiltersButton();
            }, 300);
        });
    }
}

const setupRefreshButtons = () => {
    ['Sent', 'Received'].forEach(type => {
        const refreshButton = elements[`refresh${type}Bids`];
        if (refreshButton) {
            EventManager.add(refreshButton, 'click', async () => {
                const lowerType = type.toLowerCase();

                if (state.isRefreshing) {
                    console.log('Already refreshing, skipping');
                    return;
                }

                try {
                    state.isRefreshing = true;
                    state.isLoading = true;
                    updateLoadingState(true);

                    const response = await fetch(state.currentTab === 'sent' ? '/json/sentbids' : '/json/bids', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({
                            sort_by: state.filters.sort_by,
                            sort_dir: state.filters.sort_dir,
                            with_expired: state.filters.with_expired,
                            state: state.filters.state,
                            with_extra_info: true
                        })
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    if (!Array.isArray(data)) {
                        throw new Error('Invalid response format');
                    }

                    state.data[lowerType] = data;
                    await updateTableContent(lowerType);
                    updatePaginationControls(lowerType);

                } catch (error) {
                    console.error(`Error refreshing ${type} bids:`, error);
                } finally {
                    state.isRefreshing = false;
                    state.isLoading = false;
                    updateLoadingState(false);
                }
            });
        }
    });
};

// Tabs
const switchTab = (tabId) => {
    if (state.isLoading) return;

    if (window.TooltipManager) {
        window.TooltipManager.cleanup();
    }

    cleanupTooltips();
    forceTooltipDOMCleanup();

    tooltipIdsToCleanup.clear();

    state.currentTab = tabId === '#sent' ? 'sent' : 'received';

    elements.sentContent.classList.add('hidden');
    elements.receivedContent.classList.add('hidden');

    const targetPanel = document.querySelector(tabId);
    if (targetPanel) {
        targetPanel.classList.remove('hidden');
    }

    elements.tabButtons.forEach(tab => {
        const selected = tab.dataset.tabsTarget === tabId;
        tab.setAttribute('aria-selected', selected);
        if (selected) {
            tab.classList.add('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
            tab.classList.remove('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
        } else {
            tab.classList.remove('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
            tab.classList.add('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
        }
    });
    setTimeout(() => {
        updateBidsTable();
    }, 10);
};

const setupEventListeners = () => {
    const filterControls = document.querySelector('.flex.flex-wrap.justify-center');
    if (filterControls) {
        EventManager.add(filterControls, 'submit', (e) => {
            e.preventDefault();
        });
    }

    const applyFiltersBtn = document.getElementById('applyFilters');
    if (applyFiltersBtn) {
        applyFiltersBtn.remove();
    }

    if (elements.tabButtons) {
        elements.tabButtons.forEach(button => {
            EventManager.add(button, 'click', () => {
                if (state.isLoading) return;

                const targetId = button.getAttribute('data-tabs-target');
                if (!targetId) return;

                elements.tabButtons.forEach(tab => {
                    const isSelected = tab.getAttribute('data-tabs-target') === targetId;
                    tab.setAttribute('aria-selected', isSelected);

                    if (isSelected) {
                        tab.classList.add('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
                        tab.classList.remove('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
                    } else {
                        tab.classList.remove('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
                        tab.classList.add('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
                    }
                });

                elements.sentContent.classList.toggle('hidden', targetId !== '#sent');
                elements.receivedContent.classList.toggle('hidden', targetId !== '#received');

                state.currentTab = targetId === '#sent' ? 'sent' : 'received';
                state.currentPage[state.currentTab] = 1;

                if (window.TooltipManager) {
                    window.TooltipManager.cleanup();
                }
                cleanupTooltips();

                updateBidsTable();
            });
        });
    }

    ['Sent', 'Received'].forEach(type => {
        const lowerType = type.toLowerCase();

        if (elements[`prevPage${type}`]) {
            EventManager.add(elements[`prevPage${type}`], 'click', () => {
                if (state.isLoading) return;
                if (state.currentPage[lowerType] > 1) {
                    state.currentPage[lowerType]--;
                    updateTableContent(lowerType);
                }
            });
        }

        if (elements[`nextPage${type}`]) {
            EventManager.add(elements[`nextPage${type}`], 'click', () => {
                if (state.isLoading) return;
                const totalPages = Math.ceil(state.data[lowerType].length / PAGE_SIZE);
                if (state.currentPage[lowerType] < totalPages) {
                    state.currentPage[lowerType]++;
                    updateTableContent(lowerType);
                }
            });
        }
    });

    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        EventManager.add(searchInput, 'input', handleSearch);
    }

    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');

    if (coinToSelect) {
        EventManager.add(coinToSelect, 'change', () => {
            state.filters.coin_to = coinToSelect.value;
            updateBidsTable();
            updateCoinFilterImages();
        });
    }

    if (coinFromSelect) {
        EventManager.add(coinFromSelect, 'change', () => {
            state.filters.coin_from = coinFromSelect.value;
            updateBidsTable();
            updateCoinFilterImages();
        });
    }

    const filterElements = {
        stateSelect: document.getElementById('state'),
        sortBySelect: document.getElementById('sort_by'),
        sortDirSelect: document.getElementById('sort_dir'),
        withExpiredSelect: document.getElementById('with_expired'),
        clearFiltersBtn: document.getElementById('clearFilters')
    };

    if (filterElements.stateSelect) {
        EventManager.add(filterElements.stateSelect, 'change', () => {
            const stateValue = parseInt(filterElements.stateSelect.value);

            state.filters.state = isNaN(stateValue) ? -1 : stateValue;

            console.log('State filter changed:', {
                selectedValue: filterElements.stateSelect.value,
                parsedState: state.filters.state
            });

            updateBidsTable();
            updateClearFiltersButton();
        });
    }

    [
        filterElements.sortBySelect,
        filterElements.sortDirSelect,
        filterElements.withExpiredSelect
    ].forEach(element => {
        if (element) {
            EventManager.add(element, 'change', () => {
                updateBidsTable();
                updateClearFiltersButton();
            });
        }
    });

    if (filterElements.clearFiltersBtn) {
        EventManager.add(filterElements.clearFiltersBtn, 'click', () => {
            if (filterElements.clearFiltersBtn.disabled) return;
            clearFilters();
        });
    }

    EventManager.add(document, 'change', (event) => {
        const target = event.target;
        const filterForm = document.querySelector('.flex.flex-wrap.justify-center');

        if (filterForm && filterForm.contains(target)) {
            const formData = {
                state: filterElements.stateSelect?.value,
                sort_by: filterElements.sortBySelect?.value,
                sort_dir: filterElements.sortDirSelect?.value,
                with_expired: filterElements.withExpiredSelect?.value,
                coin_from: coinFromSelect?.value,
                coin_to: coinToSelect?.value,
                searchQuery: searchInput?.value
            };

            localStorage.setItem('bidsTableSettings', JSON.stringify(formData));
        }
    });

    EventManager.add(window, 'scroll', () => {
        if (!document.hidden && !state.isLoading) {
            setTimeout(initializeTooltips, 100);
        }
    }, { passive: true });
    initializeTooltips();
    updateCoinFilterImages();
    updateClearFiltersButton();
};

function setupMemoryMonitoring() {
    const MEMORY_CHECK_INTERVAL = 2 * 60 * 1000;

    const intervalId = setInterval(() => {
        if (document.hidden) {
            console.log('Tab hidden - running memory optimization');
            IdentityManager.trimCacheIfNeeded();
            if (window.TooltipManager) {
                window.TooltipManager.cleanup();
            }
            if (state.data.sent.length > 1000) {
                console.log('Trimming sent bids data');
                state.data.sent = state.data.sent.slice(0, 1000);
            }
            
            if (state.data.received.length > 1000) {
                console.log('Trimming received bids data');
                state.data.received = state.data.received.slice(0, 1000);
            }
        } else {
            cleanupTooltips();
        }
    }, MEMORY_CHECK_INTERVAL);
    document.addEventListener('beforeunload', () => {
        clearInterval(intervalId);
    }, { once: true });
}

// Init
function initialize() {
    const filterElements = {
        stateSelect: document.getElementById('state'),
        sortBySelect: document.getElementById('sort_by'),
        sortDirSelect: document.getElementById('sort_dir'),
        withExpiredSelect: document.getElementById('with_expired'),
        coinFrom: document.getElementById('coin_from'),
        coinTo: document.getElementById('coin_to')
    };

    if (filterElements.stateSelect) filterElements.stateSelect.value = '-1';
    if (filterElements.sortBySelect) filterElements.sortBySelect.value = 'created_at';
    if (filterElements.sortDirSelect) filterElements.sortDirSelect.value = 'desc';
    if (filterElements.withExpiredSelect) filterElements.withExpiredSelect.value = 'true';
    if (filterElements.coinFrom) filterElements.coinFrom.value = 'any';
    if (filterElements.coinTo) filterElements.coinTo.value = 'any';

    setupMemoryMonitoring();

    setTimeout(() => {
        WebSocketManager.initialize();
        setupEventListeners();
    }, 10);
    
    setTimeout(() => {
        setupRefreshButtons();
        setupFilterEventListeners();
        updateCoinFilterImages();
    }, 50);
    
    setTimeout(() => {
        updateClearFiltersButton();
        state.currentTab = 'sent';
        state.filters.state = -1;
        updateBidsTable();
    }, 100);

    window.cleanupBidsTable = cleanup;
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize();
}
