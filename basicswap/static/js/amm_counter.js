const AmmCounterManager = (function() {
    const config = {
        refreshInterval: 10000,
        ammStatusEndpoint: '/amm/status',
        retryDelay: 5000,
        maxRetries: 3,
        debug: false
    };

    let refreshTimer = null;
    let fetchRetryCount = 0;
    let lastAmmStatus = null;

    function isDebugEnabled() {
        return localStorage.getItem('amm_debug_enabled') === 'true' || config.debug;
    }

    function debugLog(message, data) {
        if (isDebugEnabled()) {
            if (data) {
                console.log(`[AmmCounter] ${message}`, data);
            } else {
                console.log(`[AmmCounter] ${message}`);
            }
        }
    }

    function updateAmmCounter(count, status) {
        const ammCounter = document.getElementById('amm-counter');
        const ammCounterMobile = document.getElementById('amm-counter-mobile');

        debugLog(`Updating AMM counter: count=${count}, status=${status}`);

        if (ammCounter) {
            ammCounter.textContent = count;
            ammCounter.classList.remove('bg-blue-500', 'bg-gray-400');
            ammCounter.classList.add(status === 'running' && count > 0 ? 'bg-blue-500' : 'bg-gray-400');
        }

        if (ammCounterMobile) {
            ammCounterMobile.textContent = count;
            ammCounterMobile.classList.remove('bg-blue-500', 'bg-gray-400');
            ammCounterMobile.classList.add(status === 'running' && count > 0 ? 'bg-blue-500' : 'bg-gray-400');
        }
    }

    function fetchAmmStatus() {
        debugLog('Fetching AMM status...');

        let url = config.ammStatusEndpoint;
        if (isDebugEnabled()) {
            url += '?debug=true';
        }

        return fetch(url, {
            headers: {
                'Accept': 'application/json',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            lastAmmStatus = data;
            debugLog('AMM status data received:', data);
            updateAmmCounter(data.amm_active_count, data.status);
            fetchRetryCount = 0;
            return data;
        })
        .catch(error => {
            if (isDebugEnabled()) {
                console.error('[AmmCounter] AMM status fetch error:', error);
            }

            if (fetchRetryCount < config.maxRetries) {
                fetchRetryCount++;
                debugLog(`Retrying AMM status fetch (${fetchRetryCount}/${config.maxRetries}) in ${config.retryDelay/1000}s`);

                return new Promise(resolve => {
                    setTimeout(() => {
                        resolve(fetchAmmStatus());
                    }, config.retryDelay);
                });
            } else {
                fetchRetryCount = 0;
                throw error;
            }
        });
    }

    function startRefreshTimer() {
        stopRefreshTimer();

        debugLog('Starting AMM status refresh timer');

        fetchAmmStatus()
            .then(() => {})
            .catch(() => {});

        refreshTimer = setInterval(() => {
            fetchAmmStatus()
                .then(() => {})
                .catch(() => {});
        }, config.refreshInterval);
    }

    function stopRefreshTimer() {
        if (refreshTimer) {
            debugLog('Stopping AMM status refresh timer');
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }

    function setupWebSocketHandler() {
        if (window.WebSocketManager && typeof window.WebSocketManager.addMessageHandler === 'function') {
            debugLog('Setting up WebSocket handler for AMM status updates');
            window.WebSocketManager.addMessageHandler('message', (data) => {
                if (data && data.event) {
                    debugLog('WebSocket event received, refreshing AMM status');
                    fetchAmmStatus()
                        .then(() => {})
                        .catch(() => {});
                }
            });
        }
    }

    function setupDebugListener() {
        const debugCheckbox = document.getElementById('amm_debug');
        if (debugCheckbox) {
            debugLog('Found AMM debug checkbox, setting up listener');

            localStorage.setItem('amm_debug_enabled', debugCheckbox.checked ? 'true' : 'false');

            debugCheckbox.addEventListener('change', function() {
                localStorage.setItem('amm_debug_enabled', this.checked ? 'true' : 'false');
                debugLog(`Debug mode ${this.checked ? 'enabled' : 'disabled'}`);
            });
        }
    }

    const publicAPI = {
        initialize: function(options = {}) {
            Object.assign(config, options);

            setupWebSocketHandler();
            setupDebugListener();
            startRefreshTimer();

            debugLog('AMM Counter Manager initialized');

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('ammCounterManager', this, (mgr) => mgr.dispose());
            }

            return this;
        },

        fetchAmmStatus: fetchAmmStatus,

        startRefreshTimer: startRefreshTimer,

        stopRefreshTimer: stopRefreshTimer,

        dispose: function() {
            debugLog('Disposing AMM Counter Manager');
            stopRefreshTimer();
        }
    };

    return publicAPI;
})();

document.addEventListener('DOMContentLoaded', function() {
    if (!window.ammCounterManagerInitialized) {
        window.AmmCounterManager = AmmCounterManager.initialize();
        window.ammCounterManagerInitialized = true;
    }
});
