const AmmCounterManager = (function() {
    const AMM_REFRESH_EVENTS = new Set([
        'new_offer',
        'offer_created',
        'offer_revoked',
        'offer_expired',
        'new_bid',
        'bid_accepted',
        'swap_completed',
    ]);

    const config = {
        refreshInterval: 30000,
        wsRefreshDebounce: 250,
        ammStatusEndpoint: '/amm/status',
        retryDelay: 5000,
        maxRetries: 3,
        debug: false
    };

    let refreshTimer = null;
    let fetchRetryCount = 0;
    let lastAmmStatus = null;
    let wsRefreshTimer = null;
    let fetchInFlight = null;

    function isDebugEnabled() {
        return localStorage.getItem('amm_debug_enabled') === 'true' || config.debug;
    }

    function debugLog(message, data) {
        
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

        updateAmmTooltips(count, status);
    }

    function updateAmmTooltips(count, status) {
        debugLog(`updateAmmTooltips called with count=${count}, status=${status}`);

        const subheaderTooltip = document.getElementById('tooltip-amm-subheader');
        debugLog('Looking for tooltip-amm-subheader element:', subheaderTooltip);

        if (subheaderTooltip) {
            const statusText = status === 'running' ? 'Active' : 'Inactive';

            const newContent = `
                <p><b>Status:</b> ${statusText}</p>
                <p><b>Currently active offers/bids:</b> ${count}</p>
            `;

            const statusParagraph = subheaderTooltip.querySelector('p:first-child');
            const countParagraph = subheaderTooltip.querySelector('p:last-child');

            if (statusParagraph && countParagraph) {
                statusParagraph.innerHTML = `<b>Status:</b> ${statusText}`;
                countParagraph.innerHTML = `<b>Currently active offers/bids:</b> ${count}`;
                debugLog(`Updated AMM subheader tooltip paragraphs: status=${statusText}, count=${count}`);
            } else {
                subheaderTooltip.innerHTML = newContent;
                debugLog(`Replaced AMM subheader tooltip content: status=${statusText}, count=${count}`);
            }

            refreshTooltipInstances('tooltip-amm-subheader', newContent);
        } else {
            debugLog('AMM subheader tooltip element not found - checking all tooltip elements');
            const allTooltips = document.querySelectorAll('[id*="tooltip"]');
            debugLog('All tooltip elements found:', Array.from(allTooltips).map(el => el.id));
        }
    }

    function refreshTooltipInstances(tooltipId, newContent) {
        const triggers = document.querySelectorAll(`[data-tooltip-target="${tooltipId}"]`);

        triggers.forEach(trigger => {
            if (trigger._tippy) {
                trigger._tippy.setContent(newContent);
                debugLog(`Updated Tippy instance content for ${tooltipId}`);
            } else {
                if (window.TooltipManager && typeof window.TooltipManager.create === 'function') {
                    window.TooltipManager.create(trigger, newContent, {
                        placement: trigger.getAttribute('data-tooltip-placement') || 'top'
                    });
                    debugLog(`Created new Tippy instance for ${tooltipId}`);
                }
            }
        });

        if (window.TooltipManager && typeof window.TooltipManager.refreshTooltip === 'function') {
            window.TooltipManager.refreshTooltip(tooltipId, newContent);
            debugLog(`Refreshed tooltip via TooltipManager for ${tooltipId}`);
        }

        if (window.TooltipManager && typeof window.TooltipManager.initializeTooltips === 'function') {
            CleanupManager.setTimeout(() => {
                window.TooltipManager.initializeTooltips(`[data-tooltip-target="${tooltipId}"]`);
                debugLog(`Re-initialized tooltips for ${tooltipId}`);
            }, 50);
        }
    }

    function fetchAmmStatus() {
        debugLog('Fetching AMM status...');

        if (fetchInFlight) {
            return fetchInFlight;
        }

        let url = config.ammStatusEndpoint;
        if (isDebugEnabled()) {
            url += '?debug=true';
        }

        fetchInFlight = fetch(url, {
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
                    CleanupManager.setTimeout(() => {
                        resolve(fetchAmmStatus());
                    }, config.retryDelay);
                });
            } else {
                fetchRetryCount = 0;
                throw error;
            }
        })
        .finally(() => {
            fetchInFlight = null;
        });

        return fetchInFlight;
    }

    function scheduleAmmRefresh() {
        if (wsRefreshTimer) {
            if (window.CleanupManager) {
                window.CleanupManager.clearTimeout(wsRefreshTimer);
            } else {
                clearTimeout(wsRefreshTimer);
            }
        }

        wsRefreshTimer = window.CleanupManager
            ? window.CleanupManager.setTimeout(() => {
                wsRefreshTimer = null;
                fetchAmmStatus().catch(() => {});
            }, config.wsRefreshDebounce)
            : setTimeout(() => {
                wsRefreshTimer = null;
                fetchAmmStatus().catch(() => {});
            }, config.wsRefreshDebounce);
    }

    function startRefreshTimer() {
        stopRefreshTimer();

        debugLog('Starting AMM status refresh timer');

        fetchAmmStatus()
            .then(() => {})
            .catch(() => {});

        refreshTimer = CleanupManager.setInterval(() => {
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
                if (data && data.event && AMM_REFRESH_EVENTS.has(data.event)) {
                    debugLog('WebSocket event received, refreshing AMM status');
                    scheduleAmmRefresh();
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

        updateCounter: updateAmmCounter,

        updateTooltips: updateAmmTooltips,

        startRefreshTimer: startRefreshTimer,

        stopRefreshTimer: stopRefreshTimer,

        dispose: function() {
            debugLog('Disposing AMM Counter Manager');
            stopRefreshTimer();
            if (wsRefreshTimer) {
                if (window.CleanupManager) {
                    window.CleanupManager.clearTimeout(wsRefreshTimer);
                } else {
                    clearTimeout(wsRefreshTimer);
                }
                wsRefreshTimer = null;
            }
            fetchInFlight = null;
        }
    };

    return publicAPI;
})();

document.addEventListener('DOMContentLoaded', function() {
    if (!window.ammCounterManagerInitialized) {
        window.AmmCounterManager = AmmCounterManager.initialize();
        window.ammCounterManagerInitialized = true;

        if (window.CleanupManager) {
            CleanupManager.registerResource('ammCounter', window.AmmCounterManager, (mgr) => {
                if (mgr && mgr.dispose) mgr.dispose();
            });
        }
    }
});
