const IdentityManager = (function() {
    const state = {
        cache: new Map(),
        pendingRequests: new Map(),
        config: {
            retryDelay: 2000,
            maxRetries: 3,
            maxCacheSize: 100,
            cacheTimeout: window.config?.cacheConfig?.ttlSettings?.identity || 15 * 60 * 1000,
            debug: false
        }
    };

    function log(message, ...args) {
        if (state.config.debug) {
            console.log(`[IdentityManager] ${message}`, ...args);
        }
    }

    const publicAPI = {
        getIdentityData: async function(address) {
            if (!address) {
                return null;
            }

            const cached = state.cache.get(address);
            const now = Date.now();

            if (cached && (now - cached.timestamp) < state.config.cacheTimeout) {
                log(`Cache hit (fresh) for ${address}`);
                return cached.data;
            }

            if (cached && (now - cached.timestamp) < state.config.cacheTimeout * 2) {
                log(`Cache hit (stale) for ${address}, refreshing in background`);

                const staleData = cached.data;

                if (!state.pendingRequests.has(address)) {
                    this.refreshIdentityInBackground(address);
                }

                return staleData;
            }

            if (state.pendingRequests.has(address)) {
                log(`Using pending request for ${address}`);
                return state.pendingRequests.get(address);
            }

            log(`Fetching identity for ${address}`);
            const request = fetchWithRetry(address);
            state.pendingRequests.set(address, request);

            try {
                const data = await request;
                this.setCachedIdentity(address, data);
                return data;
            } finally {
                state.pendingRequests.delete(address);
            }
        },

        refreshIdentityInBackground: function(address) {
            const request = fetchWithRetry(address);
            state.pendingRequests.set(address, request);

            request.then(data => {
                this.setCachedIdentity(address, data);
                log(`Background refresh completed for ${address}`);
            }).catch(error => {
                log(`Background refresh failed for ${address}:`, error);
            }).finally(() => {
                state.pendingRequests.delete(address);
            });
        },

        getCachedIdentity: function(address) {
            const cached = state.cache.get(address);
            if (cached && (Date.now() - cached.timestamp) < state.config.cacheTimeout) {
                return cached.data;
            }
            return null;
        },

        setCachedIdentity: function(address, data) {
            if (state.cache.size >= state.config.maxCacheSize) {
                const oldestEntries = [...state.cache.entries()]
                    .sort((a, b) => a[1].timestamp - b[1].timestamp)
                    .slice(0, Math.floor(state.config.maxCacheSize * 0.2));

                oldestEntries.forEach(([key]) => {
                    state.cache.delete(key);
                    log(`Pruned cache entry for ${key}`);
                });
            }

            state.cache.set(address, {
                data,
                timestamp: Date.now()
            });
            log(`Cached identity for ${address}`);
        },

        clearCache: function() {
            log(`Clearing identity cache (${state.cache.size} entries)`);
            state.cache.clear();
            state.pendingRequests.clear();
        },

        limitCacheSize: function(maxSize = state.config.maxCacheSize) {
            if (state.cache.size <= maxSize) {
                return 0;
            }

            const entriesToRemove = [...state.cache.entries()]
                .sort((a, b) => a[1].timestamp - b[1].timestamp)
                .slice(0, state.cache.size - maxSize);

            entriesToRemove.forEach(([key]) => state.cache.delete(key));
            log(`Limited cache size, removed ${entriesToRemove.length} entries`);

            return entriesToRemove.length;
        },

        getCacheSize: function() {
            return state.cache.size;
        },

        configure: function(options = {}) {
            Object.assign(state.config, options);
            log(`Configuration updated:`, state.config);
            return state.config;
        },

        getStats: function() {
            const now = Date.now();
            let expiredCount = 0;
            let totalSize = 0;

            state.cache.forEach((value, key) => {
                if (now - value.timestamp > state.config.cacheTimeout) {
                    expiredCount++;
                }
                const keySize = key.length * 2;
                const dataSize = JSON.stringify(value.data).length * 2;
                totalSize += keySize + dataSize;
            });

            return {
                cacheEntries: state.cache.size,
                pendingRequests: state.pendingRequests.size,
                expiredEntries: expiredCount,
                estimatedSizeKB: Math.round(totalSize / 1024),
                config: { ...state.config }
            };
        },

        setDebugMode: function(enabled) {
            state.config.debug = Boolean(enabled);
            return `Debug mode ${state.config.debug ? 'enabled' : 'disabled'}`;
        },

        initialize: function(options = {}) {

            if (options) {
                this.configure(options);
            }

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('identityManager', this, (mgr) => mgr.dispose());
            }

            log('IdentityManager initialized');
            return this;
        },

        dispose: function() {
            this.clearCache();
            log('IdentityManager disposed');
        }
    };

    async function fetchWithRetry(address, attempt = 1) {
        try {
            let data;

            if (window.ApiManager) {
                data = await window.ApiManager.makeRequest(`/json/identities/${address}`, 'GET');
            } else {
                const response = await fetch(`/json/identities/${address}`, {
                    signal: AbortSignal.timeout(5000)
                });

                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                data = await response.json();
            }

            return data;
        } catch (error) {
            if (attempt >= state.config.maxRetries) {
                console.error(`[IdentityManager] Error:`, error.message);
                console.warn(`[IdentityManager] Failed to fetch identity for ${address} after ${attempt} attempts`);
                return null;
            }

            const delay = state.config.retryDelay * attempt;
            await new Promise(resolve => {
                CleanupManager.setTimeout(resolve, delay);
            });
            return fetchWithRetry(address, attempt + 1);
        }
    }

    return publicAPI;
})();

window.IdentityManager = IdentityManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.identityManagerInitialized) {
        IdentityManager.initialize();
        window.identityManagerInitialized = true;
    }
});

console.log('IdentityManager initialized');
