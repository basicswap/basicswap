const NetworkManager = (function() {
    const state = {
        isOnline: navigator.onLine,
        reconnectAttempts: 0,
        reconnectTimer: null,
        lastNetworkError: null,
        eventHandlers: {},
        connectionTestInProgress: false
    };

    const config = {
        maxReconnectAttempts: 5,
        reconnectDelay: 5000,
        reconnectBackoff: 1.5,
        connectionTestEndpoint: '/json',
        connectionTestTimeout: 3000,
        debug: false
    };

    function log(message, ...args) {
        if (config.debug) {
            console.log(`[NetworkManager] ${message}`, ...args);
        }
    }

    function generateHandlerId() {
        return `handler_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }

    const publicAPI = {
        initialize: function(options = {}) {
            Object.assign(config, options);
            
            window.addEventListener('online', this.handleOnlineStatus.bind(this));
            window.addEventListener('offline', this.handleOfflineStatus.bind(this));
            
            state.isOnline = navigator.onLine;
            log(`Network status initialized: ${state.isOnline ? 'online' : 'offline'}`);
            
            if (window.CleanupManager) {
                window.CleanupManager.registerResource('networkManager', this, (mgr) => mgr.dispose());
            }

            return this;
        },

        isOnline: function() {
            return state.isOnline;
        },

        getReconnectAttempts: function() {
            return state.reconnectAttempts;
        },

        resetReconnectAttempts: function() {
            state.reconnectAttempts = 0;
            return this;
        },

        handleOnlineStatus: function() {
            log('Browser reports online status');
            state.isOnline = true;
            this.notifyHandlers('online');
            
            if (state.reconnectTimer) {
                this.scheduleReconnectRefresh();
            }
        },

        handleOfflineStatus: function() {
            log('Browser reports offline status');
            state.isOnline = false;
            this.notifyHandlers('offline');
        },

        handleNetworkError: function(error) {
            if (error && (
                (error.name === 'TypeError' && error.message.includes('NetworkError')) ||
                (error.name === 'AbortError') ||
                (error.message && error.message.includes('network')) ||
                (error.message && error.message.includes('timeout'))
            )) {
                log('Network error detected:', error.message);

                if (state.isOnline) {
                    state.isOnline = false;
                    state.lastNetworkError = error;
                    this.notifyHandlers('error', error);
                }

                if (!state.reconnectTimer) {
                    this.scheduleReconnectRefresh();
                }

                return true;
            }
            return false;
        },

        scheduleReconnectRefresh: function() {
            if (state.reconnectTimer) {
                clearTimeout(state.reconnectTimer);
                state.reconnectTimer = null;
            }

            const delay = config.reconnectDelay * Math.pow(config.reconnectBackoff, 
                                                 Math.min(state.reconnectAttempts, 5));

            log(`Scheduling reconnection attempt in ${delay/1000} seconds`);

            state.reconnectTimer = setTimeout(() => {
                state.reconnectTimer = null;
                this.attemptReconnect();
            }, delay);

            return this;
        },

        attemptReconnect: function() {
            if (!navigator.onLine) {
                log('Browser still reports offline, delaying reconnection attempt');
                this.scheduleReconnectRefresh();
                return;
            }

            if (state.connectionTestInProgress) {
                log('Connection test already in progress');
                return;
            }

            state.reconnectAttempts++;
            state.connectionTestInProgress = true;

            log(`Attempting reconnect #${state.reconnectAttempts}`);

            this.testBackendConnection()
                .then(isAvailable => {
                    state.connectionTestInProgress = false;

                    if (isAvailable) {
                        log('Backend connection confirmed');
                        state.isOnline = true;
                        state.reconnectAttempts = 0;
                        state.lastNetworkError = null;
                        this.notifyHandlers('reconnected');
                    } else {
                        log('Backend still unavailable');
                        
                        if (state.reconnectAttempts < config.maxReconnectAttempts) {
                            this.scheduleReconnectRefresh();
                        } else {
                            log('Maximum reconnect attempts reached');
                            this.notifyHandlers('maxAttemptsReached');
                        }
                    }
                })
                .catch(error => {
                    state.connectionTestInProgress = false;
                    log('Error during connection test:', error);
                    
                    if (state.reconnectAttempts < config.maxReconnectAttempts) {
                        this.scheduleReconnectRefresh();
                    } else {
                        log('Maximum reconnect attempts reached');
                        this.notifyHandlers('maxAttemptsReached');
                    }
                });
        },

        testBackendConnection: function() {
            return fetch(config.connectionTestEndpoint, {
                method: 'HEAD',
                headers: {
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                },
                timeout: config.connectionTestTimeout,
                signal: AbortSignal.timeout(config.connectionTestTimeout)
            })
            .then(response => {
                return response.ok;
            })
            .catch(error => {
                log('Backend connection test failed:', error.message);
                return false;
            });
        },

        manualReconnect: function() {
            log('Manual reconnection requested');

            state.isOnline = navigator.onLine;
            state.reconnectAttempts = 0;

            this.notifyHandlers('manualReconnect');

            if (state.isOnline) {
                return this.attemptReconnect();
            } else {
                log('Cannot attempt manual reconnect while browser reports offline');
                this.notifyHandlers('offlineWarning');
                return false;
            }
        },

        addHandler: function(event, handler) {
            if (!state.eventHandlers[event]) {
                state.eventHandlers[event] = {};
            }

            const handlerId = generateHandlerId();
            state.eventHandlers[event][handlerId] = handler;
            
            return handlerId;
        },

        removeHandler: function(event, handlerId) {
            if (state.eventHandlers[event] && state.eventHandlers[event][handlerId]) {
                delete state.eventHandlers[event][handlerId];
                return true;
            }
            return false;
        },

        notifyHandlers: function(event, data) {
            if (state.eventHandlers[event]) {
                Object.values(state.eventHandlers[event]).forEach(handler => {
                    try {
                        handler(data);
                    } catch (error) {
                        log(`Error in ${event} handler:`, error);
                    }
                });
            }
        },

        setDebugMode: function(enabled) {
            config.debug = Boolean(enabled);
            return `Debug mode ${config.debug ? 'enabled' : 'disabled'}`;
        },

        getState: function() {
            return {
                isOnline: state.isOnline,
                reconnectAttempts: state.reconnectAttempts,
                hasReconnectTimer: Boolean(state.reconnectTimer),
                connectionTestInProgress: state.connectionTestInProgress
            };
        },

        dispose: function() {
            if (state.reconnectTimer) {
                clearTimeout(state.reconnectTimer);
                state.reconnectTimer = null;
            }

            window.removeEventListener('online', this.handleOnlineStatus);
            window.removeEventListener('offline', this.handleOfflineStatus);
            
            state.eventHandlers = {};
            
            log('NetworkManager disposed');
        }
    };

    return publicAPI;
})();

window.NetworkManager = NetworkManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.networkManagerInitialized) {
        NetworkManager.initialize();
        window.networkManagerInitialized = true;
    }
});

//console.log('NetworkManager initialized with methods:', Object.keys(NetworkManager));
console.log('NetworkManager initialized');

