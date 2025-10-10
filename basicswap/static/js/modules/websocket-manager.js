const WebSocketManager = (function() {
    let ws = null;

    const config = {
        reconnectAttempts: 0,
        maxReconnectAttempts: 5,
        reconnectDelay: 5000,
        debug: false
    };

    const state = {
        isConnecting: false,
        isIntentionallyClosed: false,
        lastConnectAttempt: null,
        connectTimeout: null,
        lastHealthCheck: null,
        healthCheckInterval: null,
        isPageHidden: document.hidden,
        messageHandlers: {},
        listeners: {},
        reconnectTimeout: null
    };

    function log(message, ...args) {
        if (config.debug) {
            console.log(`[WebSocketManager] ${message}`, ...args);
        }
    }

    function generateHandlerId() {
        return `handler_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    }

    function determineWebSocketPort() {
        if (window.ConfigManager && window.ConfigManager.wsPort) {
            return window.ConfigManager.wsPort.toString();
        }

        if (window.config && window.config.wsPort) {
            return window.config.wsPort.toString();
        }

        if (window.ws_port) {
            return window.ws_port.toString();
        }

        if (typeof getWebSocketConfig === 'function') {
            const wsConfig = getWebSocketConfig();
            return (wsConfig.port || wsConfig.fallbackPort || '11700').toString();
        }

        return '11700';
    }

    const publicAPI = {
        initialize: function(options = {}) {
            Object.assign(config, options);
            setupPageVisibilityHandler();
            this.connect();
            startHealthCheck();

            log('WebSocketManager initialized with options:', options);

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('webSocketManager', this, (mgr) => mgr.dispose());
            }

            return this;
        },

        connect: function() {
            if (state.isConnecting || state.isIntentionallyClosed) {
                log('Connection attempt blocked - already connecting or intentionally closed');
                return false;
            }

            if (state.reconnectTimeout) {
                if (window.CleanupManager) {
                    window.CleanupManager.clearTimeout(state.reconnectTimeout);
                } else {
                    clearTimeout(state.reconnectTimeout);
                }
                state.reconnectTimeout = null;
            }

            cleanup();
            state.isConnecting = true;
            state.lastConnectAttempt = Date.now();

            try {
                const wsPort = determineWebSocketPort();

                if (!wsPort) {
                    state.isConnecting = false;
                    return false;
                }

                ws = new WebSocket(`ws://${window.location.hostname}:${wsPort}`);
                setupEventHandlers();

                const timeoutFn = () => {
                    if (state.isConnecting) {
                        log('Connection timeout, cleaning up');
                        cleanup();
                        handleReconnect();
                    }
                };

                state.connectTimeout = window.CleanupManager
                    ? window.CleanupManager.setTimeout(timeoutFn, 5000)
                    : setTimeout(timeoutFn, 5000);

                return true;
            } catch (error) {
                log('Error during connection attempt:', error);
                state.isConnecting = false;
                handleReconnect();
                return false;
            }
        },

        disconnect: function() {
            log('Disconnecting WebSocket');
            state.isIntentionallyClosed = true;
            cleanup();
            stopHealthCheck();
        },

        isConnected: function() {
            return ws && ws.readyState === WebSocket.OPEN;
        },

        sendMessage: function(message) {
            if (!this.isConnected()) {
                log('Cannot send message - not connected');
                return false;
            }

            try {
                ws.send(JSON.stringify(message));
                return true;
            } catch (error) {
                log('Error sending message:', error);
                return false;
            }
        },

        addMessageHandler: function(type, handler) {
            if (!state.messageHandlers[type]) {
                state.messageHandlers[type] = {};
            }

            const handlerId = generateHandlerId();
            state.messageHandlers[type][handlerId] = handler;

            return handlerId;
        },

        removeMessageHandler: function(type, handlerId) {
            if (state.messageHandlers[type] && state.messageHandlers[type][handlerId]) {
                delete state.messageHandlers[type][handlerId];
            }
        },

        cleanup: function() {
            log('Cleaning up WebSocket resources');

            if (window.CleanupManager) {
                window.CleanupManager.clearTimeout(state.connectTimeout);
            } else {
                clearTimeout(state.connectTimeout);
            }
            stopHealthCheck();

            if (state.reconnectTimeout) {
                if (window.CleanupManager) {
                    window.CleanupManager.clearTimeout(state.reconnectTimeout);
                } else {
                    clearTimeout(state.reconnectTimeout);
                }
                state.reconnectTimeout = null;
            }

            state.isConnecting = false;
            state.messageHandlers = {};

            if (ws) {
                ws.onopen = null;
                ws.onmessage = null;
                ws.onerror = null;
                ws.onclose = null;

                if (ws.readyState === WebSocket.OPEN) {
                    ws.close(1000, 'Cleanup');
                }

                ws = null;
                window.ws = null;
            }
        },

        dispose: function() {
            log('Disposing WebSocketManager');

            this.disconnect();

            if (state.listeners.visibilityChange) {
                document.removeEventListener('visibilitychange', state.listeners.visibilityChange);
            }

            state.messageHandlers = {};
            state.listeners = {};
        },

        pause: function() {
            log('WebSocketManager paused');
            state.isIntentionallyClosed = true;

            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.close(1000, 'WebSocketManager paused');
            }

            stopHealthCheck();
        },

        resume: function() {
            log('WebSocketManager resumed');
            state.isIntentionallyClosed = false;

            if (!this.isConnected()) {
                this.connect();
            }

            startHealthCheck();
        }
    };

    function setupEventHandlers() {
        if (!ws) return;

        ws.onopen = () => {
            state.isConnecting = false;
            config.reconnectAttempts = 0;
            if (window.CleanupManager) {
                window.CleanupManager.clearTimeout(state.connectTimeout);
            } else {
                clearTimeout(state.connectTimeout);
            }
            state.lastHealthCheck = Date.now();
            window.ws = ws;

            log('WebSocket connection established');

            notifyHandlers('connect', { isConnected: true });

            if (typeof updateConnectionStatus === 'function') {
                updateConnectionStatus('connected');
            }
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                log('WebSocket message received:', message);
                notifyHandlers('message', message);
            } catch (error) {
                log('Error processing message:', error);
                if (typeof updateConnectionStatus === 'function') {
                    updateConnectionStatus('error');
                }
            }
        };

        ws.onerror = (error) => {
            log('WebSocket error:', error);
            if (typeof updateConnectionStatus === 'function') {
                updateConnectionStatus('error');
            }
            notifyHandlers('error', error);
        };

        ws.onclose = (event) => {
            log('WebSocket closed:', event);
            state.isConnecting = false;
            window.ws = null;

            if (typeof updateConnectionStatus === 'function') {
                updateConnectionStatus('disconnected');
            }

            notifyHandlers('disconnect', {
                code: event.code,
                reason: event.reason
            });

            if (!state.isIntentionallyClosed) {
                handleReconnect();
            }
        };
    }

    function setupPageVisibilityHandler() {
        const visibilityChangeHandler = () => {
            if (document.hidden) {
                handlePageHidden();
            } else {
                handlePageVisible();
            }
        };

        document.addEventListener('visibilitychange', visibilityChangeHandler);
        state.listeners.visibilityChange = visibilityChangeHandler;
    }

    function handlePageHidden() {
        log('Page hidden');
        state.isPageHidden = true;
        stopHealthCheck();

        if (ws && ws.readyState === WebSocket.OPEN) {
            state.isIntentionallyClosed = true;
            ws.close(1000, 'Page hidden');
        }
    }

    function handlePageVisible() {
        log('Page visible');
        state.isPageHidden = false;
        state.isIntentionallyClosed = false;

        const resumeFn = () => {
            if (!publicAPI.isConnected()) {
                publicAPI.connect();
            }
            startHealthCheck();
        };

        if (window.CleanupManager) {
            window.CleanupManager.setTimeout(resumeFn, 0);
        } else {
            setTimeout(resumeFn, 0);
        }
    }

    function startHealthCheck() {
        stopHealthCheck();
        const healthCheckFn = () => {
            performHealthCheck();
        };
        state.healthCheckInterval = window.CleanupManager
            ? window.CleanupManager.setInterval(healthCheckFn, 30000)
            : setInterval(healthCheckFn, 30000);
    }

    function stopHealthCheck() {
        if (state.healthCheckInterval) {
            if (window.CleanupManager) {
                window.CleanupManager.clearInterval(state.healthCheckInterval);
            } else {
                clearInterval(state.healthCheckInterval);
            }
            state.healthCheckInterval = null;
        }
    }

    function performHealthCheck() {
        if (!publicAPI.isConnected()) {
            log('Health check failed - not connected');
            handleReconnect();
            return;
        }

        const now = Date.now();
        const lastCheck = state.lastHealthCheck;

        if (lastCheck && (now - lastCheck) > 60000) {
            log('Health check failed - too long since last check');
            handleReconnect();
            return;
        }

        state.lastHealthCheck = now;
        log('Health check passed');
    }

    function handleReconnect() {

        if (state.reconnectTimeout) {
            if (window.CleanupManager) {
                window.CleanupManager.clearTimeout(state.reconnectTimeout);
            } else {
                clearTimeout(state.reconnectTimeout);
            }
            state.reconnectTimeout = null;
        }

        config.reconnectAttempts++;
        if (config.reconnectAttempts <= config.maxReconnectAttempts) {
            const delay = Math.min(
                config.reconnectDelay * Math.pow(1.5, config.reconnectAttempts - 1),
                30000
            );

            log(`Scheduling reconnect in ${delay}ms (attempt ${config.reconnectAttempts})`);

            const reconnectFn = () => {
                state.reconnectTimeout = null;
                if (!state.isIntentionallyClosed) {
                    publicAPI.connect();
                }
            };

            state.reconnectTimeout = window.CleanupManager
                ? window.CleanupManager.setTimeout(reconnectFn, delay)
                : setTimeout(reconnectFn, delay);
        } else {
            log('Max reconnect attempts reached');
            if (typeof updateConnectionStatus === 'function') {
                updateConnectionStatus('error');
            }

            const resetFn = () => {
                state.reconnectTimeout = null;
                config.reconnectAttempts = 0;
                publicAPI.connect();
            };

            state.reconnectTimeout = window.CleanupManager
                ? window.CleanupManager.setTimeout(resetFn, 60000)
                : setTimeout(resetFn, 60000);
        }
    }

    function notifyHandlers(type, data) {
        if (state.messageHandlers[type]) {
            Object.values(state.messageHandlers[type]).forEach(handler => {
                try {
                    handler(data);
                } catch (error) {
                    log(`Error in ${type} handler:`, error);
                }
            });
        }
    }

    function cleanup() {
        log('Cleaning up WebSocket resources');

        clearTimeout(state.connectTimeout);
        stopHealthCheck();

        if (state.reconnectTimeout) {
            clearTimeout(state.reconnectTimeout);
            state.reconnectTimeout = null;
        }

        state.isConnecting = false;

        if (ws) {
            ws.onopen = null;
            ws.onmessage = null;
            ws.onerror = null;
            ws.onclose = null;

            if (ws.readyState === WebSocket.OPEN) {
                ws.close(1000, 'Cleanup');
            }

            ws = null;
            window.ws = null;
        }
    }

    return publicAPI;
})();

window.WebSocketManager = WebSocketManager;

document.addEventListener('DOMContentLoaded', function() {

  if (!window.webSocketManagerInitialized) {
    window.WebSocketManager.initialize();
    window.webSocketManagerInitialized = true;
  }
});

console.log('WebSocketManager initialized');
