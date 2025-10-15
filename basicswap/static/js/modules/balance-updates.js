const BalanceUpdatesManager = (function() {
  'use strict';

  const config = {
    balanceUpdateDelay: 2000,
    swapEventDelay: 5000,
    periodicRefreshInterval: 120000,
    walletPeriodicRefreshInterval: 60000,
  };

  const state = {
    handlers: new Map(),
    timeouts: new Map(),
    intervals: new Map(),
    initialized: false
  };

  async function fetchBalanceData() {
    if (window.ApiManager) {
      const data = await window.ApiManager.makeRequest('/json/walletbalances', 'GET');

      if (data && data.error) {
        throw new Error(data.error);
      }

      if (!Array.isArray(data)) {
        throw new Error('Invalid response format');
      }

      return data;
    }

    return fetch('/json/walletbalances', {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      }
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Server error: ${response.status} ${response.statusText}`);
      }
      return response.json();
    })
    .then(balanceData => {
      if (balanceData.error) {
        throw new Error(balanceData.error);
      }

      if (!Array.isArray(balanceData)) {
        throw new Error('Invalid response format');
      }

      return balanceData;
    });
  }

  function clearTimeoutByKey(key) {
    if (state.timeouts.has(key)) {
      const timeoutId = state.timeouts.get(key);
      if (window.CleanupManager) {
        window.CleanupManager.clearTimeout(timeoutId);
      } else {
        clearTimeout(timeoutId);
      }
      state.timeouts.delete(key);
    }
  }

  function setTimeoutByKey(key, callback, delay) {
    clearTimeoutByKey(key);
    const timeoutId = window.CleanupManager
      ? window.CleanupManager.setTimeout(callback, delay)
      : setTimeout(callback, delay);
    state.timeouts.set(key, timeoutId);
  }

  function clearIntervalByKey(key) {
    if (state.intervals.has(key)) {
      const intervalId = state.intervals.get(key);
      if (window.CleanupManager) {
        window.CleanupManager.clearInterval(intervalId);
      } else {
        clearInterval(intervalId);
      }
      state.intervals.delete(key);
    }
  }

  function setIntervalByKey(key, callback, interval) {
    clearIntervalByKey(key);
    const intervalId = window.CleanupManager
      ? window.CleanupManager.setInterval(callback, interval)
      : setInterval(callback, interval);
    state.intervals.set(key, intervalId);
  }

  function handleBalanceUpdate(contextKey, updateCallback, errorContext) {
    clearTimeoutByKey(`${contextKey}_balance_update`);
    setTimeoutByKey(`${contextKey}_balance_update`, () => {
      fetchBalanceData()
        .then(balanceData => {
          updateCallback(balanceData);
        })
        .catch(error => {
          console.error(`Error updating ${errorContext} balances via WebSocket:`, error);
        });
    }, config.balanceUpdateDelay);
  }

  function handleSwapEvent(contextKey, updateCallback, errorContext) {
    clearTimeoutByKey(`${contextKey}_swap_event`);
    setTimeoutByKey(`${contextKey}_swap_event`, () => {
      fetchBalanceData()
        .then(balanceData => {
          updateCallback(balanceData);
        })
        .catch(error => {
          console.error(`Error updating ${errorContext} balances via swap event:`, error);
        });
    }, config.swapEventDelay);
  }

  function setupWebSocketHandler(contextKey, balanceUpdateCallback, swapEventCallback, errorContext) {
    const handlerId = window.WebSocketManager.addMessageHandler('message', (data) => {
      if (data && data.event) {
        if (data.event === 'coin_balance_updated') {
          handleBalanceUpdate(contextKey, balanceUpdateCallback, errorContext);
        }

        if (swapEventCallback) {
          const swapEvents = ['new_bid', 'bid_accepted', 'swap_completed'];
          if (swapEvents.includes(data.event)) {
            handleSwapEvent(contextKey, swapEventCallback, errorContext);
          }
        }
      }
    });

    state.handlers.set(contextKey, handlerId);
    return handlerId;
  }

  function setupPeriodicRefresh(contextKey, updateCallback, errorContext, interval) {
    const refreshInterval = interval || config.periodicRefreshInterval;

    setIntervalByKey(`${contextKey}_periodic`, () => {
      fetchBalanceData()
        .then(balanceData => {
          updateCallback(balanceData);
        })
        .catch(error => {
          console.error(`Error in periodic ${errorContext} balance refresh:`, error);
        });
    }, refreshInterval);
  }

  function cleanup(contextKey) {
    if (state.handlers.has(contextKey)) {
      const handlerId = state.handlers.get(contextKey);
      if (window.WebSocketManager && typeof window.WebSocketManager.removeMessageHandler === 'function') {
        window.WebSocketManager.removeMessageHandler('message', handlerId);
      }
      state.handlers.delete(contextKey);
    }

    clearTimeoutByKey(`${contextKey}_balance_update`);
    clearTimeoutByKey(`${contextKey}_swap_event`);

    clearIntervalByKey(`${contextKey}_periodic`);
  }

  function cleanupAll() {
    state.handlers.forEach((handlerId) => {
      if (window.WebSocketManager && typeof window.WebSocketManager.removeMessageHandler === 'function') {
        window.WebSocketManager.removeMessageHandler('message', handlerId);
      }
    });
    state.handlers.clear();

    state.timeouts.forEach(timeoutId => clearTimeout(timeoutId));
    state.timeouts.clear();

    state.intervals.forEach(intervalId => clearInterval(intervalId));
    state.intervals.clear();

    state.initialized = false;
  }

  return {
    initialize: function() {
      if (state.initialized) {
        return this;
      }

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('balanceUpdatesManager', this, (mgr) => mgr.dispose());
      }

      window.addEventListener('beforeunload', cleanupAll);

      state.initialized = true;
      console.log('BalanceUpdatesManager initialized');
      return this;
    },

    setup: function(options) {
      const {
        contextKey,
        balanceUpdateCallback,
        swapEventCallback,
        errorContext,
        enablePeriodicRefresh = false,
        periodicInterval
      } = options;

      if (!contextKey || !balanceUpdateCallback || !errorContext) {
        throw new Error('Missing required options: contextKey, balanceUpdateCallback, errorContext');
      }

      setupWebSocketHandler(contextKey, balanceUpdateCallback, swapEventCallback, errorContext);

      if (enablePeriodicRefresh) {
        setupPeriodicRefresh(contextKey, balanceUpdateCallback, errorContext, periodicInterval);
      }

      return this;
    },

    fetchBalanceData: fetchBalanceData,

    cleanup: cleanup,

    dispose: cleanupAll,

    isInitialized: function() {
      return state.initialized;
    }
  };
})();

if (typeof window !== 'undefined') {
  window.BalanceUpdatesManager = BalanceUpdatesManager;
}
