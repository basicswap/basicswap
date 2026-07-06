const SummaryManager = (function() {
  const SUMMARY_REFRESH_EVENTS = new Set([
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
    summaryEndpoint: '/json',
    retryDelay: 5000,
    maxRetries: 3,
    requestTimeout: 15000,
    debug: false
  };

  let refreshTimer = null;
  let webSocket = null;
  let fetchRetryCount = 0;
  let lastSuccessfulData = null;
  let wsRefreshTimer = null;
  let fetchInFlight = null;

  const COUNTER_ELEMENT_IDS = {
    networkOffers: ['network-offers-counter', 'network-offers-counter-mobile'],
    offers: ['offers-counter', 'offers-counter-mobile'],
    bidRequests: ['bid-requests-counter', 'bid-requests-counter-mobile'],
    sentBids: ['sent-bids-counter', 'sent-bids-counter-mobile'],
    recvBids: ['recv-bids-counter', 'recv-bids-counter-mobile'],
    swaps: ['swaps-counter', 'swaps-counter-mobile'],
    watchedOutputs: ['watched-outputs-counter', 'watched-outputs-counter-mobile'],
  };

  function updateCounterElement(element, value, preserveSvg) {
    if (!element) return;

    const safeValue = (value !== undefined && value !== null)
      ? value
      : (element.dataset.lastValue || 0);

    element.dataset.lastValue = safeValue;

    if (preserveSvg) {
      const svg = element.querySelector('svg');
      element.textContent = safeValue;
      if (svg) {
        element.insertBefore(svg, element.firstChild);
      }
    } else {
      element.textContent = safeValue;
    }

    element.classList.remove('bg-blue-500', 'bg-gray-400');
    element.classList.add(safeValue > 0 ? 'bg-blue-500' : 'bg-gray-400');
  }

  function updateCounterElements(elementIds, value, preserveSvg) {
    elementIds.forEach((elementId) => {
      const element = document.getElementById(elementId);
      updateCounterElement(element, value, preserveSvg);
    });
  }

  function updateSwapContainers(isSwapping) {
    const greenTemplate = document.getElementById('swap-in-progress-green-template');
    const idleTemplate = document.getElementById('swap-in-progress-template');
    document.querySelectorAll('#swapContainer').forEach((swapContainer) => {
      if (isSwapping) {
        swapContainer.innerHTML = greenTemplate ? greenTemplate.innerHTML : swapContainer.innerHTML;
        swapContainer.style.animation = 'spin 2s linear infinite';
      } else {
        swapContainer.innerHTML = idleTemplate ? idleTemplate.innerHTML : swapContainer.innerHTML;
        swapContainer.style.animation = 'none';
      }
    });
  }

  function updateUIFromData(data) {
    if (!data) return;

    updateCounterElements(COUNTER_ELEMENT_IDS.networkOffers, data.num_network_offers);
    updateCounterElements(COUNTER_ELEMENT_IDS.offers, data.num_sent_active_offers);
    updateCounterElements(COUNTER_ELEMENT_IDS.sentBids, data.num_sent_active_bids, true);
    updateCounterElements(COUNTER_ELEMENT_IDS.recvBids, data.num_recv_active_bids, true);
    updateCounterElements(COUNTER_ELEMENT_IDS.bidRequests, data.num_available_bids);
    updateCounterElements(COUNTER_ELEMENT_IDS.swaps, data.num_swapping);
    updateCounterElements(COUNTER_ELEMENT_IDS.watchedOutputs, data.num_watched_outputs);
    updateSwapContainers((data.num_swapping || 0) > 0);

    updateTooltips(data);

    const shutdownButtons = document.querySelectorAll('.shutdown-button');
    shutdownButtons.forEach(button => {
      button.setAttribute('data-active-swaps', data.num_swapping);
      if (data.num_swapping > 0) {
        button.classList.add('shutdown-disabled');
        button.setAttribute('data-disabled', 'true');
        button.setAttribute('title', 'Caution: Swaps in progress');
      } else {
        button.classList.remove('shutdown-disabled');
        button.removeAttribute('data-disabled');
        button.removeAttribute('title');
      }
    });
  }

  function updateTooltips(data) {
    debugLog(`updateTooltips called with data:`, data);

    const yourOffersTooltip = document.getElementById('tooltip-your-offers');
    debugLog('Looking for tooltip-your-offers element:', yourOffersTooltip);

    if (yourOffersTooltip) {
      const newContent = `
        <p><b>Total offers:</b> ${data.num_sent_offers || 0}</p>
        <p><b>Active offers:</b> ${data.num_sent_active_offers || 0}</p>
      `;

      const totalParagraph = yourOffersTooltip.querySelector('p:first-child');
      const activeParagraph = yourOffersTooltip.querySelector('p:last-child');

      debugLog('Found paragraphs:', { totalParagraph, activeParagraph });

      if (totalParagraph && activeParagraph) {
        totalParagraph.innerHTML = `<b>Total offers:</b> ${data.num_sent_offers || 0}`;
        activeParagraph.innerHTML = `<b>Active offers:</b> ${data.num_sent_active_offers || 0}`;
        debugLog(`Updated Your Offers tooltip paragraphs: total=${data.num_sent_offers}, active=${data.num_sent_active_offers}`);
      } else {
        yourOffersTooltip.innerHTML = newContent;
        debugLog(`Replaced Your Offers tooltip content: total=${data.num_sent_offers}, active=${data.num_sent_active_offers}`);
      }

      refreshTooltipInstances('tooltip-your-offers', newContent);
    } else {
      debugLog('Your Offers tooltip element not found - checking all tooltip elements');
      const allTooltips = document.querySelectorAll('[id*="tooltip"]');
      debugLog('All tooltip elements found:', Array.from(allTooltips).map(el => el.id));
    }

    const bidsTooltip = document.getElementById('tooltip-bids');
    if (bidsTooltip) {
      const newBidsContent = `
        <p><b>Sent bids:</b> ${data.num_sent_bids || 0} (${data.num_sent_active_bids || 0} active)</p>
        <p><b>Received bids:</b> ${data.num_recv_bids || 0} (${data.num_recv_active_bids || 0} active)</p>
      `;

      const sentParagraph = bidsTooltip.querySelector('p:first-child');
      const recvParagraph = bidsTooltip.querySelector('p:last-child');

      if (sentParagraph && recvParagraph) {
        sentParagraph.innerHTML = `<b>Sent bids:</b> ${data.num_sent_bids || 0} (${data.num_sent_active_bids || 0} active)`;
        recvParagraph.innerHTML = `<b>Received bids:</b> ${data.num_recv_bids || 0} (${data.num_recv_active_bids || 0} active)`;
        debugLog(`Updated Bids tooltip: sent=${data.num_sent_bids}(${data.num_sent_active_bids}), recv=${data.num_recv_bids}(${data.num_recv_active_bids})`);
      } else {
        bidsTooltip.innerHTML = newBidsContent;
        debugLog(`Replaced Bids tooltip content: sent=${data.num_sent_bids}(${data.num_sent_active_bids}), recv=${data.num_recv_bids}(${data.num_recv_active_bids})`);
      }

      refreshTooltipInstances('tooltip-bids', newBidsContent);
    } else {
      debugLog('Bids tooltip element not found');
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

  function debugLog(message) {
    if (config.debug && console && console.log) {
      console.log(`[SummaryManager] ${message}`);
    }
  }

  function cacheSummaryData(data) {
    if (!data) return;

    localStorage.setItem('summary_data_cache', JSON.stringify({
      timestamp: Date.now(),
      data: data
    }));
  }

  function getCachedSummaryData() {
    let cachedData = null;

    cachedData = localStorage.getItem('summary_data_cache');
    if (!cachedData) return null;

    const parsedCache = JSON.parse(cachedData);
    const maxAge = 24 * 60 * 60 * 1000;

    if (Date.now() - parsedCache.timestamp < maxAge) {
      return parsedCache.data;
    }

    return null;
  }

  function fetchSummaryDataWithTimeout() {
    if (window.ApiManager) {
      return window.ApiManager.makeRequest(config.summaryEndpoint, 'GET', {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      });
    }

    const controller = new AbortController();
    const timeoutId = CleanupManager.setTimeout(() => controller.abort(), config.requestTimeout);

    return fetch(config.summaryEndpoint, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      }
    })
    .then(response => {
      if (window.CleanupManager) {
        window.CleanupManager.clearTimeout(timeoutId);
      } else {
        clearTimeout(timeoutId);
      }

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      return response.json();
    })
    .catch(error => {
      if (window.CleanupManager) {
        window.CleanupManager.clearTimeout(timeoutId);
      } else {
        clearTimeout(timeoutId);
      }
      throw error;
    });
  }

  function shouldRefreshForEvent(eventName) {
    return SUMMARY_REFRESH_EVENTS.has(eventName);
  }

  function scheduleSummaryRefresh() {
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
          publicAPI.fetchSummaryData().catch(() => {});
        }, config.wsRefreshDebounce)
      : setTimeout(() => {
          wsRefreshTimer = null;
          publicAPI.fetchSummaryData().catch(() => {});
        }, config.wsRefreshDebounce);
  }

  function handleWebSocketEvent(data) {
    if (!data || !data.event) return;

    if (shouldRefreshForEvent(data.event)) {
      scheduleSummaryRefresh();
    }

    if (window.NotificationManager && typeof window.NotificationManager.handleWebSocketEvent === 'function') {
      window.NotificationManager.handleWebSocketEvent(data);
    }
  }

  function setupWebSocket() {
    if (webSocket) {
      webSocket.close();
    }

    const wsPort = window.config?.wsPort ||
                   (typeof determineWebSocketPort === 'function' ? determineWebSocketPort() : '11700');

    const wsUrl = "ws://" + window.location.hostname + ":" + wsPort;
    webSocket = new WebSocket(wsUrl);

    webSocket.onopen = () => {
      publicAPI.fetchSummaryData()
        .then(() => {})
        .catch(() => {});
    };

    webSocket.onmessage = (event) => {
      let data;

      try {
        data = JSON.parse(event.data);
      } catch (error) {
        if (window.logger && window.logger.error) {
          window.logger.error('WebSocket message processing error: ' + error.message);
        }
        return;
      }

      if (data.event) {
        handleWebSocketEvent(data);
      }
    };

    webSocket.onclose = () => {
      CleanupManager.setTimeout(setupWebSocket, 5000);
    };
  }

  function ensureSwapTemplates() {
    if (!document.getElementById('swap-in-progress-template')) {
      const template = document.createElement('template');
      template.id = 'swap-in-progress-template';
      template.innerHTML = document.querySelector('[id^="swapContainer"]')?.innerHTML || '';
      document.body.appendChild(template);
    }

    if (!document.getElementById('swap-in-progress-green-template') &&
        document.querySelector('[id^="swapContainer"]')?.innerHTML) {
      const greenTemplate = document.createElement('template');
      greenTemplate.id = 'swap-in-progress-green-template';
      greenTemplate.innerHTML = document.querySelector('[id^="swapContainer"]')?.innerHTML || '';
      document.body.appendChild(greenTemplate);
    }
  }

  function startRefreshTimer() {
    stopRefreshTimer();

    publicAPI.fetchSummaryData()
      .then(() => {})
      .catch(() => {});

    refreshTimer = CleanupManager.setInterval(() => {
      publicAPI.fetchSummaryData()
        .then(() => {})
        .catch(() => {});
    }, config.refreshInterval);
  }

  function stopRefreshTimer() {
    if (refreshTimer) {
      clearInterval(refreshTimer);
      refreshTimer = null;
    }
  }

  const publicAPI = {
    initialize: function(options = {}) {
      Object.assign(config, options);

      ensureSwapTemplates();

      const cachedData = getCachedSummaryData();
      if (cachedData) {
        updateUIFromData(cachedData);
      }

      if (window.WebSocketManager && typeof window.WebSocketManager.initialize === 'function') {
        const wsManager = window.WebSocketManager;

        if (!wsManager.isConnected()) {
          wsManager.connect();
        }

        wsManager.addMessageHandler('message', handleWebSocketEvent);
      } else {
        setupWebSocket();
      }

      startRefreshTimer();

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('summaryManager', this, (mgr) => mgr.dispose());
      }

      return this;
    },

    fetchSummaryData: function() {
      if (fetchInFlight) {
        return fetchInFlight;
      }

      fetchInFlight = fetchSummaryDataWithTimeout()
        .then(data => {
          lastSuccessfulData = data;
          cacheSummaryData(data);
          fetchRetryCount = 0;

          updateUIFromData(data);

          return data;
        })
        .catch(error => {
          if (window.logger && window.logger.error) {
            window.logger.error('Summary data fetch error: ' + error.message);
          }

          if (fetchRetryCount < config.maxRetries) {
            fetchRetryCount++;

            if (window.logger && window.logger.warn) {
              window.logger.warn(`Retrying summary data fetch (${fetchRetryCount}/${config.maxRetries}) in ${config.retryDelay/1000}s`);
            }

            return new Promise(resolve => {
              CleanupManager.setTimeout(() => {
                resolve(this.fetchSummaryData());
              }, config.retryDelay);
            });
          } else {
            const cachedData = lastSuccessfulData || getCachedSummaryData();

            if (cachedData) {
              if (window.logger && window.logger.warn) {
                window.logger.warn('Using cached summary data after fetch failures');
              }
              updateUIFromData(cachedData);
            }

            fetchRetryCount = 0;

            throw error;
          }
        })
        .finally(() => {
          fetchInFlight = null;
        });

      return fetchInFlight;
    },

    updateTooltips: function(data) {
      updateTooltips(data || lastSuccessfulData);
    },

    updateUI: function(data) {
      updateUIFromData(data || lastSuccessfulData);
    },

    startRefreshTimer: function() {
      startRefreshTimer();
    },

    stopRefreshTimer: function() {
      stopRefreshTimer();
    },

    dispose: function() {
      stopRefreshTimer();

      if (wsRefreshTimer) {
        if (window.CleanupManager) {
          window.CleanupManager.clearTimeout(wsRefreshTimer);
        } else {
          clearTimeout(wsRefreshTimer);
        }
        wsRefreshTimer = null;
      }

      if (webSocket && webSocket.readyState === WebSocket.OPEN) {
        webSocket.close();
      }

      webSocket = null;
      fetchInFlight = null;
    }
  };

  return publicAPI;
})();

window.SummaryManager = SummaryManager;

document.addEventListener('DOMContentLoaded', function() {
  if (!window.summaryManagerInitialized) {
    window.SummaryManager = SummaryManager.initialize();
    window.summaryManagerInitialized = true;
  }
});

console.log('SummaryManager initialized');
