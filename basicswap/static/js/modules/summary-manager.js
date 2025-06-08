const SummaryManager = (function() {
  const config = {
    refreshInterval: window.config?.cacheDuration || 30000,
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

  function updateElement(elementId, value) {
    const element = document.getElementById(elementId);
    if (!element) return false;

    const safeValue = (value !== undefined && value !== null)
      ? value
      : (element.dataset.lastValue || 0);

    element.dataset.lastValue = safeValue;

    if (elementId === 'sent-bids-counter' || elementId === 'recv-bids-counter') {
      const svg = element.querySelector('svg');
      element.textContent = safeValue;
      if (svg) {
        element.insertBefore(svg, element.firstChild);
      }
    } else {
      element.textContent = safeValue;
    }

    if (['offers-counter', 'bid-requests-counter', 'sent-bids-counter',
         'recv-bids-counter', 'swaps-counter', 'network-offers-counter',
         'watched-outputs-counter'].includes(elementId)) {
      element.classList.remove('bg-blue-500', 'bg-gray-400');
      element.classList.add(safeValue > 0 ? 'bg-blue-500' : 'bg-gray-400');
    }

    if (elementId === 'swaps-counter') {
      const swapContainer = document.getElementById('swapContainer');
      if (swapContainer) {
        const isSwapping = safeValue > 0;
        if (isSwapping) {
          swapContainer.innerHTML = document.querySelector('#swap-in-progress-green-template').innerHTML || '';
          swapContainer.style.animation = 'spin 2s linear infinite';
        } else {
          swapContainer.innerHTML = document.querySelector('#swap-in-progress-template').innerHTML || '';
          swapContainer.style.animation = 'none';
        }
      }
    }
    return true;
  }

  function updateUIFromData(data) {
    if (!data) return;

    updateElement('network-offers-counter', data.num_network_offers);
    updateElement('offers-counter', data.num_sent_active_offers);
    updateElement('offers-counter-mobile', data.num_sent_active_offers);
    updateElement('sent-bids-counter', data.num_sent_active_bids);
    updateElement('recv-bids-counter', data.num_recv_active_bids);
    updateElement('bid-requests-counter', data.num_available_bids);
    updateElement('swaps-counter', data.num_swapping);
    updateElement('watched-outputs-counter', data.num_watched_outputs);

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
      setTimeout(() => {
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
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.requestTimeout);

    return fetch(config.summaryEndpoint, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
      }
    })
    .then(response => {
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }

      return response.json();
    })
    .catch(error => {
      clearTimeout(timeoutId);
      throw error;
    });
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
        publicAPI.fetchSummaryData()
          .then(() => {})
          .catch(() => {});

        if (window.NotificationManager && typeof window.NotificationManager.handleWebSocketEvent === 'function') {
          window.NotificationManager.handleWebSocketEvent(data);
        }
      }
    };

    webSocket.onclose = () => {
      setTimeout(setupWebSocket, 5000);
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

    refreshTimer = setInterval(() => {
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

        wsManager.addMessageHandler('message', (data) => {
          if (data.event) {
            this.fetchSummaryData()
              .then(() => {})
              .catch(() => {});

            if (window.NotificationManager && typeof window.NotificationManager.handleWebSocketEvent === 'function') {
              window.NotificationManager.handleWebSocketEvent(data);
            }
          }
        });
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
      return fetchSummaryDataWithTimeout()
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
              setTimeout(() => {
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
        });
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

      if (webSocket && webSocket.readyState === WebSocket.OPEN) {
        webSocket.close();
      }

      webSocket = null;
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

//console.log('SummaryManager initialized with methods:', Object.keys(SummaryManager));
console.log('SummaryManager initialized');
