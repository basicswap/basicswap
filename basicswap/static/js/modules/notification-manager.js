const NotificationManager = (function() {


  const defaultConfig = {
    showNewOffers: false,
    showNewBids: true,
    showBidAccepted: true,
    showBalanceChanges: true,
    showOutgoingTransactions: true,
    notificationDuration: 20000
  };


  function loadConfig() {
    const saved = localStorage.getItem('notification_settings');
    if (saved) {
      try {
        return { ...defaultConfig, ...JSON.parse(saved) };
      } catch (e) {
        console.error('Error loading notification settings:', e);
      }
    }
    return { ...defaultConfig };
  }


  function saveConfig(newConfig) {
    try {
      localStorage.setItem('notification_settings', JSON.stringify(newConfig));
      Object.assign(config, newConfig);
    } catch (e) {
      console.error('Error saving notification settings:', e);
    }
  }

  let config = loadConfig();

  function ensureToastContainer() {
    let container = document.getElementById('ul_updates');
    if (!container) {
      const floating_div = document.createElement('div');
      floating_div.classList.add('floatright');
      container = document.createElement('ul');
      container.setAttribute('id', 'ul_updates');
      floating_div.appendChild(container);
      document.body.appendChild(floating_div);
    }
    return container;
  }

  function getCoinIcon(coinSymbol) {
    if (window.CoinManager && typeof window.CoinManager.getCoinIcon === 'function') {
      return window.CoinManager.getCoinIcon(coinSymbol);
    }
    return 'default.png';
  }

  function getToastIcon(type) {
    const icons = {
      'new_offer': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
      </svg>`,
      'new_bid': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"></path>
      </svg>`,
      'bid_accepted': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
      </svg>`,
      'balance_change': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v4a2 2 0 002 2V6h10a2 2 0 00-2-2H4zm2 6a2 2 0 012-2h8a2 2 0 012 2v4a2 2 0 01-2 2H8a2 2 0 01-2-2v-4zm6 4a2 2 0 100-4 2 2 0 000 4z" clip-rule="evenodd"></path>
      </svg>`,
      'success': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
      </svg>`
    };
    return icons[type] || icons['success'];
  }

  function getToastColor(type, options = {}) {
    const colors = {
      'new_offer': 'bg-blue-500',
      'new_bid': 'bg-green-500',
      'bid_accepted': 'bg-purple-500',
      'balance_change': 'bg-yellow-500',
      'success': 'bg-blue-500'
    };

    if (type === 'balance_change' && options.subtitle) {
      if (options.subtitle.includes('sent') || options.subtitle.includes('sending')) {
        return 'bg-red-500';
      } else {
        return 'bg-green-500';
      }
    }

    return colors[type] || colors['success'];
  }

  const publicAPI = {
    initialize: function(options = {}) {
      Object.assign(config, options);


      this.initializeBalanceTracking();

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('notificationManager', this, (mgr) => {
  
          if (this.balanceTimeouts) {
            Object.values(this.balanceTimeouts).forEach(timeout => clearTimeout(timeout));
          }
          console.log('NotificationManager disposed');
        });
      }

      return this;
    },

    updateSettings: function(newSettings) {
      saveConfig(newSettings);
      return this;
    },

    getSettings: function() {
      return { ...config };
    },

    testToasts: function() {
      if (!this.createToast) return;

      setTimeout(() => {
        this.createToast(
          '+0.05000000 PART',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Incoming funds pending' }
        );
      }, 500);

      setTimeout(() => {
        this.createToast(
          '+0.00123456 XMR',
          'balance_change',
          { coinSymbol: 'XMR', subtitle: 'Incoming funds confirmed' }
        );
      }, 1000);

      setTimeout(() => {
        this.createToast(
          '-29.86277595 PART',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Funds sent' }
        );
      }, 1500);

      setTimeout(() => {
        this.createToast(
          '-0.05000000 PART (Anon)',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Funds sending' }
        );
      }, 2000);

      setTimeout(() => {
        this.createToast(
          '+1.23456789 PART (Anon)',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Incoming funds confirmed' }
        );
      }, 2500);

      setTimeout(() => {
        this.createToast(
          'New network offer',
          'new_offer',
          { offerId: '000000006873f4ef17d4f220730400f4fdd57157492289c5d414ea66', subtitle: 'Click to view offer' }
        );
      }, 3000);

      setTimeout(() => {
        this.createToast(
          'New bid received',
          'new_bid',
          { bidId: '000000006873f4ef17d4f220730400f4fdd57157492289c5d414ea66', subtitle: 'Click to view bid' }
        );
      }, 3500);
    },



    initializeBalanceTracking: function() {

      fetch('/json/walletbalances')
        .then(response => response.json())
        .then(balanceData => {
          if (Array.isArray(balanceData)) {
            balanceData.forEach(coin => {
              const balance = parseFloat(coin.balance) || 0;
              const pending = parseFloat(coin.pending) || 0;

              const coinKey = coin.name.replace(/\s+/g, '_');
              const storageKey = `prev_balance_${coinKey}`;
              const pendingStorageKey = `prev_pending_${coinKey}`;


              if (!localStorage.getItem(storageKey)) {
                localStorage.setItem(storageKey, balance.toString());
              }
              if (!localStorage.getItem(pendingStorageKey)) {
                localStorage.setItem(pendingStorageKey, pending.toString());
              }
            });
          }
        })
        .catch(error => {
          console.error('Error initializing balance tracking:', error);
        });
    },

    createToast: function(title, type = 'success', options = {}) {
      const messages = ensureToastContainer();
      const message = document.createElement('li');
      const toastId = `toast-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const iconColor = getToastColor(type, options);
      const icon = getToastIcon(type);


      let coinIconHtml = '';
      if (options.coinSymbol) {
        const coinIcon = getCoinIcon(options.coinSymbol);
        coinIconHtml = `<img src="/static/images/coins/${coinIcon}" class="w-5 h-5 mr-2" alt="${options.coinSymbol}" onerror="this.style.display='none'">`;
      }


      let clickAction = '';
      let cursorStyle = 'cursor-default';

      if (options.offerId) {
        clickAction = `onclick="window.location.href='/offer/${options.offerId}'"`;
        cursorStyle = 'cursor-pointer';
      } else if (options.bidId) {
        clickAction = `onclick="window.location.href='/bid/${options.bidId}'"`;
        cursorStyle = 'cursor-pointer';
      } else if (options.coinSymbol) {

        const coinParam = options.coinSymbol.toLowerCase();
        clickAction = `onclick="window.location.href='/wallet/${coinParam}'"`;
        cursorStyle = 'cursor-pointer';
      }

      message.innerHTML = `
        <div class="toast-slide-in">
          <div id="${toastId}" class="flex items-center p-4 mb-3 w-full max-w-sm text-gray-500
            bg-white dark:bg-gray-800 dark:text-gray-400 rounded-lg shadow-lg border border-gray-200
            dark:border-gray-700 ${cursorStyle} hover:shadow-xl transition-shadow" role="alert" ${clickAction}>
            <div class="inline-flex flex-shrink-0 justify-center items-center w-10 h-10
              ${iconColor} rounded-lg text-white">
              ${icon}
            </div>
            <div class="flex items-center ml-3 text-sm font-medium text-gray-900 dark:text-white">
              ${coinIconHtml}
              <div class="flex flex-col">
                <span class="font-semibold">${title}</span>
                ${options.subtitle ? `<span class="text-xs text-gray-500 dark:text-gray-400">${options.subtitle}</span>` : ''}
              </div>
            </div>
            <button type="button" onclick="event.stopPropagation(); closeAlert(event)" class="ml-auto -mx-1.5 -my-1.5
              bg-white dark:bg-gray-800 text-gray-400 hover:text-gray-900 dark:hover:text-white
              rounded-lg p-1.5 hover:bg-gray-100 dark:hover:bg-gray-700 inline-flex h-8 w-8 transition-colors
              focus:outline-none">
              <span class="sr-only">Close</span>
              <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1
                  1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293
                  4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z"
                  clip-rule="evenodd"></path>
              </svg>
            </button>
          </div>
        </div>
      `;
      messages.appendChild(message);


      setTimeout(() => {
        if (message.parentNode) {
          message.classList.add('toast-slide-out');
          setTimeout(() => {
            if (message.parentNode) {
              message.parentNode.removeChild(message);
            }
          }, 300);
        }
      }, config.notificationDuration);
    },

    handleWebSocketEvent: function(data) {
      if (!data || !data.event) return;
      let toastTitle, toastType, toastOptions = {};
      let shouldShowToast = false;

      switch (data.event) {
        case 'new_offer':
          toastTitle = `New network offer`;
          toastType = 'new_offer';
          toastOptions.offerId = data.offer_id;
          toastOptions.subtitle = 'Click to view offer';
          shouldShowToast = config.showNewOffers;
          break;
        case 'new_bid':
          toastTitle = `New bid received`;
          toastOptions.bidId = data.bid_id;
          toastOptions.subtitle = 'Click to view bid';
          toastType = 'new_bid';
          shouldShowToast = config.showNewBids;
          break;
        case 'bid_accepted':
          toastTitle = `Bid accepted`;
          toastOptions.bidId = data.bid_id;
          toastOptions.subtitle = 'Click to view swap';
          toastType = 'bid_accepted';
          shouldShowToast = config.showBidAccepted;
          break;
        case 'coin_balance_updated':
          if (data.coin && config.showBalanceChanges) {
            this.handleBalanceUpdate(data);
          }
          return;
      }

      if (toastTitle && shouldShowToast) {
        this.createToast(toastTitle, toastType, toastOptions);
      }
    },

    handleBalanceUpdate: function(data) {
      if (!data.coin) return;

      this.fetchAndShowBalanceChange(data.coin);
      const balanceKey = `balance_${data.coin}`;

      if (this.balanceTimeouts && this.balanceTimeouts[balanceKey]) {
        clearTimeout(this.balanceTimeouts[balanceKey]);
      }

      if (!this.balanceTimeouts) {
        this.balanceTimeouts = {};
      }

      this.balanceTimeouts[balanceKey] = setTimeout(() => {
        this.fetchAndShowBalanceChange(data.coin);
      }, 2000);
    },

    fetchAndShowBalanceChange: function(coinSymbol) {

      fetch('/json/walletbalances')
        .then(response => response.json())
        .then(balanceData => {
          if (Array.isArray(balanceData)) {

            let coinsToCheck;
            if (coinSymbol === 'PART') {
              coinsToCheck = balanceData.filter(coin => coin.ticker === 'PART');
            } else if (coinSymbol === 'LTC') {
              coinsToCheck = balanceData.filter(coin => coin.ticker === 'LTC');
            } else {
              coinsToCheck = balanceData.filter(coin =>
                coin.ticker === coinSymbol ||
                coin.name.toLowerCase() === coinSymbol.toLowerCase()
              );
            }

            coinsToCheck.forEach(coinData => {
              this.checkSingleCoinBalance(coinData, coinSymbol);
            });
          }
        })
        .catch(error => {
          console.error('Error fetching balance for notification:', error);
        });
    },

    checkSingleCoinBalance: function(coinData, originalCoinSymbol) {
      const currentBalance = parseFloat(coinData.balance) || 0;
      const currentPending = parseFloat(coinData.pending) || 0;

      const coinKey = coinData.name.replace(/\s+/g, '_');
      const storageKey = `prev_balance_${coinKey}`;
      const pendingStorageKey = `prev_pending_${coinKey}`;
      const prevBalance = parseFloat(localStorage.getItem(storageKey)) || 0;
      const prevPending = parseFloat(localStorage.getItem(pendingStorageKey)) || 0;


      const balanceIncrease = currentBalance - prevBalance;
      const pendingIncrease = currentPending - prevPending;
      const pendingDecrease = prevPending - currentPending;


      const isPendingToConfirmed = pendingDecrease > 0.00000001 && balanceIncrease > 0.00000001;


      const displaySymbol = originalCoinSymbol;
      let variantInfo = '';

      if (coinData.name !== 'Particl' && coinData.name.includes('Particl')) {

        variantInfo = ` (${coinData.name.replace('Particl ', '')})`;
      } else if (coinData.name !== 'Litecoin' && coinData.name.includes('Litecoin')) {

        variantInfo = ` (${coinData.name.replace('Litecoin ', '')})`;
      }

      if (balanceIncrease > 0.00000001) {
        const displayAmount = balanceIncrease.toFixed(8).replace(/\.?0+$/, '');
        const subtitle = isPendingToConfirmed ? 'Funds confirmed' : 'Incoming funds confirmed';
        this.createToast(
          `+${displayAmount} ${displaySymbol}${variantInfo}`,
          'balance_change',
          {
            coinSymbol: originalCoinSymbol,
            subtitle: subtitle
          }
        );
      }

      if (balanceIncrease < -0.00000001 && config.showOutgoingTransactions) {
        const displayAmount = Math.abs(balanceIncrease).toFixed(8).replace(/\.?0+$/, '');
        this.createToast(
          `-${displayAmount} ${displaySymbol}${variantInfo}`,
          'balance_change',
          {
            coinSymbol: originalCoinSymbol,
            subtitle: 'Funds sent'
          }
        );
      }

      if (pendingIncrease > 0.00000001) {
        const displayAmount = pendingIncrease.toFixed(8).replace(/\.?0+$/, '');
        this.createToast(
          `+${displayAmount} ${displaySymbol}${variantInfo}`,
          'balance_change',
          {
            coinSymbol: originalCoinSymbol,
            subtitle: 'Incoming funds pending'
          }
        );
      }

      if (pendingIncrease < -0.00000001 && config.showOutgoingTransactions && !isPendingToConfirmed) {
        const displayAmount = Math.abs(pendingIncrease).toFixed(8).replace(/\.?0+$/, '');
        this.createToast(
          `-${displayAmount} ${displaySymbol}${variantInfo}`,
          'balance_change',
          {
            coinSymbol: originalCoinSymbol,
            subtitle: 'Funds sending'
          }
        );
      }


      if (pendingDecrease > 0.00000001 && !isPendingToConfirmed) {
        const displayAmount = pendingDecrease.toFixed(8).replace(/\.?0+$/, '');
        this.createToast(
          `${displayAmount} ${displaySymbol}${variantInfo}`,
          'balance_change',
          {
            coinSymbol: originalCoinSymbol,
            subtitle: 'Pending funds confirmed'
          }
        );
      }


      localStorage.setItem(storageKey, currentBalance.toString());
      localStorage.setItem(pendingStorageKey, currentPending.toString());
    },



    updateConfig: function(newConfig) {
      Object.assign(config, newConfig);
      return this;
    }
  };

  window.closeAlert = function(event) {
    let element = event.target;
    while (element.nodeName !== "BUTTON") {
      element = element.parentNode;
    }
    element.parentNode.parentNode.removeChild(element.parentNode);
  };

  return publicAPI;
})();

window.NotificationManager = NotificationManager;

document.addEventListener('DOMContentLoaded', function() {

  if (!window.notificationManagerInitialized) {
    window.NotificationManager.initialize(window.notificationConfig || {});
    window.notificationManagerInitialized = true;
  }
});


console.log('NotificationManager initialized');
