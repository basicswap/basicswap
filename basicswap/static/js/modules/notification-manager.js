const NotificationManager = (function() {

  const defaultConfig = {
    showNewOffers: false,
    showNewBids: true,
    showBidAccepted: true,
    showBalanceChanges: true,
    showOutgoingTransactions: true,
    showSwapCompleted: true,
    showUpdateNotifications: true,
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
  let notificationHistory = [];
  const MAX_HISTORY_ITEMS = 10;

  function loadNotificationHistory() {
    try {
      const saved = localStorage.getItem('notification_history');
      if (saved) {
        notificationHistory = JSON.parse(saved);
      }
    } catch (e) {
      console.error('Error loading notification history:', e);
      notificationHistory = [];
    }
  }

  function saveNotificationHistory() {
    try {
      localStorage.setItem('notification_history', JSON.stringify(notificationHistory));
    } catch (e) {
      console.error('Error saving notification history:', e);
    }
  }

  function addToHistory(title, type, options) {
    const historyItem = {
      id: Date.now(),
      title: title,
      type: type,
      subtitle: options.subtitle || '',
      coinSymbol: options.coinSymbol || '',
      coinFrom: options.coinFrom || null,
      coinTo: options.coinTo || null,
      releaseUrl: options.releaseUrl || null,
      timestamp: new Date().toLocaleString(),
      timestampMs: Date.now()
    };

    notificationHistory.unshift(historyItem);

    if (notificationHistory.length > MAX_HISTORY_ITEMS) {
      notificationHistory = notificationHistory.slice(0, MAX_HISTORY_ITEMS);
    }

    saveNotificationHistory();
    updateHistoryDropdown();
  }

  function updateHistoryDropdown() {
    const dropdown = document.getElementById('notification-history-dropdown');
    const mobileDropdown = document.getElementById('notification-history-dropdown-mobile');

    const emptyMessage = '<div class="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">No notifications yet</div>';
    const emptyMessageMobile = '<div class="px-4 py-3 text-sm text-gray-400">No notifications yet</div>';

    if (notificationHistory.length === 0) {
      if (dropdown) dropdown.innerHTML = emptyMessage;
      if (mobileDropdown) mobileDropdown.innerHTML = emptyMessageMobile;
      return;
    }

    const clearAllButton = `
      <div class="px-4 py-2 border-t border-gray-100 dark:border-gray-400 text-center">
        <button onclick="clearAllNotifications()"
                class="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300">
          Clear All
        </button>
      </div>
    `;

    let historyHTML = '';
    let mobileHistoryHTML = '';

    notificationHistory.forEach(item => {
      let coinIconHtml = '';
      if (item.coinSymbol) {
        const coinIcon = getCoinIcon(item.coinSymbol);
        coinIconHtml = `<img src="/static/images/coins/${coinIcon}" class="w-5 h-5 mr-2 flex-shrink-0" alt="${item.coinSymbol}" onerror="this.style.display='none'">`;
      }

      const typeIcon = getToastIcon(item.type);
      const typeColor = getToastColor(item.type, item);
      const typeIconHtml = `<div class="inline-flex flex-shrink-0 justify-center items-center w-8 h-8 ${typeColor} rounded-lg text-white mr-3">${typeIcon}</div>`;

      let enhancedTitle = item.title;
      if ((item.type === 'new_offer' || item.type === 'new_bid') && item.coinFrom && item.coinTo) {
        const coinFromIcon = getCoinIcon(getCoinDisplayName(item.coinFrom));
        const coinToIcon = getCoinIcon(getCoinDisplayName(item.coinTo));
        const coinFromName = getCoinDisplayName(item.coinFrom);
        const coinToName = getCoinDisplayName(item.coinTo);

        enhancedTitle = item.title
          .replace(new RegExp(`(\\d+\\.\\d+)\\s+${coinFromName}`, 'g'), `<img src="/static/images/coins/${coinFromIcon}" class="w-4 h-4 inline mr-1" alt="${coinFromName}" onerror="this.style.display='none'">$1 ${coinFromName}`)
          .replace(new RegExp(`(\\d+\\.\\d+)\\s+${coinToName}`, 'g'), `<img src="/static/images/coins/${coinToIcon}" class="w-4 h-4 inline mr-1" alt="${coinToName}" onerror="this.style.display='none'">$1 ${coinToName}`);
      }

      const clickAction = getNotificationClickAction(item);
      const itemHTML = `
        <div class="block py-4 px-4 hover:bg-gray-100 dark:hover:bg-gray-700 dark:text-white cursor-pointer transition-colors" ${clickAction ? `onclick="${clickAction}"` : ''}>
          <div class="flex items-center">
            ${typeIconHtml}
            ${coinIconHtml}
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-gray-900 dark:text-white break-words">${enhancedTitle}</div>
              ${item.subtitle ? `<div class="text-xs text-gray-500 dark:text-gray-400 break-words">${item.subtitle}</div>` : ''}
              <div class="text-xs text-gray-400 dark:text-gray-500">${item.timestamp}</div>
            </div>
          </div>
        </div>
      `;

      historyHTML += itemHTML;

      const mobileItemHTML = `
        <div class="block py-4 px-4 hover:bg-gray-700 text-white cursor-pointer transition-colors" ${clickAction ? `onclick="${clickAction}"` : ''}>
          <div class="flex items-center">
            ${typeIconHtml}
            ${coinIconHtml}
            <div class="flex-1 min-w-0">
              <div class="text-sm font-medium text-gray-100 break-words">${enhancedTitle}</div>
              ${item.subtitle ? `<div class="text-xs text-gray-300 break-words">${item.subtitle}</div>` : ''}
              <div class="text-xs text-gray-400">${item.timestamp}</div>
            </div>
          </div>
        </div>
      `;

      mobileHistoryHTML += mobileItemHTML;
    });

    historyHTML += clearAllButton;
    mobileHistoryHTML += clearAllButton;

    if (dropdown) dropdown.innerHTML = historyHTML;
    if (mobileDropdown) mobileDropdown.innerHTML = mobileHistoryHTML;
  }

  function getNotificationClickAction(item) {
  if (item.type === 'balance_change' && item.coinSymbol) {
    return `window.location.href='/wallet/${item.coinSymbol.toLowerCase()}'`;
  }

  if (item.type === 'new_offer') {
    return `window.location.href='/offers'`;
  }

  if (item.type === 'new_bid' || item.type === 'bid_accepted') {
    return `window.location.href='/bids'`;
  }

  if (item.type === 'update_available' && item.releaseUrl) {
    return `window.open('${item.releaseUrl}', '_blank')`;
  }

  if (item.title.includes('offer') || item.title.includes('Offer')) {
    return `window.location.href='/offers'`;
  }

  if (item.title.includes('bid') || item.title.includes('Bid') || item.title.includes('swap') || item.title.includes('Swap')) {
    return `window.location.href='/bids'`;
  }

  return null;
}

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
      'swap_completed': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>
      </svg>`,
      'balance_change': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v4a2 2 0 002 2V6h10a2 2 0 00-2-2H4zm2 6a2 2 0 012-2h8a2 2 0 012 2v4a2 2 0 01-2 2H8a2 2 0 01-2-2v-4zm6 4a2 2 0 100-4 2 2 0 000 4z" clip-rule="evenodd"></path>
      </svg>`,
      'update_available': `<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd"></path>
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
      'swap_completed': 'bg-green-600',
      'balance_change': 'bg-yellow-500',
      'update_available': 'bg-blue-600',
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

  function getCoinDisplayName(coinId) {
    const coinMap = {
      1: 'PART',
      2: 'BTC',
      3: 'LTC',
      4: 'DCR',
      5: 'NMC',
      6: 'XMR',
      7: 'PART (Blind)',
      8: 'PART (Anon)',
      9: 'WOW',
      11: 'PIVX',
      12: 'DASH',
      13: 'FIRO',
      14: 'NAV',
      15: 'LTC (MWEB)',
      17: 'BCH',
      18: 'DOGE'
    };
    return coinMap[coinId] || `Coin ${coinId}`;
  }

  function formatCoinAmount(amount, coinId) {
    const divisors = {
      1: 100000000,     // PART - 8 decimals
      2: 100000000,     // BTC - 8 decimals
      3: 100000000,     // LTC - 8 decimals
      4: 100000000,     // DCR - 8 decimals
      5: 100000000,     // NMC - 8 decimals
      6: 1000000000000, // XMR - 12 decimals
      7: 100000000,     // PART (Blind) - 8 decimals
      8: 100000000,     // PART (Anon) - 8 decimals
      9: 100000000000,  // WOW - 11 decimals
      11: 100000000,    // PIVX - 8 decimals
      12: 100000000,    // DASH - 8 decimals
      13: 100000000,    // FIRO - 8 decimals
      14: 100000000,    // NAV - 8 decimals
      15: 100000000,    // LTC (MWEB) - 8 decimals
      17: 100000000,    // BCH - 8 decimals
      18: 100000000     // DOGE - 8 decimals
    };

    const divisor = divisors[coinId] || 100000000;
    const displayAmount = amount / divisor;

    return displayAmount.toFixed(8).replace(/\.?0+$/, '');
  }

  const publicAPI = {
    initialize: function(options = {}) {
      Object.assign(config, options);
      loadNotificationHistory();
      updateHistoryDropdown();

      this.initializeBalanceTracking();

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('notificationManager', this, (mgr) => {
          mgr.dispose();
        });
      }

      return this;
    },

    updateSettings: function(newSettings) {
      saveConfig(newSettings);
      return this;
    },

    getConfig: function() {
      return { ...config };
    },

    clearAllNotifications: function() {
      notificationHistory = [];
      localStorage.removeItem('notification_history');
      updateHistoryDropdown();
    },

    getSettings: function() {
      return { ...config };
    },

    testToasts: function() {
      if (!this.createToast) return;

      CleanupManager.setTimeout(() => {
        this.createToast(
          '+0.05000000 PART',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Incoming funds pending' }
        );
      }, 500);

      CleanupManager.setTimeout(() => {
        this.createToast(
          '+0.00123456 XMR',
          'balance_change',
          { coinSymbol: 'XMR', subtitle: 'Incoming funds confirmed' }
        );
      }, 1000);

      CleanupManager.setTimeout(() => {
        this.createToast(
          '-29.86277595 PART',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Funds sent' }
        );
      }, 1500);

      CleanupManager.setTimeout(() => {
        this.createToast(
          '-0.05000000 PART (Anon)',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Funds sending' }
        );
      }, 2000);

      CleanupManager.setTimeout(() => {
        this.createToast(
          '+1.23456789 PART (Anon)',
          'balance_change',
          { coinSymbol: 'PART', subtitle: 'Incoming funds confirmed' }
        );
      }, 2500);

      CleanupManager.setTimeout(() => {
        const btcIcon = getCoinIcon('BTC');
        const xmrIcon = getCoinIcon('XMR');
        this.createToast(
          'New Network Offer',
          'new_offer',
          {
            offerId: '000000006873f4ef17d4f220730400f4fdd57157492289c5d414ea66',
            subtitle: `<img src="/static/images/coins/${btcIcon}" class="w-4 h-4 inline mr-1" alt="BTC" onerror="this.style.display='none'">1.00000000 BTC → <img src="/static/images/coins/${xmrIcon}" class="w-4 h-4 inline mr-1" alt="XMR" onerror="this.style.display='none'">15.50000000 XMR<br>Rate: 1 BTC = 15.50000000 XMR`,
            coinFrom: 2,
            coinTo: 6
          }
        );
      }, 3000);

      CleanupManager.setTimeout(() => {
        const btcIcon = getCoinIcon('BTC');
        const xmrIcon = getCoinIcon('XMR');
        this.createToast(
          'New Bid Received',
          'new_bid',
          {
            bidId: '000000006873f4ef17d4f220730400f4fdd57157492289c5d414ea66',
            subtitle: `<img src="/static/images/coins/${btcIcon}" class="w-4 h-4 inline mr-1" alt="BTC" onerror="this.style.display='none'">0.50000000 BTC → <img src="/static/images/coins/${xmrIcon}" class="w-4 h-4 inline mr-1" alt="XMR" onerror="this.style.display='none'">7.75000000 XMR<br>Rate: 1 BTC = 15.50000000 XMR`,
            coinFrom: 2,
            coinTo: 6
          }
        );
      }, 3500);

      CleanupManager.setTimeout(() => {
        this.createToast(
          'Swap completed successfully',
          'swap_completed',
          {
            bidId: '000000006873f4ef17d4f220730400f4fdd57157492289c5d414ea66',
            subtitle: 'Click to view details'
          }
        );
      }, 4000);

      CleanupManager.setTimeout(async () => {
        try {
          const response = await fetch('/json/checkupdates', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          const data = await response.json();

          if (data.error) {
            console.warn('Test notification - API returned error, using fallback:', data.error);
            this.createToast(
              'Update Available: v0.15.0',
              'update_available',
              {
                subtitle: 'Current: v0.14.6 • Click to view release',
                releaseUrl: 'https://github.com/basicswap/basicswap/releases/tag/v0.15.0',
                releaseNotes: 'New version v0.15.0 is available. Click to view details on GitHub.'
              }
            );
            return;
          }

          const currentVer = (data.current_version && String(data.current_version) !== 'null' && String(data.current_version) !== 'None')
            ? String(data.current_version)
            : '0.14.6';
          const latestVer = (data.latest_version && String(data.latest_version) !== 'null' && String(data.latest_version) !== 'None')
            ? String(data.latest_version)
            : currentVer;

          this.createToast(
            `Update Available: v${latestVer}`,
            'update_available',
            {
              subtitle: `Current: v${currentVer} • Click to view release`,
              releaseUrl: `https://github.com/basicswap/basicswap/releases/tag/v${latestVer}`,
              releaseNotes: `New version v${latestVer} is available. Click to view details on GitHub.`
            }
          );
        } catch (error) {
          console.error('Test notification - API error:', error);
          this.createToast(
            'Update Available: v0.15.0',
            'update_available',
            {
              subtitle: 'Current: v0.14.6 • Click to view release',
              releaseUrl: 'https://github.com/basicswap/basicswap/releases/tag/v0.15.0',
              releaseNotes: 'New version v0.15.0 is available. Click to view details on GitHub.'
            }
          );
        }
      }, 4500);

    },

    initializeBalanceTracking: async function() {
      this.checkAndResetStaleBalanceTracking();

      const fetchBalances = window.ApiManager
        ? window.ApiManager.makeRequest('/json/walletbalances', 'GET')
        : fetch('/json/walletbalances').then(response => response.json());

      fetchBalances
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
                localStorage.setItem(`${storageKey}_timestamp`, Date.now().toString());
              }
              if (!localStorage.getItem(pendingStorageKey)) {
                localStorage.setItem(pendingStorageKey, pending.toString());
                localStorage.setItem(`${pendingStorageKey}_timestamp`, Date.now().toString());
              }
            });

            localStorage.setItem('last_balance_fetch', Date.now().toString());
          }
        })
        .catch(error => {
          console.error('Error initializing balance tracking:', error);
        });
    },

    checkAndResetStaleBalanceTracking: function() {
      const lastFetch = localStorage.getItem('last_balance_fetch');
      const now = Date.now();
      const staleThreshold = 10 * 60 * 1000;

      if (!lastFetch || (now - parseInt(lastFetch)) > staleThreshold) {
        this.resetBalanceTracking();
      }
    },

    resetBalanceTracking: function() {
      const keys = Object.keys(localStorage);
      keys.forEach(key => {
        if (key.startsWith('prev_balance_') || key.startsWith('prev_pending_') || key.startsWith('last_notification_') || key.startsWith('balance_change_')) {
          localStorage.removeItem(key);
        }
      });
    },

    getNotificationHistory: function() {
      return notificationHistory;
    },

    clearNotificationHistory: function() {
      notificationHistory = [];
      localStorage.removeItem('notification_history');
      updateHistoryDropdown();
    },

    updateHistoryDropdown: function() {
      updateHistoryDropdown();
    },

    createToast: function(title, type = 'success', options = {}) {
      const plainTitle = title.replace(/<[^>]*>/g, '');
      addToHistory(plainTitle, type, options);

      const messages = ensureToastContainer();
      const message = document.createElement('li');
      const toastId = `toast-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
      const iconColor = getToastColor(type, options);
      const icon = getToastIcon(type);

      const isPersistent = type === 'update_available';

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
        clickAction = `onclick="window.location.href='/wallet/${options.coinSymbol}'"`;
        cursorStyle = 'cursor-pointer';
      } else if (options.releaseUrl) {
        clickAction = `onclick="window.open('${options.releaseUrl}', '_blank')"`;
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

      if (!isPersistent) {
        CleanupManager.setTimeout(() => {
          if (message.parentNode) {
            message.classList.add('toast-slide-out');
            CleanupManager.setTimeout(() => {
              if (message.parentNode) {
                message.parentNode.removeChild(message);
              }

            }, 300);
          }
        }, config.notificationDuration);
      }
    },

    handleWebSocketEvent: function(data) {
      if (!data || !data.event) return;
      let toastTitle, toastType, toastOptions = {};
      let shouldShowToast = false;

      switch (data.event) {
        case 'new_offer':
          if (data.coin_from && data.coin_to && data.amount_from && data.amount_to) {
            const coinFromName = getCoinDisplayName(data.coin_from);
            const coinToName = getCoinDisplayName(data.coin_to);
            const amountFrom = formatCoinAmount(data.amount_from, data.coin_from);
            const amountTo = formatCoinAmount(data.amount_to, data.coin_to);
            const coinFromIcon = getCoinIcon(coinFromName);
            const coinToIcon = getCoinIcon(coinToName);
            toastTitle = `New Network Offer`;
            toastOptions.subtitle = `<img src="/static/images/coins/${coinFromIcon}" class="w-4 h-4 inline mr-1" alt="${coinFromName}" onerror="this.style.display='none'">${amountFrom} ${coinFromName} → <img src="/static/images/coins/${coinToIcon}" class="w-4 h-4 inline mr-1" alt="${coinToName}" onerror="this.style.display='none'">${amountTo} ${coinToName}<br>Rate: 1 ${coinFromName} = ${(data.amount_to / data.amount_from).toFixed(8)} ${coinToName}`;
            toastOptions.coinFrom = data.coin_from;
            toastOptions.coinTo = data.coin_to;
          } else {
            toastTitle = `New Network Offer`;
            toastOptions.subtitle = 'Click to view offer';
          }
          toastType = 'new_offer';
          toastOptions.offerId = data.offer_id;
          shouldShowToast = config.showNewOffers;
          break;
        case 'new_bid':
          if (data.coin_from && data.coin_to && data.bid_amount && data.bid_amount_to) {
            const coinFromName = getCoinDisplayName(data.coin_from);
            const coinToName = getCoinDisplayName(data.coin_to);
            const bidAmountFrom = formatCoinAmount(data.bid_amount, data.coin_from);
            const bidAmountTo = formatCoinAmount(data.bid_amount_to, data.coin_to);
            const coinFromIcon = getCoinIcon(coinFromName);
            const coinToIcon = getCoinIcon(coinToName);
            toastTitle = `New Bid Received`;
            toastOptions.subtitle = `<img src="/static/images/coins/${coinFromIcon}" class="w-4 h-4 inline mr-1" alt="${coinFromName}" onerror="this.style.display='none'">${bidAmountFrom} ${coinFromName} → <img src="/static/images/coins/${coinToIcon}" class="w-4 h-4 inline mr-1" alt="${coinToName}" onerror="this.style.display='none'">${bidAmountTo} ${coinToName}<br>Rate: 1 ${coinFromName} = ${(data.bid_amount_to / data.bid_amount).toFixed(8)} ${coinToName}`;
            toastOptions.coinFrom = data.coin_from;
            toastOptions.coinTo = data.coin_to;
          } else {
            toastTitle = `New Bid Received`;
            toastOptions.subtitle = 'Click to view bid';
          }
          toastOptions.bidId = data.bid_id;
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

        case 'swap_completed':
          toastTitle = `Swap completed successfully`;
          toastOptions.bidId = data.bid_id;
          toastOptions.subtitle = 'Click to view details';
          toastType = 'swap_completed';
          shouldShowToast = config.showSwapCompleted;
          break;

        case 'update_available':
          toastTitle = `Update Available: v${data.latest_version}`;
          toastOptions.subtitle = `Current: v${data.current_version} • Click to view release`;
          toastOptions.releaseUrl = data.release_url;
          toastOptions.releaseNotes = data.release_notes;
          toastType = 'update_available';
          shouldShowToast = config.showUpdateNotifications;
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

      this.balanceTimeouts[balanceKey] = CleanupManager.setTimeout(() => {
        this.fetchAndShowBalanceChange(data.coin);
      }, 2000);
    },

    fetchAndShowBalanceChange: function(coinSymbol) {
      const fetchBalances = window.ApiManager
        ? window.ApiManager.makeRequest('/json/walletbalances', 'GET')
        : fetch('/json/walletbalances').then(response => response.json());

      fetchBalances
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

            localStorage.setItem('last_balance_fetch', Date.now().toString());
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
      const lastNotificationKey = `last_notification_${coinKey}`;

      const prevBalance = parseFloat(localStorage.getItem(storageKey)) || 0;
      const prevPending = parseFloat(localStorage.getItem(pendingStorageKey)) || 0;
      const lastNotificationTime = parseInt(localStorage.getItem(lastNotificationKey)) || 0;

      const balanceIncrease = currentBalance - prevBalance;
      const pendingIncrease = currentPending - prevPending;
      const pendingDecrease = prevPending - currentPending;

      const totalChange = Math.abs(balanceIncrease) + Math.abs(pendingIncrease);
      const maxReasonableChange = Math.max(currentBalance, prevBalance) * 0.5;

      if (totalChange > maxReasonableChange && totalChange > 1.0) {
        localStorage.setItem(storageKey, currentBalance.toString());
        localStorage.setItem(pendingStorageKey, currentPending.toString());
        return;
      }

      const now = Date.now();
      const minTimeBetweenNotifications = 30000;
      const balanceChangeKey = `balance_change_${coinKey}`;
      const lastBalanceChange = localStorage.getItem(balanceChangeKey);

      const currentChangeSignature = `${currentBalance}_${currentPending}`;

      if (lastBalanceChange === currentChangeSignature) {
        localStorage.setItem(storageKey, currentBalance.toString());
        localStorage.setItem(pendingStorageKey, currentPending.toString());
        return;
      }

      if (now - lastNotificationTime < minTimeBetweenNotifications) {
        localStorage.setItem(storageKey, currentBalance.toString());
        localStorage.setItem(pendingStorageKey, currentPending.toString());
        localStorage.setItem(balanceChangeKey, currentChangeSignature);
        return;
      }

      const isPendingToConfirmed = pendingDecrease > 0.00000001 && balanceIncrease > 0.00000001;

      const displaySymbol = originalCoinSymbol;
      let variantInfo = '';

      if (coinData.name !== 'Particl' && coinData.name.includes('Particl')) {

        variantInfo = ` (${coinData.name.replace('Particl ', '')})`;
      } else if (coinData.name !== 'Litecoin' && coinData.name.includes('Litecoin')) {

        variantInfo = ` (${coinData.name.replace('Litecoin ', '')})`;
      }

      let notificationShown = false;

      if (balanceIncrease > 0.00000001 && config.showBalanceChanges) {
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
        notificationShown = true;
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
        notificationShown = true;
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
        notificationShown = true;
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
        notificationShown = true;
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
        notificationShown = true;
      }

      localStorage.setItem(storageKey, currentBalance.toString());
      localStorage.setItem(pendingStorageKey, currentPending.toString());
      localStorage.setItem(balanceChangeKey, currentChangeSignature);

      if (notificationShown) {
        localStorage.setItem(lastNotificationKey, now.toString());
      }
    },

    updateConfig: function(newConfig) {
      Object.assign(config, newConfig);
      return this;
    },

    manualResetBalanceTracking: function() {
      this.resetBalanceTracking();
      this.initializeBalanceTracking();
    },

    dispose: function() {
      if (this.balanceTimeouts) {
        Object.values(this.balanceTimeouts).forEach(timeout => {
          clearTimeout(timeout);
        });
        this.balanceTimeouts = {};
      }
    }
  };

  window.closeAlert = function(event) {
    let element = event.target;
    while (element.nodeName !== "BUTTON") {
      element = element.parentNode;
    }
    const toastElement = element.parentNode;

    toastElement.parentNode.removeChild(toastElement);
  };

  return publicAPI;
})();

window.NotificationManager = NotificationManager;

window.resetBalanceTracking = function() {
  if (window.NotificationManager && window.NotificationManager.manualResetBalanceTracking) {
    window.NotificationManager.manualResetBalanceTracking();
  }
};

window.testNotification = function() {
  if (window.NotificationManager) {
    window.NotificationManager.createToast('Test Notification', 'success', { subtitle: 'This is a test notification' });
  }
};

document.addEventListener('DOMContentLoaded', function() {
  if (!window.notificationManagerInitialized) {
    window.NotificationManager.initialize(window.notificationConfig || {});
    window.notificationManagerInitialized = true;
  }
});
