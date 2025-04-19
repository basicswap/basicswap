const WalletManager = (function() {

  const config = {
    maxRetries: 5,
    baseDelay: 500,
    cacheExpiration: 5 * 60 * 1000,
    priceUpdateInterval: 5 * 60 * 1000,
    apiTimeout: 30000,
    debounceDelay: 300,
    cacheMinInterval: 60 * 1000,
    defaultTTL: 300,
    priceSource: {
      primary: 'coingecko.com',
      fallback: 'cryptocompare.com',
      enabledSources: ['coingecko.com', 'cryptocompare.com']
    }
  };

  const stateKeys = {
    lastUpdate: 'last-update-time',
    previousTotal: 'previous-total-usd',
    currentTotal: 'current-total-usd',
    balancesVisible: 'balancesVisible'
  };

  const state = {
    lastFetchTime: 0,
    toggleInProgress: false,
    toggleDebounceTimer: null,
    priceUpdateInterval: null,
    lastUpdateTime: 0,
    isWalletsPage: false,
    initialized: false,
    cacheKey: 'rates_crypto_prices'
  };

  function getShortName(fullName) {
    return window.CoinManager.getSymbol(fullName) || fullName;
  }

  function getCoingeckoId(coinName) {
    if (!window.CoinManager) {
      console.warn('[WalletManager] CoinManager not available');
      return coinName;
    }

    const coin = window.CoinManager.getCoinByAnyIdentifier(coinName);

    if (!coin) {
      console.warn(`[WalletManager] No coin found for: ${coinName}`);
      return coinName;
    }

    return coin.symbol;
  }

  async function fetchPrices(forceUpdate = false) {
    const now = Date.now();
    const timeSinceLastFetch = now - state.lastFetchTime;

    if (!forceUpdate && timeSinceLastFetch < config.cacheMinInterval) {
      const cachedData = CacheManager.get(state.cacheKey);
      if (cachedData) {
        return cachedData.value;
      }
    }

    let lastError = null;
    for (let attempt = 0; attempt < config.maxRetries; attempt++) {
      try {
        const processedData = {};
        const currentSource = config.priceSource.primary;

        const shouldIncludeWow = currentSource === 'coingecko.com';

        const coinsToFetch = [];
        const processedCoins = new Set();

        document.querySelectorAll('.coinname-value').forEach(el => {
          const coinName = el.getAttribute('data-coinname');

          if (!coinName || processedCoins.has(coinName)) return;

          const adjustedName = coinName === 'Zcoin' ? 'Firo' :
                               coinName.includes('Particl') ? 'Particl' :
                               coinName;

          const coinId = getCoingeckoId(adjustedName);

          if (coinId && (shouldIncludeWow || coinId !== 'WOW')) {
            coinsToFetch.push(coinId);
            processedCoins.add(coinName);
          }
        });

        const fetchCoinsString = coinsToFetch.join(',');

        const mainResponse = await fetch("/json/coinprices", {
          method: "POST",
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            coins: fetchCoinsString,
            source: currentSource,
            ttl: config.defaultTTL
          })
        });

        if (!mainResponse.ok) {
          throw new Error(`HTTP error: ${mainResponse.status}`);
        }

        const mainData = await mainResponse.json();

        if (mainData && mainData.rates) {
          document.querySelectorAll('.coinname-value').forEach(el => {
            const coinName = el.getAttribute('data-coinname');
            if (!coinName) return;

            const adjustedName = coinName === 'Zcoin' ? 'Firo' :
                                 coinName.includes('Particl') ? 'Particl' :
                                 coinName;

            const coinId = getCoingeckoId(adjustedName);
            const price = mainData.rates[coinId];

            if (price) {
              const coinKey = coinName.toLowerCase().replace(' ', '-');
              processedData[coinKey] = {
                usd: price,
                btc: coinId === 'BTC' ? 1 : price / (mainData.rates.BTC || 1)
              };
            }
          });
        }

        CacheManager.set(state.cacheKey, processedData, config.cacheExpiration);
        state.lastFetchTime = now;
        return processedData;
      } catch (error) {
        lastError = error;
        console.error(`Price fetch attempt ${attempt + 1} failed:`, error);

        if (attempt === config.maxRetries - 1 &&
            config.priceSource.fallback &&
            config.priceSource.fallback !== config.priceSource.primary) {
          const temp = config.priceSource.primary;
          config.priceSource.primary = config.priceSource.fallback;
          config.priceSource.fallback = temp;

          console.warn(`Switching to fallback source: ${config.priceSource.primary}`);
          attempt = -1;
          continue;
        }

        if (attempt < config.maxRetries - 1) {
          const delay = Math.min(config.baseDelay * Math.pow(2, attempt), 10000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }

    const cachedData = CacheManager.get(state.cacheKey);
    if (cachedData) {
      console.warn('Using cached data after fetch failures');
      return cachedData.value;
    }

    throw lastError || new Error('Failed to fetch prices');
  }

  function storeOriginalValues() {
    document.querySelectorAll('.coinname-value').forEach(el => {
      const coinName = el.getAttribute('data-coinname');
      const value = el.textContent?.trim() || '';

      if (coinName) {
        const amount = value ? parseFloat(value.replace(/[^0-9.-]+/g, '')) : 0;
        const coinSymbol = window.CoinManager.getSymbol(coinName);
        const shortName = getShortName(coinName);

        if (coinSymbol) {
          if (coinName === 'Particl') {
            const isBlind = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('Blind');
            const isAnon = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('Anon');
            const balanceType = isBlind ? 'blind' : isAnon ? 'anon' : 'public';
            localStorage.setItem(`particl-${balanceType}-amount`, amount.toString());
          } else if (coinName === 'Litecoin') {
            const isMWEB = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('MWEB');
            const balanceType = isMWEB ? 'mweb' : 'public';
            localStorage.setItem(`litecoin-${balanceType}-amount`, amount.toString());
          } else {
            localStorage.setItem(`${coinSymbol.toLowerCase()}-amount`, amount.toString());
          }

          el.setAttribute('data-original-value', `${amount} ${shortName}`);
        }
      }
    });

    document.querySelectorAll('.usd-value').forEach(el => {
      const text = el.textContent?.trim() || '';
      if (text === 'Loading...') {
        el.textContent = '';
      }
    });
  }

  async function updatePrices(forceUpdate = false) {
    try {
      const prices = await fetchPrices(forceUpdate);
      let newTotal = 0;

      const currentTime = Date.now();
      localStorage.setItem(stateKeys.lastUpdate, currentTime.toString());
      state.lastUpdateTime = currentTime;

      if (prices) {
        Object.entries(prices).forEach(([coinId, priceData]) => {
          if (priceData?.usd) {
            localStorage.setItem(`${coinId}-price`, priceData.usd.toString());
          }
        });
      }

      document.querySelectorAll('.coinname-value').forEach(el => {
        const coinName = el.getAttribute('data-coinname');
        const amountStr = el.getAttribute('data-original-value') || el.textContent?.trim() || '';

        if (!coinName) return;

        let amount = 0;
        if (amountStr) {
          const matches = amountStr.match(/([0-9]*[.])?[0-9]+/);
          if (matches && matches.length > 0) {
            amount = parseFloat(matches[0]);
          }
        }

        const coinId = coinName.toLowerCase().replace(' ', '-');

        if (!prices[coinId]) {
          return;
        }

        const price = prices[coinId]?.usd || parseFloat(localStorage.getItem(`${coinId}-price`) || '0');
        if (!price) return;

        const usdValue = (amount * price).toFixed(2);

        if (coinName === 'Particl') {
          const isBlind = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('Blind');
          const isAnon = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('Anon');
          const balanceType = isBlind ? 'blind' : isAnon ? 'anon' : 'public';
          localStorage.setItem(`particl-${balanceType}-last-value`, usdValue);
          localStorage.setItem(`particl-${balanceType}-amount`, amount.toString());
        } else if (coinName === 'Litecoin') {
          const isMWEB = el.closest('.flex')?.querySelector('h4')?.textContent?.includes('MWEB');
          const balanceType = isMWEB ? 'mweb' : 'public';
          localStorage.setItem(`litecoin-${balanceType}-last-value`, usdValue);
          localStorage.setItem(`litecoin-${balanceType}-amount`, amount.toString());
        } else {
          localStorage.setItem(`${coinId}-last-value`, usdValue);
          localStorage.setItem(`${coinId}-amount`, amount.toString());
        }

        if (amount > 0) {
          newTotal += parseFloat(usdValue);
        }

        let usdEl = null;

        const flexContainer = el.closest('.flex');
        if (flexContainer) {
          const nextFlex = flexContainer.nextElementSibling;
          if (nextFlex) {
            const usdInNextFlex = nextFlex.querySelector('.usd-value');
            if (usdInNextFlex) {
              usdEl = usdInNextFlex;
            }
          }
        }

        if (!usdEl) {
          const parentCell = el.closest('td');
          if (parentCell) {
            const usdInSameCell = parentCell.querySelector('.usd-value');
            if (usdInSameCell) {
              usdEl = usdInSameCell;
            }
          }
        }

        if (!usdEl) {
          const sibling = el.nextElementSibling;
          if (sibling && sibling.classList.contains('usd-value')) {
            usdEl = sibling;
          }
        }

        if (!usdEl) {
          const parentElement = el.parentElement;
          if (parentElement) {
            const usdElNearby = parentElement.querySelector('.usd-value');
            if (usdElNearby) {
              usdEl = usdElNearby;
            }
          }
        }

        if (usdEl) {
          usdEl.textContent = `$${usdValue}`;
          usdEl.setAttribute('data-original-value', usdValue);
        }
      });

      document.querySelectorAll('.usd-value').forEach(el => {
        if (el.closest('tr')?.querySelector('td')?.textContent?.includes('Fee Estimate:')) {
          const parentCell = el.closest('td');
          if (!parentCell) return;

          const coinValueEl = parentCell.querySelector('.coinname-value');
          if (!coinValueEl) return;

          const coinName = coinValueEl.getAttribute('data-coinname');
          if (!coinName) return;

          const amountStr = coinValueEl.textContent?.trim() || '0';
          const amount = parseFloat(amountStr) || 0;

          const coinId = coinName.toLowerCase().replace(' ', '-');
          if (!prices[coinId]) return;

          const price = prices[coinId]?.usd || parseFloat(localStorage.getItem(`${coinId}-price`) || '0');
          if (!price) return;

          const usdValue = (amount * price).toFixed(8);
          el.textContent = `$${usdValue}`;
          el.setAttribute('data-original-value', usdValue);
        }
      });

      if (state.isWalletsPage) {
        updateTotalValues(newTotal, prices?.bitcoin?.usd);
      }

      localStorage.setItem(stateKeys.previousTotal, localStorage.getItem(stateKeys.currentTotal) || '0');
      localStorage.setItem(stateKeys.currentTotal, newTotal.toString());

      return true;
    } catch (error) {
      console.error('Price update failed:', error);
      return false;
    }
  }

  function updateTotalValues(totalUsd, btcPrice) {
    const totalUsdEl = document.getElementById('total-usd-value');
    if (totalUsdEl) {
      totalUsdEl.textContent = `$${totalUsd.toFixed(2)}`;
      totalUsdEl.setAttribute('data-original-value', totalUsd.toString());
      localStorage.setItem('total-usd', totalUsd.toString());
    }

    if (btcPrice) {
      const btcTotal = btcPrice ? totalUsd / btcPrice : 0;
      const totalBtcEl = document.getElementById('total-btc-value');
      if (totalBtcEl) {
        totalBtcEl.textContent = `~ ${btcTotal.toFixed(8)} BTC`;
        totalBtcEl.setAttribute('data-original-value', btcTotal.toString());
      }
    }
  }

  async function toggleBalances() {
    if (state.toggleInProgress) return;

    try {
      state.toggleInProgress = true;
      const balancesVisible = localStorage.getItem('balancesVisible') === 'true';
      const newVisibility = !balancesVisible;

      localStorage.setItem('balancesVisible', newVisibility.toString());
      updateVisibility(newVisibility);

      if (state.toggleDebounceTimer) {
        clearTimeout(state.toggleDebounceTimer);
      }

      state.toggleDebounceTimer = window.setTimeout(async () => {
        state.toggleInProgress = false;
        if (newVisibility) {
          await updatePrices(true);
        }
      }, config.debounceDelay);
    } catch (error) {
      console.error('Failed to toggle balances:', error);
      state.toggleInProgress = false;
    }
  }

  function updateVisibility(isVisible) {
    if (isVisible) {
      showBalances();
    } else {
      hideBalances();
    }

    const eyeIcon = document.querySelector("#hide-usd-amount-toggle svg");
    if (eyeIcon) {
      eyeIcon.innerHTML = isVisible ?
        '<path d="M23.444,10.239C21.905,8.062,17.708,3,12,3S2.1,8.062,.555,10.24a3.058,3.058,0,0,0,0,3.52h0C2.1,15.938,6.292,21,12,21s9.905-5.062,11.445-7.24A3.058,3.058,0,0,0,23.444,10.239ZM12,17a5,5,0,1,1,5-5A5,5,0,0,1,12,17Z"></path>' :
        '<path d="M23.444,10.239a22.936,22.936,0,0,0-2.492-2.948l-4.021,4.021A5.026,5.026,0,0,1,17,12a5,5,0,0,1-5,5,5.026,5.026,0,0,1-.688-.069L8.055,20.188A10.286,10.286,0,0,0,12,21c5.708,0,9.905-5.062,11.445-7.24A3.058,3.058,0,0,0,23.444,10.239Z"></path><path d="M12,3C6.292,3,2.1,8.062,.555,10.24a3.058,3.058,0,0,0,0,3.52h0a21.272,21.272,0,0,0,4.784,4.9l3.124-3.124a5,5,0,0,1,7.071-7.072L8.464,15.536l10.2-10.2A11.484,11.484,0,0,0,12,3Z"></path><path data-color="color-2" d="M1,24a1,1,0,0,1-.707-1.707l22-22a1,1,0,0,1,1.414,1.414l-22,22A1,1,0,0,1,1,24Z"></path>';
    }
  }

  function showBalances() {
    const usdText = document.getElementById('usd-text');
    if (usdText) {
      usdText.style.display = 'inline';
    }

    document.querySelectorAll('.coinname-value').forEach(el => {
      const originalValue = el.getAttribute('data-original-value');
      if (originalValue) {
        el.textContent = originalValue;
      }
    });

    document.querySelectorAll('.usd-value').forEach(el => {
      const storedValue = el.getAttribute('data-original-value');
      if (storedValue !== null && storedValue !== undefined) {
        if (el.closest('tr')?.querySelector('td')?.textContent?.includes('Fee Estimate:')) {
          el.textContent = `$${parseFloat(storedValue).toFixed(8)}`;
        } else {
          el.textContent = `$${parseFloat(storedValue).toFixed(2)}`;
        }
      } else {
        if (el.closest('tr')?.querySelector('td')?.textContent?.includes('Fee Estimate:')) {
          el.textContent = '$0.00000000';
        } else {
          el.textContent = '$0.00';
        }
      }
    });

    if (state.isWalletsPage) {
      ['total-usd-value', 'total-btc-value'].forEach(id => {
        const el = document.getElementById(id);
        const originalValue = el?.getAttribute('data-original-value');
        if (el && originalValue) {
          if (id === 'total-usd-value') {
            el.textContent = `$${parseFloat(originalValue).toFixed(2)}`;
            el.classList.add('font-extrabold');
          } else {
            el.textContent = `~ ${parseFloat(originalValue).toFixed(8)} BTC`;
          }
        }
      });
    }
  }

  function hideBalances() {
    const usdText = document.getElementById('usd-text');
    if (usdText) {
      usdText.style.display = 'none';
    }

    document.querySelectorAll('.coinname-value').forEach(el => {
      el.textContent = '****';
    });

    document.querySelectorAll('.usd-value').forEach(el => {
      el.textContent = '****';
    });

    if (state.isWalletsPage) {
      ['total-usd-value', 'total-btc-value'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
          el.textContent = '****';
        }
      });

      const totalUsdEl = document.getElementById('total-usd-value');
      if (totalUsdEl) {
        totalUsdEl.classList.remove('font-extrabold');
      }
    }
  }

  async function loadBalanceVisibility() {
    const balancesVisible = localStorage.getItem('balancesVisible') === 'true';
    updateVisibility(balancesVisible);

    if (balancesVisible) {
      await updatePrices(true);
    }
  }

  // Public API
  const publicAPI = {
    initialize: async function(options) {
      if (state.initialized) {
        console.warn('[WalletManager] Already initialized');
        return this;
      }

      if (options) {
        Object.assign(config, options);
      }

      state.lastUpdateTime = parseInt(localStorage.getItem(stateKeys.lastUpdate) || '0');
      state.isWalletsPage = document.querySelector('.wallet-list') !== null ||
        window.location.pathname.includes('/wallets');

      document.querySelectorAll('.usd-value').forEach(el => {
        const text = el.textContent?.trim() || '';
        if (text === 'Loading...') {
          el.textContent = '';
        }
      });

      storeOriginalValues();

      if (localStorage.getItem('balancesVisible') === null) {
        localStorage.setItem('balancesVisible', 'true');
      }

      const hideBalancesToggle = document.getElementById('hide-usd-amount-toggle');
      if (hideBalancesToggle) {
        hideBalancesToggle.addEventListener('click', toggleBalances);
      }

      await loadBalanceVisibility();

      if (state.priceUpdateInterval) {
        clearInterval(state.priceUpdateInterval);
      }

      state.priceUpdateInterval = setInterval(() => {
        if (localStorage.getItem('balancesVisible') === 'true' && !state.toggleInProgress) {
          updatePrices(false);
        }
      }, config.priceUpdateInterval);

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('walletManager', this, (mgr) => mgr.dispose());
      }

      state.initialized = true;
      console.log('WalletManager initialized');

      return this;
    },

    updatePrices: function(forceUpdate = false) {
      return updatePrices(forceUpdate);
    },

    toggleBalances: function() {
      return toggleBalances();
    },

    setPriceSource: function(primarySource, fallbackSource = null) {
      if (!config.priceSource.enabledSources.includes(primarySource)) {
        throw new Error(`Invalid primary source: ${primarySource}`);
      }

      if (fallbackSource && !config.priceSource.enabledSources.includes(fallbackSource)) {
        throw new Error(`Invalid fallback source: ${fallbackSource}`);
      }

      config.priceSource.primary = primarySource;
      if (fallbackSource) {
        config.priceSource.fallback = fallbackSource;
      }

      return this;
    },

    getConfig: function() {
      return { ...config };
    },

    getState: function() {
      return {
        initialized: state.initialized,
        lastUpdateTime: state.lastUpdateTime,
        isWalletsPage: state.isWalletsPage,
        balancesVisible: localStorage.getItem('balancesVisible') === 'true'
      };
    },

    dispose: function() {
      if (state.priceUpdateInterval) {
        clearInterval(state.priceUpdateInterval);
        state.priceUpdateInterval = null;
      }

      if (state.toggleDebounceTimer) {
        clearTimeout(state.toggleDebounceTimer);
        state.toggleDebounceTimer = null;
      }

      state.initialized = false;
      console.log('WalletManager disposed');
    }
  };

  return publicAPI;
})();

window.WalletManager = WalletManager;

document.addEventListener('DOMContentLoaded', function() {
  if (!window.walletManagerInitialized) {
    WalletManager.initialize();
    window.walletManagerInitialized = true;
  }
});

//console.log('WalletManager initialized with methods:', Object.keys(WalletManager));
console.log('WalletManager initialized');
