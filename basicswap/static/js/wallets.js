const Wallets = (function() {
  const CONFIG = {
    MAX_RETRIES: 5,
    BASE_DELAY: 500,
    CACHE_EXPIRATION: 5 * 60 * 1000,
    PRICE_UPDATE_INTERVAL: 5 * 60 * 1000,
    API_TIMEOUT: 30000,
    DEBOUNCE_DELAY: 300,
    CACHE_MIN_INTERVAL: 60 * 1000,
    DEFAULT_TTL: 300,
    PRICE_SOURCE: {
      PRIMARY: 'coingecko.com',
      FALLBACK: 'cryptocompare.com',
      ENABLED_SOURCES: ['coingecko.com', 'cryptocompare.com']
    }
  };

  const COIN_SYMBOLS = {
    'Bitcoin': 'BTC',
    'Particl': 'PART',
    'Monero': 'XMR',
    'Wownero': 'WOW',
    'Litecoin': 'LTC',
    'Dogecoin': 'DOGE',
    'Firo': 'FIRO',
    'Dash': 'DASH',
    'PIVX': 'PIVX',
    'Decred': 'DCR',
    'Bitcoin Cash': 'BCH'
  };

  const COINGECKO_IDS = {
    'BTC': 'btc',
    'PART': 'part',
    'XMR': 'xmr',
    'WOW': 'wownero',
    'LTC': 'ltc',
    'DOGE': 'doge',
    'FIRO': 'firo',
    'DASH': 'dash',
    'PIVX': 'pivx',
    'DCR': 'dcr',
    'BCH': 'bch'
  };

  const SHORT_NAMES = {
    'Bitcoin': 'BTC',
    'Particl': 'PART',
    'Monero': 'XMR',
    'Wownero': 'WOW',
    'Litecoin': 'LTC',
    'Litecoin MWEB': 'LTC MWEB',
    'Firo': 'FIRO',
    'Dash': 'DASH',
    'PIVX': 'PIVX',
    'Decred': 'DCR',
    'Bitcoin Cash': 'BCH',
     'Dogecoin': 'DOGE'
  };

  class Cache {
    constructor(expirationTime) {
      this.data = null;
      this.timestamp = null;
      this.expirationTime = expirationTime;
    }

    isValid() {
      return Boolean(
        this.data && 
        this.timestamp &&
        (Date.now() - this.timestamp < this.expirationTime)
      );
    }

    set(data) {
      this.data = data;
      this.timestamp = Date.now();
    }

    get() {
      if (this.isValid()) {
        return this.data;
      }
      return null;
    }

    clear() {
      this.data = null;
      this.timestamp = null;
    }
  }

  class ApiClient {
    constructor() {
      this.cache = new Cache(CONFIG.CACHE_EXPIRATION);
      this.lastFetchTime = 0;
    }

    async fetchPrices(forceUpdate = false) {
      const now = Date.now();
      const timeSinceLastFetch = now - this.lastFetchTime;

      if (!forceUpdate && timeSinceLastFetch < CONFIG.CACHE_MIN_INTERVAL) {
        const cachedData = this.cache.get();
        if (cachedData) {
          return cachedData;
        }
      }

      const mainCoins = Object.values(COIN_SYMBOLS)
        .filter(symbol => symbol !== 'WOW')
        .map(symbol => COINGECKO_IDS[symbol] || symbol.toLowerCase())
        .join(',');

      let lastError = null;
      for (let attempt = 0; attempt < CONFIG.MAX_RETRIES; attempt++) {
        try {
          const processedData = {};

          const mainResponse = await fetch("/json/coinprices", {
            method: "POST",
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              coins: mainCoins,
              source: CONFIG.PRICE_SOURCE.PRIMARY,
              ttl: CONFIG.DEFAULT_TTL
            })
          });

          if (!mainResponse.ok) {
            throw new Error(`HTTP error: ${mainResponse.status}`);
          }

          const mainData = await mainResponse.json();

          if (mainData && mainData.rates) {
            Object.entries(mainData.rates).forEach(([coinId, price]) => {
              const symbol = Object.entries(COINGECKO_IDS).find(([sym, id]) => id.toLowerCase() === coinId.toLowerCase())?.[0];
              if (symbol) {
                const coinKey = Object.keys(COIN_SYMBOLS).find(key => COIN_SYMBOLS[key] === symbol);
                if (coinKey) {
                  processedData[coinKey.toLowerCase().replace(' ', '-')] = {
                    usd: price,
                    btc: symbol === 'BTC' ? 1 : price / (mainData.rates.btc || 1)
                  };
                }
              }
            });
          }

          try {
            const wowResponse = await fetch("/json/coinprices", {
              method: "POST",
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({
                coins: "wownero",
                source: "coingecko.com",
                ttl: CONFIG.DEFAULT_TTL
              })
            });

            if (wowResponse.ok) {
              const wowData = await wowResponse.json();
              if (wowData && wowData.rates && wowData.rates.wownero) {
                processedData['wownero'] = {
                  usd: wowData.rates.wownero,
                  btc: processedData.bitcoin ? wowData.rates.wownero / processedData.bitcoin.usd : 0
                };
              }
            }
          } catch (wowError) {
            console.error('Error fetching WOW price:', wowError);
          }

          this.cache.set(processedData);
          this.lastFetchTime = now;
          return processedData;
        } catch (error) {
          lastError = error;
          console.error(`Price fetch attempt ${attempt + 1} failed:`, error);

          if (attempt === CONFIG.MAX_RETRIES - 1 && 
              CONFIG.PRICE_SOURCE.FALLBACK && 
              CONFIG.PRICE_SOURCE.FALLBACK !== CONFIG.PRICE_SOURCE.PRIMARY) {
            const temp = CONFIG.PRICE_SOURCE.PRIMARY;
            CONFIG.PRICE_SOURCE.PRIMARY = CONFIG.PRICE_SOURCE.FALLBACK;
            CONFIG.PRICE_SOURCE.FALLBACK = temp;

            console.warn(`Switching to fallback source: ${CONFIG.PRICE_SOURCE.PRIMARY}`);
            attempt = -1;
            continue;
          }

          if (attempt < CONFIG.MAX_RETRIES - 1) {
            const delay = Math.min(CONFIG.BASE_DELAY * Math.pow(2, attempt), 10000);
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
      }

      const cachedData = this.cache.get();
      if (cachedData) {
        console.warn('Using cached data after fetch failures');
        return cachedData;
      }

      throw lastError || new Error('Failed to fetch prices');
    }

    setPriceSource(primarySource, fallbackSource = null) {
      if (!CONFIG.PRICE_SOURCE.ENABLED_SOURCES.includes(primarySource)) {
        throw new Error(`Invalid primary source: ${primarySource}`);
      }

      if (fallbackSource && !CONFIG.PRICE_SOURCE.ENABLED_SOURCES.includes(fallbackSource)) {
        throw new Error(`Invalid fallback source: ${fallbackSource}`);
      }

      CONFIG.PRICE_SOURCE.PRIMARY = primarySource;
      if (fallbackSource) {
        CONFIG.PRICE_SOURCE.FALLBACK = fallbackSource;
      }
    }
  }

  class UiManager {
    constructor() {
      this.api = new ApiClient();
      this.toggleInProgress = false;
      this.toggleDebounceTimer = null;
      this.priceUpdateInterval = null;
      this.lastUpdateTime = parseInt(localStorage.getItem(STATE_KEYS.LAST_UPDATE) || '0');
      this.isWalletsPage = document.querySelector('.wallet-list') !== null || 
                            window.location.pathname.includes('/wallets');
    }

    getShortName(fullName) {
      return SHORT_NAMES[fullName] || fullName;
    }

    storeOriginalValues() {
      document.querySelectorAll('.coinname-value').forEach(el => {
        const coinName = el.getAttribute('data-coinname');
        const value = el.textContent?.trim() || '';

        if (coinName) {
          const amount = value ? parseFloat(value.replace(/[^0-9.-]+/g, '')) : 0;
          const coinId = COIN_SYMBOLS[coinName];
          const shortName = this.getShortName(coinName);

          if (coinId) {
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
              localStorage.setItem(`${coinId.toLowerCase()}-amount`, amount.toString());
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

    async updatePrices(forceUpdate = false) {
      try {
        const prices = await this.api.fetchPrices(forceUpdate);
        let newTotal = 0;

        const currentTime = Date.now();
        localStorage.setItem(STATE_KEYS.LAST_UPDATE, currentTime.toString());
        this.lastUpdateTime = currentTime;

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

        if (this.isWalletsPage) {
          this.updateTotalValues(newTotal, prices?.bitcoin?.usd);
        }

        localStorage.setItem(STATE_KEYS.PREVIOUS_TOTAL, localStorage.getItem(STATE_KEYS.CURRENT_TOTAL) || '0');
        localStorage.setItem(STATE_KEYS.CURRENT_TOTAL, newTotal.toString());

        return true;
      } catch (error) {
        console.error('Price update failed:', error);
        return false;
      }
    }
    
    updateTotalValues(totalUsd, btcPrice) {
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

    async toggleBalances() {
      if (this.toggleInProgress) return;

      try {
        this.toggleInProgress = true;
        const balancesVisible = localStorage.getItem('balancesVisible') === 'true';
        const newVisibility = !balancesVisible;

        localStorage.setItem('balancesVisible', newVisibility.toString());
        this.updateVisibility(newVisibility);

        if (this.toggleDebounceTimer) {
          clearTimeout(this.toggleDebounceTimer);
        }

        this.toggleDebounceTimer = window.setTimeout(async () => {
          this.toggleInProgress = false;
          if (newVisibility) {
            await this.updatePrices(true);
          }
        }, CONFIG.DEBOUNCE_DELAY);
      } catch (error) {
        console.error('Failed to toggle balances:', error);
        this.toggleInProgress = false;
      }
    }

    updateVisibility(isVisible) {
      if (isVisible) {
        this.showBalances();
      } else {
        this.hideBalances();
      }

      const eyeIcon = document.querySelector("#hide-usd-amount-toggle svg");
      if (eyeIcon) {
        eyeIcon.innerHTML = isVisible ? 
          '<path d="M23.444,10.239C21.905,8.062,17.708,3,12,3S2.1,8.062,.555,10.24a3.058,3.058,0,0,0,0,3.52h0C2.1,15.938,6.292,21,12,21s9.905-5.062,11.445-7.24A3.058,3.058,0,0,0,23.444,10.239ZM12,17a5,5,0,1,1,5-5A5,5,0,0,1,12,17Z"></path>' :
          '<path d="M23.444,10.239a22.936,22.936,0,0,0-2.492-2.948l-4.021,4.021A5.026,5.026,0,0,1,17,12a5,5,0,0,1-5,5,5.026,5.026,0,0,1-.688-.069L8.055,20.188A10.286,10.286,0,0,0,12,21c5.708,0,9.905-5.062,11.445-7.24A3.058,3.058,0,0,0,23.444,10.239Z"></path><path d="M12,3C6.292,3,2.1,8.062,.555,10.24a3.058,3.058,0,0,0,0,3.52h0a21.272,21.272,0,0,0,4.784,4.9l3.124-3.124a5,5,0,0,1,7.071-7.072L8.464,15.536l10.2-10.2A11.484,11.484,0,0,0,12,3Z"></path><path data-color="color-2" d="M1,24a1,1,0,0,1-.707-1.707l22-22a1,1,0,0,1,1.414,1.414l-22,22A1,1,0,0,1,1,24Z"></path>';
      }
    }

    showBalances() {
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

      if (this.isWalletsPage) {
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

    hideBalances() {
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

      if (this.isWalletsPage) {
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

    async initialize() {
      document.querySelectorAll('.usd-value').forEach(el => {
        const text = el.textContent?.trim() || '';
        if (text === 'Loading...') {
          el.textContent = '';
        }
      });

      this.storeOriginalValues();
      
      if (localStorage.getItem('balancesVisible') === null) {
        localStorage.setItem('balancesVisible', 'true');
      }

      const hideBalancesToggle = document.getElementById('hide-usd-amount-toggle');
      if (hideBalancesToggle) {
        hideBalancesToggle.addEventListener('click', () => this.toggleBalances());
      }

      await this.loadBalanceVisibility();

      if (this.priceUpdateInterval) {
        clearInterval(this.priceUpdateInterval);
      }

      this.priceUpdateInterval = setInterval(() => {
        if (localStorage.getItem('balancesVisible') === 'true' && !this.toggleInProgress) {
          this.updatePrices(false);
        }
      }, CONFIG.PRICE_UPDATE_INTERVAL);
    }

    async loadBalanceVisibility() {
      const balancesVisible = localStorage.getItem('balancesVisible') === 'true';
      this.updateVisibility(balancesVisible);

      if (balancesVisible) {
        await this.updatePrices(true);
      }
    }

    cleanup() {
      if (this.priceUpdateInterval) {
        clearInterval(this.priceUpdateInterval);
      }
    }
  }

  const STATE_KEYS = {
    LAST_UPDATE: 'last-update-time',
    PREVIOUS_TOTAL: 'previous-total-usd',
    CURRENT_TOTAL: 'current-total-usd',
    BALANCES_VISIBLE: 'balancesVisible'
  };

  return {
    initialize: function() {
      const uiManager = new UiManager();

      window.cryptoPricingManager = uiManager;

      window.addEventListener('beforeunload', () => {
        uiManager.cleanup();
      });

      uiManager.initialize().catch(error => {
        console.error('Failed to initialize crypto pricing:', error);
      });

      return uiManager;
    },

    getUiManager: function() {
      return window.cryptoPricingManager;
    },

    setPriceSource: function(primarySource, fallbackSource = null) {
      const uiManager = this.getUiManager();
      if (uiManager && uiManager.api) {
        uiManager.api.setPriceSource(primarySource, fallbackSource);
      }
    }
  };
})();

document.addEventListener('DOMContentLoaded', function() {
  Wallets.initialize();
});
