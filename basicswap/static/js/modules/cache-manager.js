const CacheManager = (function() {
  function getDefaults() {
    if (window.config?.cacheConfig?.storage) {
      return window.config.cacheConfig.storage;
    }
    if (window.ConfigManager?.cacheConfig?.storage) {
      return window.ConfigManager.cacheConfig.storage;
    }
    return {
      maxSizeBytes: 10 * 1024 * 1024,
      maxItems: 200,
      defaultTTL: 5 * 60 * 1000
    };
  }

  const defaults = getDefaults();

  const PRICES_CACHE_KEY = 'crypto_prices_unified';

  const CACHE_KEY_PATTERNS = [
    'coinData_',
    'chartData_',
    'historical_',
    'rates_',
    'prices_',
    'offers_',
    'fallback_',
    'volumeData'
  ];

  const isCacheKey = (key) => {
    return CACHE_KEY_PATTERNS.some(pattern => key.startsWith(pattern)) ||
           key === 'coinGeckoOneLiner' ||
           key === PRICES_CACHE_KEY;
  };

  const isLocalStorageAvailable = () => {
    try {
      const testKey = '__storage_test__';
      localStorage.setItem(testKey, testKey);
      localStorage.removeItem(testKey);
      return true;
    } catch (e) {
      return false;
    }
  };

  let storageAvailable = isLocalStorageAvailable();

  const memoryCache = new Map();

  if (!storageAvailable) {
    console.warn('localStorage is not available. Using in-memory cache instead.');
  }

  const cacheAPI = {
    getTTL: function(resourceType) {
      const ttlConfig = window.config?.cacheConfig?.ttlSettings ||
                        window.ConfigManager?.cacheConfig?.ttlSettings || {};
      const defaultTTL = window.config?.cacheConfig?.defaultTTL ||
                         window.ConfigManager?.cacheConfig?.defaultTTL ||
                         defaults.defaultTTL;
      return ttlConfig[resourceType] || defaultTTL;
    },

    set: function(key, value, resourceTypeOrCustomTtl = null) {
      try {
        this.cleanup();

        if (!value) {
          console.warn('Attempted to cache null/undefined value for key:', key);
          return false;
        }

        let ttl;
        if (typeof resourceTypeOrCustomTtl === 'string') {
          ttl = this.getTTL(resourceTypeOrCustomTtl);
        } else if (typeof resourceTypeOrCustomTtl === 'number') {
          ttl = resourceTypeOrCustomTtl;
        } else {
          ttl = window.config?.cacheConfig?.defaultTTL || defaults.defaultTTL;
        }

        const item = {
          value: value,
          timestamp: Date.now(),
          expiresAt: Date.now() + ttl
        };

        const serializedItem = window.ErrorHandler
          ? window.ErrorHandler.safeExecute(() => JSON.stringify(item), 'CacheManager.set.serialize', null)
          : (() => {
              try {
                return JSON.stringify(item);
              } catch (e) {
                console.error('Failed to serialize cache item:', e);
                return null;
              }
            })();

        if (!serializedItem) return false;

        const itemSize = new Blob([serializedItem]).size;
        if (itemSize > defaults.maxSizeBytes) {
          console.warn(`Cache item exceeds maximum size (${(itemSize/1024/1024).toFixed(2)}MB)`);
          return false;
        }

        if (storageAvailable) {
          try {
            localStorage.setItem(key, serializedItem);
            return true;
          } catch (storageError) {
            if (storageError.name === 'QuotaExceededError') {
              this.cleanup(true);
              try {
                localStorage.setItem(key, serializedItem);
                return true;
              } catch (retryError) {
                console.error('Storage quota exceeded even after cleanup:', retryError);
                storageAvailable = false;
                console.warn('Switching to in-memory cache due to quota issues');
                memoryCache.set(key, item);
                return true;
              }
            } else {
              console.error('localStorage error:', storageError);
              storageAvailable = false;
              console.warn('Switching to in-memory cache due to localStorage error');
              memoryCache.set(key, item);
              return true;
            }
          }
        } else {
          memoryCache.set(key, item);
          if (memoryCache.size > defaults.maxItems) {
            const keysToDelete = Array.from(memoryCache.keys())
              .filter(k => isCacheKey(k))
              .sort((a, b) => memoryCache.get(a).timestamp - memoryCache.get(b).timestamp)
              .slice(0, Math.floor(memoryCache.size * 0.2)); 

            keysToDelete.forEach(k => memoryCache.delete(k));
          }

          return true;
        }
      } catch (error) {
        console.error('Cache set error:', error);
        try {
          memoryCache.set(key, {
            value: value,
            timestamp: Date.now(),
            expiresAt: Date.now() + (window.config?.cacheConfig?.defaultTTL || defaults.defaultTTL)
          });
          return true;
        } catch (e) {
          console.error('Memory cache set error:', e);
          return false;
        }
      }
    },

    get: function(key) {
      try {
        if (storageAvailable) {
          try {
            const itemStr = localStorage.getItem(key);
            if (itemStr) {
              let item;
              try {
                item = JSON.parse(itemStr);
              } catch (parseError) {
                console.error('Failed to parse cached item:', parseError);
                localStorage.removeItem(key);
                return null;
              }

              if (!item || typeof item.expiresAt !== 'number' || !Object.prototype.hasOwnProperty.call(item, 'value')) {
                console.warn('Invalid cache item structure for key:', key);
                localStorage.removeItem(key);
                return null;
              }

              const now = Date.now();
              if (now < item.expiresAt) {
                return {
                  value: item.value,
                  remainingTime: item.expiresAt - now
                };
              }

              localStorage.removeItem(key);
              return null;
            }
          } catch (error) {
            console.error("localStorage access error:", error);
            storageAvailable = false;
            console.warn('Switching to in-memory cache due to localStorage error');
          }
        }

        if (memoryCache.has(key)) {
          const item = memoryCache.get(key);
          const now = Date.now();

          if (now < item.expiresAt) {
            return {
              value: item.value,
              remainingTime: item.expiresAt - now
            };
          } else {

            memoryCache.delete(key);
          }
        }

        return null;
      } catch (error) {
        console.error("Cache retrieval error:", error);
        try {
          if (storageAvailable) {
            localStorage.removeItem(key);
          }
          memoryCache.delete(key);
        } catch (removeError) {
          console.error("Failed to remove invalid cache entry:", removeError);
        }
        return null;
      }
    },

    isValid: function(key) {
      return this.get(key) !== null;
    },

    cleanup: function(aggressive = false) {
      const now = Date.now();
      let totalSize = 0;
      let itemCount = 0;
      const items = [];

      if (storageAvailable) {
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (!isCacheKey(key)) continue;

            try {
              const itemStr = localStorage.getItem(key);
              const size = new Blob([itemStr]).size;
              const item = JSON.parse(itemStr);

              if (now >= item.expiresAt) {
                localStorage.removeItem(key);
                continue;
              }

              items.push({
                key,
                size,
                expiresAt: item.expiresAt,
                timestamp: item.timestamp
              });

              totalSize += size;
              itemCount++;
            } catch (error) {
              console.error("Error processing cache item:", error);
              localStorage.removeItem(key);
            }
          }

          if (aggressive || totalSize > defaults.maxSizeBytes || itemCount > defaults.maxItems) {
            items.sort((a, b) => b.timestamp - a.timestamp);

            while ((totalSize > defaults.maxSizeBytes || itemCount > defaults.maxItems) && items.length > 0) {
              const item = items.pop();
              try {
                localStorage.removeItem(item.key);
                totalSize -= item.size;
                itemCount--;
              } catch (error) {
                console.error("Error removing cache item:", error);
              }
            }
          }
        } catch (error) {
          console.error("Error during localStorage cleanup:", error);
          storageAvailable = false;
          console.warn('Switching to in-memory cache due to localStorage error');
        }
      }

      const expiredKeys = [];
      memoryCache.forEach((item, key) => {
        if (now >= item.expiresAt) {
          expiredKeys.push(key);
        }
      });

      expiredKeys.forEach(key => memoryCache.delete(key));

      if (aggressive && memoryCache.size > defaults.maxItems / 2) {
        const keysToDelete = Array.from(memoryCache.keys())
          .filter(key => isCacheKey(key))
          .sort((a, b) => memoryCache.get(a).timestamp - memoryCache.get(b).timestamp)
          .slice(0, Math.floor(memoryCache.size * 0.3)); 

        keysToDelete.forEach(key => memoryCache.delete(key));
      }

      return {
        totalSize,
        itemCount,
        memoryCacheSize: memoryCache.size,
        cleaned: items.length,
        storageAvailable
      };
    },

    clear: function() {

      if (storageAvailable) {
        try {
          const keys = [];
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (isCacheKey(key)) {
              keys.push(key);
            }
          }

          keys.forEach(key => {
            try {
              localStorage.removeItem(key);
            } catch (error) {
              console.error("Error clearing cache item:", error);
            }
          });
        } catch (error) {
          console.error("Error clearing localStorage cache:", error);
          storageAvailable = false;
        }
      }

      Array.from(memoryCache.keys())
        .filter(key => isCacheKey(key))
        .forEach(key => memoryCache.delete(key));

      return true;
    },

    getStats: function() {
      let totalSize = 0;
      let itemCount = 0;
      let expiredCount = 0;
      const now = Date.now();

      if (storageAvailable) {
        try {
          for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (!isCacheKey(key)) continue;

            try {
              const itemStr = localStorage.getItem(key);
              const size = new Blob([itemStr]).size;
              const item = JSON.parse(itemStr);

              totalSize += size;
              itemCount++;

              if (now >= item.expiresAt) {
                expiredCount++;
              }
            } catch (error) {
              console.error("Error getting cache stats:", error);
            }
          }
        } catch (error) {
          console.error("Error getting localStorage stats:", error);
          storageAvailable = false;
        }
      }

      let memoryCacheSize = 0;
      let memoryCacheItems = 0;
      let memoryCacheExpired = 0;

      memoryCache.forEach((item, key) => {
        if (isCacheKey(key)) {
          memoryCacheItems++;
          if (now >= item.expiresAt) {
            memoryCacheExpired++;
          }
          try {
            memoryCacheSize += new Blob([JSON.stringify(item)]).size;
          } catch (e) {
          }
        }
      });

      return {
        totalSizeMB: (totalSize / 1024 / 1024).toFixed(2),
        itemCount,
        expiredCount,
        utilization: ((totalSize / defaults.maxSizeBytes) * 100).toFixed(1) + '%',
        memoryCacheItems,
        memoryCacheExpired,
        memoryCacheSizeKB: (memoryCacheSize / 1024).toFixed(2),
        storageType: storageAvailable ? 'localStorage' : 'memory'
      };
    },

    checkStorage: function() {
      const wasAvailable = storageAvailable;
      storageAvailable = isLocalStorageAvailable();

      if (storageAvailable && !wasAvailable && memoryCache.size > 0) {
        console.log('localStorage is now available. Migrating memory cache...');
        let migratedCount = 0;
        memoryCache.forEach((item, key) => {
          if (isCacheKey(key)) {
            try {
              localStorage.setItem(key, JSON.stringify(item));
              memoryCache.delete(key);
              migratedCount++;
            } catch (e) {
              if (e.name === 'QuotaExceededError') {
                console.warn('Storage quota exceeded during migration. Keeping items in memory cache.');
                return false;
              }
            }
          }
        });

        console.log(`Migrated ${migratedCount} items from memory cache to localStorage.`);
      }

      return {
        available: storageAvailable,
        type: storageAvailable ? 'localStorage' : 'memory'
      };
    }
  };

  const publicAPI = {
    ...cacheAPI,

    setPrices: function(priceData, customTtl = null) {
      return this.set(PRICES_CACHE_KEY, priceData,
        customTtl || (typeof customTtl === 'undefined' ? 'prices' : null));
    },

    getPrices: function() {
      return this.get(PRICES_CACHE_KEY);
    },

    getCoinPrice: function(symbol) {
      const prices = this.getPrices();
      if (!prices || !prices.value) {
        return null;
      }

      const normalizedSymbol = symbol.toLowerCase();
      return prices.value[normalizedSymbol] || null;
    },

    getCompatiblePrices: function(format) {
      const prices = this.getPrices();
      if (!prices || !prices.value) {
        return null;
      }

      switch(format) {
        case 'rates':
          const ratesFormat = {};
          Object.entries(prices.value).forEach(([coin, data]) => {
            const coinKey = coin.replace(/-/g, ' ')
              .split(' ')
              .map(word => word.charAt(0).toUpperCase() + word.slice(1))
              .join(' ')
              .toLowerCase()
              .replace(' ', '-');

            ratesFormat[coinKey] = {
              usd: data.price || data.usd,
              btc: data.price_btc || data.btc
            };
          });
          return {
            value: ratesFormat,
            remainingTime: prices.remainingTime
          };

        case 'coinGecko':
          const geckoFormat = {};
          Object.entries(prices.value).forEach(([coin, data]) => {
            const symbol = this.getSymbolFromCoinId(coin);
            if (symbol) {
              geckoFormat[symbol.toLowerCase()] = {
                current_price: data.price || data.usd,
                price_btc: data.price_btc || data.btc,
                total_volume: data.total_volume,
                price_change_percentage_24h: data.price_change_percentage_24h,
                displayName: symbol
              };
            }
          });
          return {
            value: geckoFormat,
            remainingTime: prices.remainingTime
          };

        default:
          return prices;
      }
    },

    getSymbolFromCoinId: function(coinId) {
      const symbolMap = {
        'bitcoin': 'BTC',
        'litecoin': 'LTC',
        'monero': 'XMR',
        'wownero': 'WOW',
        'particl': 'PART',
        'pivx': 'PIVX',
        'firo': 'FIRO',
        'zcoin': 'FIRO',
        'dash': 'DASH',
        'decred': 'DCR',
        'namecoin': 'NMR',
        'bitcoin-cash': 'BCH',
        'dogecoin': 'DOGE'
      };

      return symbolMap[coinId] || null;
    }
  };

  if (window.CleanupManager) {
    window.CleanupManager.registerResource('cacheManager', publicAPI, (cm) => {
      cm.clear();
    });
  }

  return publicAPI;
})();

window.CacheManager = CacheManager;

console.log('CacheManager initialized');
