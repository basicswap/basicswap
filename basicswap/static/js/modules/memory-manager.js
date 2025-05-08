const MemoryManager = (function() {
  const config = {
    tooltipCleanupInterval: 300000,
    diagnosticsInterval: 600000,
    elementVerificationInterval: 300000,
    maxTooltipsThreshold: 100,
    maxTooltips: 300,
    cleanupThreshold: 1.5,
    minTimeBetweenCleanups: 180000,
    memoryGrowthThresholdMB: 100,
    debug: false,
    protectedWebSockets: ['wsPort', 'ws_port'],
    interactiveSelectors: [
      'tr:hover', 
      '[data-tippy-root]:hover', 
      '.tooltip:hover', 
      '[data-tooltip-trigger-id]:hover', 
      '[data-tooltip-target]:hover'
    ],
    protectedContainers: [
      '#sent-tbody', 
      '#received-tbody', 
      '#offers-body'
    ]
  };

  const state = {
    pendingAnimationFrames: new Set(),
    pendingTimeouts: new Set(),
    cleanupInterval: null,
    diagnosticsInterval: null,
    elementVerificationInterval: null,
    mutationObserver: null,
    lastCleanupTime: Date.now(),
    startTime: Date.now(),
    isCleanupRunning: false,
    metrics: {
      tooltipsRemoved: 0,
      cleanupRuns: 0,
      lastMemoryUsage: null,
      lastCleanupDetails: {},
      history: []
    },
    originalTooltipFunctions: {}
  };

  function log(message, ...args) {
    if (config.debug) {
      console.log(`[MemoryManager] ${message}`, ...args);
    }
  }

  function preserveTooltipFunctions() {
    if (window.TooltipManager && !state.originalTooltipFunctions.destroy) {
      state.originalTooltipFunctions = {
        destroy: window.TooltipManager.destroy,
        cleanup: window.TooltipManager.cleanup,
        create: window.TooltipManager.create
      };
    }
  }

  function isInProtectedContainer(element) {
    if (!element) return false;

    for (const selector of config.protectedContainers) {
      if (element.closest && element.closest(selector)) {
        return true;
      }
    }

    return false;
  }

  function shouldSkipCleanup() {
    if (state.isCleanupRunning) return true;
    
    const selector = config.interactiveSelectors.join(', ');
    const hoveredElements = document.querySelectorAll(selector);
    
    return hoveredElements.length > 0;
  }

  function performCleanup(force = false) {
    if (shouldSkipCleanup() && !force) {
      return false;
    }

    if (state.isCleanupRunning) {
      return false;
    }

    const now = Date.now();
    if (!force && now - state.lastCleanupTime < config.minTimeBetweenCleanups) {
      return false;
    }

    try {
      state.isCleanupRunning = true;
      state.lastCleanupTime = now;
      state.metrics.cleanupRuns++;

      const startTime = performance.now();
      const startMemory = checkMemoryUsage();

      state.pendingAnimationFrames.forEach(id => {
        cancelAnimationFrame(id);
      });
      state.pendingAnimationFrames.clear();

      state.pendingTimeouts.forEach(id => {
        clearTimeout(id);
      });
      state.pendingTimeouts.clear();

      const tooltipsResult = removeOrphanedTooltips();
      state.metrics.tooltipsRemoved += tooltipsResult;

      const disconnectedResult = checkForDisconnectedElements();

      tryRunGarbageCollection(false);

      const endTime = performance.now();
      const endMemory = checkMemoryUsage();

      const runStats = {
        timestamp: new Date().toISOString(),
        duration: endTime - startTime,
        tooltipsRemoved: tooltipsResult,
        disconnectedRemoved: disconnectedResult,
        memoryBefore: startMemory ? startMemory.usedMB : null,
        memoryAfter: endMemory ? endMemory.usedMB : null,
        memorySaved: startMemory && endMemory ? 
          (startMemory.usedMB - endMemory.usedMB).toFixed(2) : null
      };

      state.metrics.history.unshift(runStats);
      if (state.metrics.history.length > 10) {
        state.metrics.history.pop();
      }

      state.metrics.lastCleanupDetails = runStats;

      if (config.debug) {
        log(`Cleanup completed in ${runStats.duration.toFixed(2)}ms, removed ${tooltipsResult} tooltips`);
      }

      return true;
    } catch (error) {
      console.error("Error during cleanup:", error);
      return false;
    } finally {
      state.isCleanupRunning = false;
    }
  }

  function removeOrphanedTooltips() {
    try {

      const tippyRoots = document.querySelectorAll('[data-tippy-root]:not(:hover)');
      let removed = 0;

      tippyRoots.forEach(root => {
        const tooltipId = root.getAttribute('data-for-tooltip-id');
        const trigger = tooltipId ? 
          document.querySelector(`[data-tooltip-trigger-id="${tooltipId}"]`) : null;

        if (!trigger || !document.body.contains(trigger)) {
          if (root.parentNode) {
            root.parentNode.removeChild(root);
            removed++;
          }
        }
      });

      return removed;
    } catch (error) {
      console.error("Error removing orphaned tooltips:", error);
      return 0;
    }
  }

  function checkForDisconnectedElements() {
    try {

      const tooltipTriggers = document.querySelectorAll('[data-tooltip-trigger-id]:not(:hover)');
      const disconnectedElements = new Set();

      tooltipTriggers.forEach(el => {
        if (!document.body.contains(el)) {
          const tooltipId = el.getAttribute('data-tooltip-trigger-id');
          disconnectedElements.add(tooltipId);
        }
      });

      const tooltipRoots = document.querySelectorAll('[data-for-tooltip-id]');
      let removed = 0;

      disconnectedElements.forEach(id => {
        for (const root of tooltipRoots) {
          if (root.getAttribute('data-for-tooltip-id') === id && root.parentNode) {
            root.parentNode.removeChild(root);
            removed++;
            break;
          }
        }
      });

      return disconnectedElements.size;
    } catch (error) {
      console.error("Error checking for disconnected elements:", error);
      return 0;
    }
  }

  function tryRunGarbageCollection(aggressive = false) {
    setTimeout(() => {

      const cache = {};
      for (let i = 0; i < 100; i++) {
        cache[`key${i}`] = {};
      }

      for (const key in cache) {
        delete cache[key];
      }
    }, 100);

    return true;
  }
  
  function checkMemoryUsage() {
    const result = {
      usedJSHeapSize: 0,
      totalJSHeapSize: 0,
      jsHeapSizeLimit: 0,
      percentUsed: "0",
      usedMB: "0",
      totalMB: "0",
      limitMB: "0"
    };

    if (window.performance && window.performance.memory) {
      result.usedJSHeapSize = window.performance.memory.usedJSHeapSize;
      result.totalJSHeapSize = window.performance.memory.totalJSHeapSize;
      result.jsHeapSizeLimit = window.performance.memory.jsHeapSizeLimit;
      result.percentUsed = (result.usedJSHeapSize / result.jsHeapSizeLimit * 100).toFixed(2);
      result.usedMB = (result.usedJSHeapSize / (1024 * 1024)).toFixed(2);
      result.totalMB = (result.totalJSHeapSize / (1024 * 1024)).toFixed(2);
      result.limitMB = (result.jsHeapSizeLimit / (1024 * 1024)).toFixed(2);
    } else {
      result.usedMB = "Unknown";
      result.totalMB = "Unknown";
      result.limitMB = "Unknown";
      result.percentUsed = "Unknown";
    }

    state.metrics.lastMemoryUsage = result;
    return result;
  }

  function handleVisibilityChange() {
    if (document.hidden) {
      removeOrphanedTooltips();
      checkForDisconnectedElements();
    }
  }

  function setupMutationObserver() {
    if (state.mutationObserver) {
      state.mutationObserver.disconnect();
      state.mutationObserver = null;
    }

    let processingScheduled = false;
    let lastProcessTime = 0;
    const MIN_PROCESS_INTERVAL = 10000;

    const processMutations = (mutations) => {
      const now = Date.now();

      if (now - lastProcessTime < MIN_PROCESS_INTERVAL || processingScheduled) {
        return;
      }

      processingScheduled = true;

      setTimeout(() => {
        processingScheduled = false;
        lastProcessTime = Date.now();
        
        if (state.isCleanupRunning) {
          return;
        }

        const tooltipSelectors = ['[data-tippy-root]', '[data-tooltip-trigger-id]', '.tooltip'];
        let tooltipCount = 0;

        tooltipCount = document.querySelectorAll(tooltipSelectors.join(', ')).length;

        if (tooltipCount > config.maxTooltipsThreshold && 
            (Date.now() - state.lastCleanupTime > config.minTimeBetweenCleanups)) {

          removeOrphanedTooltips();
          checkForDisconnectedElements();
          state.lastCleanupTime = Date.now();
        }
      }, 5000);
    };

    state.mutationObserver = new MutationObserver(processMutations);

    state.mutationObserver.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false
    });

    return state.mutationObserver;
  }

  function enhanceTooltipManager() {
    if (!window.TooltipManager || window.TooltipManager._memoryManagerEnhanced) return false;

    preserveTooltipFunctions();

    const originalDestroy = window.TooltipManager.destroy;
    const originalCleanup = window.TooltipManager.cleanup;

    window.TooltipManager.destroy = function(element) {
      if (!element) return;

      try {
        const tooltipId = element.getAttribute('data-tooltip-trigger-id');

        if (isInProtectedContainer(element)) {
          if (originalDestroy) {
            return originalDestroy.call(window.TooltipManager, element);
          }
          return;
        }

        if (tooltipId) {
          if (originalDestroy) {
            originalDestroy.call(window.TooltipManager, element);
          }

          const tooltipRoot = document.querySelector(`[data-for-tooltip-id="${tooltipId}"]`);
          if (tooltipRoot && tooltipRoot.parentNode) {
            tooltipRoot.parentNode.removeChild(tooltipRoot);
          }

          element.removeAttribute('data-tooltip-trigger-id');
          element.removeAttribute('aria-describedby');

          if (element._tippy) {
            try {
              element._tippy.destroy();
              element._tippy = null;
            } catch (e) {}
          }
        }
      } catch (error) {
        console.error('Error in enhanced tooltip destroy:', error);

        if (originalDestroy) {
          originalDestroy.call(window.TooltipManager, element);
        }
      }
    };

    window.TooltipManager.cleanup = function() {
      try {
        if (originalCleanup) {
          originalCleanup.call(window.TooltipManager);
        }

        removeOrphanedTooltips();
      } catch (error) {
        console.error('Error in enhanced tooltip cleanup:', error);

        if (originalCleanup) {
          originalCleanup.call(window.TooltipManager);
        }
      }
    };

    window.TooltipManager._memoryManagerEnhanced = true;
    window.TooltipManager._originalDestroy = originalDestroy;
    window.TooltipManager._originalCleanup = originalCleanup;

    return true;
  }

  function initializeScheduledCleanups() {
    if (state.cleanupInterval) {
      clearInterval(state.cleanupInterval);
      state.cleanupInterval = null;
    }

    if (state.diagnosticsInterval) {
      clearInterval(state.diagnosticsInterval);
      state.diagnosticsInterval = null;
    }

    if (state.elementVerificationInterval) {
      clearInterval(state.elementVerificationInterval);
      state.elementVerificationInterval = null;
    }

    state.cleanupInterval = setInterval(() => {
      removeOrphanedTooltips();
      checkForDisconnectedElements();
    }, config.tooltipCleanupInterval);

    state.diagnosticsInterval = setInterval(() => {
      checkMemoryUsage();
    }, config.diagnosticsInterval);

    state.elementVerificationInterval = setInterval(() => {
      checkForDisconnectedElements();
    }, config.elementVerificationInterval);

    document.removeEventListener('visibilitychange', handleVisibilityChange);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    setupMutationObserver();

    return true;
  }
  
  function initialize(options = {}) {
    preserveTooltipFunctions();

    if (options) {
      Object.assign(config, options);
    }

    enhanceTooltipManager();

    if (window.WebSocketManager && !window.WebSocketManager.cleanupOrphanedSockets) {
      window.WebSocketManager.cleanupOrphanedSockets = function() {
        return 0;
      };
    }

    const manager = window.ApiManager || window.Api;
    if (manager && !manager.abortPendingRequests) {
      manager.abortPendingRequests = function() {
        return 0;
      };
    }

    initializeScheduledCleanups();

    setTimeout(() => {
      removeOrphanedTooltips();
      checkForDisconnectedElements();
    }, 5000);

    return this;
  }

  function dispose() {
    if (state.cleanupInterval) {
      clearInterval(state.cleanupInterval);
      state.cleanupInterval = null;
    }

    if (state.diagnosticsInterval) {
      clearInterval(state.diagnosticsInterval);
      state.diagnosticsInterval = null;
    }

    if (state.elementVerificationInterval) {
      clearInterval(state.elementVerificationInterval);
      state.elementVerificationInterval = null;
    }

    if (state.mutationObserver) {
      state.mutationObserver.disconnect();
      state.mutationObserver = null;
    }

    document.removeEventListener('visibilitychange', handleVisibilityChange);

    return true;
  }

  function displayStats() {
    const stats = getDetailedStats();

    console.group('Memory Manager Stats');
    console.log('Memory Usage:', stats.memory ? 
      `${stats.memory.usedMB}MB / ${stats.memory.limitMB}MB (${stats.memory.percentUsed}%)` : 
      'Not available');
    console.log('Total Cleanups:', stats.metrics.cleanupRuns);
    console.log('Total Tooltips Removed:', stats.metrics.tooltipsRemoved);
    console.log('Current Tooltips:', stats.tooltips.total);
    console.log('Last Cleanup:', stats.metrics.lastCleanupDetails);
    console.log('Cleanup History:', stats.metrics.history);
    console.groupEnd();

    return stats;
  }

  function getDetailedStats() {

    const allTooltipElements = document.querySelectorAll('[data-tippy-root], [data-tooltip-trigger-id], .tooltip');

    const tooltips = {
      roots: document.querySelectorAll('[data-tippy-root]').length,
      triggers: document.querySelectorAll('[data-tooltip-trigger-id]').length,
      tooltipElements: document.querySelectorAll('.tooltip').length,
      total: allTooltipElements.length,
      protectedContainers: {}
    };

    config.protectedContainers.forEach(selector => {
      const container = document.querySelector(selector);
      if (container) {
        tooltips.protectedContainers[selector] = {
          tooltips: container.querySelectorAll('.tooltip').length,
          triggers: container.querySelectorAll('[data-tooltip-trigger-id]').length,
          roots: document.querySelectorAll(`[data-tippy-root][data-for-tooltip-id]`).length
        };
      }
    });

    return {
      memory: checkMemoryUsage(),
      metrics: { ...state.metrics },
      tooltips,
      config: { ...config }
    };
  }

  return {
    initialize,
    cleanup: performCleanup,
    forceCleanup: function() {
      return performCleanup(true);
    },
    fullCleanup: function() {
      return performCleanup(true);
    },
    getStats: getDetailedStats,
    displayStats,
    setDebugMode: function(enabled) {
      config.debug = Boolean(enabled);
      return config.debug;
    },
    addProtectedContainer: function(selector) {
      if (!config.protectedContainers.includes(selector)) {
        config.protectedContainers.push(selector);
      }
      return config.protectedContainers;
    },
    removeProtectedContainer: function(selector) {
      const index = config.protectedContainers.indexOf(selector);
      if (index !== -1) {
        config.protectedContainers.splice(index, 1);
      }
      return config.protectedContainers;
    },
    dispose
  };
})();

document.addEventListener('DOMContentLoaded', function() {
  const isDevMode = window.location.hostname === 'localhost' || 
                   window.location.hostname === '127.0.0.1';

  MemoryManager.initialize({
    debug: isDevMode
  });

  console.log('Memory Manager initialized');
});

window.MemoryManager = MemoryManager;
