const MemoryManager = (function() {
  const config = {
    tooltipCleanupInterval: 60000,
    maxTooltipsThreshold: 100,
    diagnosticsInterval: 300000,
    tooltipLifespan: 240000,
    debug: false,
    autoCleanup: true,
    elementVerificationInterval: 50000,
    tooltipSelectors: [
      '[data-tippy-root]',
      '[data-tooltip-trigger-id]',
      '.tooltip',
      '.tippy-box',
      '.tippy-content'
    ]
  };

  let mutationObserver = null;

  const safeGet = (obj, path, defaultValue = null) => {
    if (!obj) return defaultValue;
    const pathParts = path.split('.');
    let result = obj;
    for (const part of pathParts) {
      if (result === null || result === undefined) return defaultValue;
      result = result[part];
    }
    return result !== undefined ? result : defaultValue;
  };

  const state = {
    intervals: new Map(),
    trackedTooltips: new Map(),
    trackedElements: new WeakMap(),
    startTime: Date.now(),
    lastCleanupTime: Date.now(),
    metrics: {
      tooltipsCreated: 0,
      tooltipsDestroyed: 0,
      orphanedTooltipsRemoved: 0,
      elementsProcessed: 0,
      cleanupRuns: 0,
      manualCleanupRuns: 0,
      lastMemoryUsage: null
    }
  };

  const log = (message, ...args) => {
    if (!config.debug) return;
    const now = new Date().toISOString();
    console.log(`[MemoryManager ${now}]`, message, ...args);
  };

  const logError = (message, error) => {
    console.error(`[MemoryManager] ${message}`, error);
  };

  const trackTooltip = (element, tooltipInstance) => {
    try {
      if (!element || !tooltipInstance) return;

      const timestamp = Date.now();
      const tooltipId = element.getAttribute('data-tooltip-trigger-id') || `tooltip_${timestamp}_${Math.random().toString(36).substring(2, 9)}`;

      state.trackedTooltips.set(tooltipId, {
        timestamp,
        element,
        instance: tooltipInstance,
        processed: false
      });

      state.metrics.tooltipsCreated++;

      setTimeout(() => {
        if (state.trackedTooltips.has(tooltipId)) {
          destroyTooltip(tooltipId);
        }
      }, config.tooltipLifespan);

      return tooltipId;
    } catch (error) {
      logError('Error tracking tooltip:', error);
      return null;
    }
  };

  const destroyTooltip = (tooltipId) => {
    try {
      const tooltipInfo = state.trackedTooltips.get(tooltipId);
      if (!tooltipInfo) return false;

      const { element, instance } = tooltipInfo;

      if (instance && typeof instance.destroy === 'function') {
        instance.destroy();
      }

      if (element && element.removeAttribute) {
        element.removeAttribute('data-tooltip-trigger-id');
        element.removeAttribute('aria-describedby');
      }

      const tippyRoot = document.querySelector(`[data-for-tooltip-id="${tooltipId}"]`);
      if (tippyRoot && tippyRoot.parentNode) {
        tippyRoot.parentNode.removeChild(tippyRoot);
      }

      state.trackedTooltips.delete(tooltipId);
      state.metrics.tooltipsDestroyed++;

      return true;
    } catch (error) {
      logError(`Error destroying tooltip ${tooltipId}:`, error);
      return false;
    }
  };

  const removeOrphanedTooltips = () => {
    try {
      const tippyRoots = document.querySelectorAll('[data-tippy-root]');
      let removed = 0;

      tippyRoots.forEach(root => {
        const tooltipId = root.getAttribute('data-for-tooltip-id');

        const trigger = tooltipId ? 
          document.querySelector(`[data-tooltip-trigger-id="${tooltipId}"]`) : 
          null;

        if (!trigger || !document.body.contains(trigger)) {
          if (root.parentNode) {
            root.parentNode.removeChild(root);
            removed++;
          }
        }
      });

      document.querySelectorAll('[data-tooltip-trigger-id]').forEach(trigger => {
        const tooltipId = trigger.getAttribute('data-tooltip-trigger-id');
        const root = document.querySelector(`[data-for-tooltip-id="${tooltipId}"]`);

        if (!root) {
          trigger.removeAttribute('data-tooltip-trigger-id');
          trigger.removeAttribute('aria-describedby');
          removed++;
        }
      });

      state.metrics.orphanedTooltipsRemoved += removed;
      return removed;
    } catch (error) {
      logError('Error removing orphaned tooltips:', error);
      return 0;
    }
  };

  const checkMemoryUsage = () => {
    if (window.performance && window.performance.memory) {
      const memoryUsage = {
        usedJSHeapSize: window.performance.memory.usedJSHeapSize,
        totalJSHeapSize: window.performance.memory.totalJSHeapSize,
        jsHeapSizeLimit: window.performance.memory.jsHeapSizeLimit,
        percentUsed: (window.performance.memory.usedJSHeapSize / window.performance.memory.jsHeapSizeLimit * 100).toFixed(2)
      };

      state.metrics.lastMemoryUsage = memoryUsage;
      return memoryUsage;
    }

    return null;
  };

  const checkForDisconnectedElements = () => {
    try {
      const disconnectedElements = new Set();

      state.trackedTooltips.forEach((info, id) => {
        const { element } = info;
        if (element && !document.body.contains(element)) {
          disconnectedElements.add(id);
        }
      });

      disconnectedElements.forEach(id => {
        destroyTooltip(id);
      });

      return disconnectedElements.size;
    } catch (error) {
      logError('Error checking for disconnected elements:', error);
      return 0;
    }
  };

  const setupMutationObserver = () => {
    if (mutationObserver) {
      mutationObserver.disconnect();
    }

    mutationObserver = new MutationObserver(mutations => {
      let needsCleanup = false;

      mutations.forEach(mutation => {
        if (mutation.removedNodes.length) {
          Array.from(mutation.removedNodes).forEach(node => {
            if (node.nodeType === 1) {
              if (node.hasAttribute && node.hasAttribute('data-tooltip-trigger-id')) {
                const tooltipId = node.getAttribute('data-tooltip-trigger-id');
                destroyTooltip(tooltipId);
                needsCleanup = true;
              }

              if (node.querySelectorAll) {
                const tooltipTriggers = node.querySelectorAll('[data-tooltip-trigger-id]');
                if (tooltipTriggers.length > 0) {
                  tooltipTriggers.forEach(el => {
                    const tooltipId = el.getAttribute('data-tooltip-trigger-id');
                    destroyTooltip(tooltipId);
                  });
                  needsCleanup = true;
                }
              }
            }
          });
        }
      });

      if (needsCleanup) {
        removeOrphanedTooltips();
      }
    });

    mutationObserver.observe(document.body, {
      childList: true,
      subtree: true
    });

    return mutationObserver;
  };

  const performCleanup = (force = false) => {
    try {
      log('Starting tooltip cleanup' + (force ? ' (forced)' : ''));

      state.lastCleanupTime = Date.now();
      state.metrics.cleanupRuns++;

      if (force) {
        state.metrics.manualCleanupRuns++;
      }

      document.querySelectorAll('[data-tippy-root]').forEach(root => {
        const instance = safeGet(root, '_tippy');
        if (instance && instance._animationFrame) {
          cancelAnimationFrame(instance._animationFrame);
          instance._animationFrame = null;
        }
      });

      const orphanedRemoved = removeOrphanedTooltips();

      const disconnectedRemoved = checkForDisconnectedElements();

      const tooltipCount = document.querySelectorAll('[data-tippy-root]').length;
      const triggerCount = document.querySelectorAll('[data-tooltip-trigger-id]').length;

      if (force || tooltipCount > config.maxTooltipsThreshold) {
        if (tooltipCount > config.maxTooltipsThreshold) {
          document.querySelectorAll('[data-tooltip-trigger-id]').forEach(trigger => {
            const tooltipId = trigger.getAttribute('data-tooltip-trigger-id');
            destroyTooltip(tooltipId);
          });

          document.querySelectorAll('[data-tippy-root]').forEach(root => {
            if (root.parentNode) {
              root.parentNode.removeChild(root);
            }
          });
        }

        document.querySelectorAll('[data-tooltip-trigger-id], [aria-describedby]').forEach(el => {
          if (window.CleanupManager && window.CleanupManager.removeListenersByElement) {
            window.CleanupManager.removeListenersByElement(el);
          } else {
            if (el.parentNode) {
              const clone = el.cloneNode(true);
              el.parentNode.replaceChild(clone, el);
            }
          }
        });
      }

      if (window.gc) {
        window.gc();
      } else if (force) {
        const arr = new Array(1000);
        for (let i = 0; i < 1000; i++) {
          arr[i] = new Array(10000).join('x');
        }
      }

      checkMemoryUsage();

      const result = {
        orphanedRemoved,
        disconnectedRemoved,
        tooltipCount: document.querySelectorAll('[data-tippy-root]').length,
        triggerCount: document.querySelectorAll('[data-tooltip-trigger-id]').length,
        memoryUsage: state.metrics.lastMemoryUsage
      };

      log('Cleanup completed', result);
      return result;
    } catch (error) {
      logError('Error during cleanup:', error);
      return { error: error.message };
    }
  };

  const runDiagnostics = () => {
    try {
      log('Running memory diagnostics');

      const memoryUsage = checkMemoryUsage();
      const tooltipCount = document.querySelectorAll('[data-tippy-root]').length;
      const triggerCount = document.querySelectorAll('[data-tooltip-trigger-id]').length;

      const diagnostics = {
        time: new Date().toISOString(),
        uptime: Date.now() - state.startTime,
        memoryUsage,
        elementsCount: {
          tippyRoots: tooltipCount,
          tooltipTriggers: triggerCount,
          orphanedTriggers: triggerCount - tooltipCount > 0 ? triggerCount - tooltipCount : 0,
          orphanedTooltips: tooltipCount - triggerCount > 0 ? tooltipCount - triggerCount : 0
        },
        metrics: { ...state.metrics },
        issues: []
      };

      if (tooltipCount > config.maxTooltipsThreshold) {
        diagnostics.issues.push({
          severity: 'high',
          message: `Excessive tooltip count: ${tooltipCount} (threshold: ${config.maxTooltipsThreshold})`,
          recommendation: 'Run cleanup and check for tooltip creation loops'
        });
      }

      if (Math.abs(tooltipCount - triggerCount) > 10) {
        diagnostics.issues.push({
          severity: 'medium',
          message: `Mismatch between tooltips (${tooltipCount}) and triggers (${triggerCount})`,
          recommendation: 'Remove orphaned tooltips and tooltip triggers'
        });
      }

      if (memoryUsage && memoryUsage.percentUsed > 80) {
        diagnostics.issues.push({
          severity: 'high',
          message: `High memory usage: ${memoryUsage.percentUsed}%`,
          recommendation: 'Force garbage collection and check for memory leaks'
        });
      }

      if (config.autoCleanup && diagnostics.issues.some(issue => issue.severity === 'high')) {
        log('Critical issues detected, triggering automatic cleanup');
        performCleanup(true);
      }

      return diagnostics;
    } catch (error) {
      logError('Error running diagnostics:', error);
      return { error: error.message };
    }
  };

  const patchTooltipManager = () => {
    try {
      if (!window.TooltipManager) {
        log('TooltipManager not found');
        return false;
      }

      log('Patching TooltipManager');

      const originalCreate = window.TooltipManager.create;
      const originalDestroy = window.TooltipManager.destroy;
      const originalCleanup = window.TooltipManager.cleanup;

      window.TooltipManager.create = function(element, content, options = {}) {
        if (!element) return null;

        try {
          const result = originalCreate.call(this, element, content, options);
          const tooltipId = element.getAttribute('data-tooltip-trigger-id');

          if (tooltipId) {
            const tippyInstance = safeGet(element, '_tippy') || null;
            trackTooltip(element, tippyInstance);
          }

          return result;
        } catch (error) {
          logError('Error in patched create:', error);
          return originalCreate.call(this, element, content, options);
        }
      };

      window.TooltipManager.destroy = function(element) {
        if (!element) return;

        try {
          const tooltipId = element.getAttribute('data-tooltip-trigger-id');

          originalDestroy.call(this, element);

          if (tooltipId) {
            state.trackedTooltips.delete(tooltipId);
            state.metrics.tooltipsDestroyed++;
          }
        } catch (error) {
          logError('Error in patched destroy:', error);
          originalDestroy.call(this, element);
        }
      };

      window.TooltipManager.cleanup = function() {
        try {
          originalCleanup.call(this);
          removeOrphanedTooltips();
        } catch (error) {
          logError('Error in patched cleanup:', error);
          originalCleanup.call(this);
        }
      };

      return true;
    } catch (error) {
      logError('Error patching TooltipManager:', error);
      return false;
    }
  };

  const patchTippy = () => {
    try {
      if (typeof tippy !== 'function') {
        log('tippy.js not found globally');
        return false;
      }

      log('Patching global tippy');

      const originalTippy = window.tippy;

      window.tippy = function(...args) {
        const result = originalTippy.apply(this, args);
        
        if (Array.isArray(result)) {
          result.forEach(instance => {
            const reference = instance.reference;

            if (reference) {
              const originalShow = instance.show;
              const originalHide = instance.hide;
              const originalDestroy = instance.destroy;

              instance.show = function(...showArgs) {
                return originalShow.apply(this, showArgs);
              };

              instance.hide = function(...hideArgs) {
                return originalHide.apply(this, hideArgs);
              };

              instance.destroy = function(...destroyArgs) {
                return originalDestroy.apply(this, destroyArgs);
              };
            }
          });
        }

        return result;
      };

      Object.assign(window.tippy, originalTippy);

      return true;
    } catch (error) {
      logError('Error patching tippy:', error);
      return false;
    }
  };

  const startMonitoring = () => {
    try {
      stopMonitoring();

      state.intervals.set('cleanup', setInterval(() => {
        performCleanup();
      }, config.tooltipCleanupInterval));

      state.intervals.set('diagnostics', setInterval(() => {
        runDiagnostics();
      }, config.diagnosticsInterval));

      state.intervals.set('elementVerification', setInterval(() => {
        checkForDisconnectedElements();
      }, config.elementVerificationInterval));

      setupMutationObserver();

      log('Monitoring started');
      return true;
    } catch (error) {
      logError('Error starting monitoring:', error);
      return false;
    }
  };

  const stopMonitoring = () => {
    try {
      state.intervals.forEach((interval, key) => {
        clearInterval(interval);
      });

      state.intervals.clear();

      if (mutationObserver) {
        mutationObserver.disconnect();
        mutationObserver = null;
      }

      log('Monitoring stopped');
      return true;
    } catch (error) {
      logError('Error stopping monitoring:', error);
      return false;
    }
  };

  const autoFix = () => {
    try {
      log('Running auto-fix');

      performCleanup(true);

      document.querySelectorAll('[data-tooltip-trigger-id]').forEach(element => {
        const tooltipId = element.getAttribute('data-tooltip-trigger-id');
        const duplicates = document.querySelectorAll(`[data-tooltip-trigger-id="${tooltipId}"]`);

        if (duplicates.length > 1) {
          for (let i = 1; i < duplicates.length; i++) {
            duplicates[i].removeAttribute('data-tooltip-trigger-id');
            duplicates[i].removeAttribute('aria-describedby');
          }
        }
      });

      const tippyRoots = document.querySelectorAll('[data-tippy-root]');
      tippyRoots.forEach(root => {
        if (!document.body.contains(root) && root.parentNode) {
          root.parentNode.removeChild(root);
        }
      });

      if (window.TooltipManager && window.TooltipManager.getInstance) {
        const manager = window.TooltipManager.getInstance();
        if (manager && manager.chartRefs && manager.chartRefs.clear) {
          manager.chartRefs.clear();
        }

        if (manager && manager.tooltipElementsMap && manager.tooltipElementsMap.clear) {
          manager.tooltipElementsMap.clear();
        }
      }

      patchTooltipManager();
      patchTippy();

      return true;
    } catch (error) {
      logError('Error during auto-fix:', error);
      return false;
    }
  };

  const initialize = (options = {}) => {
    try {
      Object.assign(config, options);
      
      if (document.head) {
        const metaCache = document.createElement('meta');
        metaCache.setAttribute('http-equiv', 'Cache-Control');
        metaCache.setAttribute('content', 'no-store, max-age=0');
        document.head.appendChild(metaCache);
      }

      patchTooltipManager();
      patchTippy();

      startMonitoring();

      if (window.CleanupManager && window.CleanupManager.registerResource) {
        window.CleanupManager.registerResource('memorymanager', MemoryManager, (optimizer) => {
          optimizer.dispose();
        });
      }

      log('Memory Optimizer initialized', config);

      setTimeout(() => {
        runDiagnostics();
      }, 5000);

      return MemoryManager;
    } catch (error) {
      logError('Error initializing Memory Optimizer:', error);
      return null;
    }
  };

  const dispose = () => {
    try {
      log('Disposing Memory Optimizer');

      performCleanup(true);

      stopMonitoring();

      state.trackedTooltips.clear();

      return true;
    } catch (error) {
      logError('Error disposing Memory Optimizer:', error);
      return false;
    }
  };

  return {
    initialize,
    dispose,
    performCleanup,
    runDiagnostics,
    autoFix,
    getConfig: () => ({ ...config }),
    getMetrics: () => ({ ...state.metrics }),
    setDebugMode: (enabled) => {
      config.debug = Boolean(enabled);
      return config.debug;
    }
  };
})();

if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', function() {
    MemoryManager.initialize();
  });
}

window.MemoryManager = MemoryManager;
console.log('Memory Manager initialized');
