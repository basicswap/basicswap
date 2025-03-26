const MemoryManager = (function() {

    const state = {
        isMonitoringEnabled: false,
        monitorInterval: null,
        cleanupInterval: null
    };

    const config = {
        monitorInterval: 30000,
        cleanupInterval: 60000,
        debug: false
    };

    function log(message, ...args) {
        if (config.debug) {
            console.log(`[MemoryManager] ${message}`, ...args);
        }
    }

    const publicAPI = {
        enableMonitoring: function(interval = config.monitorInterval) {
            if (state.monitorInterval) {
                clearInterval(state.monitorInterval);
            }

            state.isMonitoringEnabled = true;
            config.monitorInterval = interval;

            this.logMemoryUsage();

            state.monitorInterval = setInterval(() => {
                this.logMemoryUsage();
            }, interval);

            console.log(`Memory monitoring enabled - reporting every ${interval/1000} seconds`);
            return true;
        },

        disableMonitoring: function() {
            if (state.monitorInterval) {
                clearInterval(state.monitorInterval);
                state.monitorInterval = null;
            }

            state.isMonitoringEnabled = false;
            console.log('Memory monitoring disabled');
            return true;
        },

        logMemoryUsage: function() {
            const timestamp = new Date().toLocaleTimeString();
            console.log(`=== Memory Monitor [${timestamp}] ===`);

            if (window.performance && window.performance.memory) {
                console.log('Memory usage:', {
                    usedJSHeapSize: (window.performance.memory.usedJSHeapSize / 1024 / 1024).toFixed(2) + ' MB',
                    totalJSHeapSize: (window.performance.memory.totalJSHeapSize / 1024 / 1024).toFixed(2) + ' MB'
                });
            }

            if (navigator.deviceMemory) {
                console.log('Device memory:', navigator.deviceMemory, 'GB');
            }

            const nodeCount = document.querySelectorAll('*').length;
            console.log('DOM node count:', nodeCount);

            if (window.CleanupManager) {
                const counts = CleanupManager.getResourceCounts();
                console.log('Managed resources:', counts);
            }

            if (window.TooltipManager) {
                const tooltipInstances = document.querySelectorAll('[data-tippy-root]').length;
                const tooltipTriggers = document.querySelectorAll('[data-tooltip-trigger-id]').length;
                console.log('Tooltip instances:', tooltipInstances, '- Tooltip triggers:', tooltipTriggers);
            }

            if (window.CacheManager && window.CacheManager.getStats) {
                const cacheStats = CacheManager.getStats();
                console.log('Cache stats:', cacheStats);
            }

            if (window.IdentityManager && window.IdentityManager.getStats) {
                const identityStats = window.IdentityManager.getStats();
                console.log('Identity cache stats:', identityStats);
            }

            console.log('==============================');
        },

        enableAutoCleanup: function(interval = config.cleanupInterval) {
            if (state.cleanupInterval) {
                clearInterval(state.cleanupInterval);
            }

            config.cleanupInterval = interval;

            this.forceCleanup();

            state.cleanupInterval = setInterval(() => {
                this.forceCleanup();
            }, interval);

            log('Auto-cleanup enabled every', interval/1000, 'seconds');
            return true;
        },

        disableAutoCleanup: function() {
            if (state.cleanupInterval) {
                clearInterval(state.cleanupInterval);
                state.cleanupInterval = null;
            }

            console.log('Memory auto-cleanup disabled');
            return true;
        },

        forceCleanup: function() {
            if (config.debug) {
                console.log('Running memory cleanup...', new Date().toLocaleTimeString());
            }

            if (window.CacheManager && CacheManager.cleanup) {
                CacheManager.cleanup(true);
            }

            if (window.TooltipManager && TooltipManager.cleanup) {
                window.TooltipManager.cleanup();
            }

            document.querySelectorAll('[data-tooltip-trigger-id]').forEach(element => {
                if (window.TooltipManager && TooltipManager.destroy) {
                    window.TooltipManager.destroy(element);
                }
            });

            if (window.chartModule && chartModule.cleanup) {
                chartModule.cleanup();
            }

            if (window.gc) {
                window.gc();
            } else {
                const arr = new Array(1000);
                for (let i = 0; i < 1000; i++) {
                    arr[i] = new Array(10000).join('x');
                }
            }

            if (config.debug) {
                console.log('Memory cleanup completed');
            }

            return true;
        },

        setDebugMode: function(enabled) {
            config.debug = Boolean(enabled);
            return `Debug mode ${config.debug ? 'enabled' : 'disabled'}`;
        },

        getStatus: function() {
            return {
                monitoring: {
                    enabled: Boolean(state.monitorInterval),
                    interval: config.monitorInterval
                },
                autoCleanup: {
                    enabled: Boolean(state.cleanupInterval),
                    interval: config.cleanupInterval
                },
                debug: config.debug
            };
        },

        initialize: function(options = {}) {
            if (options.debug !== undefined) {
                this.setDebugMode(options.debug);
            }

            if (options.enableMonitoring) {
                this.enableMonitoring(options.monitorInterval || config.monitorInterval);
            }

            if (options.enableAutoCleanup) {
                this.enableAutoCleanup(options.cleanupInterval || config.cleanupInterval);
            }

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('memoryManager', this, (mgr) => mgr.dispose());
            }

            log('MemoryManager initialized');
            return this;
        },

        dispose: function() {
            this.disableMonitoring();
            this.disableAutoCleanup();
            log('MemoryManager disposed');
        }
    };

    return publicAPI;
})();

window.MemoryManager = MemoryManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.memoryManagerInitialized) {
        MemoryManager.initialize();
        window.memoryManagerInitialized = true;
    }
});

//console.log('MemoryManager initialized with methods:', Object.keys(MemoryManager));
console.log('MemoryManager initialized');
