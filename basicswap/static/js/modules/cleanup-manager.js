const CleanupManager = (function() {
    const state = {
        eventListeners: [],
        timeouts: [],
        intervals: [],
        animationFrames: [],
        resources: new Map(),
        debug: false,
        memoryOptimizationInterval: null
    };

    function log(message, ...args) {
        if (state.debug) {
            console.log(`[CleanupManager] ${message}`, ...args);
        }
    }

    const publicAPI = {
        addListener: function(element, type, handler, options = false) {
            if (!element) {
                log('Warning: Attempted to add listener to null/undefined element');
                return handler;
            }

            element.addEventListener(type, handler, options);
            state.eventListeners.push({ element, type, handler, options });
            log(`Added ${type} listener to`, element);
            return handler;
        },

        setTimeout: function(callback, delay) {
            const id = window.setTimeout(callback, delay);
            state.timeouts.push(id);
            log(`Created timeout ${id} with ${delay}ms delay`);
            return id;
        },

        setInterval: function(callback, delay) {
            const id = window.setInterval(callback, delay);
            state.intervals.push(id);
            log(`Created interval ${id} with ${delay}ms delay`);
            return id;
        },

        requestAnimationFrame: function(callback) {
            const id = window.requestAnimationFrame(callback);
            state.animationFrames.push(id);
            log(`Requested animation frame ${id}`);
            return id;
        },

        registerResource: function(type, resource, cleanupFn) {
            const id = `${type}_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
            state.resources.set(id, { resource, cleanupFn });
            log(`Registered custom resource ${id} of type ${type}`);
            return id;
        },

        unregisterResource: function(id) {
            const resourceInfo = state.resources.get(id);
            if (resourceInfo) {
                try {
                    resourceInfo.cleanupFn(resourceInfo.resource);
                    state.resources.delete(id);
                    log(`Unregistered and cleaned up resource ${id}`);
                    return true;
                } catch (error) {
                    console.error(`[CleanupManager] Error cleaning up resource ${id}:`, error);
                    return false;
                }
            }
            log(`Resource ${id} not found`);
            return false;
        },

        clearTimeout: function(id) {
            const index = state.timeouts.indexOf(id);
            if (index !== -1) {
                window.clearTimeout(id);
                state.timeouts.splice(index, 1);
                log(`Cleared timeout ${id}`);
            }
        },

        clearInterval: function(id) {
            const index = state.intervals.indexOf(id);
            if (index !== -1) {
                window.clearInterval(id);
                state.intervals.splice(index, 1);
                log(`Cleared interval ${id}`);
            }
        },

        cancelAnimationFrame: function(id) {
            const index = state.animationFrames.indexOf(id);
            if (index !== -1) {
                window.cancelAnimationFrame(id);
                state.animationFrames.splice(index, 1);
                log(`Cancelled animation frame ${id}`);
            }
        },

        removeListener: function(element, type, handler, options = false) {
            if (!element) return;

            try {
                element.removeEventListener(type, handler, options);
                log(`Removed ${type} listener from`, element);
            } catch (error) {
                console.error(`[CleanupManager] Error removing event listener:`, error);
            }

            state.eventListeners = state.eventListeners.filter(
                listener => !(listener.element === element &&
                            listener.type === type &&
                            listener.handler === handler)
            );
        },

        removeListenersByElement: function(element) {
            if (!element) return;

            const listenersToRemove = state.eventListeners.filter(
                listener => listener.element === element
            );

            listenersToRemove.forEach(({ element, type, handler, options }) => {
                try {
                    element.removeEventListener(type, handler, options);
                    log(`Removed ${type} listener from`, element);
                } catch (error) {
                    console.error(`[CleanupManager] Error removing event listener:`, error);
                }
            });

            state.eventListeners = state.eventListeners.filter(
                listener => listener.element !== element
            );
        },

        clearAllTimeouts: function() {
            state.timeouts.forEach(id => {
                window.clearTimeout(id);
            });
            const count = state.timeouts.length;
            state.timeouts = [];
            log(`Cleared all timeouts (${count})`);
        },

        clearAllIntervals: function() {
            state.intervals.forEach(id => {
                window.clearInterval(id);
            });
            const count = state.intervals.length;
            state.intervals = [];
            log(`Cleared all intervals (${count})`);
        },

        clearAllAnimationFrames: function() {
            state.animationFrames.forEach(id => {
                window.cancelAnimationFrame(id);
            });
            const count = state.animationFrames.length;
            state.animationFrames = [];
            log(`Cancelled all animation frames (${count})`);
        },

        clearAllResources: function() {
            let successCount = 0;
            let errorCount = 0;

            state.resources.forEach((resourceInfo, id) => {
                try {
                    resourceInfo.cleanupFn(resourceInfo.resource);
                    successCount++;
                } catch (error) {
                    console.error(`[CleanupManager] Error cleaning up resource ${id}:`, error);
                    errorCount++;
                }
            });

            state.resources.clear();
            log(`Cleared all custom resources (${successCount} success, ${errorCount} errors)`);
        },

        clearAllListeners: function() {
            state.eventListeners.forEach(({ element, type, handler, options }) => {
                if (element) {
                    try {
                        element.removeEventListener(type, handler, options);
                    } catch (error) {
                        console.error(`[CleanupManager] Error removing event listener:`, error);
                    }
                }
            });
            const count = state.eventListeners.length;
            state.eventListeners = [];
            log(`Removed all event listeners (${count})`);
        },

        clearAll: function() {
            const counts = {
                listeners: state.eventListeners.length,
                timeouts: state.timeouts.length,
                intervals: state.intervals.length,
                animationFrames: state.animationFrames.length,
                resources: state.resources.size
            };

            this.clearAllListeners();
            this.clearAllTimeouts();
            this.clearAllIntervals();
            this.clearAllAnimationFrames();
            this.clearAllResources();

            log(`All resources cleaned up:`, counts);
            return counts;
        },

        getResourceCounts: function() {
            return {
                listeners: state.eventListeners.length,
                timeouts: state.timeouts.length,
                intervals: state.intervals.length,
                animationFrames: state.animationFrames.length,
                resources: state.resources.size,
                total: state.eventListeners.length +
                      state.timeouts.length +
                      state.intervals.length +
                      state.animationFrames.length +
                      state.resources.size
            };
        },

        setupMemoryOptimization: function(options = {}) {
            const memoryCheckInterval = options.interval || 2 * 60 * 1000; // Default: 2 minutes
            const maxCacheSize = options.maxCacheSize || 100;
            const maxDataSize = options.maxDataSize || 1000;

            if (state.memoryOptimizationInterval) {
                this.clearInterval(state.memoryOptimizationInterval);
            }

            this.addListener(document, 'visibilitychange', () => {
                if (document.hidden) {
                    log('Tab hidden - running memory optimization');
                    this.optimizeMemory({
                        maxCacheSize: maxCacheSize,
                        maxDataSize: maxDataSize
                    });
                } else if (window.TooltipManager) {
                    window.TooltipManager.cleanup();
                }
            });

            state.memoryOptimizationInterval = this.setInterval(() => {
                if (document.hidden) {
                    log('Periodic memory optimization');
                    this.optimizeMemory({
                        maxCacheSize: maxCacheSize,
                        maxDataSize: maxDataSize
                    });
                }
            }, memoryCheckInterval);

            log('Memory optimization setup complete');
            return state.memoryOptimizationInterval;
        },

        optimizeMemory: function(options = {}) {
            log('Running memory optimization');

            if (window.TooltipManager && typeof window.TooltipManager.cleanup === 'function') {
                window.TooltipManager.cleanup();
            }

            if (window.IdentityManager && typeof window.IdentityManager.limitCacheSize === 'function') {
                window.IdentityManager.limitCacheSize(options.maxCacheSize || 100);
            }

            this.cleanupOrphanedResources();

            if (window.gc) {
                try {
                    window.gc();
                    log('Forced garbage collection');
                } catch (e) {
                }
            }

            document.dispatchEvent(new CustomEvent('memoryOptimized', { 
                detail: { 
                    timestamp: Date.now(),
                    maxDataSize: options.maxDataSize || 1000
                } 
            }));

            log('Memory optimization complete');
        },

        cleanupOrphanedResources: function() {
            let removedListeners = 0;
            const validListeners = [];

            for (let i = 0; i < state.eventListeners.length; i++) {
                const listener = state.eventListeners[i];
                if (!listener.element) {
                    removedListeners++;
                    continue;
                }

                try {

                    const isDetached = !(listener.element instanceof Node) || 
                                    !document.body.contains(listener.element) || 
                                    (listener.element.classList && listener.element.classList.contains('hidden')) ||
                                    (listener.element.style && listener.element.style.display === 'none');
                                    
                    if (isDetached) {
                        try {
                            if (listener.element instanceof Node) {
                                listener.element.removeEventListener(listener.type, listener.handler, listener.options);
                            }
                            removedListeners++;
                        } catch (e) {

                        }
                    } else {
                        validListeners.push(listener);
                    }
                } catch (e) {

                    log(`Error checking listener (removing): ${e.message}`);
                    removedListeners++;
                }
            }

            if (removedListeners > 0) {
                state.eventListeners = validListeners;
                log(`Removed ${removedListeners} event listeners for detached/hidden elements`);
            }

            let removedResources = 0;
            const resourcesForRemoval = [];

            state.resources.forEach((info, id) => {
                const resource = info.resource;

                try {

                    if (resource instanceof Element && !document.body.contains(resource)) {
                        resourcesForRemoval.push(id);
                    }

                    if (resource && resource.element) {

                        if (resource.element instanceof Node && !document.body.contains(resource.element)) {
                            resourcesForRemoval.push(id);
                        }
                    }
                } catch (e) {
                    log(`Error checking resource ${id}: ${e.message}`);
                }
            });
            
            resourcesForRemoval.forEach(id => {
                this.unregisterResource(id);
                removedResources++;
            });
            
            if (removedResources > 0) {
                log(`Removed ${removedResources} orphaned resources`);
            }

            if (window.TooltipManager) {
                if (typeof window.TooltipManager.cleanupOrphanedTooltips === 'function') {
                    try {
                        window.TooltipManager.cleanupOrphanedTooltips();
                    } catch (e) {

                        if (typeof window.TooltipManager.cleanup === 'function') {
                            try {
                                window.TooltipManager.cleanup();
                            } catch (err) {
                                log(`Error cleaning up tooltips: ${err.message}`);
                            }
                        }
                    }
                } else if (typeof window.TooltipManager.cleanup === 'function') {
                    try {
                        window.TooltipManager.cleanup();
                    } catch (e) {
                        log(`Error cleaning up tooltips: ${e.message}`);
                    }
                }
            }

            try {
                this.cleanupTooltipDOM();
            } catch (e) {
                log(`Error in cleanupTooltipDOM: ${e.message}`);
            }
        },

        cleanupTooltipDOM: function() {
            let removedElements = 0;

            try {

                const tooltipSelectors = [
                    '[role="tooltip"]', 
                    '[id^="tooltip-"]', 
                    '.tippy-box', 
                    '[data-tippy-root]'
                ];

                tooltipSelectors.forEach(selector => {
                    try {
                        const elements = document.querySelectorAll(selector);
                        
                        elements.forEach(element => {
                            try {

                                if (!(element instanceof Element)) return;
                                
                                const isDetached = !element.parentElement || 
                                                !document.body.contains(element.parentElement) ||
                                                element.classList.contains('hidden') ||
                                                element.style.display === 'none' ||
                                                element.style.visibility === 'hidden';

                                if (isDetached) {
                                    try {
                                        element.remove();
                                        removedElements++;
                                    } catch (e) {

                                    }
                                }
                            } catch (err) {

                            }
                        });
                    } catch (err) {

                        log(`Error querying for ${selector}: ${err.message}`);
                    }
                });
            } catch (e) {
                log(`Error in tooltip DOM cleanup: ${e.message}`);
            }

            if (removedElements > 0) {
                log(`Removed ${removedElements} detached tooltip elements`);
            }
        },

        setDebugMode: function(enabled) {
            state.debug = Boolean(enabled);
            log(`Debug mode ${state.debug ? 'enabled' : 'disabled'}`);
            return state.debug;
        },

        dispose: function() {
            this.clearAll();
            log('CleanupManager disposed');
        },

        initialize: function(options = {}) {
            if (options.debug !== undefined) {
                this.setDebugMode(options.debug);
            }

            if (typeof window !== 'undefined' && !options.noAutoCleanup) {
                this.addListener(window, 'beforeunload', () => {
                    this.clearAll();
                });
            }

            if (typeof window !== 'undefined' && !options.noMemoryOptimization) {
                this.setupMemoryOptimization(options.memoryOptions || {});
            }

            log('CleanupManager initialized');
            return this;
        }
    };

    return publicAPI;
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = CleanupManager;
}

if (typeof window !== 'undefined') {
    window.CleanupManager = CleanupManager;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        CleanupManager.initialize({ debug: false });
    } else {
        document.addEventListener('DOMContentLoaded', () => {
            CleanupManager.initialize({ debug: false });
        }, { once: true });
    }
}
