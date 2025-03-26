const CleanupManager = (function() {

    const state = {
        eventListeners: [],
        timeouts: [],
        intervals: [],
        animationFrames: [],
        resources: new Map(),
        debug: false
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
            log('CleanupManager initialized');
            return this;
        }
    };

    return publicAPI;
})();


window.CleanupManager = CleanupManager;


document.addEventListener('DOMContentLoaded', function() {
    if (!window.cleanupManagerInitialized) {
        CleanupManager.initialize();
        window.cleanupManagerInitialized = true;
    }
});

//console.log('CleanupManager initialized with methods:', Object.keys(CleanupManager));
console.log('CleanupManager initialized');
