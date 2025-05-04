const TooltipManager = (function() {
    let instance = null;

    const tooltipInstanceMap = new WeakMap();

    class TooltipManagerImpl {
        constructor() {
            if (instance) {
                return instance;
            }
            this.pendingAnimationFrames = new Set();
            this.pendingTimeouts = new Set();
            this.tooltipIdCounter = 0;
            this.maxTooltips = 200;
            this.cleanupThreshold = 1.2;
            this.disconnectedCheckInterval = null;
            this.cleanupInterval = null;
            this.mutationObserver = null;
            this.debug = false;
            this.tooltipData = new WeakMap();
            this.setupStyles();
            this.setupMutationObserver();
            this.startPeriodicCleanup();
            this.startDisconnectedElementsCheck();
            instance = this;
        }

        log(message, ...args) {
            if (this.debug) {
                console.log(`[TooltipManager] ${message}`, ...args);
            }
        }

        create(element, content, options = {}) {
            if (!element || !document.body.contains(element)) return null;
            
            if (!document.contains(element)) {
                this.log('Tried to create tooltip for detached element');
                return null;
            }

            this.destroy(element);

            const currentTooltipCount = document.querySelectorAll('[data-tooltip-trigger-id]').length;
            if (currentTooltipCount > this.maxTooltips * this.cleanupThreshold) {
                this.cleanupOrphanedTooltips();
                this.performPeriodicCleanup(true);
            }

            const rafId = requestAnimationFrame(() => {
                this.pendingAnimationFrames.delete(rafId);

                if (!document.body.contains(element)) return;

                const rect = element.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                    this.createTooltipInstance(element, content, options);
                } else {
                    let retryCount = 0;
                    const maxRetries = 3;
                    
                    const retryCreate = () => {
                        const newRect = element.getBoundingClientRect();
                        if ((newRect.width > 0 && newRect.height > 0) || retryCount >= maxRetries) {
                            if (newRect.width > 0 && newRect.height > 0) {
                                this.createTooltipInstance(element, content, options);
                            }
                        } else {
                            retryCount++;
                            const timeoutId = setTimeout(() => {
                                this.pendingTimeouts.delete(timeoutId);
                                const newRafId = requestAnimationFrame(retryCreate);
                                this.pendingAnimationFrames.add(newRafId);
                            }, 100);
                            this.pendingTimeouts.add(timeoutId);
                        }
                    };

                    const initialTimeoutId = setTimeout(() => {
                        this.pendingTimeouts.delete(initialTimeoutId);
                        const retryRafId = requestAnimationFrame(retryCreate);
                        this.pendingAnimationFrames.add(retryRafId);
                    }, 100);
                    this.pendingTimeouts.add(initialTimeoutId);
                }
            });

            this.pendingAnimationFrames.add(rafId);
            return null;
        }
        
        createTooltipInstance(element, content, options = {}) {
            if (!element || !document.body.contains(element) || !window.tippy) {
                return null;
            }

            try {
                const tooltipId = `tooltip-${++this.tooltipIdCounter}`;

                const tooltipOptions = {
                    content: content,
                    allowHTML: true,
                    placement: options.placement || 'top',
                    appendTo: document.body,
                    animation: false,
                    duration: 0,
                    delay: 0,
                    interactive: true,
                    arrow: false,
                    theme: '',
                    moveTransition: 'none',
                    offset: [0, 10],
                    onShow(instance) {
                        if (!document.body.contains(element)) {
                            return false;
                        }
                        return true;
                    },
                    onMount(instance) {
                        if (instance.popper && instance.popper.firstElementChild) {
                            const bgClass = options.bgClass || 'bg-gray-400';
                            instance.popper.firstElementChild.classList.add(bgClass);
                            instance.popper.setAttribute('data-for-tooltip-id', tooltipId);
                        }
                        const arrow = instance.popper.querySelector('.tippy-arrow');
                        if (arrow) {
                            const arrowColor = options.arrowColor || 'rgb(156 163 175)';
                            arrow.style.setProperty('color', arrowColor, 'important');
                        }
                    },
                    onHidden(instance) {
                        if (!document.body.contains(element)) {
                            setTimeout(() => {
                                if (instance && instance.destroy) {
                                    instance.destroy();
                                }
                            }, 100);
                        }
                    },
                    popperOptions: {
                        strategy: 'fixed',
                        modifiers: [
                            {
                                name: 'preventOverflow',
                                options: {
                                    boundary: 'viewport',
                                    padding: 10
                                }
                            },
                            {
                                name: 'flip',
                                options: {
                                    padding: 10,
                                    fallbackPlacements: ['top', 'bottom', 'right', 'left']
                                }
                            }
                        ]
                    }
                };

                const tippyInstance = window.tippy(element, tooltipOptions);

                if (tippyInstance && Array.isArray(tippyInstance) && tippyInstance[0]) {
                    this.tooltipData.set(element, {
                        id: tooltipId,
                        instance: tippyInstance[0],
                        timestamp: Date.now()
                    });

                    element.setAttribute('data-tooltip-trigger-id', tooltipId);

                    tooltipInstanceMap.set(element, tippyInstance[0]);

                    return tippyInstance[0];
                }

                return null;
            } catch (error) {
                console.error('Error creating tooltip:', error);
                return null;
            }
        }

        destroy(element) {
            if (!element) return;

            try {
                const tooltipId = element.getAttribute('data-tooltip-trigger-id');
                if (!tooltipId) return;

                const tooltipData = this.tooltipData.get(element);
                const instance = tooltipData?.instance || tooltipInstanceMap.get(element);

                if (instance) {
                    try {
                        instance.destroy();
                    } catch (e) {
                        console.warn('Error destroying tooltip instance:', e);
                    }
                }

                element.removeAttribute('data-tooltip-trigger-id');
                element.removeAttribute('aria-describedby');

                const tippyRoot = document.querySelector(`[data-for-tooltip-id="${tooltipId}"]`);
                if (tippyRoot && tippyRoot.parentNode) {
                    tippyRoot.parentNode.removeChild(tippyRoot);
                }

                this.tooltipData.delete(element);
                tooltipInstanceMap.delete(element);
            } catch (error) {
                console.error('Error destroying tooltip:', error);
            }
        }

        cleanup() {
            this.log('Running tooltip cleanup');

            this.pendingAnimationFrames.forEach(id => {
                cancelAnimationFrame(id);
            });
            this.pendingAnimationFrames.clear();

            this.pendingTimeouts.forEach(id => {
                clearTimeout(id);
            });
            this.pendingTimeouts.clear();

            const elements = document.querySelectorAll('[data-tooltip-trigger-id]');
            const batchSize = 20;

            const processElementsBatch = (startIdx) => {
                const endIdx = Math.min(startIdx + batchSize, elements.length);

                for (let i = startIdx; i < endIdx; i++) {
                    this.destroy(elements[i]);
                }

                if (endIdx < elements.length) {
                    const rafId = requestAnimationFrame(() => {
                        this.pendingAnimationFrames.delete(rafId);
                        processElementsBatch(endIdx);
                    });
                    this.pendingAnimationFrames.add(rafId);
                } else {
                    this.cleanupOrphanedTooltips();
                }
            };

            if (elements.length > 0) {
                processElementsBatch(0);
            } else {
                this.cleanupOrphanedTooltips();
            }
        }

        cleanupOrphanedTooltips() {
            const tippyElements = document.querySelectorAll('[data-tippy-root]');
            let removed = 0;

            tippyElements.forEach(element => {
                const tooltipId = element.getAttribute('data-for-tooltip-id');
                const trigger = tooltipId ? 
                    document.querySelector(`[data-tooltip-trigger-id="${tooltipId}"]`) : 
                    null;

                if (!trigger || !document.body.contains(trigger)) {
                    if (element.parentNode) {
                        element.parentNode.removeChild(element);
                        removed++;
                    }
                }
            });

            if (removed > 0) {
                this.log(`Removed ${removed} orphaned tooltip elements`);
            }

            return removed;
        }

        setupMutationObserver() {
            if (this.mutationObserver) {
                this.mutationObserver.disconnect();
            }

            this.mutationObserver = new MutationObserver(mutations => {
                let needsCleanup = false;

                mutations.forEach(mutation => {
                    if (mutation.removedNodes.length) {
                        Array.from(mutation.removedNodes).forEach(node => {
                            if (node.nodeType === Node.ELEMENT_NODE) {
                                if (node.hasAttribute && node.hasAttribute('data-tooltip-trigger-id')) {
                                    this.destroy(node);
                                    needsCleanup = true;
                                }

                                if (node.querySelectorAll) {
                                    const tooltipTriggers = node.querySelectorAll('[data-tooltip-trigger-id]');
                                    if (tooltipTriggers.length > 0) {
                                        tooltipTriggers.forEach(trigger => {
                                            this.destroy(trigger);
                                        });
                                        needsCleanup = true;
                                    }
                                }
                            }
                        });
                    }
                });
                
                if (needsCleanup) {
                    this.cleanupOrphanedTooltips();
                }
            });

            this.mutationObserver.observe(document.body, {
                childList: true,
                subtree: true
            });

            return this.mutationObserver;
        }

        startDisconnectedElementsCheck() {
            if (this.disconnectedCheckInterval) {
                clearInterval(this.disconnectedCheckInterval);
            }

            this.disconnectedCheckInterval = setInterval(() => {
                this.checkForDisconnectedElements();
            }, 60000);
        }

        checkForDisconnectedElements() {
            const elements = document.querySelectorAll('[data-tooltip-trigger-id]');
            let removedCount = 0;

            elements.forEach(element => {
                if (!document.body.contains(element)) {
                    this.destroy(element);
                    removedCount++;
                }
            });

            if (removedCount > 0) {
                this.log(`Removed ${removedCount} tooltips for disconnected elements`);
                this.cleanupOrphanedTooltips();
            }
        }

        startPeriodicCleanup() {
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
            }

            this.cleanupInterval = setInterval(() => {
                this.performPeriodicCleanup();
            }, 120000);
        }

        performPeriodicCleanup(force = false) {
            this.cleanupOrphanedTooltips();

            this.checkForDisconnectedElements();

            const tooltipCount = document.querySelectorAll('[data-tippy-root]').length;

            if (force || tooltipCount > this.maxTooltips) {
                this.log(`Performing aggressive cleanup (${tooltipCount} tooltips)`);

                this.cleanup();

                if (window.gc) {
                    window.gc();
                } else {
                    const arr = new Array(1000);
                    for (let i = 0; i < 1000; i++) {
                        arr[i] = new Array(10000).join('x');
                    }
                }
            }
        }

        setupStyles() {
            if (document.getElementById('tooltip-styles')) return;

            document.head.insertAdjacentHTML('beforeend', `
                <style id="tooltip-styles">
                    [data-tippy-root] {
                        position: fixed !important;
                        z-index: 9999 !important;
                        pointer-events: none !important;
                    }

                    .tippy-box {
                        font-size: 0.875rem;
                        line-height: 1.25rem;
                        font-weight: 500;
                        border-radius: 0.5rem;
                        color: white;
                        position: relative !important;
                        pointer-events: auto !important;
                    }

                    .tippy-content {
                        padding: 0.5rem 0.75rem !important;
                    }

                    .tippy-box .bg-gray-400 {
                        background-color: rgb(156 163 175);
                        padding: 0.5rem 0.75rem;
                    }
                    .tippy-box:has(.bg-gray-400) .tippy-arrow {
                        color: rgb(156 163 175);
                    }

                    .tippy-box .bg-red-500 {
                        background-color: rgb(239 68 68);
                        padding: 0.5rem 0.75rem;
                    }
                    .tippy-box:has(.bg-red-500) .tippy-arrow {
                        color: rgb(239 68 68);
                    }

                    .tippy-box .bg-gray-300 {
                        background-color: rgb(209 213 219);
                        padding: 0.5rem 0.75rem;
                    }
                    .tippy-box:has(.bg-gray-300) .tippy-arrow {
                        color: rgb(209 213 219);
                    }

                    .tippy-box .bg-green-700 {
                        background-color: rgb(21 128 61);
                        padding: 0.5rem 0.75rem;
                    }
                    .tippy-box:has(.bg-green-700) .tippy-arrow {
                        color: rgb(21 128 61);
                    }

                    .tippy-box[data-placement^='top'] > .tippy-arrow::before {
                        border-top-color: currentColor;
                    }

                    .tippy-box[data-placement^='bottom'] > .tippy-arrow::before {
                        border-bottom-color: currentColor;
                    }

                    .tippy-box[data-placement^='left'] > .tippy-arrow::before {
                        border-left-color: currentColor;
                    }

                    .tippy-box[data-placement^='right'] > .tippy-arrow::before {
                        border-right-color: currentColor;
                    }

                    .tippy-box[data-placement^='top'] > .tippy-arrow {
                        bottom: 0;
                    }

                    .tippy-box[data-placement^='bottom'] > .tippy-arrow {
                        top: 0;
                    }

                    .tippy-box[data-placement^='left'] > .tippy-arrow {
                        right: 0;
                    }

                    .tippy-box[data-placement^='right'] > .tippy-arrow {
                        left: 0;
                    }
                </style>
            `);
        }

        initializeTooltips(selector = '[data-tooltip-target]') {
            document.querySelectorAll(selector).forEach(element => {
                const targetId = element.getAttribute('data-tooltip-target');
                if (!targetId) return;

                const tooltipContent = document.getElementById(targetId);

                if (tooltipContent) {
                    this.create(element, tooltipContent.innerHTML, {
                        placement: element.getAttribute('data-tooltip-placement') || 'top'
                    });
                }
            });
        }

        dispose() {
            this.log('Disposing TooltipManager');
            
            this.cleanup();

            this.pendingAnimationFrames.forEach(id => {
                cancelAnimationFrame(id);
            });
            this.pendingAnimationFrames.clear();

            this.pendingTimeouts.forEach(id => {
                clearTimeout(id);
            });
            this.pendingTimeouts.clear();

            if (this.disconnectedCheckInterval) {
                clearInterval(this.disconnectedCheckInterval);
                this.disconnectedCheckInterval = null;
            }

            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                this.cleanupInterval = null;
            }

            if (this.mutationObserver) {
                this.mutationObserver.disconnect();
                this.mutationObserver = null;
            }

            const styleElement = document.getElementById('tooltip-styles');
            if (styleElement && styleElement.parentNode) {
                styleElement.parentNode.removeChild(styleElement);
            }

            instance = null;
            return true;
        }

        setDebugMode(enabled) {
            this.debug = Boolean(enabled);
            return this.debug;
        }

        initialize(options = {}) {
            if (options.maxTooltips) {
                this.maxTooltips = options.maxTooltips;
            }

            if (options.debug !== undefined) {
                this.setDebugMode(options.debug);
            }

            this.log('TooltipManager initialized');
            return this;
        }
    }

    return {
        initialize: function(options = {}) {
            if (!instance) {
                const manager = new TooltipManagerImpl();
                manager.initialize(options);
            }
            return instance;
        },

        getInstance: function() {
            if (!instance) {
                this.initialize();
            }
            return instance;
        },

        create: function(...args) {
            const manager = this.getInstance();
            return manager.create(...args);
        },

        destroy: function(...args) {
            const manager = this.getInstance();
            return manager.destroy(...args);
        },

        cleanup: function(...args) {
            const manager = this.getInstance();
            return manager.cleanup(...args);
        },

        initializeTooltips: function(...args) {
            const manager = this.getInstance();
            return manager.initializeTooltips(...args);
        },
        
        setDebugMode: function(enabled) {
            const manager = this.getInstance();
            return manager.setDebugMode(enabled);
        },

        dispose: function(...args) {
            const manager = this.getInstance();
            return manager.dispose(...args);
        }
    };
})();

function installTooltipManager() {
    const originalTooltipManager = window.TooltipManager;

    window.TooltipManager = TooltipManager;

    window.TooltipManager.initialize({
        maxTooltips: 200,
        debug: false
    });

    document.addEventListener('DOMContentLoaded', function() {
        if (!window.tooltipManagerInitialized) {
            window.TooltipManager.initializeTooltips();
            window.tooltipManagerInitialized = true;
        }
    });
    
    return originalTooltipManager;
}

if (typeof document !== 'undefined') {
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        installTooltipManager();
    } else {
        document.addEventListener('DOMContentLoaded', installTooltipManager);
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TooltipManager;
}

window.TooltipManager = TooltipManager;
console.log('TooltipManager initialized');
