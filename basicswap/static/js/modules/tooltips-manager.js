const TooltipManager = (function() {
    let instance = null;

    class TooltipManagerImpl {
        constructor() {

            if (instance) {
                return instance;
            }

            this.activeTooltips = new WeakMap();
            this.tooltipIdCounter = 0;
            this.pendingAnimationFrames = new Set();
            this.tooltipElementsMap = new Map();
            this.maxTooltips = 300;
            this.cleanupThreshold = 1.3;
            this.disconnectedCheckInterval = null;

            this.setupStyles();
            this.setupCleanupEvents();
            this.initializeMutationObserver();
            this.startDisconnectedElementsCheck();

            instance = this;
        }

        create(element, content, options = {}) {
            if (!element) return null;

            this.destroy(element);

            if (this.tooltipElementsMap.size > this.maxTooltips * this.cleanupThreshold) {
                const oldestEntries = Array.from(this.tooltipElementsMap.entries())
                    .sort((a, b) => a[1].timestamp - b[1].timestamp)
                    .slice(0, 20);

                oldestEntries.forEach(([el]) => {
                    this.destroy(el);
                });
            }

            const originalContent = content;

            const rafId = requestAnimationFrame(() => {
                this.pendingAnimationFrames.delete(rafId);

                if (!document.body.contains(element)) return;

                const rect = element.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                    this.createTooltip(element, originalContent, options, rect);
                } else {
                    let retryCount = 0;
                    const retryCreate = () => {
                        const newRect = element.getBoundingClientRect();
                        if ((newRect.width > 0 && newRect.height > 0) || retryCount >= 3) {
                            if (newRect.width > 0 && newRect.height > 0) {
                                this.createTooltip(element, originalContent, options, newRect);
                            }
                        } else {
                            retryCount++;
                            const newRafId = requestAnimationFrame(retryCreate);
                            this.pendingAnimationFrames.add(newRafId);
                        }
                    };
                                        const initialRetryId = requestAnimationFrame(retryCreate);
                    this.pendingAnimationFrames.add(initialRetryId);
                }
            });

            this.pendingAnimationFrames.add(rafId);
            return null;
        }

        createTooltip(element, content, options, rect) {
            const targetId = element.getAttribute('data-tooltip-target');
            let bgClass = 'bg-gray-400';
            let arrowColor = 'rgb(156 163 175)';

            if (targetId?.includes('tooltip-offer-') && window.jsonData) {
                try {
                    const offerId = targetId.split('tooltip-offer-')[1];
                    let actualOfferId = offerId;

                    if (offerId.includes('_')) {
                        [actualOfferId] = offerId.split('_');
                    }

                    let offer = null;
                    if (Array.isArray(window.jsonData)) {
                        for (let i = 0; i < window.jsonData.length; i++) {
                            const o = window.jsonData[i];
                            if (o && (o.unique_id === offerId || o.offer_id === actualOfferId)) {
                                offer = o;
                                break;
                            }
                        }
                    }

                    if (offer) {
                        if (offer.is_revoked) {
                            bgClass = 'bg-red-500';
                            arrowColor = 'rgb(239 68 68)';
                        } else if (offer.is_own_offer) {
                            bgClass = 'bg-gray-300';
                            arrowColor = 'rgb(209 213 219)';
                        } else {
                            bgClass = 'bg-green-700';
                            arrowColor = 'rgb(21 128 61)';
                        }
                    }
                } catch (e) {
                    console.warn('Error finding offer for tooltip:', e);
                }
            }

            const tooltipId = `tooltip-${++this.tooltipIdCounter}`;

            try {
                if (typeof tippy !== 'function') {
                    console.error('Tippy.js is not loaded. Cannot create tooltip.');
                    return null;
                }

                const instance = tippy(element, {
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
                            instance.popper.firstElementChild.classList.add(bgClass);
                            instance.popper.setAttribute('data-for-tooltip-id', tooltipId);
                        }
                        const arrow = instance.popper.querySelector('.tippy-arrow');
                        if (arrow) {
                            arrow.style.setProperty('color', arrowColor, 'important');
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
                });

                element.setAttribute('data-tooltip-trigger-id', tooltipId);
                this.activeTooltips.set(element, instance);

                this.tooltipElementsMap.set(element, {
                    timestamp: Date.now(),
                    id: tooltipId
                });

                return instance;
            } catch (e) {
                console.error('Error creating tooltip:', e);
                return null;
            }
        }

        destroy(element) {
            if (!element) return;

            const id = element.getAttribute('data-tooltip-trigger-id');
            if (!id) return;

            const instance = this.activeTooltips.get(element);
            if (instance?.[0]) {
                try {
                    instance[0].destroy();
                } catch (e) {
                    console.warn('Error destroying tooltip:', e);

                    const tippyRoot = document.querySelector(`[data-for-tooltip-id="${id}"]`);
                    if (tippyRoot && tippyRoot.parentNode) {
                        tippyRoot.parentNode.removeChild(tippyRoot);
                    }
                }
            }

            this.activeTooltips.delete(element);
            this.tooltipElementsMap.delete(element);

            element.removeAttribute('data-tooltip-trigger-id');
        }

        cleanup() {
            this.pendingAnimationFrames.forEach(id => {
                cancelAnimationFrame(id);
            });
            this.pendingAnimationFrames.clear();

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
                    this.cleanupOrphanedTippyElements();
                }
            };

            if (elements.length > 0) {
                processElementsBatch(0);
            } else {
                this.cleanupOrphanedTippyElements();
            }

            this.tooltipElementsMap.clear();
        }

        cleanupOrphanedTippyElements() {
            const tippyElements = document.querySelectorAll('[data-tippy-root]');
            tippyElements.forEach(element => {
                if (element.parentNode) {
                    element.parentNode.removeChild(element);
                }
            });
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

        setupCleanupEvents() {
            this.boundCleanup = this.cleanup.bind(this);
            this.handleVisibilityChange = () => {
                if (document.hidden) {
                    this.cleanup();

                    if (window.MemoryManager) {
                        window.MemoryManager.forceCleanup();
                    }
                }
            };

            window.addEventListener('beforeunload', this.boundCleanup);
            window.addEventListener('unload', this.boundCleanup);
            document.addEventListener('visibilitychange', this.handleVisibilityChange);

            if (window.CleanupManager) {
                window.CleanupManager.registerResource('tooltipManager', this, (tm) => tm.dispose());
            }

            this.cleanupInterval = setInterval(() => {
                this.performPeriodicCleanup();
            }, 120000);
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
            if (this.tooltipElementsMap.size === 0) return;

            const elementsToCheck = Array.from(this.tooltipElementsMap.keys());
            let removedCount = 0;

            elementsToCheck.forEach(element => {

                if (!document.body.contains(element)) {
                    this.destroy(element);
                    removedCount++;
                }
            });

            if (removedCount > 0) {
                this.cleanupOrphanedTippyElements();
            }
        }

        performPeriodicCleanup() {
            this.cleanupOrphanedTippyElements();
            this.checkForDisconnectedElements();

            if (this.tooltipElementsMap.size > this.maxTooltips * this.cleanupThreshold) {
                const sortedTooltips = Array.from(this.tooltipElementsMap.entries())
                    .sort((a, b) => a[1].timestamp - b[1].timestamp);

                const tooltipsToRemove = sortedTooltips.slice(0, sortedTooltips.length - this.maxTooltips);
                tooltipsToRemove.forEach(([element]) => {
                    this.destroy(element);
                });
            }
        }

        removeCleanupEvents() {
            window.removeEventListener('beforeunload', this.boundCleanup);
            window.removeEventListener('unload', this.boundCleanup);
            document.removeEventListener('visibilitychange', this.handleVisibilityChange);

            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                this.cleanupInterval = null;
            }

            if (this.disconnectedCheckInterval) {
                clearInterval(this.disconnectedCheckInterval);
                this.disconnectedCheckInterval = null;
            }
        }

        initializeMutationObserver() {
            if (this.mutationObserver) return;

            this.mutationObserver = new MutationObserver(mutations => {
                let needsCleanup = false;

                mutations.forEach(mutation => {
                    if (mutation.removedNodes.length) {
                        Array.from(mutation.removedNodes).forEach(node => {
                            if (node.nodeType === 1) {

                                if (node.hasAttribute && node.hasAttribute('data-tooltip-trigger-id')) {
                                    this.destroy(node);
                                    needsCleanup = true;
                                }

                                if (node.querySelectorAll) {
                                    const tooltipTriggers = node.querySelectorAll('[data-tooltip-trigger-id]');
                                    if (tooltipTriggers.length > 0) {
                                        tooltipTriggers.forEach(el => {
                                            this.destroy(el);
                                        });
                                        needsCleanup = true;
                                    }
                                }
                            }
                        });
                    }
                });

                if (needsCleanup) {
                    this.cleanupOrphanedTippyElements();
                }
            });

            this.mutationObserver.observe(document.body, {
                childList: true,
                subtree: true
            });
        }

        initializeTooltips(selector = '[data-tooltip-target]') {
            document.querySelectorAll(selector).forEach(element => {
                const targetId = element.getAttribute('data-tooltip-target');
                const tooltipContent = document.getElementById(targetId);

                if (tooltipContent) {
                    this.create(element, tooltipContent.innerHTML, {
                        placement: element.getAttribute('data-tooltip-placement') || 'top'
                    });
                }
            });
        }

        dispose() {
            this.cleanup();

            this.pendingAnimationFrames.forEach(id => {
                cancelAnimationFrame(id);
            });
            this.pendingAnimationFrames.clear();

            if (this.mutationObserver) {
                this.mutationObserver.disconnect();
                this.mutationObserver = null;
            }

            this.removeCleanupEvents();

            const styleElement = document.getElementById('tooltip-styles');
            if (styleElement && styleElement.parentNode) {
                styleElement.parentNode.removeChild(styleElement);
            }

            this.activeTooltips = new WeakMap();
            this.tooltipElementsMap.clear();

            instance = null;
        }

        initialize(options = {}) {

            if (options.maxTooltips) {
                this.maxTooltips = options.maxTooltips;
            }

            console.log('TooltipManager initialized');
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
                const manager = new TooltipManagerImpl();
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

        dispose: function(...args) {
            const manager = this.getInstance();
            return manager.dispose(...args);
        }
    };
})();

window.TooltipManager = TooltipManager;

document.addEventListener('DOMContentLoaded', function() {
    if (!window.tooltipManagerInitialized) {
        TooltipManager.initialize();
        TooltipManager.initializeTooltips();
        window.tooltipManagerInitialized = true;
    }
});

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TooltipManager;
}

//console.log('TooltipManager initialized with methods:', Object.keys(TooltipManager));
console.log('TooltipManager initialized');
