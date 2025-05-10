const TooltipManager = (function() {
    let instance = null;
    const tooltipInstanceMap = new WeakMap();

    class TooltipManagerImpl {
        constructor() {
            if (instance) {
                return instance;
            }

            this.tooltipIdCounter = 0;
            this.maxTooltips = 200;
            this.cleanupThreshold = 1.2;
            this.debug = false;
            this.tooltipData = new WeakMap();
            this.resources = {};

            if (window.CleanupManager) {
                CleanupManager.registerResource(
                    'tooltipManager',
                    this,
                    (manager) => manager.dispose()
                );
            }

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

            const createTooltip = () => {
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
                            CleanupManager.setTimeout(() => {
                                CleanupManager.requestAnimationFrame(retryCreate);
                            }, 100);
                        }
                    };

                    CleanupManager.setTimeout(() => {
                        CleanupManager.requestAnimationFrame(retryCreate);
                    }, 100);
                }
            };

            CleanupManager.requestAnimationFrame(createTooltip);
            return null;
        }

        createTooltipInstance(element, content, options = {}) {
            if (!element || !document.body.contains(element)) {
                return null;
            }

            if (typeof window.tippy !== 'function') {
                console.error('Tippy.js is not available.');
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
                            CleanupManager.setTimeout(() => {
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

                    const resourceId = CleanupManager.registerResource(
                        'tooltip',
                        { element, instance: tippyInstance[0] },
                        (resource) => {
                            try {
                                if (resource.instance && resource.instance.destroy) {
                                    resource.instance.destroy();
                                }
                                if (resource.element) {
                                    resource.element.removeAttribute('data-tooltip-trigger-id');
                                    resource.element.removeAttribute('aria-describedby');
                                }
                            } catch (e) {
                                console.warn('Error destroying tooltip during cleanup:', e);
                            }
                        }
                    );
                    
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

        getActiveTooltipInstances() {
            const result = [];
            try {
                document.querySelectorAll('[data-tooltip-trigger-id]').forEach(element => {
                    const instance = element._tippy ? [element._tippy] : null;
                    if (instance) {
                        result.push([element, instance]);
                    }
                });
            } catch (error) {
                console.error('Error getting active tooltip instances:', error);
            }
            return result;
        }

        cleanup() {
            this.log('Running tooltip cleanup');

            try {
                if ((window.location.pathname.includes('/offers') || window.location.pathname.includes('/bids')) && 
                    (document.querySelector('[data-tippy-root]:hover') || document.querySelector('[data-tooltip-trigger-id]:hover'))) {
                    console.log('Skipping tooltip cleanup - tooltip is being hovered');
                    return;
                }

                const elements = document.querySelectorAll('[data-tooltip-trigger-id]:not(:hover)');
                const batchSize = 20;

                const processElementsBatch = (startIdx) => {
                    const endIdx = Math.min(startIdx + batchSize, elements.length);

                    for (let i = startIdx; i < endIdx; i++) {
                        this.destroy(elements[i]);
                    }

                    if (endIdx < elements.length) {
                        CleanupManager.requestAnimationFrame(() => {
                            processElementsBatch(endIdx);
                        });
                    } else {
                        this.cleanupOrphanedTooltips();
                    }
                };

                if (elements.length > 0) {
                    processElementsBatch(0);
                } else {
                    this.cleanupOrphanedTooltips();
                }
            } catch (error) {
                console.error('Error during cleanup:', error);
            }
        }

        thoroughCleanup() {
            this.log('Running thorough tooltip cleanup');

            try {
                this.cleanup();
                this.cleanupAllTooltips();
                this.log('Thorough tooltip cleanup completed');
            } catch (error) {
                console.error('Error in thorough tooltip cleanup:', error);
            }
        }

        cleanupAllTooltips() {
            this.log('Cleaning up all tooltips');

            try {
                if ((window.location.pathname.includes('/offers') || window.location.pathname.includes('/bids')) && 
                    document.querySelector('#offers-body tr:hover')) {
                    this.log('Skipping all tooltips cleanup on offers/bids page with row hover');
                    return;
                }

                const tooltipRoots = document.querySelectorAll('[data-tippy-root]');
                const tooltipTriggers = document.querySelectorAll('[data-tooltip-trigger-id]');
                const tooltipElements = document.querySelectorAll('.tooltip');

                const isHovered = element => {
                    try {
                        return element.matches && element.matches(':hover');
                    } catch (e) {

                        return false;
                    }
                };

                tooltipRoots.forEach(root => {
                    if (!isHovered(root) && root.parentNode) {
                        root.parentNode.removeChild(root);
                    }
                });

                tooltipTriggers.forEach(trigger => {
                    if (!isHovered(trigger)) {
                        trigger.removeAttribute('data-tooltip-trigger-id');
                        trigger.removeAttribute('aria-describedby');
                        
                        if (trigger._tippy) {
                            try {
                                trigger._tippy.destroy();
                                trigger._tippy = null;
                            } catch (e) {}
                        }
                    }
                });

                tooltipElements.forEach(tooltip => {
                    if (!isHovered(tooltip) && tooltip.parentNode) {
                        let closestHoveredRow = false;

                        try {
                            if (tooltip.closest && tooltip.closest('tr') && isHovered(tooltip.closest('tr'))) {
                                closestHoveredRow = true;
                            }
                        } catch (e) {}

                        if (!closestHoveredRow) {
                            const style = window.getComputedStyle(tooltip);
                            const isVisible = style.display !== 'none' && 
                                        style.visibility !== 'hidden' &&
                                        style.opacity !== '0';

                            if (!isVisible) {
                                tooltip.parentNode.removeChild(tooltip);
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error cleaning up all tooltips:', error);
            }
        }

        cleanupOrphanedTooltips() {
            try {
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
            } catch (error) {
                console.error('Error cleaning up orphaned tooltips:', error);
                return 0;
            }
        }

        setupMutationObserver() {
            try {
                const mutationObserver = new MutationObserver(mutations => {
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

                mutationObserver.observe(document.body, {
                    childList: true,
                    subtree: true
                });

                this.resources.mutationObserver = CleanupManager.registerResource(
                    'mutationObserver',
                    mutationObserver,
                    (observer) => observer.disconnect()
                );

                return mutationObserver;
            } catch (error) {
                console.error('Error setting up mutation observer:', error);
                return null;
            }
        }

        startDisconnectedElementsCheck() {
            try {
                this.resources.disconnectedCheckInterval = CleanupManager.setInterval(() => {
                    this.checkForDisconnectedElements();
                }, 60000);
            } catch (error) {
                console.error('Error starting disconnected elements check:', error);
            }
        }

        checkForDisconnectedElements() {
            try {
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
            } catch (error) {
                console.error('Error checking for disconnected elements:', error);
            }
        }

        startPeriodicCleanup() {
            try {
                this.resources.cleanupInterval = CleanupManager.setInterval(() => {
                    this.performPeriodicCleanup();
                }, 120000);
            } catch (error) {
                console.error('Error starting periodic cleanup:', error);
            }
        }

        performPeriodicCleanup(force = false) {
            try {
                if ((window.location.pathname.includes('/offers') || window.location.pathname.includes('/bids')) && 
                    !force) {
                    return;
                }

                this.cleanupOrphanedTooltips();
                this.checkForDisconnectedElements();

                const tooltipCount = document.querySelectorAll('[data-tippy-root]').length;

                if (force || tooltipCount > this.maxTooltips) {
                    this.log(`Performing aggressive cleanup (${tooltipCount} tooltips)`);
                    this.cleanup();
                }
            } catch (error) {
                console.error('Error performing periodic cleanup:', error);
            }
        }

        setupStyles() {
            if (document.getElementById('tooltip-styles')) return;

            try {
                const style = document.createElement('style');
                style.id = 'tooltip-styles';
                style.textContent = `
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
                `;
                document.head.appendChild(style);

                this.resources.tooltipStyles = CleanupManager.registerResource(
                    'tooltipStyles',
                    style,
                    (styleElement) => {
                        if (styleElement && styleElement.parentNode) {
                            styleElement.parentNode.removeChild(styleElement);
                        }
                    }
                );
            } catch (error) {
                console.error('Error setting up styles:', error);
                try {
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

                    const styleElement = document.getElementById('tooltip-styles');
                    if (styleElement) {
                        this.resources.tooltipStyles = CleanupManager.registerResource(
                            'tooltipStyles',
                            styleElement,
                            (elem) => {
                                if (elem && elem.parentNode) {
                                    elem.parentNode.removeChild(elem);
                                }
                            }
                        );
                    }
                } catch (e) {
                    console.error('Failed to add tooltip styles:', e);
                }
            }
        }

        initializeTooltips(selector = '[data-tooltip-target]') {
            try {
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
            } catch (error) {
                console.error('Error initializing tooltips:', error);
            }
        }

        dispose() {
            this.log('Disposing TooltipManager');

            try {
                this.cleanup();

                Object.values(this.resources).forEach(resourceId => {
                    if (resourceId) {
                        CleanupManager.unregisterResource(resourceId);
                    }
                });

                this.resources = {};

                instance = null;
                return true;
            } catch (error) {
                console.error('Error disposing TooltipManager:', error);
                return false;
            }
        }

        setDebugMode(enabled) {
            this.debug = Boolean(enabled);
            return this.debug;
        }

        initialize(options = {}) {
            try {
                if (options.maxTooltips) {
                    this.maxTooltips = options.maxTooltips;
                }

                if (options.debug !== undefined) {
                    this.setDebugMode(options.debug);
                }

                this.setupStyles();
                this.setupMutationObserver();
                this.startPeriodicCleanup();
                this.startDisconnectedElementsCheck();

                this.log('TooltipManager initialized');
                return this;
            } catch (error) {
                console.error('Error initializing TooltipManager:', error);
                return this;
            }
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

        thoroughCleanup: function() {
            const manager = this.getInstance();
            return manager.thoroughCleanup();
        },

        initializeTooltips: function(...args) {
            const manager = this.getInstance();
            return manager.initializeTooltips(...args);
        },
        
        setDebugMode: function(enabled) {
            const manager = this.getInstance();
            return manager.setDebugMode(enabled);
        },

        getActiveTooltipInstances: function() {
            const manager = this.getInstance();
            return manager.getActiveTooltipInstances();
        },

        dispose: function(...args) {
            const manager = this.getInstance();
            return manager.dispose(...args);
        }
    };
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TooltipManager;
}

if (typeof window !== 'undefined') {
    window.TooltipManager = TooltipManager;
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
    function initializeTooltipManager() {
        if (!window.tooltipManagerInitialized) {

            if (!window.CleanupManager) {
                console.warn('CleanupManager not found. TooltipManager will run with limited functionality.');

                window.CleanupManager = window.CleanupManager || {
                    registerResource: (type, resource, cleanup) => {
                        return Math.random().toString(36).substring(2, 9);
                    },
                    unregisterResource: () => {},
                    setTimeout: (callback, delay) => setTimeout(callback, delay),
                    setInterval: (callback, delay) => setInterval(callback, delay),
                    requestAnimationFrame: (callback) => requestAnimationFrame(callback),
                    addListener: (element, type, handler, options) => {
                        element.addEventListener(type, handler, options);
                        return handler;
                    }
                };
            }

            window.TooltipManager.initialize({
                maxTooltips: 200,
                debug: false
            });

            window.TooltipManager.initializeTooltips();
            window.tooltipManagerInitialized = true;
        }
    }

    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        initializeTooltipManager();
    } else {
        document.addEventListener('DOMContentLoaded', initializeTooltipManager, { once: true });
    }
}

if (typeof window !== 'undefined' && typeof console !== 'undefined') {
    console.log('TooltipManager initialized');
}
