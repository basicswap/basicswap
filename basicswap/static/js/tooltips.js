class TooltipManager {
    constructor() {
        this.activeTooltips = new WeakMap();
        this.sizeCheckIntervals = new WeakMap();
        this.tooltipIdCounter = 0;
        this.setupStyles();
        this.setupCleanupEvents();
        this.initializeMutationObserver();
    }

    static initialize() {
        if (!window.TooltipManager) {
            window.TooltipManager = new TooltipManager();
        }
        return window.TooltipManager;
    }

    create(element, content, options = {}) {
        if (!element) return null;
        
        this.destroy(element);

        const checkSize = () => {
            if (!document.body.contains(element)) {
                return;
            }
            
            const rect = element.getBoundingClientRect();
            if (rect.width && rect.height) {
                delete element._tooltipRetryCount;
                this.createTooltip(element, content, options, rect);
            } else {
                const retryCount = element._tooltipRetryCount || 0;
                if (retryCount < 5) {
                    element._tooltipRetryCount = retryCount + 1;
                    requestAnimationFrame(checkSize);
                } else {
                    delete element._tooltipRetryCount;
                }
            }
        };

        requestAnimationFrame(checkSize);
        return null;
    }

    createTooltip(element, content, options, rect) {
        const targetId = element.getAttribute('data-tooltip-target');
        let bgClass = 'bg-gray-400';
        let arrowColor = 'rgb(156 163 175)';

        if (targetId?.includes('tooltip-offer-')) {
            const offerId = targetId.split('tooltip-offer-')[1];
            const [actualOfferId] = offerId.split('_');
            
            if (window.jsonData) {
                const offer = window.jsonData.find(o => 
                    o.unique_id === offerId || 
                    o.offer_id === actualOfferId
                );

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
            }
        }

        const tooltipId = `tooltip-${++this.tooltipIdCounter}`;

        const instance = tippy(element, {
            content,
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

                const rect = element.getBoundingClientRect();
                if (!rect.width || !rect.height) {
                    return false;
                }

                return true;
            },
            onMount(instance) {
                if (instance.popper.firstElementChild) {
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
        
        return instance;
    }

    destroy(element) {
        if (!element) return;

        delete element._tooltipRetryCount;
        
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
        element.removeAttribute('data-tooltip-trigger-id');
    }

    cleanup() {
        document.querySelectorAll('[data-tooltip-trigger-id]').forEach(element => {
            this.destroy(element);
        });

        document.querySelectorAll('[data-tippy-root]').forEach(element => {
            if (element.parentNode) {
                element.parentNode.removeChild(element);
            }
        });
    }

    getActiveTooltipInstances() {
        const result = [];
        
        document.querySelectorAll('[data-tooltip-trigger-id]').forEach(element => {
            const instance = this.activeTooltips.get(element);
            if (instance) {
                result.push([element, instance]);
            }
        });
        
        return result;
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
                                node.querySelectorAll('[data-tooltip-trigger-id]').forEach(el => {
                                    this.destroy(el);
                                    needsCleanup = true;
                                });
                            }
                        }
                    });
                }
            });
            
            if (needsCleanup) {
                document.querySelectorAll('[data-tippy-root]').forEach(element => {
                    const id = element.getAttribute('data-for-tooltip-id');
                    if (id && !document.querySelector(`[data-tooltip-trigger-id="${id}"]`)) {
                        if (element.parentNode) {
                            element.parentNode.removeChild(element);
                        }
                    }
                });
            }
        });
        
        this.mutationObserver.observe(document.body, { 
            childList: true,
            subtree: true
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
            }
        };
        
        window.addEventListener('beforeunload', this.boundCleanup);
        window.addEventListener('unload', this.boundCleanup);
        document.addEventListener('visibilitychange', this.handleVisibilityChange);
    }

    removeCleanupEvents() {
        window.removeEventListener('beforeunload', this.boundCleanup);
        window.removeEventListener('unload', this.boundCleanup);
        document.removeEventListener('visibilitychange', this.handleVisibilityChange);
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
        
        if (this.mutationObserver) {
            this.mutationObserver.disconnect();
            this.mutationObserver = null;
        }
        
        this.removeCleanupEvents();
        
        const styleElement = document.getElementById('tooltip-styles');
        if (styleElement && styleElement.parentNode) {
            styleElement.parentNode.removeChild(styleElement);
        }
        
        if (window.TooltipManager === this) {
            window.TooltipManager = null;
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TooltipManager;
}

document.addEventListener('DOMContentLoaded', () => {
    TooltipManager.initialize();
});
