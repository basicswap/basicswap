class TooltipManager {
    constructor() {
        this.activeTooltips = new Map();
        this.sizeCheckIntervals = new Map();
        this.setupStyles();
        this.setupCleanupEvents();
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
            const rect = element.getBoundingClientRect();
            if (rect.width && rect.height) {
                clearInterval(this.sizeCheckIntervals.get(element));
                this.sizeCheckIntervals.delete(element);
                this.createTooltip(element, content, options, rect);
            }
        };

        this.sizeCheckIntervals.set(element, setInterval(checkSize, 50));
        checkSize();
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
            },
            onCreate(instance) {
                instance._originalPlacement = instance.props.placement;
            },
            onShow(instance) {
                if (!document.body.contains(element)) {
                    return false;
                }

                const rect = element.getBoundingClientRect();
                if (!rect.width || !rect.height) {
                    return false;
                }

                instance.setProps({
                    placement: instance._originalPlacement
                });

                if (instance.popper.firstElementChild) {
                    instance.popper.firstElementChild.classList.add(bgClass);
                }

                return true;
            },
            onMount(instance) {
                if (instance.popper.firstElementChild) {
                    instance.popper.firstElementChild.classList.add(bgClass);
                }
                const arrow = instance.popper.querySelector('.tippy-arrow');
                if (arrow) {
                    arrow.style.setProperty('color', arrowColor, 'important');
                }
            }
        });

        const id = element.getAttribute('data-tooltip-trigger-id') || 
                  `tooltip-${Math.random().toString(36).substring(7)}`;
        element.setAttribute('data-tooltip-trigger-id', id);
        this.activeTooltips.set(id, instance);
        
        return instance;
    }

    destroy(element) {
        if (!element) return;

        if (this.sizeCheckIntervals.has(element)) {
            clearInterval(this.sizeCheckIntervals.get(element));
            this.sizeCheckIntervals.delete(element);
        }

        const id = element.getAttribute('data-tooltip-trigger-id');
        if (!id) return;

        const instance = this.activeTooltips.get(id);
        if (instance?.[0]) {
            try {
                instance[0].destroy();
            } catch (e) {
                console.warn('Error destroying tooltip:', e);
            }
        }
        this.activeTooltips.delete(id);
        element.removeAttribute('data-tooltip-trigger-id');
    }

    cleanup() {
        this.sizeCheckIntervals.forEach((interval) => clearInterval(interval));
        this.sizeCheckIntervals.clear();

        this.activeTooltips.forEach((instance, id) => {
            if (instance?.[0]) {
                try {
                    instance[0].destroy();
                } catch (e) {
                    console.warn('Error cleaning up tooltip:', e);
                }
            }
        });
        this.activeTooltips.clear();

        document.querySelectorAll('[data-tippy-root]').forEach(element => {
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
        window.addEventListener('beforeunload', () => this.cleanup());
        window.addEventListener('unload', () => this.cleanup());
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.cleanup();
            }
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
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = TooltipManager;
}

document.addEventListener('DOMContentLoaded', () => {
    TooltipManager.initialize();
});
