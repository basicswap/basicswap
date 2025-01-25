(function(window) {
    'use strict';

    const tooltipContainer = document.createElement('div');
    tooltipContainer.className = 'tooltip-container';

    const style = document.createElement('style');
    style.textContent = `
        [role="tooltip"] {
            position: absolute;
            z-index: 9999;
            transition: opacity 0.2s ease-in-out;
            pointer-events: auto;
            opacity: 0;
            visibility: hidden;
        }
        
        .tooltip-container {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 0;
            overflow: visible;
            pointer-events: none;
            z-index: 9999;
        }
    `;

    function ensureContainerExists() {
        if (!document.body.contains(tooltipContainer)) {
            document.body.appendChild(tooltipContainer);
        }
    }

    function rafThrottle(callback) {
        let requestId = null;
        let lastArgs = null;

        const later = (context) => {
            requestId = null;
            callback.apply(context, lastArgs);
        };

        return function(...args) {
            lastArgs = args;
            if (requestId === null) {
                requestId = requestAnimationFrame(() => later(this));
            }
        };
    }

    function positionElement(targetEl, triggerEl, placement = 'top', offsetDistance = 8) {
        const triggerRect = triggerEl.getBoundingClientRect();
        const targetRect = targetEl.getBoundingClientRect();
        let top, left;

        switch (placement) {
            case 'top':
                top = triggerRect.top - targetRect.height - offsetDistance;
                left = triggerRect.left + (triggerRect.width - targetRect.width) / 2;
                break;
            case 'bottom':
                top = triggerRect.bottom + offsetDistance;
                left = triggerRect.left + (triggerRect.width - targetRect.width) / 2;
                break;
            case 'left':
                top = triggerRect.top + (triggerRect.height - targetRect.height) / 2;
                left = triggerRect.left - targetRect.width - offsetDistance;
                break;
            case 'right':
                top = triggerRect.top + (triggerRect.height - targetRect.height) / 2;
                left = triggerRect.right + offsetDistance;
                break;
        }

        const viewport = {
            width: window.innerWidth,
            height: window.innerHeight
        };

        if (left < 0) left = 0;
        if (top < 0) top = 0;
        if (left + targetRect.width > viewport.width) 
            left = viewport.width - targetRect.width;
        if (top + targetRect.height > viewport.height)
            top = viewport.height - targetRect.height;

        targetEl.style.transform = `translate(${Math.round(left)}px, ${Math.round(top)}px)`;
    }

    const tooltips = new WeakMap();

    class Tooltip {
        constructor(targetEl, triggerEl, options = {}) {
            ensureContainerExists();

            this._targetEl = targetEl;
            this._triggerEl = triggerEl;
            this._options = {
                placement: options.placement || 'top',
                triggerType: options.triggerType || 'hover',
                offset: options.offset || 8,
                onShow: options.onShow || function() {},
                onHide: options.onHide || function() {}
            };
            this._visible = false;
            this._initialized = false;
            this._hideTimeout = null;
            this._showTimeout = null;
            this._rafId = null;

            if (this._targetEl.parentNode !== tooltipContainer) {
                tooltipContainer.appendChild(this._targetEl);
            }

            this._targetEl.style.visibility = 'hidden';
            this._targetEl.style.opacity = '0';

            this._showHandler = this.show.bind(this);
            this._hideHandler = this._handleHide.bind(this);
            this._scrollHandler = rafThrottle(() => {
                if (this._visible) {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );
                }
            });

            this.init();
        }

        init() {
            if (!this._initialized) {
                this._setupEventListeners();
                this._initialized = true;
                positionElement(
                    this._targetEl,
                    this._triggerEl,
                    this._options.placement,
                    this._options.offset
                );
            }
        }

        _setupEventListeners() {
            this._triggerEl.addEventListener('mouseenter', this._showHandler);
            this._triggerEl.addEventListener('mouseleave', this._hideHandler);
            this._triggerEl.addEventListener('focus', this._showHandler);
            this._triggerEl.addEventListener('blur', this._hideHandler);

            this._targetEl.addEventListener('mouseenter', () => {
                clearTimeout(this._hideTimeout);
                clearTimeout(this._showTimeout);
                this._visible = true;
                this._targetEl.style.visibility = 'visible';
                this._targetEl.style.opacity = '1';
            });

            this._targetEl.addEventListener('mouseleave', this._hideHandler);

            if (this._options.triggerType === 'click') {
                this._triggerEl.addEventListener('click', this._showHandler);
            }

            window.addEventListener('scroll', this._scrollHandler, { passive: true });
            document.addEventListener('scroll', this._scrollHandler, { passive: true, capture: true });
            window.addEventListener('resize', this._scrollHandler, { passive: true });
        }

        _handleHide() {
            clearTimeout(this._hideTimeout);
            clearTimeout(this._showTimeout);
            
            this._hideTimeout = setTimeout(() => {
                if (this._visible) {
                    this.hide();
                }
            }, 100);
        }

        show() {
            clearTimeout(this._hideTimeout);
            clearTimeout(this._showTimeout);

            this._showTimeout = setTimeout(() => {
                if (!this._visible) {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );

                    this._targetEl.style.visibility = 'visible';
                    this._targetEl.style.opacity = '1';
                    this._visible = true;
                    this._startSmoothUpdate();
                    this._options.onShow();
                }
            }, 20);
        }

        hide() {
            this._targetEl.style.opacity = '0';
            this._targetEl.style.visibility = 'hidden';
            this._visible = false;
            this._stopSmoothUpdate();
            this._options.onHide();
        }

        _startSmoothUpdate() {
            const update = () => {
                if (this._visible) {
                    this._scrollHandler();
                    this._rafId = requestAnimationFrame(update);
                }
            };
            this._rafId = requestAnimationFrame(update);
        }

        _stopSmoothUpdate() {
            if (this._rafId) {
                cancelAnimationFrame(this._rafId);
                this._rafId = null;
            }
        }

        destroy() {
            clearTimeout(this._hideTimeout);
            clearTimeout(this._showTimeout);
            
            if (this._rafId) {
                cancelAnimationFrame(this._rafId);
                this._rafId = null;
            }

            this._triggerEl.removeEventListener('mouseenter', this._showHandler);
            this._triggerEl.removeEventListener('mouseleave', this._hideHandler);
            this._triggerEl.removeEventListener('focus', this._showHandler);
            this._triggerEl.removeEventListener('blur', this._hideHandler);
            this._targetEl.removeEventListener('mouseenter', this._showHandler);
            this._targetEl.removeEventListener('mouseleave', this._hideHandler);

            if (this._options.triggerType === 'click') {
                this._triggerEl.removeEventListener('click', this._showHandler);
            }

            window.removeEventListener('scroll', this._scrollHandler);
            document.removeEventListener('scroll', this._scrollHandler, true);
            window.removeEventListener('resize', this._scrollHandler);

            this._targetEl.style.visibility = '';
            this._targetEl.style.opacity = '';
            this._targetEl.style.transform = '';

            if (this._targetEl.parentNode === tooltipContainer) {
                this._targetEl.parentNode.removeChild(this._targetEl);
            }

            this._targetEl = null;
            this._triggerEl = null;
            this._options = null;
            this._initialized = false;
            this._visible = false;
        }

        toggle() {
            if (this._visible) {
                this.hide();
            } else {
                this.show();
            }
        }
    }

    document.head.appendChild(style);

    function initTooltips() {
        ensureContainerExists();
        
        document.querySelectorAll('[data-tooltip-target]').forEach(triggerEl => {
            const oldTooltip = tooltips.get(triggerEl);
            if (oldTooltip) {
                oldTooltip.destroy();
                tooltips.delete(triggerEl);
            }
        });
        
        document.querySelectorAll('[data-tooltip-target]').forEach(triggerEl => {
            const targetId = triggerEl.getAttribute('data-tooltip-target');
            const targetEl = document.getElementById(targetId);
            
            if (targetEl) {
                const placement = triggerEl.getAttribute('data-tooltip-placement');
                const triggerType = triggerEl.getAttribute('data-tooltip-trigger');
                
                const tooltip = new Tooltip(targetEl, triggerEl, {
                    placement: placement || 'top',
                    triggerType: triggerType || 'hover',
                    offset: 8
                });

                tooltips.set(triggerEl, tooltip);
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTooltips);
    } else {
        initTooltips();
    }

    window.Tooltip = Tooltip;
    window.initTooltips = initTooltips;

})(window);
