(function(window) {
    'use strict';

    const style = document.createElement('style');
    style.textContent = `
        [role="tooltip"] {
            position: fixed;
            z-index: 9999;
            transition: opacity 0.2s ease-in-out;
            pointer-events: none;
            opacity: 0;
            visibility: hidden;
        }
    `;
    document.head.appendChild(style);

    function throttle(func, limit) {
        let inThrottle;
        return function(...args) {
            if (!inThrottle) {
                func.apply(this, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    function positionElement(targetEl, triggerEl, placement = 'top', offsetDistance = 8) {
        const triggerRect = triggerEl.getBoundingClientRect();
        let top, left;

        const wasHidden = targetEl.style.visibility === 'hidden';
        if (wasHidden) {
            targetEl.style.visibility = 'hidden';
            targetEl.style.opacity = '0';
            targetEl.style.display = 'block';
        }

        const targetRect = targetEl.getBoundingClientRect();
        
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

        targetEl.style.top = Math.round(top) + 'px';
        targetEl.style.left = Math.round(left) + 'px';

        if (wasHidden) {
            targetEl.style.display = '';
            targetEl.style.visibility = 'hidden';
            targetEl.style.opacity = '0';
        }
    }

    const tooltips = new WeakMap();

    class Tooltip {
        constructor(targetEl, triggerEl, options = {}) {
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

            this._targetEl.style.visibility = 'hidden';
            this._targetEl.style.opacity = '0';

            this._showHandler = this.show.bind(this);
            this._hideHandler = this.hide.bind(this);
            this._updatePosition = throttle(() => {
                if (this._visible) {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );
                }
            }, 100);

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

            if (this._options.triggerType === 'click') {
                this._triggerEl.addEventListener('click', this._showHandler);
            }

            window.addEventListener('scroll', this._updatePosition, true);
            window.addEventListener('resize', this._updatePosition);
        }

        show() {
            if (!this._visible) {
                positionElement(
                    this._targetEl,
                    this._triggerEl,
                    this._options.placement,
                    this._options.offset
                );

                requestAnimationFrame(() => {
                    this._targetEl.style.visibility = 'visible';
                    this._targetEl.style.opacity = '1';
                });

                this._visible = true;
                this._options.onShow();
            }
        }

        hide() {
            if (this._visible) {
                this._targetEl.style.opacity = '0';
                this._targetEl.style.visibility = 'hidden';
                this._visible = false;
                this._options.onHide();
            }
        }

        toggle() {
            if (this._visible) {
                this.hide();
            } else {
                this.show();
            }
        }
    }

    function initTooltips() {
        document.querySelectorAll('[data-tooltip-target]').forEach(triggerEl => {
            if (tooltips.has(triggerEl)) return;

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
