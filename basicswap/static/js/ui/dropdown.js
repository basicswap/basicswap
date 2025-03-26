(function(window) {
    'use strict';

    const dropdownInstances = [];

    function positionElement(targetEl, triggerEl, placement = 'bottom', offsetDistance = 8) {
        targetEl.style.visibility = 'hidden';
        targetEl.style.display = 'block';

        const triggerRect = triggerEl.getBoundingClientRect();
        const targetRect = targetEl.getBoundingClientRect();
        const scrollLeft = window.pageXOffset || document.documentElement.scrollLeft;
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;

        let top, left;

        top = triggerRect.bottom + offsetDistance;
        left = triggerRect.left + (triggerRect.width - targetRect.width) / 2;

        switch (placement) {
            case 'bottom-start':
                left = triggerRect.left;
                break;
            case 'bottom-end':
                left = triggerRect.right - targetRect.width;
                break;
        }

        const viewport = {
            width: window.innerWidth,
            height: window.innerHeight
        };

        if (left < 10) left = 10;
        if (left + targetRect.width > viewport.width - 10) {
            left = viewport.width - targetRect.width - 10;
        }

        targetEl.style.position = 'fixed';
        targetEl.style.top = `${Math.round(top)}px`;
        targetEl.style.left = `${Math.round(left)}px`;
        targetEl.style.margin = '0';
        targetEl.style.maxHeight = `${viewport.height - top - 10}px`;
        targetEl.style.overflow = 'auto';
        targetEl.style.visibility = 'visible';
    }

    class Dropdown {
        constructor(targetEl, triggerEl, options = {}) {
            this._targetEl = targetEl;
            this._triggerEl = triggerEl;
            this._options = {
                placement: options.placement || 'bottom',
                offset: options.offset || 5,
                onShow: options.onShow || function() {},
                onHide: options.onHide || function() {}
            };
            this._visible = false;
            this._initialized = false;
            this._handleScroll = this._handleScroll.bind(this);
            this._handleResize = this._handleResize.bind(this);
            this._handleOutsideClick = this._handleOutsideClick.bind(this);

            dropdownInstances.push(this);

            this.init();
        }

        init() {
            if (!this._initialized) {
                this._targetEl.style.margin = '0';
                this._targetEl.style.display = 'none';
                this._targetEl.style.position = 'fixed';
                this._targetEl.style.zIndex = '40';
                this._targetEl.classList.add('dropdown-menu');

                this._setupEventListeners();
                this._initialized = true;
            }
        }

        _setupEventListeners() {
            this._triggerEl.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggle();
            });

            document.addEventListener('click', this._handleOutsideClick);
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape') this.hide();
            });
            window.addEventListener('scroll', this._handleScroll, true);
            window.addEventListener('resize', this._handleResize);
        }

        _handleScroll() {
            if (this._visible) {
                requestAnimationFrame(() => {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );
                });
            }
        }

        _handleResize() {
            if (this._visible) {
                requestAnimationFrame(() => {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );
                });
            }
        }

        _handleOutsideClick(e) {
            if (this._visible &&
                !this._targetEl.contains(e.target) &&
                !this._triggerEl.contains(e.target)) {
                this.hide();
            }
        }

        show() {
            if (!this._visible) {
                dropdownInstances.forEach(instance => {
                    if (instance !== this && instance._visible) {
                        instance.hide();
                    }
                });

                this._targetEl.style.display = 'block';
                this._targetEl.style.visibility = 'hidden';

                requestAnimationFrame(() => {
                    positionElement(
                        this._targetEl,
                        this._triggerEl,
                        this._options.placement,
                        this._options.offset
                    );

                    this._visible = true;
                    this._options.onShow();
                });
            }
        }

        hide() {
            if (this._visible) {
                this._targetEl.style.display = 'none';
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

        destroy() {
            document.removeEventListener('click', this._handleOutsideClick);
            window.removeEventListener('scroll', this._handleScroll, true);
            window.removeEventListener('resize', this._handleResize);

            const index = dropdownInstances.indexOf(this);
            if (index > -1) {
                dropdownInstances.splice(index, 1);
            }

            this._initialized = false;
        }
    }

    function initDropdowns() {
        document.querySelectorAll('[data-dropdown-toggle]').forEach(triggerEl => {
            const targetId = triggerEl.getAttribute('data-dropdown-toggle');
            const targetEl = document.getElementById(targetId);

            if (targetEl) {
                const placement = triggerEl.getAttribute('data-dropdown-placement');
                new Dropdown(targetEl, triggerEl, {
                    placement: placement || 'bottom-start'
                });
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDropdowns);
    } else {
        initDropdowns();
    }

    Dropdown.instances = dropdownInstances;

    window.Dropdown = Dropdown;
    window.initDropdowns = initDropdowns;

})(window);
