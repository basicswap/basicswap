(function(window) {
    'use strict';

    class Tabs {
        constructor(tabsEl, items = [], options = {}) {
            this._tabsEl = tabsEl;
            this._items = items;
            this._activeTab = options.defaultTabId ? this.getTab(options.defaultTabId) : null;
            this._options = {
                defaultTabId: options.defaultTabId || null,
                activeClasses: options.activeClasses || 'text-blue-600 hover:text-blue-600 dark:text-blue-500 dark:hover:text-blue-500 border-blue-600 dark:border-blue-500',
                inactiveClasses: options.inactiveClasses || 'dark:border-transparent text-gray-500 hover:text-gray-600 dark:text-gray-400 border-gray-100 hover:border-gray-300 dark:border-gray-700 dark:hover:text-gray-300',
                onShow: options.onShow || function() {}
            };
            this._initialized = false;
            this.init();
        }

        init() {
            if (this._items.length && !this._initialized) {
                if (!this._activeTab) {
                    this.setActiveTab(this._items[0]);
                }

                this.show(this._activeTab.id, true);

                this._items.forEach(tab => {
                    tab.triggerEl.addEventListener('click', () => {
                        this.show(tab.id);
                    });
                });

                this._initialized = true;
            }
        }

        show(tabId, force = false) {
            const tab = this.getTab(tabId);
            
            if ((tab !== this._activeTab) || force) {
                this._items.forEach(t => {
                    if (t !== tab) {
                        t.triggerEl.classList.remove(...this._options.activeClasses.split(' '));
                        t.triggerEl.classList.add(...this._options.inactiveClasses.split(' '));
                        t.targetEl.classList.add('hidden');
                        t.triggerEl.setAttribute('aria-selected', false);
                    }
                });

                tab.triggerEl.classList.add(...this._options.activeClasses.split(' '));
                tab.triggerEl.classList.remove(...this._options.inactiveClasses.split(' '));
                tab.triggerEl.setAttribute('aria-selected', true);
                tab.targetEl.classList.remove('hidden');

                this.setActiveTab(tab);
                this._options.onShow(this, tab);
            }
        }

        getTab(id) {
            return this._items.find(t => t.id === id);
        }

        getActiveTab() {
            return this._activeTab;
        }

        setActiveTab(tab) {
            this._activeTab = tab;
        }
    }

    function initTabs() {
        document.querySelectorAll('[data-tabs-toggle]').forEach(tabsEl => {
            const items = [];
            let defaultTabId = null;

            tabsEl.querySelectorAll('[role="tab"]').forEach(triggerEl => {
                const isActive = triggerEl.getAttribute('aria-selected') === 'true';
                const tab = {
                    id: triggerEl.getAttribute('data-tabs-target'),
                    triggerEl: triggerEl,
                    targetEl: document.querySelector(triggerEl.getAttribute('data-tabs-target'))
                };
                items.push(tab);

                if (isActive) {
                    defaultTabId = tab.id;
                }
            });

            new Tabs(tabsEl, items, {
                defaultTabId: defaultTabId
            });
        });
    }

    const style = document.createElement('style');
    style.textContent = `
        [data-tabs-toggle] [role="tab"] {
            cursor: pointer;
        }
    `;
    document.head.appendChild(style);

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initTabs);
    } else {
        initTabs();
    }

    window.Tabs = Tabs;
    window.initTabs = initTabs;

})(window);
