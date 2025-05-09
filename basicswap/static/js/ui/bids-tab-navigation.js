(function() {
    'use strict';
    const originalOnload = window.onload;

    window.onload = function() {
        if (typeof originalOnload === 'function') {
            originalOnload();
        }

        setTimeout(function() {
            initBidsTabNavigation();
            handleInitialNavigation();
        }, 100);
    };

    document.addEventListener('DOMContentLoaded', function() {
        initBidsTabNavigation();
    });
    
    window.addEventListener('hashchange', handleHashChange);

    window.bidsTabNavigationInitialized = false;

    function initBidsTabNavigation() {
        if (window.bidsTabNavigationInitialized) {
            return;
        }

        document.querySelectorAll('.bids-tab-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                const targetTabId = this.getAttribute('data-tab-target');
                if (targetTabId) {
                    if (window.location.pathname === '/bids') {
                        navigateToTabDirectly(targetTabId);
                    } else {
                        localStorage.setItem('bidsTabToActivate', targetTabId.replace('#', ''));
                        window.location.href = '/bids';
                    }
                }
            });
        });

        window.bidsTabNavigationInitialized = true;
        console.log('Bids tab navigation initialized');
    }

    function handleInitialNavigation() {
        if (window.location.pathname !== '/bids') {
            return;
        }

        const tabToActivate = localStorage.getItem('bidsTabToActivate');
        
        if (tabToActivate) {
            //console.log('Activating tab from localStorage:', tabToActivate);
            localStorage.removeItem('bidsTabToActivate');
            activateTabWithRetry('#' + tabToActivate);
        } else if (window.location.hash) {
            //console.log('Activating tab from hash:', window.location.hash);
            activateTabWithRetry(window.location.hash);
        } else {
            //console.log('Activating default tab: #all');
            activateTabWithRetry('#all');
        }
    }

    function handleHashChange() {
        if (window.location.pathname !== '/bids') {
            return;
        }
        
        const hash = window.location.hash;
        if (hash) {
            //console.log('Hash changed, activating tab:', hash);
            activateTabWithRetry(hash);
        } else {
            //console.log('Hash cleared, activating default tab: #all');
            activateTabWithRetry('#all');
        }
    }

    function activateTabWithRetry(tabId, retryCount = 0) {
        const normalizedTabId = tabId.startsWith('#') ? tabId : '#' + tabId;

        if (normalizedTabId !== '#all' && normalizedTabId !== '#sent' && normalizedTabId !== '#received') {
            //console.log('Invalid tab ID, defaulting to #all');
            activateTabWithRetry('#all');
            return;
        }

        const tabButtonId = normalizedTabId === '#all' ? 'all-tab' : 
                           (normalizedTabId === '#sent' ? 'sent-tab' : 'received-tab');
        const tabButton = document.getElementById(tabButtonId);
        
        if (!tabButton) {
            if (retryCount < 5) {
                //console.log('Tab button not found, retrying...', retryCount + 1);
                setTimeout(() => {
                    activateTabWithRetry(normalizedTabId, retryCount + 1);
                }, 100);
            } else {
                //console.error('Failed to find tab button after retries');
            }
            return;
        }
        
        //console.log('Activating tab:', normalizedTabId);

        tabButton.click();

        if (window.Tabs) {
            const tabsEl = document.querySelector('[data-tabs-toggle="#bidstab"]');
            if (tabsEl) {
                const allTabs = Array.from(tabsEl.querySelectorAll('[role="tab"]'));
                const targetTab = allTabs.find(tab => tab.getAttribute('data-tabs-target') === normalizedTabId);
                
                if (targetTab) {

                    allTabs.forEach(tab => {
                        tab.setAttribute('aria-selected', tab === targetTab ? 'true' : 'false');

                        if (tab === targetTab) {
                            tab.classList.add('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
                            tab.classList.remove('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
                        } else {
                            tab.classList.remove('bg-gray-100', 'dark:bg-gray-600', 'text-gray-900', 'dark:text-white');
                            tab.classList.add('hover:text-gray-600', 'hover:bg-gray-50', 'dark:hover:bg-gray-500');
                        }
                    });

                    const allContent = document.getElementById('all');
                    const sentContent = document.getElementById('sent');
                    const receivedContent = document.getElementById('received');
                    
                    if (allContent && sentContent && receivedContent) {
                        allContent.classList.toggle('hidden', normalizedTabId !== '#all');
                        sentContent.classList.toggle('hidden', normalizedTabId !== '#sent');
                        receivedContent.classList.toggle('hidden', normalizedTabId !== '#received');
                    }
                }
            }
        }

        const allPanel = document.getElementById('all');
        const sentPanel = document.getElementById('sent');
        const receivedPanel = document.getElementById('received');
        
        if (allPanel && sentPanel && receivedPanel) {
            allPanel.classList.toggle('hidden', normalizedTabId !== '#all');
            sentPanel.classList.toggle('hidden', normalizedTabId !== '#sent');
            receivedPanel.classList.toggle('hidden', normalizedTabId !== '#received');
        }

        const newHash = normalizedTabId.replace('#', '');
        if (window.location.hash !== '#' + newHash) {
            history.replaceState(null, null, '#' + newHash);
        }

        triggerDataLoad(normalizedTabId);
    }

    function triggerDataLoad(tabId) {
        setTimeout(() => {
            if (window.state) {
                window.state.currentTab = tabId === '#all' ? 'all' : 
                                          (tabId === '#sent' ? 'sent' : 'received');

                if (typeof window.updateBidsTable === 'function') {
                    //console.log('Triggering data load for', tabId);
                    window.updateBidsTable();
                }
            }

            const event = new CustomEvent('tabactivated', {
                detail: { 
                    tabId: tabId,
                    type: tabId === '#all' ? 'all' : 
                          (tabId === '#sent' ? 'sent' : 'received')
                }
            });
            document.dispatchEvent(event);

            if (window.TooltipManager && typeof window.TooltipManager.cleanup === 'function') {
                setTimeout(() => {
                    window.TooltipManager.cleanup();
                    if (typeof window.initializeTooltips === 'function') {
                        window.initializeTooltips();
                    }
                }, 200);
            }
        }, 100);
    }

    function navigateToTabDirectly(tabId) {
        const oldScrollPosition = window.scrollY;
        
        activateTabWithRetry(tabId);
        
        setTimeout(function() {
            window.scrollTo(0, oldScrollPosition);
        }, 0);
    }

    window.navigateToBidsTab = function(tabId) {
        if (window.location.pathname === '/bids') {
            navigateToTabDirectly('#' + tabId);
        } else {
            localStorage.setItem('bidsTabToActivate', tabId);
            window.location.href = '/bids';
        }
    };
})();
