(function() {
    'use strict';

    document.addEventListener('DOMContentLoaded', initBidsTabNavigation);
    window.addEventListener('load', handleHashChange);
    window.addEventListener('hashchange', preventScrollOnHashChange);

    function initBidsTabNavigation() {
        const sentTabButton = document.getElementById('sent-tab');
        const receivedTabButton = document.getElementById('received-tab');
        
        if (!sentTabButton || !receivedTabButton) {
            return;
        }
        
        document.querySelectorAll('.bids-tab-link').forEach(link => {
            link.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                
                const targetTabId = this.getAttribute('data-tab-target');
                
                if (targetTabId) {
                    if (window.location.pathname === '/bids') {
                        const oldScrollPosition = window.scrollY;
                        
                        activateTab(targetTabId);
                        
                        setTimeout(function() {
                            window.scrollTo(0, oldScrollPosition);
                            
                            history.replaceState(null, null, '#' + targetTabId.replace('#', ''));
                        }, 0);
                    } else {
                        localStorage.setItem('bidsTabToActivate', targetTabId.replace('#', ''));
                        window.location.href = '/bids';
                    }
                }
            });
        });

        const tabToActivate = localStorage.getItem('bidsTabToActivate');
        if (tabToActivate) {
            localStorage.removeItem('bidsTabToActivate');
            activateTab('#' + tabToActivate);
        } else if (window.location.pathname === '/bids' && !window.location.hash) {
            activateTab('#sent');
        }
    }

    function preventScrollOnHashChange(e) {
        if (window.location.pathname !== '/bids') {
            return;
        }
        
        e.preventDefault();
        
        const oldScrollPosition = window.scrollY;
        const hash = window.location.hash;
        
        if (hash) {
            const tabId = `#${hash.replace('#', '')}`;
            activateTab(tabId);
        } else {
            activateTab('#sent');
        }
        
        setTimeout(function() {
            window.scrollTo(0, oldScrollPosition);
        }, 0);
    }

    function handleHashChange() {
        if (window.location.pathname !== '/bids') {
            return;
        }
        
        const oldScrollPosition = window.scrollY;
        const hash = window.location.hash;
        
        if (hash) {
            const tabId = `#${hash.replace('#', '')}`;
            activateTab(tabId);
        } else {
            activateTab('#sent');
        }
        
        setTimeout(function() {
            window.scrollTo(0, oldScrollPosition);
        }, 0);
    }

    function activateTab(tabId) {
        if (tabId !== '#sent' && tabId !== '#received') {
            tabId = '#sent';
        }
        
        const tabButtonId = tabId === '#sent' ? 'sent-tab' : 'received-tab';
        const tabButton = document.getElementById(tabButtonId);
        
        if (tabButton) {
            const oldScrollPosition = window.scrollY;
            
            tabButton.click();
            
            setTimeout(function() {
                window.scrollTo(0, oldScrollPosition);
            }, 0);
        }
    }

    window.navigateToBidsTab = function(tabId) {
        if (window.location.pathname === '/bids') {
            const oldScrollPosition = window.scrollY;
            
            activateTab('#' + (tabId === 'sent' || tabId === 'received' ? tabId : 'sent'));
            
            setTimeout(function() {
                window.scrollTo(0, oldScrollPosition);
                history.replaceState(null, null, '#' + tabId);
            }, 0);
        } else {
            localStorage.setItem('bidsTabToActivate', tabId);
            window.location.href = '/bids';
        }
    };
})();
