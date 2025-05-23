const AmmTablesManager = (function() {
    const config = {
        refreshInterval: 30000,
        debug: false
    };

    let refreshTimer = null;
    let stateData = null;
    let coinData = {};

    const offersTab = document.getElementById('offers-tab');
    const bidsTab = document.getElementById('bids-tab');
    const offersContent = document.getElementById('offers-content');
    const bidsContent = document.getElementById('bids-content');
    const offersCount = document.getElementById('offers-count');
    const bidsCount = document.getElementById('bids-count');
    const offersBody = document.getElementById('amm-offers-body');
    const bidsBody = document.getElementById('amm-bids-body');
    const refreshButton = document.getElementById('refreshAmmTables');

    function isDebugEnabled() {
        return localStorage.getItem('amm_debug_enabled') === 'true' || config.debug;
    }

    function debugLog(message, data) {
        if (isDebugEnabled()) {
            if (data) {
                console.log(`[AmmTables] ${message}`, data);
            } else {
                console.log(`[AmmTables] ${message}`);
            }
        }
    }

    function initializeTabs() {
        if (offersTab && bidsTab && offersContent && bidsContent) {
            offersTab.addEventListener('click', function() {
                offersContent.classList.remove('hidden');
                offersContent.classList.add('block');
                bidsContent.classList.add('hidden');
                bidsContent.classList.remove('block');

                offersTab.classList.add('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
                bidsTab.classList.remove('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
            });

            bidsTab.addEventListener('click', function() {
                offersContent.classList.add('hidden');
                offersContent.classList.remove('block');
                bidsContent.classList.remove('hidden');
                bidsContent.classList.add('block');

                bidsTab.classList.add('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
                offersTab.classList.remove('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
            });

            offersTab.click();
        }
    }

    function getImageFilename(coinSymbol) {
        if (!coinSymbol) return 'Unknown.png';

        const coinNameToSymbol = {
            'bitcoin': 'BTC',
            'monero': 'XMR',
            'particl': 'PART',
            'particl anon': 'PART_ANON',
            'particl blind': 'PART_BLIND',
            'litecoin': 'LTC',
            'bitcoincash': 'BCH',
            'bitcoin cash': 'BCH',
            'firo': 'FIRO',
            'zcoin': 'FIRO',
            'pivx': 'PIVX',
            'dash': 'DASH',
            'ethereum': 'ETH',
            'dogecoin': 'DOGE',
            'decred': 'DCR',
            'namecoin': 'NMC',
            'zano': 'ZANO',
            'wownero': 'WOW'
        };

        let normalizedInput = coinSymbol.toLowerCase();

        if (coinNameToSymbol[normalizedInput]) {
            normalizedInput = coinNameToSymbol[normalizedInput];
        }

        const normalizedSymbol = normalizedInput.toUpperCase();

        if (normalizedSymbol === 'FIRO' || normalizedSymbol === 'ZCOIN') return 'Firo.png';
        if (normalizedSymbol === 'BCH' || normalizedSymbol === 'BITCOINCASH') return 'Bitcoin-Cash.png';
        if (normalizedSymbol === 'PART_ANON' || normalizedSymbol === 'PARTICL_ANON') return 'Particl.png';
        if (normalizedSymbol === 'PART_BLIND' || normalizedSymbol === 'PARTICL_BLIND') return 'Particl.png';

        if (window.CoinManager && window.CoinManager.getCoinBySymbol) {
            const coin = window.CoinManager.getCoinBySymbol(normalizedSymbol);
            if (coin && coin.image) return coin.image;
        }

        const coinImages = {
            'BTC': 'Bitcoin.png',
            'XMR': 'Monero.png',
            'PART': 'Particl.png',
            'LTC': 'Litecoin.png',
            'FIRO': 'Firo.png',
            'PIVX': 'PIVX.png',
            'DASH': 'Dash.png',
            'ETH': 'Ethereum.png',
            'DOGE': 'Dogecoin.png',
            'DCR': 'Decred.png',
            'NMC': 'Namecoin.png',
            'ZANO': 'Zano.png',
            'WOW': 'Wownero.png'
        };

        const result = coinImages[normalizedSymbol] || 'Unknown.png';
        debugLog(`Coin symbol: ${coinSymbol}, normalized: ${normalizedSymbol}, image: ${result}`);
        return result;
    }

    function createSwapColumn(coinFrom, coinTo) {
        const fromImage = getImageFilename(coinFrom);
        const toImage = getImageFilename(coinTo);

        return `
            <td class="py-0 px-0 text-right text-sm">
                <div class="flex items-center justify-center monospace">
                    <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${fromImage}" alt="${coinFrom}">
                    </span>
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${toImage}" alt="${coinTo}">
                    </span>
                </div>
            </td>
        `;
    }

    function createActiveCount(templateName, activeItems) {
        const count = activeItems && activeItems[templateName] ? activeItems[templateName].length : 0;

        return `
            <td class="py-3 px-4 text-center">
                <span class="inline-flex items-center px-3 py-1 text-xs font-medium rounded-full
                    ${count > 0
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                        : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                    ${count}
                </span>
            </td>
        `;
    }

    function renderOffersTable(stateData) {
        if (!offersBody) return;

        debugLog('Rendering offers table with data:', stateData);

        let offers = [];
        if (stateData && stateData.config) {
            if (Array.isArray(stateData.config.offers)) {
                offers = stateData.config.offers;
            } else if (typeof stateData.config.offers === 'object') {
                offers = [stateData.config.offers];
            }
        }

        const activeOffers = stateData && stateData.state && stateData.state.offers ? stateData.state.offers : {};

        if (offers.length === 0) {
            offersBody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-4 px-4 text-center text-gray-500 dark:text-gray-400">
                        No offers configured. Edit the AMM configuration to add offers.
                    </td>
                </tr>
            `;
            offersCount.textContent = '(0)';
            return;
        }

        offersCount.textContent = `(${offers.length})`;

        let tableHtml = '';

        offers.forEach(offer => {
            const name = offer.name || 'Unnamed Offer';
            const coinFrom = offer.coin_from || '';
            const coinTo = offer.coin_to || '';
            const amount = parseFloat(offer.amount || 0);
            const minrate = parseFloat(offer.minrate || 0);
            const enabled = offer.enabled !== undefined ? offer.enabled : false;
            const amountVariable = offer.amount_variable !== undefined ? offer.amount_variable : false;
            const minCoinFromAmt = parseFloat(offer.min_coin_from_amt || 0);
            const offerValidSeconds = parseInt(offer.offer_valid_seconds || 3600);
            const rateTweakPercent = parseFloat(offer.ratetweakpercent || 0);

            const amountToReceive = amount * minrate;

            const activeOffersCount = activeOffers[name] && Array.isArray(activeOffers[name]) ?
                activeOffers[name].length : 0;

            tableHtml += `
                <tr class="relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600">
                    <td class="py-3 px-4">
                        <div class="font-medium">${name}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${amountVariable ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                ${amountVariable ? 'Variable Amount' : 'Fixed Amount'}
                            </span>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ml-1 bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                                Valid: ${formatDuration(offerValidSeconds)}
                            </span>
                        </div>
                    </td>
                    ${createSwapColumn(coinFrom, coinTo)}
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${amount.toFixed(8)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-300">${coinFrom}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Min: ${minCoinFromAmt.toFixed(8)}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${minrate.toFixed(8)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300">
                            Tweak: ${rateTweakPercent > 0 ? '+' : ''}${rateTweakPercent}%
                        </div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Receive: ~${amountToReceive.toFixed(8)} ${coinTo}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex flex-col items-center">
                            <span class="inline-flex items-center px-3 py-1 text-xs font-medium rounded-full
                                ${enabled
                                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                                    : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'}">
                                ${enabled ? 'Enabled' : 'Disabled'}
                            </span>
                            <span class="mt-1 inline-flex items-center px-3 py-1 text-xs font-medium rounded-full hidden
                                ${activeOffersCount > 0
                                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                ${activeOffersCount} Running Offer${activeOffersCount !== 1 ? 's' : ''}
                            </span>
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex items-center justify-center space-x-2">
                            <button type="button" class="edit-amm-item text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                data-type="offer" data-id="${offer.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"></path>
                                </svg>
                            </button>
                            <button type="button" class="delete-amm-item text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                                data-type="offer" data-id="${offer.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        offersBody.innerHTML = tableHtml;
    }

    function renderBidsTable(stateData) {
        if (!bidsBody) return;

        debugLog('Rendering bids table with data:', stateData);

        let bids = [];
        if (stateData && stateData.config) {
            if (Array.isArray(stateData.config.bids)) {
                bids = stateData.config.bids;
            } else if (typeof stateData.config.bids === 'object') {
                bids = [stateData.config.bids];
            }
        }

        const activeBids = stateData && stateData.state && stateData.state.bids ? stateData.state.bids : {};

        if (bids.length === 0) {
            bidsBody.innerHTML = `
                <tr>
                    <td colspan="6" class="py-4 px-4 text-center text-gray-500 dark:text-gray-400">
                        No bids configured. Edit the AMM configuration to add bids.
                    </td>
                </tr>
            `;
            bidsCount.textContent = '(0)';
            return;
        }

        bidsCount.textContent = `(${bids.length})`;

        let tableHtml = '';

        bids.forEach(bid => {
            const name = bid.name || 'Unnamed Bid';
            const coinFrom = bid.coin_from || '';
            const coinTo = bid.coin_to || '';
            const amount = parseFloat(bid.amount || 0);
            const maxRate = parseFloat(bid.max_rate || 0);
            const enabled = bid.enabled !== undefined ? bid.enabled : false;
            const amountVariable = bid.amount_variable !== undefined ? bid.amount_variable : false;
            const minCoinToBalance = parseFloat(bid.min_coin_to_balance || 0);
            const maxConcurrent = parseInt(bid.max_concurrent || 1);
            const amountToSend = amount * maxRate;
            const activeBidsCount = activeBids[name] && Array.isArray(activeBids[name]) ?
                activeBids[name].length : 0;

            tableHtml += `
                <tr class="relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600">
                    <td class="py-3 px-4">
                        <div class="font-medium">${name}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${amountVariable ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                ${amountVariable ? 'Variable Amount' : 'Fixed Amount'}
                            </span>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ml-1 bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                                Max Concurrent: ${maxConcurrent}
                            </span>
                        </div>
                    </td>
                    ${createSwapColumn(coinTo, coinFrom)}
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${amount.toFixed(8)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-300">${coinFrom}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Min ${coinTo} Balance: ${minCoinToBalance.toFixed(8)}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${maxRate.toFixed(8)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Send: ~${amountToSend.toFixed(8)} ${coinTo}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex flex-col items-center">
                            <span class="inline-flex items-center px-3 py-1 text-xs font-medium rounded-full
                                ${enabled
                                    ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                                    : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'}">
                                ${enabled ? 'Enabled' : 'Disabled'}
                            </span>
                            <span class="mt-1 inline-flex items-center px-3 py-1 text-xs font-medium rounded-full
                                ${activeBidsCount > 0
                                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                ${activeBidsCount} Running Bid${activeBidsCount !== 1 ? 's' : ''}
                            </span>
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex items-center justify-center space-x-2">
                            <button type="button" class="edit-amm-item text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                data-type="bid" data-id="${bid.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"></path>
                                </svg>
                            </button>
                            <button type="button" class="delete-amm-item text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                                data-type="bid" data-id="${bid.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                                </svg>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        });

        bidsBody.innerHTML = tableHtml;
    }

    function formatDuration(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
        return `${Math.floor(seconds / 86400)}d`;
    }

    function getInitialData() {
        if (window.ammTablesConfig) {
            const stateData = window.ammTablesConfig.stateData || {};
            let configData = window.ammTablesConfig.configData || {};

            if (!configData || Object.keys(configData).length === 0) {
                try {
                    if (window.ammTablesConfig.configContent) {
                        if (typeof window.ammTablesConfig.configContent === 'string') {
                            configData = JSON.parse(window.ammTablesConfig.configContent);
                        } else if (typeof window.ammTablesConfig.configContent === 'object') {
                            configData = window.ammTablesConfig.configContent;
                        }
                    }
                } catch (error) {
                    debugLog('Error parsing config content:', error);
                }
            }

            debugLog('Initial state data:', stateData);
            debugLog('Initial config data:', configData);

            return {
                state: stateData,
                config: configData
            };
        }
        return null;
    }

    function parseStateData() {
        const stateContent = document.querySelector('.font-mono.bg-gray-50.overflow-y-auto');
        if (!stateContent) return null;

        try {
            const stateText = stateContent.textContent.trim();
            if (!stateText) return null;

            const parsedState = JSON.parse(stateText);
            return { state: parsedState };
        } catch (error) {
            debugLog('Error parsing state data:', error);
            return null;
        }
    }

    function parseConfigData() {
        const configTextarea = document.querySelector('textarea[name="config_content"]');
        if (!configTextarea) return null;

        try {
            const configText = configTextarea.value.trim();
            if (!configText) return null;

            const parsedConfig = JSON.parse(configText);
            return { config: parsedConfig };
        } catch (error) {
            debugLog('Error parsing config data:', error);
            return null;
        }
    }

    function getCombinedData() {
        const initialData = getInitialData();
        if (initialData) {
            return initialData;
        }

        const stateData = parseStateData();
        const configData = parseConfigData();

        return {
            ...stateData,
            ...configData
        };
    }
    function updateTables() {
        const data = getCombinedData();
        if (!data) {
            debugLog('No data available for tables');
            return;
        }

        stateData = data;
        debugLog('Updated state data:', stateData);

        renderOffersTable(stateData);
        renderBidsTable(stateData);
    }

    function startRefreshTimer() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
        }

        refreshTimer = setInterval(function() {
            updateTables();
        }, config.refreshInterval);

        return refreshTimer;
    }

    function stopRefreshTimer() {
        if (refreshTimer) {
            clearInterval(refreshTimer);
            refreshTimer = null;
        }
    }

    function setupConfigFormListener() {
        const configForm = document.querySelector('form[method="post"]');
        if (configForm) {
            configForm.addEventListener('submit', function() {
                localStorage.setItem('amm_update_tables', 'true');
            });

            if (localStorage.getItem('amm_update_tables') === 'true') {
                localStorage.removeItem('amm_update_tables');
                setTimeout(updateTables, 500);
            }
        }
    }

    function setupButtonHandlers() {
        const addOfferButton = document.getElementById('add-new-offer-btn');
        if (addOfferButton) {
            addOfferButton.addEventListener('click', function() {
                openAddModal('offer');
            });
        }

        const addBidButton = document.getElementById('add-new-bid-btn');
        if (addBidButton) {
            addBidButton.addEventListener('click', function() {
                openAddModal('bid');
            });
        }

        const addCancelButton = document.getElementById('add-amm-cancel');
        if (addCancelButton) {
            addCancelButton.addEventListener('click', closeAddModal);
        }

        const addSaveButton = document.getElementById('add-amm-save');
        if (addSaveButton) {
            addSaveButton.addEventListener('click', saveNewItem);
        }

        const editCancelButton = document.getElementById('edit-amm-cancel');
        if (editCancelButton) {
            editCancelButton.addEventListener('click', closeEditModal);
        }

        const editSaveButton = document.getElementById('edit-amm-save');
        if (editSaveButton) {
            editSaveButton.addEventListener('click', saveEditedItem);
        }

        document.addEventListener('click', function(e) {
            if (e.target && (e.target.classList.contains('delete-amm-item') || e.target.closest('.delete-amm-item'))) {
                const button = e.target.classList.contains('delete-amm-item') ? e.target : e.target.closest('.delete-amm-item');
                const type = button.getAttribute('data-type');
                const id = button.getAttribute('data-id');
                const name = button.getAttribute('data-name');

                if (!id && !name) {
                    alert('Error: Could not identify the item to delete.');
                    return;
                }

                if (confirm(`Are you sure you want to delete this ${type}?`)) {
                    deleteAmmItem(type, id, name);
                }
            }

            if (e.target && (e.target.classList.contains('edit-amm-item') || e.target.closest('.edit-amm-item'))) {
                const button = e.target.classList.contains('edit-amm-item') ? e.target : e.target.closest('.edit-amm-item');
                const type = button.getAttribute('data-type');
                const id = button.getAttribute('data-id');
                const name = button.getAttribute('data-name');

                if (!id && !name) {
                    alert('Error: Could not identify the item to edit.');
                    return;
                }

                openEditModal(type, id, name);
            }
        });

        const addModal = document.getElementById('add-amm-modal');
        if (addModal) {
            addModal.addEventListener('click', function(e) {
                if (e.target === addModal) {
                    closeAddModal();
                }
            });
        }

        const editModal = document.getElementById('edit-amm-modal');
        if (editModal) {
            editModal.addEventListener('click', function(e) {
                if (e.target === editModal) {
                    closeEditModal();
                }
            });
        }
    }

    function openAddModal(type) {
        debugLog(`Opening add modal for ${type}`);

        const modalTitle = document.getElementById('add-modal-title');
        if (modalTitle) {
            modalTitle.textContent = `Add New ${type.charAt(0).toUpperCase() + type.slice(1)}`;
        }

        document.getElementById('add-amm-type').value = type;

        document.getElementById('add-amm-name').value = '';
        document.getElementById('add-amm-enabled').checked = false;

        const coinFromSelect = document.getElementById('add-amm-coin-from');
        const coinToSelect = document.getElementById('add-amm-coin-to');

        if (coinFromSelect && coinFromSelect.options.length > 0) {
            coinFromSelect.selectedIndex = 0;
            coinFromSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }

        if (coinToSelect && coinToSelect.options.length > 0) {
            coinToSelect.selectedIndex = 0;
            coinToSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }

        document.getElementById('add-amm-amount').value = '';

        const adjustRatesCheckbox = document.getElementById('add-offer-adjust-rates');
        if (adjustRatesCheckbox) {
            adjustRatesCheckbox.checked = true;
        }

        if (type === 'offer') {
            const offerFields = document.getElementById('add-offer-fields');
            if (offerFields) {
                offerFields.classList.remove('hidden');
            }

            const bidFields = document.getElementById('add-bid-fields');
            if (bidFields) {
                bidFields.classList.add('hidden');
            }

            document.getElementById('add-amm-rate-label').textContent = 'Min Rate';
            document.getElementById('add-amm-rate').value = '0.0001';
            document.getElementById('add-offer-ratetweakpercent').value = '0';
            document.getElementById('add-offer-min-coin-from-amt').value = '';
            document.getElementById('add-offer-valid-seconds').value = '3600';
            document.getElementById('add-offer-address').value = 'auto';
            document.getElementById('add-offer-min-swap-amount').value = '0.001';
            document.getElementById('add-offer-amount-step').value = '';

            const coinFrom = document.getElementById('add-amm-coin-from');
            const coinTo = document.getElementById('add-amm-coin-to');
            const swapType = document.getElementById('add-offer-swap-type');

            if (coinFrom && coinTo && swapType) {
                updateSwapTypeOptions(coinFrom.value, coinTo.value, swapType);
            }
        } else if (type === 'bid') {
            const offerFields = document.getElementById('add-offer-fields');
            if (offerFields) {
                offerFields.classList.add('hidden');
            }

            const bidFields = document.getElementById('add-bid-fields');
            if (bidFields) {
                bidFields.classList.remove('hidden');

                document.getElementById('add-amm-rate-label').textContent = 'Max Rate';
                document.getElementById('add-amm-rate').value = '10000.0';
                document.getElementById('add-bid-min-coin-to-balance').value = '1.0';
                document.getElementById('add-bid-max-concurrent').value = '1';
                document.getElementById('add-bid-address').value = 'auto';
                document.getElementById('add-bid-min-swap-amount').value = '0.001';
            }
        }

        const modal = document.getElementById('add-amm-modal');
        if (modal) {
            modal.classList.remove('hidden');
        }
    }

    function closeAddModal() {
        const modal = document.getElementById('add-amm-modal');
        if (modal) {
            modal.classList.add('hidden');
            closeAllDropdowns();
        }
    }

    function saveNewItem() {
        const type = document.getElementById('add-amm-type').value;

        debugLog(`Saving new ${type}`);

        const configTextarea = document.querySelector('textarea[name="config_content"]');
        if (!configTextarea) {
            alert('Error: Could not find the configuration textarea.');
            return;
        }

        try {
            const configText = configTextarea.value.trim();
            if (!configText) {
                alert('Error: Configuration is empty.');
                return;
            }

            const config = JSON.parse(configText);

            const uniqueId = `${type}_${Date.now()}`;

            const newItem = {
                id: uniqueId,
                name: document.getElementById('add-amm-name').value,
                enabled: document.getElementById('add-amm-enabled').checked,
                coin_from: document.getElementById('add-amm-coin-from').value,
                coin_to: document.getElementById('add-amm-coin-to').value,
                amount: parseFloat(document.getElementById('add-amm-amount').value),
                amount_variable: true,

            if (type === 'offer') {
                newItem.minrate = parseFloat(document.getElementById('add-amm-rate').value);
                newItem.ratetweakpercent = parseFloat(document.getElementById('add-offer-ratetweakpercent').value || '0');
                newItem.adjust_rates_based_on_market = document.getElementById('add-offer-adjust-rates').checked;
                newItem.swap_type = document.getElementById('add-offer-swap-type').value || 'adaptor_sig';

                const minCoinFromAmt = document.getElementById('add-offer-min-coin-from-amt').value;
                if (minCoinFromAmt) {
                    newItem.min_coin_from_amt = parseFloat(minCoinFromAmt);
                }

                const validSeconds = document.getElementById('add-offer-valid-seconds').value;
                if (validSeconds) {
                    const seconds = parseInt(validSeconds);
                    if (seconds < 600) {
                        alert('Offer valid seconds must be at least 600 (10 minutes)');
                        return;
                    }
                    newItem.offer_valid_seconds = seconds;
                }

                const address = document.getElementById('add-offer-address').value;
                if (address) {
                    newItem.address = address;
                }

                const minSwapAmount = document.getElementById('add-offer-min-swap-amount').value;
                if (minSwapAmount) {
                    newItem.min_swap_amount = parseFloat(minSwapAmount);
                }

                const amountStep = document.getElementById('add-offer-amount-step').value;
                if (amountStep) {
                    if (/^[0-9]*\.?[0-9]*$/.test(amountStep)) {
                        const parsedValue = parseFloat(amountStep);
                        if (parsedValue > 0) {
                            newItem.amount_step = parsedValue.toString();
                            console.log(`Amount step set to: ${newItem.amount_step}`);
                        } else {
                            alert('Amount step must be greater than zero.');
                            return;
                        }
                    } else {
                        alert('Invalid amount step value. Please enter a valid decimal number.');
                        return;
                    }
                }
            } else if (type === 'bid') {
                newItem.max_rate = parseFloat(document.getElementById('add-amm-rate').value);

                const minCoinToBalance = document.getElementById('add-bid-min-coin-to-balance').value;
                if (minCoinToBalance) {
                    newItem.min_coin_to_balance = parseFloat(minCoinToBalance);
                }

                const maxConcurrent = document.getElementById('add-bid-max-concurrent').value;
                if (maxConcurrent) {
                    newItem.max_concurrent = parseInt(maxConcurrent);
                }

                const address = document.getElementById('add-bid-address').value;
                if (address) {
                    newItem.address = address;
                }

                const minSwapAmount = document.getElementById('add-bid-min-swap-amount').value;
                if (minSwapAmount) {
                    newItem.min_swap_amount = parseFloat(minSwapAmount);
                }
            }

            if (type === 'offer') {
                if (!Array.isArray(config.offers)) {
                    config.offers = [];
                }
                config.offers.push(newItem);
            } else if (type === 'bid') {
                if (!Array.isArray(config.bids)) {
                    config.bids = [];
                }
                config.bids.push(newItem);
            } else {
                alert(`Error: Invalid type ${type}`);
                return;
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            closeAddModal();

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton) {
                saveButton.click();
            } else {
                const form = configTextarea.closest('form');
                if (form) {
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'save_config';
                    hiddenInput.value = 'true';
                    form.appendChild(hiddenInput);
                    form.submit();
                } else {
                    alert('Error: Could not save the configuration.');
                }
            }
        } catch (error) {
            alert(`Error processing the configuration: ${error.message}`);
            debugLog('Error saving new item:', error);
        }
    }

    function openEditModal(type, id, name) {
        debugLog(`Opening edit modal for ${type} with id: ${id}, name: ${name}`);

        const configTextarea = document.querySelector('textarea[name="config_content"]');
        if (!configTextarea) {
            alert('Error: Could not find the configuration textarea.');
            return;
        }

        try {
            const configText = configTextarea.value.trim();
            if (!configText) {
                alert('Error: Configuration is empty.');
                return;
            }

            const config = JSON.parse(configText);

            let item = null;

            if (type === 'offer' && Array.isArray(config.offers)) {
                item = config.offers.find(offer =>
                    (id && offer.id === id) || (!id && offer.name === name)
                );
            } else if (type === 'bid' && Array.isArray(config.bids)) {
                item = config.bids.find(bid =>
                    (id && bid.id === id) || (!id && bid.name === name)
                );
            }

            if (!item) {
                alert(`Could not find the ${type} to edit.`);
                return;
            }

            const modalTitle = document.getElementById('edit-modal-title');
            if (modalTitle) {
                modalTitle.textContent = `Edit ${type.charAt(0).toUpperCase() + type.slice(1)}`;
            }

            document.getElementById('edit-amm-type').value = type;
            document.getElementById('edit-amm-id').value = id || '';
            document.getElementById('edit-amm-original-name').value = name;

            document.getElementById('edit-amm-name').value = item.name || '';
            document.getElementById('edit-amm-enabled').checked = item.enabled || false;

            const coinFromSelect = document.getElementById('edit-amm-coin-from');
            const coinToSelect = document.getElementById('edit-amm-coin-to');

            coinFromSelect.value = item.coin_from || '';
            coinToSelect.value = item.coin_to || '';

            coinFromSelect.dispatchEvent(new Event('change', { bubbles: true }));
            coinToSelect.dispatchEvent(new Event('change', { bubbles: true }));

            document.getElementById('edit-amm-amount').value = item.amount || '';

            if (type === 'offer') {
                const offerFields = document.getElementById('edit-offer-fields');
                if (offerFields) {
                    offerFields.classList.remove('hidden');
                }

                const bidFields = document.getElementById('edit-bid-fields');
                if (bidFields) {
                    bidFields.classList.add('hidden');
                }

                document.getElementById('edit-amm-rate-label').textContent = 'Min Rate';

                document.getElementById('edit-amm-rate').value = item.minrate || '';
                document.getElementById('edit-offer-ratetweakpercent').value = item.ratetweakpercent || '0';
                document.getElementById('edit-offer-min-coin-from-amt').value = item.min_coin_from_amt || '';
                document.getElementById('edit-offer-valid-seconds').value = item.offer_valid_seconds || '3600';
                document.getElementById('edit-offer-address').value = item.address || 'auto';
                document.getElementById('edit-offer-adjust-rates').checked = item.adjust_rates_based_on_market !== false;
                document.getElementById('edit-offer-swap-type').value = item.swap_type || 'adaptor_sig';
                document.getElementById('edit-offer-min-swap-amount').value = item.min_swap_amount || '0.001';
                document.getElementById('edit-offer-amount-step').value = item.amount_step || '';

                const coinFrom = document.getElementById('edit-amm-coin-from');
                const coinTo = document.getElementById('edit-amm-coin-to');
                const swapType = document.getElementById('edit-offer-swap-type');

                if (coinFrom && coinTo && swapType) {
                    updateSwapTypeOptions(coinFrom.value, coinTo.value, swapType);
                }
            } else if (type === 'bid') {
                const offerFields = document.getElementById('edit-offer-fields');
                if (offerFields) {
                    offerFields.classList.add('hidden');
                }

                const bidFields = document.getElementById('edit-bid-fields');
                if (bidFields) {
                    bidFields.classList.remove('hidden');

                    document.getElementById('edit-amm-rate-label').textContent = 'Max Rate';

                    document.getElementById('edit-amm-rate').value = item.max_rate || '';
                    document.getElementById('edit-bid-min-coin-to-balance').value = item.min_coin_to_balance || '';
                    document.getElementById('edit-bid-max-concurrent').value = item.max_concurrent || '1';
                    document.getElementById('edit-bid-address').value = item.address || 'auto';
                    document.getElementById('edit-bid-min-swap-amount').value = item.min_swap_amount || '';
                }
            }

            const modal = document.getElementById('edit-amm-modal');
            if (modal) {
                modal.classList.remove('hidden');
            }
        } catch (error) {
            alert(`Error processing the configuration: ${error.message}`);
            debugLog('Error opening edit modal:', error);
        }
    }

    function closeAllDropdowns() {
        const dropdowns = document.querySelectorAll('.absolute.z-50');
        dropdowns.forEach(dropdown => {
            dropdown.classList.add('hidden');
        });
    }


    function closeEditModal() {
        const modal = document.getElementById('edit-amm-modal');
        if (modal) {
            modal.classList.add('hidden');
            closeAllDropdowns();
        }
    }

    function saveEditedItem() {
        const type = document.getElementById('edit-amm-type').value;
        const id = document.getElementById('edit-amm-id').value;
        const originalName = document.getElementById('edit-amm-original-name').value;

        debugLog(`Saving edited ${type} with id: ${id}, original name: ${originalName}`);

        const configTextarea = document.querySelector('textarea[name="config_content"]');
        if (!configTextarea) {
            alert('Error: Could not find the configuration textarea.');
            return;
        }

        try {
            const configText = configTextarea.value.trim();
            if (!configText) {
                alert('Error: Configuration is empty.');
                return;
            }

            const config = JSON.parse(configText);

            const updatedItem = {
                name: document.getElementById('edit-amm-name').value,
                enabled: document.getElementById('edit-amm-enabled').checked,
                coin_from: document.getElementById('edit-amm-coin-from').value,
                coin_to: document.getElementById('edit-amm-coin-to').value,
                amount: parseFloat(document.getElementById('edit-amm-amount').value),
                amount_variable: true,
            };

            if (id) {
                updatedItem.id = id;
            }

            if (type === 'offer') {
                updatedItem.minrate = parseFloat(document.getElementById('edit-amm-rate').value);
                updatedItem.ratetweakpercent = parseFloat(document.getElementById('edit-offer-ratetweakpercent').value || '0');
                updatedItem.adjust_rates_based_on_market = document.getElementById('edit-offer-adjust-rates').checked;
                updatedItem.swap_type = document.getElementById('edit-offer-swap-type').value || 'adaptor_sig';

                const minCoinFromAmt = document.getElementById('edit-offer-min-coin-from-amt').value;
                if (minCoinFromAmt) {
                    updatedItem.min_coin_from_amt = parseFloat(minCoinFromAmt);
                }

                const validSeconds = document.getElementById('edit-offer-valid-seconds').value;
                if (validSeconds) {
                    const seconds = parseInt(validSeconds);
                    if (seconds < 600) {
                        alert('Offer valid seconds must be at least 600 (10 minutes)');
                        return;
                    }
                    updatedItem.offer_valid_seconds = seconds;
                }

                const address = document.getElementById('edit-offer-address').value;
                if (address) {
                    updatedItem.address = address;
                }

                const minSwapAmount = document.getElementById('edit-offer-min-swap-amount').value;
                if (minSwapAmount) {
                    updatedItem.min_swap_amount = parseFloat(minSwapAmount);
                }

                const amountStep = document.getElementById('edit-offer-amount-step').value;
                if (amountStep) {
                    if (/^[0-9]*\.?[0-9]*$/.test(amountStep)) {
                        const parsedValue = parseFloat(amountStep);
                        if (parsedValue > 0) {
                            updatedItem.amount_step = parsedValue.toString();
                            console.log(`Amount step set to: ${updatedItem.amount_step}`);
                        } else {
                            alert('Amount step must be greater than zero.');
                            return;
                        }
                    } else {
                        alert('Invalid amount step value. Please enter a valid decimal number.');
                        return;
                    }
                }
            } else if (type === 'bid') {
                updatedItem.max_rate = parseFloat(document.getElementById('edit-amm-rate').value);

                const minCoinToBalance = document.getElementById('edit-bid-min-coin-to-balance').value;
                if (minCoinToBalance) {
                    updatedItem.min_coin_to_balance = parseFloat(minCoinToBalance);
                }

                const maxConcurrent = document.getElementById('edit-bid-max-concurrent').value;
                if (maxConcurrent) {
                    updatedItem.max_concurrent = parseInt(maxConcurrent);
                }

                const address = document.getElementById('edit-bid-address').value;
                if (address) {
                    updatedItem.address = address;
                }

                const minSwapAmount = document.getElementById('edit-bid-min-swap-amount').value;
                if (minSwapAmount) {
                    updatedItem.min_swap_amount = parseFloat(minSwapAmount);
                }
            }

            if (type === 'offer' && Array.isArray(config.offers)) {
                const index = config.offers.findIndex(item =>
                    (id && item.id === id) || (!id && item.name === originalName)
                );

                if (index !== -1) {
                    config.offers[index] = updatedItem;
                    debugLog(`Updated offer at index ${index}`);
                } else {
                    alert(`Could not find the offer to update.`);
                    return;
                }
            } else if (type === 'bid' && Array.isArray(config.bids)) {
                const index = config.bids.findIndex(item =>
                    (id && item.id === id) || (!id && item.name === originalName)
                );

                if (index !== -1) {
                    config.bids[index] = updatedItem;
                    debugLog(`Updated bid at index ${index}`);
                } else {
                    alert(`Could not find the bid to update.`);
                    return;
                }
            } else {
                alert(`Error: Invalid type or no ${type}s found in config.`);
                return;
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            closeEditModal();

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton) {
                saveButton.click();
            } else {
                const form = configTextarea.closest('form');
                if (form) {
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'save_config';
                    hiddenInput.value = 'true';
                    form.appendChild(hiddenInput);
                    form.submit();
                } else {
                    alert('Error: Could not save the configuration.');
                }
            }
        } catch (error) {
            alert(`Error processing the configuration: ${error.message}`);
            debugLog('Error saving edited item:', error);
        }
    }

    function deleteAmmItem(type, id, name) {
        debugLog(`Deleting ${type} with id: ${id}, name: ${name}`);

        const configTextarea = document.querySelector('textarea[name="config_content"]');
        if (!configTextarea) {
            alert('Error: Could not find the configuration textarea.');
            return;
        }

        try {
            const configText = configTextarea.value.trim();
            if (!configText) {
                alert('Error: Configuration is empty.');
                return;
            }

            const config = JSON.parse(configText);

            if (type === 'offer' && Array.isArray(config.offers)) {
                const index = config.offers.findIndex(item =>
                    (id && item.id === id) || (!id && item.name === name)
                );

                if (index !== -1) {
                    config.offers.splice(index, 1);
                    debugLog(`Removed offer at index ${index}`);
                } else {
                    alert(`Could not find the offer to delete.`);
                    return;
                }
            } else if (type === 'bid' && Array.isArray(config.bids)) {
                const index = config.bids.findIndex(item =>
                    (id && item.id === id) || (!id && item.name === name)
                );

                if (index !== -1) {
                    config.bids.splice(index, 1);
                    debugLog(`Removed bid at index ${index}`);
                } else {
                    alert(`Could not find the bid to delete.`);
                    return;
                }
            } else {
                alert(`Error: Invalid type or no ${type}s found in config.`);
                return;
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton) {
                saveButton.click();
            } else {

                const form = configTextarea.closest('form');
                if (form) {
                    const hiddenInput = document.createElement('input');
                    hiddenInput.type = 'hidden';
                    hiddenInput.name = 'save_config';
                    hiddenInput.value = 'true';
                    form.appendChild(hiddenInput);
                    form.submit();
                } else {
                    alert('Error: Could not save the configuration.');
                }
            }
        } catch (error) {
            alert(`Error processing the configuration: ${error.message}`);
            debugLog('Error deleting item:', error);
        }
    }

    const adaptor_sig_only_coins = ['6', '9', '8', '7', '13', '18', '17', 'Monero', 'Firo', 'Pivx', 'Dash', 'Namecoin', 'Wownero', 'Zano'];
    const secret_hash_only_coins = ['11', '12', 'Ethereum', 'Dogecoin'];

    function updateSwapTypeOptions(coinFromValue, coinToValue, swapTypeSelect) {
        if (!swapTypeSelect) return;

        coinFromValue = String(coinFromValue);
        coinToValue = String(coinToValue);

        let disableSelect = false;

        if (adaptor_sig_only_coins.includes(coinFromValue) || adaptor_sig_only_coins.includes(coinToValue)) {
            swapTypeSelect.value = 'adaptor_sig';
            disableSelect = true;
        } else if (secret_hash_only_coins.includes(coinFromValue) || secret_hash_only_coins.includes(coinToValue)) {
            swapTypeSelect.value = 'seller_first';
            disableSelect = true;
        } else {
            swapTypeSelect.value = 'adaptor_sig';
            disableSelect = false;
        }

        swapTypeSelect.disabled = disableSelect;

        if (disableSelect) {
            swapTypeSelect.classList.add('bg-gray-200', 'dark:bg-gray-600', 'cursor-not-allowed');
        } else {
            swapTypeSelect.classList.remove('bg-gray-200', 'dark:bg-gray-600', 'cursor-not-allowed');
        }
    }

    function initializeCustomSelects() {
        const coinSelects = [
            document.getElementById('add-amm-coin-from'),
            document.getElementById('add-amm-coin-to'),
            document.getElementById('edit-amm-coin-from'),
            document.getElementById('edit-amm-coin-to')
        ];

        const swapTypeSelects = [
            document.getElementById('add-offer-swap-type'),
            document.getElementById('edit-offer-swap-type')
        ];

        function createCoinDropdown(select) {
            if (!select) return;

            const wrapper = document.createElement('div');
            wrapper.className = 'relative';

            const display = document.createElement('div');
            display.className = 'flex items-center w-full p-2.5 bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white cursor-pointer';

            const icon = document.createElement('img');
            icon.className = 'w-5 h-5 mr-2';
            icon.alt = '';

            const text = document.createElement('span');
            text.className = 'flex-grow';

            const arrow = document.createElement('span');
            arrow.className = 'ml-2';
            arrow.innerHTML = '▼';

            display.appendChild(icon);
            display.appendChild(text);
            display.appendChild(arrow);

            const dropdown = document.createElement('div');
            dropdown.className = 'absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg hidden dark:bg-gray-700 dark:border-gray-600 max-h-60 overflow-y-auto';

            Array.from(select.options).forEach(option => {
                const item = document.createElement('div');
                item.className = 'flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-600 cursor-pointer text-gray-900 dark:text-white';
                item.setAttribute('data-value', option.value);
                item.setAttribute('data-symbol', option.getAttribute('data-symbol') || '');

                const optionIcon = document.createElement('img');
                optionIcon.className = 'w-5 h-5 mr-2';
                optionIcon.src = `/static/images/coins/${getImageFilename(option.value)}`;
                optionIcon.alt = '';

                const optionText = document.createElement('span');
                optionText.textContent = option.textContent.trim();

                item.appendChild(optionIcon);
                item.appendChild(optionText);

                item.addEventListener('click', function() {
                    select.value = this.getAttribute('data-value');

                    text.textContent = optionText.textContent;
                    icon.src = optionIcon.src;

                    dropdown.classList.add('hidden');

                    const event = new Event('change', { bubbles: true });
                    select.dispatchEvent(event);

                    if (select.id === 'add-amm-coin-from' || select.id === 'add-amm-coin-to') {
                        const coinFrom = document.getElementById('add-amm-coin-from');
                        const coinTo = document.getElementById('add-amm-coin-to');
                        const swapType = document.getElementById('add-offer-swap-type');

                        if (coinFrom && coinTo && swapType) {
                            updateSwapTypeOptions(coinFrom.value, coinTo.value, swapType);
                        }
                    } else if (select.id === 'edit-amm-coin-from' || select.id === 'edit-amm-coin-to') {
                        const coinFrom = document.getElementById('edit-amm-coin-from');
                        const coinTo = document.getElementById('edit-amm-coin-to');
                        const swapType = document.getElementById('edit-offer-swap-type');

                        if (coinFrom && coinTo && swapType) {
                            updateSwapTypeOptions(coinFrom.value, coinTo.value, swapType);
                        }
                    }
                });

                dropdown.appendChild(item);
            });

            const selectedOption = select.options[select.selectedIndex];
            text.textContent = selectedOption.textContent.trim();
            icon.src = `/static/images/coins/${getImageFilename(selectedOption.value)}`;

            display.addEventListener('click', function(e) {
                e.stopPropagation();
                dropdown.classList.toggle('hidden');
            });

            document.addEventListener('click', function() {
                dropdown.classList.add('hidden');
            });

            wrapper.appendChild(display);
            wrapper.appendChild(dropdown);
            select.parentNode.insertBefore(wrapper, select);

            select.style.display = 'none';

            select.addEventListener('change', function() {
                const selectedOption = this.options[this.selectedIndex];
                text.textContent = selectedOption.textContent.trim();
                icon.src = `/static/images/coins/${getImageFilename(selectedOption.value)}`;
            });
        }

        function createSwapTypeDropdown(select) {
            if (!select) return;

            const wrapper = document.createElement('div');
            wrapper.className = 'relative';

            const display = document.createElement('div');
            display.className = 'flex items-center w-full p-2.5 bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 dark:bg-gray-700 dark:border-gray-600 dark:text-white cursor-pointer';

            const text = document.createElement('span');
            text.className = 'flex-grow';

            const arrow = document.createElement('span');
            arrow.className = 'ml-2';
            arrow.innerHTML = '▼';

            display.appendChild(text);
            display.appendChild(arrow);

            const dropdown = document.createElement('div');
            dropdown.className = 'absolute z-50 w-full mt-1 bg-white border border-gray-300 rounded-lg shadow-lg hidden dark:bg-gray-700 dark:border-gray-600 max-h-60 overflow-y-auto';

            Array.from(select.options).forEach(option => {
                const item = document.createElement('div');
                item.className = 'flex items-center p-2 hover:bg-gray-100 dark:hover:bg-gray-600 cursor-pointer text-gray-900 dark:text-white';
                item.setAttribute('data-value', option.value);

                const optionText = document.createElement('span');
                const displayText = option.getAttribute('data-desc') || option.textContent.trim();
                optionText.textContent = displayText;

                item.appendChild(optionText);

                item.addEventListener('click', function() {
                    if (select.disabled) return;

                    select.value = this.getAttribute('data-value');
                    text.textContent = displayText;
                    dropdown.classList.add('hidden');

                    const event = new Event('change', { bubbles: true });
                    select.dispatchEvent(event);
                });

                dropdown.appendChild(item);
            });

            const selectedOption = select.options[select.selectedIndex];
            text.textContent = selectedOption.getAttribute('data-desc') || selectedOption.textContent.trim();

            display.addEventListener('click', function(e) {
                if (select.disabled) return;
                e.stopPropagation();
                dropdown.classList.toggle('hidden');
            });

            document.addEventListener('click', function() {
                dropdown.classList.add('hidden');
            });

            wrapper.appendChild(display);
            wrapper.appendChild(dropdown);
            select.parentNode.insertBefore(wrapper, select);

            select.style.display = 'none';

            select.addEventListener('change', function() {
                const selectedOption = this.options[this.selectedIndex];
                text.textContent = selectedOption.getAttribute('data-desc') || selectedOption.textContent.trim();
            });

            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.attributeName === 'disabled') {
                        if (select.disabled) {
                            display.classList.add('bg-gray-200', 'dark:bg-gray-600', 'cursor-not-allowed');
                        } else {
                            display.classList.remove('bg-gray-200', 'dark:bg-gray-600', 'cursor-not-allowed');
                        }
                    }
                });
            });

            observer.observe(select, { attributes: true });

            if (select.disabled) {
                display.classList.add('bg-gray-200', 'dark:bg-gray-600', 'cursor-not-allowed');
            }
        }

        coinSelects.forEach(select => createCoinDropdown(select));

        swapTypeSelects.forEach(select => createSwapTypeDropdown(select));
    }

    function getRateFromCoinGecko(coinFromSelect, coinToSelect, rateInput) {
        const coinFromOption = coinFromSelect.options[coinFromSelect.selectedIndex];
        const coinToOption = coinToSelect.options[coinToSelect.selectedIndex];

        if (!coinFromOption || !coinToOption) {
            alert('Coins from and to must be set first.');
            return;
        }

        const coinFromSymbol = coinFromOption.getAttribute('data-symbol');
        const coinToSymbol = coinToOption.getAttribute('data-symbol');

        if (!coinFromSymbol || !coinToSymbol) {
            alert('Coin symbols not found.');
            return;
        }

        const originalValue = rateInput.value;
        rateInput.value = 'Loading...';
        rateInput.disabled = true;

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/json/rates');
        xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        xhr.onload = function() {
            if (xhr.status === 200) {
                try {
                    const response = JSON.parse(xhr.responseText);
                    debugLog('Rate response:', response);

                    if (response.coingecko && response.coingecko.rate_inferred) {
                        rateInput.value = response.coingecko.rate_inferred;
                    } else if (response.error) {
                        console.error('API error:', response.error);
                        rateInput.value = originalValue || '';
                        alert('Error: ' + response.error);
                    } else if (response.coingecko_error) {
                        console.error('CoinGecko error:', response.coingecko_error);
                        rateInput.value = originalValue || '';
                        alert('Unable to get rate from CoinGecko: ' + response.coingecko_error);
                    } else {
                        rateInput.value = originalValue || '';
                        alert('No rate available from CoinGecko for this pair.');
                    }
                } catch (e) {
                    console.error('Error parsing rate data:', e);
                    rateInput.value = originalValue || '';
                    alert('Error retrieving rate information. Please try again later.');
                }
            } else {
                console.error('Error fetching rate data:', xhr.status, xhr.statusText);
                rateInput.value = originalValue || '';
                alert(`Unable to retrieve rate information (HTTP ${xhr.status}). The rate service may be unavailable.`);
            }
            rateInput.disabled = false;
        };
        xhr.onerror = function(e) {
            console.error('Network error when fetching rate data:', e);
            rateInput.value = originalValue || '';
            rateInput.disabled = false;
            alert('Unable to connect to the rate service. Please check your network connection and try again.');
        };

        const params = `coin_from=${encodeURIComponent(coinFromSymbol)}&coin_to=${encodeURIComponent(coinToSymbol)}`;
        debugLog('Sending rate request with params:', params);
        xhr.send(params);
    }

    function setupRateButtons() {
        const addGetRateButton = document.getElementById('add-get-rate-button');
        if (addGetRateButton) {
            addGetRateButton.addEventListener('click', function() {
                const coinFromSelect = document.getElementById('add-amm-coin-from');
                const coinToSelect = document.getElementById('add-amm-coin-to');
                const rateInput = document.getElementById('add-amm-rate');

                if (coinFromSelect && coinToSelect && rateInput) {
                    getRateFromCoinGecko(coinFromSelect, coinToSelect, rateInput);
                } else {
                    console.error('Missing required elements for rate lookup');
                }
            });
        }

        const editGetRateButton = document.getElementById('edit-get-rate-button');
        if (editGetRateButton) {
            editGetRateButton.addEventListener('click', function() {
                const coinFromSelect = document.getElementById('edit-amm-coin-from');
                const coinToSelect = document.getElementById('edit-amm-coin-to');
                const rateInput = document.getElementById('edit-amm-rate');

                if (coinFromSelect && coinToSelect && rateInput) {
                    getRateFromCoinGecko(coinFromSelect, coinToSelect, rateInput);
                } else {
                    console.error('Missing required elements for rate lookup');
                }
            });
        }
    }

    function initialize(options = {}) {
        Object.assign(config, options);

        initializeTabs();
        setupButtonHandlers();
        initializeCustomSelects();
        setupRateButtons();

        if (refreshButton) {
            refreshButton.addEventListener('click', function() {
                updateTables();
            });
        }

        setupConfigFormListener();
        updateTables();
        startRefreshTimer();

        debugLog('AMM Tables Manager initialized');

        return {
            updateTables,
            startRefreshTimer,
            stopRefreshTimer
        };
    }

    return {
        initialize
    };
})();

document.addEventListener('DOMContentLoaded', function() {
    if (typeof AmmTablesManager !== 'undefined') {
        window.ammTablesManager = AmmTablesManager.initialize();
    }
});
