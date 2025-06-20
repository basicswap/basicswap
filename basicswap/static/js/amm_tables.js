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
        // if (isDebugEnabled()) {
        //     if (data) {
        //         console.log(`[AmmTables] ${message}`, data);
        //     } else {
        //         console.log(`[AmmTables] ${message}`);
        //     }
        // }
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

        const icon = window.CoinManager.getCoinIcon(coinSymbol);
        debugLog(`CoinManager returned icon: ${icon} for ${coinSymbol}`);
        return icon || 'Unknown.png';
    }

    function getCoinDisplayName(coinId) {
        if (config.debug) {
            console.log('[AMM Tables] getCoinDisplayName called with:', coinId, typeof coinId);
        }

        if (typeof coinId === 'string') {
            const lowerCoinId = coinId.toLowerCase();

            if (lowerCoinId === 'part_anon' ||
                lowerCoinId === 'particl_anon' ||
                lowerCoinId === 'particl anon') {
                if (config.debug) {
                    console.log('[AMM Tables] Matched Particl Anon variant:', coinId);
                }
                return 'Particl Anon';
            }

            if (lowerCoinId === 'part_blind' ||
                lowerCoinId === 'particl_blind' ||
                lowerCoinId === 'particl blind') {
                if (config.debug) {
                    console.log('[AMM Tables] Matched Particl Blind variant:', coinId);
                }
                return 'Particl Blind';
            }

            if (lowerCoinId === 'ltc_mweb' ||
                lowerCoinId === 'litecoin_mweb' ||
                lowerCoinId === 'litecoin mweb') {
                if (config.debug) {
                    console.log('[AMM Tables] Matched Litecoin MWEB variant:', coinId);
                }
                return 'Litecoin MWEB';
            }
        }

        if (window.CoinManager && window.CoinManager.getDisplayName) {
            const displayName = window.CoinManager.getDisplayName(coinId);
            if (displayName) {
                if (config.debug) {
                    console.log('[AMM Tables] CoinManager returned:', displayName);
                }
                return displayName;
            }
        }

        if (config.debug) {
            console.log('[AMM Tables] Returning coin name as-is:', coinId);
        }
        return coinId;
    }

    function createSwapColumn(coinFrom, coinTo) {
        const fromImage = getImageFilename(coinFrom);
        const toImage = getImageFilename(coinTo);
        const fromDisplayName = getCoinDisplayName(coinFrom);
        const toDisplayName = getCoinDisplayName(coinTo);

        return `
            <td class="py-0 px-0 text-right text-sm">
                <div class="flex items-center justify-center monospace">
                    <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${fromImage}" alt="${fromDisplayName}">
                    </span>
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${toImage}" alt="${toDisplayName}">
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
                    <td colspan="7" class="py-8 px-4 text-center text-gray-500 dark:text-gray-400">
                        <div class="flex flex-col items-center justify-center">
                            <svg class="w-12 h-12 mb-4 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            <p class="text-lg font-medium">No offers configured</p>
                            <p class="text-sm text-gray-400 dark:text-gray-500 mt-1">Edit the AMM configuration to add offers</p>
                        </div>
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
            const adjustRatesValue = offer.adjust_rates_based_on_market || 'false';
            const adjustRates = adjustRatesValue !== 'false';
            const amountStep = offer.amount_step || 'N/A';

            const amountToReceive = amount * minrate;

            const activeOffersCount = activeOffers[name] && Array.isArray(activeOffers[name]) ?
                activeOffers[name].length : 0;

            tableHtml += `
                <tr class="relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600">
                    <td class="py-3 pl-4 text-center">
                        <div class="font-medium">${name}</div>
                    </td>
                    ${createSwapColumn(coinFrom, coinTo)}
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${coinFrom == "Bitcoin" ? amount.toFixed(8) : amount.toFixed(4)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-300">${getCoinDisplayName(coinFrom)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Min bal: ${coinFrom == "Bitcoin" ? minCoinFromAmt.toFixed(8) : minCoinFromAmt.toFixed(4)}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-right">
                        <div class="text-xs font-semibold dark:text-white">${minrate.toFixed(8)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300">
                            Tweak: ${rateTweakPercent > 0 ? '+' : ''}${rateTweakPercent}%
                        </div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Receive: ~${(amountToReceive * (rateTweakPercent / 100 + 1)).toFixed(4)} ${getCoinDisplayName(coinTo)}
                            ${(() => {
                                const usdValue = calculateUSDPrice(amountToReceive, coinTo);
                                return usdValue ? `<br/><span class="text-green-600 dark:text-green-400">${formatUSDPrice(usdValue)}</span>` : '<br/><span class="text-gray-400">USD: N/A</span>';
                            })()}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="space-y-1">
                            <div class="flex flex-wrap gap-1 justify-center">
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${amountVariable ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                    ${amountVariable ? 'Variable' : 'Fixed'}
                                </span>
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                                    <svg class="w-3 h-3 mr-1 text-gray-600 dark:text-gray-300" fill="currentColor" viewBox="0 0 20 20">
                                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"></path>
                                    </svg>
                                    ${formatDuration(offerValidSeconds)}
                                </span>
                            </div>
                            <div class="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full ${adjustRatesValue != 'static' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"></path>
                                </svg>
                                Rates: ${adjustRatesValue === 'static'  ? 'Static'
                                       : adjustRatesValue === 'only'    ? 'Market'
                                       : adjustRatesValue === 'minrate' ? 'Market (fallback)'
                                       : adjustRatesValue === 'false'   ? 'CoinGecko'
                                       : adjustRatesValue === 'all'     ? 'Auto (all)'
                                       : adjustRates                    ? 'Auto (any)'
                                       : 'Off'}
                            </div>
                            <div class="inline-flex items-center px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300">
                                <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clip-rule="evenodd"></path>
                                </svg>
                                Step: ${amountStep}
                            </div>
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
                            <button type="button" class="edit-amm-item text-gray-500 hover:text-gray-700 dark:text-white dark:hover:text-gray-300 focus:ring-0 focus:outline-none"
                                data-type="offer" data-id="${offer.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"></path>
                                </svg>
                            </button>
                            <button type="button" class="delete-amm-item text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 focus:ring-0 focus:outline-none"
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
                    <td colspan="7" class="py-8 px-4 text-center text-gray-500 dark:text-gray-400">
                        <div class="flex flex-col items-center justify-center">
                            <svg class="w-12 h-12 mb-4 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                            </svg>
                            <p class="text-lg font-medium">No bids configured</p>
                            <p class="text-sm text-gray-400 dark:text-gray-500 mt-1">Edit the AMM configuration to add bids</p>
                        </div>
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
            const useBalanceBidding = bid.use_balance_bidding !== undefined ? bid.use_balance_bidding : false;

            tableHtml += `
                <tr class="relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600">
                    <td class="py-3 px-4">
                        <div class="font-medium">${name}</div>
                    </td>
                    ${createSwapColumn(coinTo, coinFrom)}
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${amount.toFixed(8)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-300">${getCoinDisplayName(coinFrom)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Min ${getCoinDisplayName(coinTo)} Balance: ${minCoinToBalance.toFixed(8)}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-right">
                        <div class="text-sm font-semibold dark:text-white">${maxRate.toFixed(8)}</div>
                        <div class="text-xs text-gray-500 dark:text-gray-300 mt-1">
                            Send: ~${amountToSend.toFixed(8)} ${getCoinDisplayName(coinTo)}
                            ${(() => {
                                const usdValue = calculateUSDPrice(amountToSend, coinTo);
                                return usdValue ? `<br/><span class="text-red-600 dark:text-red-400">${formatUSDPrice(usdValue)}</span>` : '<br/><span class="text-gray-400">USD: N/A</span>';
                            })()}
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="space-y-1">
                            <div class="flex flex-wrap gap-1 justify-center">
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${amountVariable ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                    ${amountVariable ? 'Variable' : 'Fixed'}
                                </span>
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                                    Max: ${maxConcurrent}
                                </span>
                                ${useBalanceBidding ? `
                                <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300">
                                    Balance Bidding
                                </span>
                                ` : ''}
                            </div>
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
                                ${activeBidsCount > 0
                                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
                                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'}">
                                ${activeBidsCount} Running Bid${activeBidsCount !== 1 ? 's' : ''}
                            </span>
                        </div>
                    </td>
                    <td class="py-3 px-4 text-center">
                        <div class="flex items-center justify-center space-x-2">
                            <button type="button" class="edit-amm-item text-gray-500 hover:text-gray-700 dark:text-white dark:hover:text-gray-300 focus:ring-0 focus:outline-none"
                                data-type="bid" data-id="${bid.id || ''}" data-name="${name}">
                                <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                    <path d="M13.586 3.586a2 2 0 112.828 2.828l-.793.793-2.828-2.828.793-.793zM11.379 5.793L3 14.172V17h2.828l8.38-8.379-2.83-2.828z"></path>
                                </svg>
                            </button>
                            <button type="button" class="delete-amm-item text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 focus:ring-0 focus:outline-none"
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

    function getPriceKey(coin) {
        if (!coin) return null;

        const lowerCoin = coin.toLowerCase();

        const coinToTicker = {
            'particl': 'PART',
            'particl anon': 'PART',
            'particl blind': 'PART',
            'part': 'PART',
            'part anon': 'PART',
            'part blind': 'PART',
            'bitcoin': 'BTC',
            'btc': 'BTC',
            'bitcoin cash': 'BCH',
            'bitcoincash': 'BCH',
            'bch': 'BCH',
            'decred': 'DCR',
            'dcr': 'DCR',
            'dogecoin': 'DOGE',
            'doge': 'DOGE',
            'monero': 'XMR',
            'xmr': 'XMR',
            'litecoin': 'LTC',
            'ltc': 'LTC',
            'namecoin': 'NMC',
            'nmc': 'NMC',
            'wownero': 'WOW',
            'wow': 'WOW',
            'dash': 'DASH',
            'pivx': 'PIVX',
            'firo': 'FIRO',
            'xzc': 'FIRO',
            'zcoin': 'FIRO',
            'BTC': 'BTC',
            'BCH': 'BCH',
            'DCR': 'DCR',
            'DOGE': 'DOGE',
            'LTC': 'LTC',
            'NMC': 'NMC',
            'XMR': 'XMR',
            'PART': 'PART',
            'WOW': 'WOW',
            'FIRO': 'FIRO',
            'DASH': 'DASH',
            'PIVX': 'PIVX'
        };

        if (coinToTicker[lowerCoin]) {
            return coinToTicker[lowerCoin];
        }

        if (coinToTicker[coin.toUpperCase()]) {
            return coinToTicker[coin.toUpperCase()];
        }

        for (const [key, value] of Object.entries(coinToTicker)) {
            if (lowerCoin.includes(key.toLowerCase())) {
                return value;
            }
        }

        if (lowerCoin.includes('particl') || lowerCoin.includes('part')) {
            return 'PART';
        }

        return coin.toUpperCase();
    }

    function calculateUSDPrice(amount, coinName) {
        if (!window.latestPrices || !coinName || !amount) {
            return null;
        }

        const ticker = getPriceKey(coinName);
        let coinPrice = null;

        if (typeof window.latestPrices[ticker] === 'number') {
            coinPrice = window.latestPrices[ticker];
        }

        else if (typeof window.latestPrices[coinName] === 'number') {
            coinPrice = window.latestPrices[coinName];
        }

        else if (typeof window.latestPrices[coinName.toUpperCase()] === 'number') {
            coinPrice = window.latestPrices[coinName.toUpperCase()];
        }


        if (!coinPrice || isNaN(coinPrice)) {
            return null;
        }

        return amount * coinPrice;
    }

    function formatUSDPrice(usdValue) {
        if (!usdValue || isNaN(usdValue)) return '';
        return `($${usdValue.toFixed(2)} USD)`;
    }

    async function fetchLatestPrices() {
        try {
            const coins = 'BTC,BCH,DCR,DOGE,LTC,NMC,XMR,PART,WOW,FIRO,DASH,PIVX';

            const response = await fetch('/json/coinprices', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `coins=${encodeURIComponent(coins)}&currency_to=USD&source=coingecko.com&match_input_key=true`
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();

            if (data && data.rates) {
                return data.rates;
            }
            return data;
        } catch (error) {
            console.error('Error fetching prices:', error);
            return null;
        }
    }

    async function initializePrices() {

        if (window.priceManager && typeof window.priceManager.getLatestPrices === 'function') {
            const prices = window.priceManager.getLatestPrices();
            if (prices && Object.keys(prices).length > 0) {
                window.latestPrices = prices;
                setTimeout(() => {
                    updateTables();
                }, 100);
                return;
            }
        }

        const prices = await fetchLatestPrices();
        if (prices) {
            window.latestPrices = prices;
            setTimeout(() => {
                updateTables();
            }, 100);
        }
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
                    if (window.showErrorModal) {
                        window.showErrorModal('Error', 'Could not identify the item to delete.');
                    } else {
                        alert('Error: Could not identify the item to delete.');
                    }
                    return;
                }

                if (window.showConfirmModal) {
                    window.showConfirmModal(
                        'Confirm Deletion',
                        `Are you sure you want to delete this ${type}?\n\nName: ${name || 'Unnamed'}\n\nThis action cannot be undone.`,
                        function() {
                            deleteAmmItem(type, id, name);
                        }
                    );
                } else {
                    if (confirm(`Are you sure you want to delete this ${type}?`)) {
                        deleteAmmItem(type, id, name);
                    }
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

        const coinFromCheck = document.getElementById('add-amm-coin-from');
        const coinToCheck = document.getElementById('add-amm-coin-to');

        if (!coinFromCheck || !coinToCheck || coinFromCheck.options.length < 2 || coinToCheck.options.length < 2) {
            if (window.showErrorModal) {
                window.showErrorModal('Configuration Error', 'At least 2 different coins must be configured in BasicSwap to create AMM offers/bids. Please configure additional coins first.');
            } else {
                alert('At least 2 different coins must be configured in BasicSwap to create AMM offers/bids. Please configure additional coins first.');
            }
            return;
        }

        const modalTitle = document.getElementById('add-modal-title');
        if (modalTitle) {
            modalTitle.textContent = `Add New ${type.charAt(0).toUpperCase() + type.slice(1)}`;
        }

        document.getElementById('add-amm-type').value = type;

        document.getElementById('add-amm-name').value = 'Unnamed Offer';
        document.getElementById('add-amm-enabled').checked = true;

        const coinFromSelect = document.getElementById('add-amm-coin-from');
        const coinToSelect = document.getElementById('add-amm-coin-to');

        if (coinFromSelect && coinFromSelect.options.length > 0) {
            coinFromSelect.selectedIndex = 0;
            coinFromSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }

        if (coinToSelect && coinToSelect.options.length > 1) {
            coinToSelect.selectedIndex = 1;
            coinToSelect.dispatchEvent(new Event('change', { bubbles: true }));
        } else if (coinToSelect && coinToSelect.options.length > 0) {
            coinToSelect.selectedIndex = 0;
            coinToSelect.dispatchEvent(new Event('change', { bubbles: true }));
        }

        document.getElementById('add-amm-amount').value = '';

        const adjustRatesSelect = document.getElementById('add-offer-adjust-rates');
        if (adjustRatesSelect) {
            adjustRatesSelect.value = 'false';
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

            document.getElementById('add-amm-rate-label').textContent = 'Minimum Rate';
            document.getElementById('add-amm-rate').value = '0.0001';
            document.getElementById('add-offer-ratetweakpercent').value = '0';
            document.getElementById('add-offer-min-coin-from-amt').value = '';
            document.getElementById('add-offer-valid-seconds').value = '3600';
            document.getElementById('add-offer-address').value = 'auto';
            document.getElementById('add-offer-min-swap-amount').value = '0.001';
            document.getElementById('add-offer-amount-step').value = '0.001';

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

        if (coinFromSelect && coinToSelect) {
            const handleCoinChange = function() {
                const fromValue = coinFromSelect.value;
                const toValue = coinToSelect.value;

                if (fromValue && toValue && fromValue === toValue) {
                    for (let i = 0; i < coinToSelect.options.length; i++) {
                        if (coinToSelect.options[i].value !== fromValue) {
                            coinToSelect.selectedIndex = i;
                            break;
                        }
                    }
                }
            };

            coinFromSelect.addEventListener('change', handleCoinChange);
            coinToSelect.addEventListener('change', handleCoinChange);
        }

        if (type === 'offer') {
            setupBiddingControls('add');
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

            const name = document.getElementById('add-amm-name').value.trim();

            if (!name || name === '') {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Name is required and cannot be empty.');
                } else {
                    alert('Name is required and cannot be empty.');
                }
                return;
            }

            const coinFrom = document.getElementById('add-amm-coin-from').value;
            const coinTo = document.getElementById('add-amm-coin-to').value;

            if (!coinFrom || !coinTo) {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Please select both Coin From and Coin To.');
                } else {
                    alert('Please select both Coin From and Coin To.');
                }
                return;
            }

            if (coinFrom === coinTo) {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Coin From and Coin To must be different.');
                } else {
                    alert('Coin From and Coin To must be different.');
                }
                return;
            }

            const newItem = {
                id: uniqueId,
                name: name,
                enabled: document.getElementById('add-amm-enabled').checked,
                coin_from: document.getElementById('add-amm-coin-from').value,
                coin_to: document.getElementById('add-amm-coin-to').value,
                amount: parseFloat(document.getElementById('add-amm-amount').value),
                amount_variable: true
            };

            if (type === 'offer') {
                newItem.minrate = parseFloat(document.getElementById('add-amm-rate').value);
                newItem.ratetweakpercent = parseFloat(document.getElementById('add-offer-ratetweakpercent').value || '0');
                newItem.adjust_rates_based_on_market = document.getElementById('add-offer-adjust-rates').value;
                newItem.swap_type = document.getElementById('add-offer-swap-type').value || 'adaptor_sig';
                const automationStrategyElement = document.getElementById('add-offer-automation-strategy');
                newItem.automation_strategy = automationStrategyElement ? automationStrategyElement.value : 'accept_all';

                const minCoinFromAmt = document.getElementById('add-offer-min-coin-from-amt').value;
                if (minCoinFromAmt) {
                    newItem.min_coin_from_amt = parseFloat(minCoinFromAmt);
                }

                const validSeconds = document.getElementById('add-offer-valid-seconds').value;
                if (validSeconds) {
                    const seconds = parseInt(validSeconds);
                    if (seconds < 600) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer valid seconds must be at least 600 (10 minutes)');
                        } else {
                            alert('Offer valid seconds must be at least 600 (10 minutes)');
                        }
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
                const offerAmount = parseFloat(document.getElementById('add-amm-amount').value);

                if (!amountStep || amountStep.trim() === '') {
                    if (window.showErrorModal) {
                        window.showErrorModal('Validation Error', 'Offer Size Increment is required. This privacy feature prevents revealing your exact wallet balance.');
                    } else {
                        alert('Offer Size Increment is required. This privacy feature prevents revealing your exact wallet balance.');
                    }
                    return;
                }

                if (/^[0-9]*\.?[0-9]*$/.test(amountStep)) {
                    const parsedValue = parseFloat(amountStep);
                    if (parsedValue <= 0) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer Size Increment must be greater than zero.');
                        } else {
                            alert('Offer Size Increment must be greater than zero.');
                        }
                        return;
                    }
                    if (parsedValue < 0.001) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer Size Increment must be at least 0.001.');
                        } else {
                            alert('Offer Size Increment must be at least 0.001.');
                        }
                        return;
                    }
                    if (parsedValue > offerAmount) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', `Offer Size Increment (${parsedValue}) cannot be greater than the offer amount (${offerAmount}).`);
                        } else {
                            alert(`Offer Size Increment (${parsedValue}) cannot be greater than the offer amount (${offerAmount}).`);
                        }
                        return;
                    }
                    newItem.amount_step = parsedValue.toString();
                    console.log(`Offer Size Increment set to: ${newItem.amount_step}`);
                } else {
                    if (window.showErrorModal) {
                        window.showErrorModal('Validation Error', 'Invalid Offer Size Increment value. Please enter a valid decimal number.');
                    } else {
                        alert('Invalid Offer Size Increment value. Please enter a valid decimal number.');
                    }
                    return;
                }

                const attemptBidsFirst = document.getElementById('add-offer-attempt-bids-first');
                if (attemptBidsFirst && attemptBidsFirst.checked) {
                    newItem.attempt_bids_first = true;

                    const bidStrategy = document.getElementById('add-offer-bid-strategy').value;
                    if (bidStrategy) {
                        newItem.bid_strategy = bidStrategy;
                    }

                    const maxBidPercentage = document.getElementById('add-offer-max-bid-percentage').value;
                    if (maxBidPercentage) {
                        newItem.max_bid_percentage = parseInt(maxBidPercentage);
                    }

                    const bidRateTolerance = document.getElementById('add-offer-bid-rate-tolerance').value;
                    if (bidRateTolerance) {
                        newItem.bid_rate_tolerance = parseFloat(bidRateTolerance);
                    }

                    const minRemainingOffer = document.getElementById('add-offer-min-remaining-offer').value;
                    if (minRemainingOffer) {
                        newItem.min_remaining_offer = parseFloat(minRemainingOffer);
                    }
                }
            } else if (type === 'bid') {
                newItem.max_rate = parseFloat(document.getElementById('add-amm-rate').value);
                newItem.offers_to_bid_on = document.getElementById('add-bid-offers-to-bid-on').value || 'all';

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

                const useBalanceBidding = document.getElementById('add-bid-use-balance-bidding').checked;
                if (useBalanceBidding) {
                    newItem.use_balance_bidding = true;
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
                if (window.showErrorModal) {
                    window.showErrorModal('Error', `Invalid type ${type}`);
                } else {
                    alert(`Error: Invalid type ${type}`);
                }
                return;
            }

            const wasReadonly = configTextarea.hasAttribute('readonly');
            if (wasReadonly) {
                configTextarea.removeAttribute('readonly');
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            closeAddModal();

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton && !saveButton.disabled) {
                saveButton.click();

                setTimeout(() => {
                    if (window.AmmCounterManager && window.AmmCounterManager.fetchAmmStatus) {
                        window.AmmCounterManager.fetchAmmStatus();
                    }
                    if (window.SummaryManager && window.SummaryManager.fetchSummaryData) {
                        window.SummaryManager.fetchSummaryData();
                    }
                }, 1000);
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
                    if (window.showErrorModal) {
                        window.showErrorModal('Error', 'Could not save the configuration. Please try using the Settings tab instead.');
                    } else {
                        alert('Error: Could not save the configuration.');
                    }
                }
            }

            if (wasReadonly) {
                configTextarea.setAttribute('readonly', '');
            }
        } catch (error) {
            if (window.showErrorModal) {
                window.showErrorModal('Configuration Error', `Error processing the configuration: ${error.message}`);
            } else {
                alert(`Error processing the configuration: ${error.message}`);
            }
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

                document.getElementById('edit-amm-rate').value = item.minrate || '';
                document.getElementById('edit-offer-ratetweakpercent').value = item.ratetweakpercent || '0';
                document.getElementById('edit-offer-min-coin-from-amt').value = item.min_coin_from_amt || '';
                document.getElementById('edit-offer-valid-seconds').value = item.offer_valid_seconds || '3600';
                document.getElementById('edit-offer-address').value = item.address || 'auto';
                document.getElementById('edit-offer-adjust-rates').value = item.adjust_rates_based_on_market || 'false';
                document.getElementById('edit-offer-swap-type').value = item.swap_type || 'adaptor_sig';
                document.getElementById('edit-offer-min-swap-amount').value = item.min_swap_amount || '0.001';
                document.getElementById('edit-offer-amount-step').value = item.amount_step || '0.001';
                const editAutomationStrategyElement = document.getElementById('edit-offer-automation-strategy');
                if (editAutomationStrategyElement) {
                    editAutomationStrategyElement.value = item.automation_strategy || 'accept_all';
                }

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
                    document.getElementById('edit-bid-offers-to-bid-on').value = item.offers_to_bid_on || 'all';
                    document.getElementById('edit-bid-use-balance-bidding').checked = item.use_balance_bidding || false;
                }
            }

            const editCoinFromSelect = coinFromSelect;
            const editCoinToSelect = coinToSelect;

            if (editCoinFromSelect && editCoinToSelect) {
                const handleEditCoinChange = function() {
                    const fromValue = editCoinFromSelect.value;
                    const toValue = editCoinToSelect.value;

                    if (fromValue && toValue && fromValue === toValue) {
                        for (let i = 0; i < editCoinToSelect.options.length; i++) {
                            if (editCoinToSelect.options[i].value !== fromValue) {
                                editCoinToSelect.selectedIndex = i;
                                break;
                            }
                        }
                    }
                };

                editCoinFromSelect.removeEventListener('change', handleEditCoinChange);
                editCoinToSelect.removeEventListener('change', handleEditCoinChange);

                editCoinFromSelect.addEventListener('change', handleEditCoinChange);
                editCoinToSelect.addEventListener('change', handleEditCoinChange);
            }

            if (type === 'offer') {
                setupBiddingControls('edit');
                populateBiddingControls('edit', item);
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

            const name = document.getElementById('edit-amm-name').value.trim();

            if (!name || name === '') {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Name is required and cannot be empty.');
                } else {
                    alert('Name is required and cannot be empty.');
                }
                return;
            }

            const coinFrom = document.getElementById('edit-amm-coin-from').value;
            const coinTo = document.getElementById('edit-amm-coin-to').value;

            if (!coinFrom || !coinTo) {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Please select both Coin From and Coin To.');
                } else {
                    alert('Please select both Coin From and Coin To.');
                }
                return;
            }

            if (coinFrom === coinTo) {
                if (window.showErrorModal) {
                    window.showErrorModal('Validation Error', 'Coin From and Coin To must be different.');
                } else {
                    alert('Coin From and Coin To must be different.');
                }
                return;
            }

            const updatedItem = {
                name: name,
                enabled: document.getElementById('edit-amm-enabled').checked,
                coin_from: document.getElementById('edit-amm-coin-from').value,
                coin_to: document.getElementById('edit-amm-coin-to').value,
                amount: parseFloat(document.getElementById('edit-amm-amount').value),
                amount_variable: true
            };

            if (id) {
                updatedItem.id = id;
            }

            if (type === 'offer') {
                updatedItem.minrate = parseFloat(document.getElementById('edit-amm-rate').value);
                updatedItem.ratetweakpercent = parseFloat(document.getElementById('edit-offer-ratetweakpercent').value || '0');
                updatedItem.adjust_rates_based_on_market = document.getElementById('edit-offer-adjust-rates').value;
                updatedItem.swap_type = document.getElementById('edit-offer-swap-type').value || 'adaptor_sig';
                const editAutomationStrategyElement = document.getElementById('edit-offer-automation-strategy');
                updatedItem.automation_strategy = editAutomationStrategyElement ? editAutomationStrategyElement.value : 'accept_all';

                const minCoinFromAmt = document.getElementById('edit-offer-min-coin-from-amt').value;
                if (minCoinFromAmt) {
                    updatedItem.min_coin_from_amt = parseFloat(minCoinFromAmt);
                }

                const validSeconds = document.getElementById('edit-offer-valid-seconds').value;
                if (validSeconds) {
                    const seconds = parseInt(validSeconds);
                    if (seconds < 600) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer valid seconds must be at least 600 (10 minutes)');
                        } else {
                            alert('Offer valid seconds must be at least 600 (10 minutes)');
                        }
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
                const offerAmount = parseFloat(document.getElementById('edit-amm-amount').value);

                if (!amountStep || amountStep.trim() === '') {
                    if (window.showErrorModal) {
                        window.showErrorModal('Validation Error', 'Offer Size Increment is required. This privacy feature prevents revealing your exact wallet balance.');
                    } else {
                        alert('Offer Size Increment is required. This privacy feature prevents revealing your exact wallet balance.');
                    }
                    return;
                }

                if (/^[0-9]*\.?[0-9]*$/.test(amountStep)) {
                    const parsedValue = parseFloat(amountStep);
                    if (parsedValue <= 0) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer Size Increment must be greater than zero.');
                        } else {
                            alert('Offer Size Increment must be greater than zero.');
                        }
                        return;
                    }
                    if (parsedValue < 0.001) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', 'Offer Size Increment must be at least 0.001.');
                        } else {
                            alert('Offer Size Increment must be at least 0.001.');
                        }
                        return;
                    }
                    if (parsedValue > offerAmount) {
                        if (window.showErrorModal) {
                            window.showErrorModal('Validation Error', `Offer Size Increment (${parsedValue}) cannot be greater than the offer amount (${offerAmount}).`);
                        } else {
                            alert(`Offer Size Increment (${parsedValue}) cannot be greater than the offer amount (${offerAmount}).`);
                        }
                        return;
                    }
                    updatedItem.amount_step = parsedValue.toString();
                    console.log(`Offer Size Increment set to: ${updatedItem.amount_step}`);
                } else {
                    if (window.showErrorModal) {
                        window.showErrorModal('Validation Error', 'Invalid Offer Size Increment value. Please enter a valid decimal number.');
                    } else {
                        alert('Invalid Offer Size Increment value. Please enter a valid decimal number.');
                    }
                    return;
                }

                const attemptBidsFirst = document.getElementById('edit-offer-attempt-bids-first');
                if (attemptBidsFirst && attemptBidsFirst.checked) {
                    updatedItem.attempt_bids_first = true;

                    const bidStrategy = document.getElementById('edit-offer-bid-strategy').value;
                    if (bidStrategy) {
                        updatedItem.bid_strategy = bidStrategy;
                    }

                    const maxBidPercentage = document.getElementById('edit-offer-max-bid-percentage').value;
                    if (maxBidPercentage) {
                        updatedItem.max_bid_percentage = parseInt(maxBidPercentage);
                    }

                    const bidRateTolerance = document.getElementById('edit-offer-bid-rate-tolerance').value;
                    if (bidRateTolerance) {
                        updatedItem.bid_rate_tolerance = parseFloat(bidRateTolerance);
                    }

                    const minRemainingOffer = document.getElementById('edit-offer-min-remaining-offer').value;
                    if (minRemainingOffer) {
                        updatedItem.min_remaining_offer = parseFloat(minRemainingOffer);
                    }
                } else {
                    updatedItem.attempt_bids_first = false;
                }
            } else if (type === 'bid') {
                updatedItem.max_rate = parseFloat(document.getElementById('edit-amm-rate').value);
                updatedItem.offers_to_bid_on = document.getElementById('edit-bid-offers-to-bid-on').value || 'all';

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

                const useBalanceBidding = document.getElementById('edit-bid-use-balance-bidding').checked;
                if (useBalanceBidding) {
                    updatedItem.use_balance_bidding = true;
                } else {
                    delete updatedItem.use_balance_bidding;
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

            const wasReadonly = configTextarea.hasAttribute('readonly');
            if (wasReadonly) {
                configTextarea.removeAttribute('readonly');
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            closeEditModal();

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton && !saveButton.disabled) {
                saveButton.click();

                setTimeout(() => {
                    if (window.AmmCounterManager && window.AmmCounterManager.fetchAmmStatus) {
                        window.AmmCounterManager.fetchAmmStatus();
                    }
                    if (window.SummaryManager && window.SummaryManager.fetchSummaryData) {
                        window.SummaryManager.fetchSummaryData();
                    }
                }, 1000);
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
                    if (window.showErrorModal) {
                        window.showErrorModal('Error', 'Could not save the configuration. Please try using the Settings tab instead.');
                    } else {
                        alert('Error: Could not save the configuration.');
                    }
                }
            }

            if (wasReadonly) {
                configTextarea.setAttribute('readonly', '');
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

            const wasReadonly = configTextarea.hasAttribute('readonly');
            if (wasReadonly) {
                configTextarea.removeAttribute('readonly');
            }

            configTextarea.value = JSON.stringify(config, null, 4);

            const saveButton = document.getElementById('save_config_btn');
            if (saveButton && !saveButton.disabled) {
                saveButton.click();

                setTimeout(() => {
                    if (window.AmmCounterManager && window.AmmCounterManager.fetchAmmStatus) {
                        window.AmmCounterManager.fetchAmmStatus();
                    }
                    if (window.SummaryManager && window.SummaryManager.fetchSummaryData) {
                        window.SummaryManager.fetchSummaryData();
                    }
                }, 1000);
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
                    if (window.showErrorModal) {
                        window.showErrorModal('Error', 'Could not save the configuration. Please try using the Settings tab instead.');
                    } else {
                        alert('Error: Could not save the configuration.');
                    }
                }
            }

            if (wasReadonly) {
                configTextarea.setAttribute('readonly', '');
            }
        } catch (error) {
            alert(`Error processing the configuration: ${error.message}`);
            debugLog('Error deleting item:', error);
        }
    }

    const adaptor_sig_only_coins = ['6', 'Monero', '7', 'Particl Blind', '8', 'Particl Anon', '9', 'Wownero', '13', 'Firo', '16', 'Zano', '17', 'Bitcoin Cash', '18', 'Dogecoin'];
    const secret_hash_only_coins = ['11', 'PIVX', '12', 'Dash'];

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
            arrow.innerHTML = `
                <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            `;

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
            arrow.innerHTML = `
                <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path>
                </svg>
            `;

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

    function setupBiddingControls(modalType) {
        const checkbox = document.getElementById(`${modalType}-offer-attempt-bids-first`);
        const optionsDiv = document.getElementById(`${modalType}-offer-bidding-options`);

        if (checkbox && optionsDiv) {
            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    optionsDiv.classList.remove('hidden');
                } else {
                    optionsDiv.classList.add('hidden');
                }
            });

            if (checkbox.checked) {
                optionsDiv.classList.remove('hidden');
            } else {
                optionsDiv.classList.add('hidden');
            }
        }
    }

    function populateBiddingControls(modalType, item) {
        if (!item) return;

        const attemptBidsFirst = document.getElementById(`${modalType}-offer-attempt-bids-first`);
        const bidStrategy = document.getElementById(`${modalType}-offer-bid-strategy`);
        const maxBidPercentage = document.getElementById(`${modalType}-offer-max-bid-percentage`);
        const bidRateTolerance = document.getElementById(`${modalType}-offer-bid-rate-tolerance`);
        const minRemainingOffer = document.getElementById(`${modalType}-offer-min-remaining-offer`);

        if (attemptBidsFirst) {
            attemptBidsFirst.checked = item.attempt_bids_first || false;
        }

        if (bidStrategy) {
            bidStrategy.value = item.bid_strategy || 'balanced';
        }

        if (maxBidPercentage) {
            maxBidPercentage.value = item.max_bid_percentage || '50';
        }

        if (bidRateTolerance) {
            bidRateTolerance.value = item.bid_rate_tolerance || '2.0';
        }

        if (minRemainingOffer) {
            minRemainingOffer.value = item.min_remaining_offer || '0.001';
        }

        if (attemptBidsFirst) {
            attemptBidsFirst.dispatchEvent(new Event('change'));
        }
    }

    function getRateFromCoinGecko(coinFromSelect, coinToSelect, rateInput) {
        const coinFromOption = coinFromSelect.options[coinFromSelect.selectedIndex];
        const coinToOption = coinToSelect.options[coinToSelect.selectedIndex];

        if (!coinFromOption || !coinToOption) {
            if (window.showErrorModal) {
                window.showErrorModal('Rate Lookup Error', 'Please select both coins before getting the rate.');
            } else {
                alert('Coins from and to must be set first.');
            }
            return;
        }

        const coinFromSymbol = coinFromOption.getAttribute('data-symbol');
        const coinToSymbol = coinToOption.getAttribute('data-symbol');

        if (!coinFromSymbol || !coinToSymbol) {
            if (window.showErrorModal) {
                window.showErrorModal('Rate Lookup Error', 'Coin information is incomplete. Please try selecting the coins again.');
            } else {
                alert('Coin symbols not found.');
            }
            return;
        }

        const originalValue = rateInput.value;
        rateInput.value = 'Loading...';
        rateInput.disabled = true;

        const getRateButton = rateInput.parentElement.querySelector('button');
        let originalButtonText = '';
        if (getRateButton) {
            originalButtonText = getRateButton.textContent;
            getRateButton.disabled = true;
            getRateButton.innerHTML = `
                <svg class="animate-spin -ml-1 mr-2 h-3 w-3 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Loading...
            `;
        }

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

                        if (getRateButton && originalButtonText) {
                            getRateButton.disabled = false;
                            getRateButton.textContent = originalButtonText;
                        }
                    } else if (response.error) {
                        console.error('API error:', response.error);
                        rateInput.value = originalValue || '';
                        if (window.showErrorModal) {
                            window.showErrorModal('Rate Service Error', `Unable to retrieve rate information: ${response.error}\n\nThis could be due to:\n• Temporary service unavailability\n• Network connectivity issues\n• Invalid coin pair\n\nPlease try again in a few moments.`);
                        } else {
                            alert('Error: ' + response.error);
                        }
                    } else if (response.coingecko_error) {
                        console.error('CoinGecko error:', response.coingecko_error);
                        rateInput.value = originalValue || '';

                        let userMessage = 'Unable to get current market rate from CoinGecko.';
                        let details = '';

                        if (typeof response.coingecko_error === 'number') {
                            switch(response.coingecko_error) {
                                case 8:
                                    details = 'This usually means:\n• One or both coins are not supported by CoinGecko\n• The trading pair is not available\n• Temporary API limitations\n\nYou can manually enter a rate or try again later.';
                                    break;
                                case 429:
                                    details = 'Rate limit exceeded. Please wait a moment and try again.';
                                    break;
                                case 404:
                                    details = 'The requested coin pair was not found on CoinGecko.';
                                    break;
                                case 500:
                                    details = 'CoinGecko service is temporarily unavailable. Please try again later.';
                                    break;
                                default:
                                    details = `Error code: ${response.coingecko_error}\n\nThis may be a temporary issue. Please try again or enter the rate manually.`;
                            }
                        } else {
                            details = `${response.coingecko_error}\n\nPlease try again or enter the rate manually.`;
                        }

                        if (window.showErrorModal) {
                            window.showErrorModal('Market Rate Unavailable', `${userMessage}\n\n${details}`);
                        } else {
                            alert('Unable to get rate from CoinGecko: ' + response.coingecko_error);
                        }
                    } else {
                        rateInput.value = originalValue || '';
                        if (window.showErrorModal) {
                            window.showErrorModal('Rate Not Available', `No current market rate is available for this ${coinFromSymbol}/${coinToSymbol} trading pair.\n\nThis could mean:\n• The coins are not traded together on major exchanges\n• CoinGecko doesn't have data for this pair\n• The coins may not be supported\n\nPlease enter a rate manually based on your research.`);
                        } else {
                            alert('No rate available from CoinGecko for this pair.');
                        }
                    }
                } catch (e) {
                    console.error('Error parsing rate data:', e);
                    rateInput.value = originalValue || '';
                    if (window.showErrorModal) {
                        window.showErrorModal('Data Processing Error', 'Unable to process the rate information received from the server.\n\nThis could be due to:\n• Temporary server issues\n• Data format problems\n• Network interference\n\nPlease try again in a moment.');
                    } else {
                        alert('Error retrieving rate information. Please try again later.');
                    }
                }
            } else {
                console.error('Error fetching rate data:', xhr.status, xhr.statusText);
                rateInput.value = originalValue || '';
                let errorMessage = 'Unable to retrieve rate information from the server.';
                let details = '';

                switch(xhr.status) {
                    case 404:
                        details = 'The rate service endpoint was not found. This may be a configuration issue.';
                        break;
                    case 500:
                        details = 'The server encountered an internal error. Please try again later.';
                        break;
                    case 503:
                        details = 'The rate service is temporarily unavailable. Please try again in a few minutes.';
                        break;
                    case 429:
                        details = 'Too many requests. Please wait a moment before trying again.';
                        break;
                    default:
                        details = `Server returned error ${xhr.status}. The rate service may be temporarily unavailable.`;
                }

                if (window.showErrorModal) {
                    window.showErrorModal('Rate Service Unavailable', `${errorMessage}\n\n${details}\n\nYou can enter the rate manually if needed.`);
                } else {
                    alert(`Unable to retrieve rate information (HTTP ${xhr.status}). The rate service may be unavailable.`);
                }
            }
            rateInput.disabled = false;

            if (getRateButton && originalButtonText) {
                getRateButton.disabled = false;
                getRateButton.textContent = originalButtonText;
            }
        };
        xhr.onerror = function(e) {
            console.error('Network error when fetching rate data:', e);
            rateInput.value = originalValue || '';
            rateInput.disabled = false;

            if (getRateButton && originalButtonText) {
                getRateButton.disabled = false;
                getRateButton.textContent = originalButtonText;
            }

            if (window.showErrorModal) {
                window.showErrorModal('Network Connection Error', 'Unable to connect to the rate service.\n\nPlease check:\n• Your internet connection\n• BasicSwap server status\n• Firewall settings\n\nTry again once your connection is stable, or enter the rate manually.');
            } else {
                alert('Unable to connect to the rate service. Please check your network connection and try again.');
            }
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

    async function initialize(options = {}) {
        Object.assign(config, options);

        initializeTabs();
        setupButtonHandlers();
        initializeCustomSelects();
        setupRateButtons();

        await initializePrices();

        if (refreshButton) {
            refreshButton.addEventListener('click', async function() {
                const icon = refreshButton.querySelector('svg');
                if (icon) {
                    icon.classList.add('animate-spin');
                }

                await initializePrices();
                updateTables();

                setTimeout(() => {
                    if (icon) {
                        icon.classList.remove('animate-spin');
                    }
                }, 1000);
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

document.addEventListener('DOMContentLoaded', async function() {
    if (typeof AmmTablesManager !== 'undefined') {
        window.ammTablesManager = await AmmTablesManager.initialize();
    }
});
