const PAGE_SIZE = 50;

const state = {
    identities: new Map(),
    currentPage: 1,
    wsConnected: false,
    swapsData: [],
    isLoading: false,
    isRefreshing: false,
    refreshPromise: null
};

const elements = {
    swapsBody: document.getElementById('active-swaps-body'),
    prevPageButton: document.getElementById('prevPage'),
    nextPageButton: document.getElementById('nextPage'),
    currentPageSpan: document.getElementById('currentPage'),
    paginationControls: document.getElementById('pagination-controls'),
    activeSwapsCount: document.getElementById('activeSwapsCount'),
    refreshSwapsButton: document.getElementById('refreshSwaps'),
    statusDot: document.getElementById('status-dot'),
    statusText: document.getElementById('status-text')
};

const safeParseInt = (value) => {
    const parsed = parseInt(value);
    return isNaN(parsed) ? 0 : parsed;
};

const getStatusClass = (status, tx_a, tx_b) => {
    switch (status) {
        case 'Completed':
            return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
        case 'Expired':
        case 'Timed-out':
            return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-white';
        case 'Error':
        case 'Failed':
            return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
        case 'Failed, swiped':
        case 'Failed, refunded':
            return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-red-500';
        case 'InProgress':
        case 'Script coin locked':
        case 'Scriptless coin locked':
        case 'Script coin lock released':
        case 'SendingInitialTx':
        case 'SendingPaymentTx':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Received':
        case 'Exchanged script lock tx sigs msg':
        case 'Exchanged script lock spend tx msg':
        case 'Script tx redeemed':
        case 'Scriptless tx redeemed':
        case 'Scriptless tx recovered':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Accepted':
        case 'Request accepted':
            return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
        case 'Delaying':
        case 'Auto accept delay':
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        case 'Abandoned':
        case 'Rejected':
            return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
        default:
            return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
    }
};

const getTxStatusClass = (status) => {
    if (!status || status === 'None') return 'text-gray-400';

    if (status.includes('Complete') || status.includes('Confirmed')) {
        return 'text-green-500';
    }
    if (status.includes('Error') || status.includes('Failed')) {
        return 'text-red-500';
    }
    if (status.includes('Progress') || status.includes('Sending')) {
        return 'text-yellow-500';
    }
    return 'text-blue-500';
};

const formatTimeAgo = (timestamp) => {
    const now = Math.floor(Date.now() / 1000);
    const diff = now - timestamp;

    if (diff < 60) return `${diff} seconds ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)} minutes ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)} hours ago`;
    return `${Math.floor(diff / 86400)} days ago`;
};

const formatTime = (timestamp) => {
    if (!timestamp) return '';
    const date = new Date(timestamp * 1000);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
};

const formatAddress = (address, displayLength = 15) => {
    if (!address) return '';
    if (address.length <= displayLength) return address;
    return `${address.slice(0, displayLength)}...`;
};

const getStatusColor = (status) => {
    const statusColors = {
        'Received': 'text-blue-500',
        'Accepted': 'text-green-500',
        'InProgress': 'text-yellow-500',
        'Complete': 'text-green-600',
        'Failed': 'text-red-500',
        'Expired': 'text-gray-500'
    };
    return statusColors[status] || 'text-gray-500';
};

const getTimeStrokeColor = (expireTime) => {
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = expireTime - now;

    if (timeLeft <= 300) return '#9CA3AF'; // 5 minutes or less
    if (timeLeft <= 1800) return '#3B82F6'; // 30 minutes or less
    return '#10B981'; // More than 30 minutes
};

const updateConnectionStatus = (status) => {
    const { statusDot, statusText } = elements;
    if (!statusDot || !statusText) return;

    const statusConfig = {
        connected: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-green-500 mr-2',
            textClass: 'text-sm text-green-500',
            message: 'Connected'
        },
        disconnected: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-red-500 mr-2',
            textClass: 'text-sm text-red-500',
            message: 'Disconnected - Reconnecting...'
        },
        error: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-yellow-500 mr-2',
            textClass: 'text-sm text-yellow-500',
            message: 'Connection Error'
        },
        default: {
            dotClass: 'w-2.5 h-2.5 rounded-full bg-gray-500 mr-2',
            textClass: 'text-sm text-gray-500',
            message: 'Connecting...'
        }
    };

    const config = statusConfig[status] || statusConfig.default;
    statusDot.className = config.dotClass;
    statusText.className = config.textClass;
    statusText.textContent = config.message;
};

const updateLoadingState = (isLoading) => {
    state.isLoading = isLoading;
    if (elements.refreshSwapsButton) {
        elements.refreshSwapsButton.disabled = isLoading;
        elements.refreshSwapsButton.classList.toggle('opacity-75', isLoading);
        elements.refreshSwapsButton.classList.toggle('cursor-wait', isLoading);

        const refreshIcon = elements.refreshSwapsButton.querySelector('svg');
        const refreshText = elements.refreshSwapsButton.querySelector('#refreshText');

        if (refreshIcon) {
            refreshIcon.style.transition = 'transform 0.3s ease';
            refreshIcon.classList.toggle('animate-spin', isLoading);
        }

        if (refreshText) {
            refreshText.textContent = isLoading ? 'Refreshing...' : 'Refresh';
        }
    }
};

const processIdentityStats = (identity) => {
    if (!identity) return null;

    const stats = {
        sentSuccessful: safeParseInt(identity.num_sent_bids_successful),
        recvSuccessful: safeParseInt(identity.num_recv_bids_successful),
        sentFailed: safeParseInt(identity.num_sent_bids_failed),
        recvFailed: safeParseInt(identity.num_recv_bids_failed),
        sentRejected: safeParseInt(identity.num_sent_bids_rejected),
        recvRejected: safeParseInt(identity.num_recv_bids_rejected)
    };

    stats.totalSuccessful = stats.sentSuccessful + stats.recvSuccessful;
    stats.totalFailed = stats.sentFailed + stats.recvFailed;
    stats.totalRejected = stats.sentRejected + stats.recvRejected;
    stats.totalBids = stats.totalSuccessful + stats.totalFailed + stats.totalRejected;

    stats.successRate = stats.totalBids > 0
        ? ((stats.totalSuccessful / stats.totalBids) * 100).toFixed(1)
        : '0.0';

    return stats;
};

const createIdentityTooltip = (identity) => {
    if (!identity) return '';

    const stats = processIdentityStats(identity);
    if (!stats) return '';

    const getSuccessRateColor = (rate) => {
        const numRate = parseFloat(rate);
        if (numRate >= 80) return 'text-green-600';
        if (numRate >= 60) return 'text-yellow-600';
        return 'text-red-600';
    };

    return `
        <div class="identity-info space-y-2">
            ${identity.label ? `
                <div class="border-b border-gray-400 pb-2">
                    <div class="text-white text-xs tracking-wide font-semibold">Label:</div>
                    <div class="text-white">${identity.label}</div>
                </div>
            ` : ''}

            <div class="space-y-1">
                <div class="text-white text-xs tracking-wide font-semibold">Address:</div>
                <div class="monospace text-xs break-all bg-gray-500 p-2 rounded-md text-white">
                    ${identity.address || ''}
                </div>
            </div>

            ${identity.note ? `
                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Note:</div>
                    <div class="text-white text-sm italic">${identity.note}</div>
                </div>
            ` : ''}

            <div class="pt-2 mt-2">
                <div class="text-white text-xs tracking-wide font-semibold mb-2">Swap History:</div>
                <div class="grid grid-cols-2 gap-2">
                    <div class="text-center p-2 bg-gray-500 rounded-md">
                        <div class="text-lg font-bold ${getSuccessRateColor(stats.successRate)}">
                            ${stats.successRate}%
                        </div>
                        <div class="text-xs text-white">Success Rate</div>
                    </div>
                    <div class="text-center p-2 bg-gray-500 rounded-md">
                        <div class="text-lg font-bold text-blue-500">${stats.totalBids}</div>
                        <div class="text-xs text-white">Total Trades</div>
                    </div>
                </div>
                <div class="grid grid-cols-3 gap-2 mt-2 text-center text-xs">
                    <div>
                        <div class="text-green-600 font-semibold">
                            ${stats.totalSuccessful}
                        </div>
                        <div class="text-white">Successful</div>
                    </div>
                    <div>
                        <div class="text-yellow-600 font-semibold">
                            ${stats.totalRejected}
                        </div>
                        <div class="text-white">Rejected</div>
                    </div>
                    <div>
                        <div class="text-red-600 font-semibold">
                            ${stats.totalFailed}
                        </div>
                        <div class="text-white">Failed</div>
                    </div>
                </div>
            </div>
        </div>
    `;
};

const createSwapTableRow = async (swap) => {
    if (!swap || !swap.bid_id) {
        console.warn('Invalid swap data:', swap);
        return '';
    }

    const identity = await IdentityManager.getIdentityData(swap.addr_from);
    const uniqueId = `${swap.bid_id}_${swap.created_at}`;
    const fromSymbol = window.CoinManager.getSymbol(swap.coin_from) || swap.coin_from;
    const toSymbol = window.CoinManager.getSymbol(swap.coin_to) || swap.coin_to;
    const timeColor = getTimeStrokeColor(swap.expire_at);
    const fromAmount = parseFloat(swap.amount_from) || 0;
    const toAmount = parseFloat(swap.amount_to) || 0;

    return `
        <tr class="relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600" data-bid-id="${swap.bid_id}">
            <td class="relative w-0 p-0 m-0">
                <div class="absolute top-0 bottom-0 left-0 w-1"></div>
            </td>

            <!-- Time Column -->
            <td class="py-3 pl-1 pr-2 text-xs whitespace-nowrap">
                <div class="flex items-center">
                    <div class="relative" data-tooltip-target="tooltip-time-${uniqueId}">
                        <svg class="w-5 h-5 rounded-full mr-4 cursor-pointer" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${timeColor}" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="11"></circle>
                                <polyline points="12,6 12,12 18,12"></polyline>
                            </g>
                        </svg>
                    </div>
                    <div class="flex flex-col hidden xl:block">
                        <div class="text-xs whitespace-nowrap">
                            <span class="bold">Posted:</span> ${formatTimeAgo(swap.created_at)}
                        </div>
                    </div>
                </div>
            </td>

           <!-- Details Column -->
            <td class="py-8 px-4 text-xs text-left hidden xl:block">
              <div class="flex flex-col gap-2 relative">
                  <div class="flex items-center">
                     <a href="/identity/${swap.addr_from}" data-tooltip-target="tooltip-identity-${uniqueId}" class="flex items-center">
                        <svg class="w-4 h-4 mr-2 text-gray-400 dark:text-white" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="monospace ${identity?.label ? 'dark:text-white' : 'dark:text-white'}">
                        ${identity?.label || formatAddress(swap.addr_from)}
                    </span>
                </a>
            </div>
            <div class="monospace text-xs text-gray-500 dark:text-gray-300">
                <span class="font-semibold">Bid ID:</span>
                <a href="/bid/${swap.bid_id}" data-tooltip-target="tooltip-bid-${uniqueId}" class="hover:underline">
                    ${formatAddress(swap.bid_id)}
                </a>
            </div>
            <div class="monospace text-xs text-gray-500 dark:text-gray-300">
                <span class="font-semibold">Offer ID:</span>
                <a href="/offer/${swap.offer_id}" data-tooltip-target="tooltip-offer-${uniqueId}" class="hover:underline">
                    ${formatAddress(swap.offer_id)}
                </a>
             </div>
            </div>
           </td>
            <!-- You Send Column -->
            <td class="py-0">
                <div class="py-3 px-4 text-left">
                    <div class="items-center monospace">
                        <div class="pr-2">
                            <div class="text-sm font-semibold">${fromAmount.toFixed(8)}</div>
                            <div class="text-sm text-gray-500 dark:text-gray-400">${fromSymbol}</div>
                        </div>
                    </div>
                </div>
            </td>

            <!-- Swap Column -->
            <td class="py-0">
                <div class="py-3 px-4 text-center">
                    <div class="flex items-center justify-center">
                        <span class="inline-flex mr-3 align-middle items-center justify-center w-18 h-20 rounded">
                            <img class="h-12"
                                 src="/static/images/coins/${swap.coin_from.replace(' ', '-')}.png"
                                 alt="${swap.coin_from}"
                                 onerror="this.src='/static/images/coins/default.png'">
                        </span>
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z"></path>
                        </svg>
                        <span class="inline-flex ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                            <img class="h-12"
                                 src="/static/images/coins/${swap.coin_to.replace(' ', '-')}.png"
                                 alt="${swap.coin_to}"
                                 onerror="this.src='/static/images/coins/default.png'">
                        </span>
                    </div>
                </div>
            </td>

            <!-- You Receive Column -->
            <td class="py-0">
                <div class="py-3 px-4 text-right">
                    <div class="items-center monospace">
                        <div class="text-sm font-semibold">${toAmount.toFixed(8)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-400">${toSymbol}</div>
                    </div>
                </div>
            </td>
            <!-- Status Column -->
            <td class="py-3 px-4 text-center">
                <div data-tooltip-target="tooltip-status-${uniqueId}" class="flex justify-center">
                    <span class="w-full lg:w-7/8 xl:w-2/3 px-2.5 py-1 inline-flex items-center justify-center text-center rounded-full text-xs font-medium bold ${getStatusClass(swap.bid_state, swap.tx_state_a, swap.tx_state_b)}">
                        ${swap.bid_state}
                    </span>
                </div>
            </td>

            <!-- Actions Column -->
            <td class="py-3 px-4 text-center">
                <a href="/bid/${swap.bid_id}"
                   class="inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md bg-blue-500 text-white border border-blue-500 hover:bg-blue-600 transition duration-200">
                    Details
                </a>
            </td>

            <!-- Tooltips -->
            <div id="tooltip-time-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
                <div class="active-revoked-expired">
                    <span class="bold">
                        <div class="text-xs"><span class="bold">Posted:</span> ${formatTimeAgo(swap.created_at)}</div>
                        <div class="text-xs"><span class="bold">Expires in:</span> ${formatTime(swap.expire_at)}</div>
                    </span>
                </div>
                <div class="mt-5 text-xs">
                    <p class="font-bold mb-3">Time Indicator Colors:</p>
                    <p class="flex items-center">
                        <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#10B981" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="11"></circle>
                                <polyline points="12,6 12,12 18,12" stroke="#10B981"></polyline>
                            </g>
                        </svg>
                        Green: More than 30 minutes left
                    </p>
                    <p class="flex items-center mt-3">
                        <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#3B82F6" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="11"></circle>
                                <polyline points="12,6 12,12 18,12" stroke="#3B82F6"></polyline>
                            </g>
                        </svg>
                        Blue: Between 5 and 30 minutes left
                    </p>
                    <p class="flex items-center mt-3 mb-3">
                        <svg class="w-5 h-5 mr-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="#9CA3AF" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="11"></circle>
                                <polyline points="12,6 12,12 18,12" stroke="#9CA3AF"></polyline>
                            </g>
                        </svg>
                        Grey: Less than 5 minutes left or expired
                    </p>
                </div>
                <div class="tooltip-arrow" data-popper-arrow></div>
            </div>

            <div id="tooltip-identity-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
                ${createIdentityTooltip(identity)}
                <div class="tooltip-arrow" data-popper-arrow></div>
            </div>

            <div id="tooltip-offer-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Offer ID:</div>
                    <div class="monospace text-xs break-all">
                        ${swap.offer_id}
                    </div>
                </div>
                <div class="tooltip-arrow" data-popper-arrow></div>
            </div>

            <div id="tooltip-bid-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Bid ID:</div>
                    <div class="monospace text-xs break-all">
                        ${swap.bid_id}
                    </div>
                </div>
                <div class="tooltip-arrow" data-popper-arrow></div>
            </div>

            <div id="tooltip-status-${uniqueId}" role="tooltip" class="inline-block absolute z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip dark:bg-gray-600">
                <div class="text-white">
                    <p class="font-bold mb-2">Transaction Status</p>
                    <div class="grid grid-cols-2 gap-2">
                        <div class="bg-gray-500 p-2 rounded">
                            <p class="text-xs font-bold">ITX:</p>
                            <p>${swap.tx_state_a || 'N/A'}</p>
                        </div>
                        <div class="bg-gray-500 p-2 rounded">
                            <p class="text-xs font-bold">PTX:</p>
                            <p>${swap.tx_state_b || 'N/A'}</p>
                        </div>
                    </div>
                </div>
                <div class="tooltip-arrow" data-popper-arrow></div>
            </div>
        </tr>
    `;
};

async function updateSwapsTable(options = {}) {
    const { resetPage = false, refreshData = true } = options;

    //console.log('Updating swaps table:', { resetPage, refreshData });

    if (state.refreshPromise) {
        await state.refreshPromise;
        return;
    }

    try {
        updateLoadingState(true);

        if (refreshData) {
            state.refreshPromise = (async () => {
                try {
                    const response = await fetch('/json/active', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            sort_by: "created_at",
                            sort_dir: "desc"
                        })
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }

                    const data = await response.json();
                    //console.log('Received swap data:', data);

                    state.swapsData = Array.isArray(data)
                        ? data.filter(swap => {
                            const isActive = isActiveSwap(swap);
                            //console.log(`Swap ${swap.bid_id}: ${isActive ? 'Active' : 'Inactive'}`, swap.bid_state);
                            return isActive;
                        })
                        : [];

                    //console.log('Filtered active swaps:', state.swapsData);
                } catch (error) {
                    //console.error('Error fetching swap data:', error);
                    state.swapsData = [];
                } finally {
                    state.refreshPromise = null;
                }
            })();

            await state.refreshPromise;
        }

        if (elements.activeSwapsCount) {
            elements.activeSwapsCount.textContent = state.swapsData.length;
        }

        const totalPages = Math.ceil(state.swapsData.length / PAGE_SIZE);

        if (resetPage && state.swapsData.length > 0) {
            state.currentPage = 1;
        }

        state.currentPage = Math.min(Math.max(1, state.currentPage), Math.max(1, totalPages));

        const startIndex = (state.currentPage - 1) * PAGE_SIZE;
        const endIndex = startIndex + PAGE_SIZE;
        const currentPageSwaps = state.swapsData.slice(startIndex, endIndex);

        //console.log('Current page swaps:', currentPageSwaps);

        if (elements.swapsBody) {
            if (currentPageSwaps.length > 0) {
                const rowPromises = currentPageSwaps.map(swap => createSwapTableRow(swap));
                const rows = await Promise.all(rowPromises);
                elements.swapsBody.innerHTML = rows.join('');

                if (window.TooltipManager) {
                    window.TooltipManager.cleanup();
                    const tooltipTriggers = document.querySelectorAll('[data-tooltip-target]');
                    tooltipTriggers.forEach(trigger => {
                        const targetId = trigger.getAttribute('data-tooltip-target');
                        const tooltipContent = document.getElementById(targetId);
                        if (tooltipContent) {
                            window.TooltipManager.create(trigger, tooltipContent.innerHTML, {
                                placement: trigger.getAttribute('data-tooltip-placement') || 'top'
                            });
                        }
                    });
                }
            } else {
                //console.log('No active swaps found, displaying empty state');
                elements.swapsBody.innerHTML = `
                    <tr>
                        <td colspan="8" class="text-center py-4 text-gray-500 dark:text-white">
                            No active swaps found
                        </td>
                    </tr>`;
            }
        }

    } catch (error) {
        console.error('Error updating swaps table:', error);
        if (elements.swapsBody) {
            elements.swapsBody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-4 text-red-500">
                        Error loading active swaps. Please try again later.
                    </td>
                </tr>`;
        }
    } finally {
        updateLoadingState(false);
    }
}

function isActiveSwap(swap) {
    const activeStates = [

        'InProgress',
        'Accepted',
        'Delaying',
        'Auto accept delay',
        'Request accepted',
        //'Received',

        'Script coin locked',
        'Scriptless coin locked',
        'Script coin lock released',

        'SendingInitialTx',
        'SendingPaymentTx',

        'Exchanged script lock tx sigs msg',
        'Exchanged script lock spend tx msg',

        'Script tx redeemed',
        'Scriptless tx redeemed',
        'Scriptless tx recovered'
    ];

    return activeStates.includes(swap.bid_state);
}

const setupEventListeners = () => {
    if (elements.refreshSwapsButton) {
        elements.refreshSwapsButton.addEventListener('click', async (e) => {
            e.preventDefault();
            if (state.isRefreshing) return;

            updateLoadingState(true);
            try {
                await updateSwapsTable({ resetPage: true, refreshData: true });
            } finally {
                updateLoadingState(false);
            }
        });
    }

    if (elements.prevPageButton) {
        elements.prevPageButton.addEventListener('click', async (e) => {
            e.preventDefault();
            if (state.isLoading) return;
            if (state.currentPage > 1) {
                state.currentPage--;
                await updateSwapsTable({ resetPage: false, refreshData: false });
            }
        });
    }

    if (elements.nextPageButton) {
        elements.nextPageButton.addEventListener('click', async (e) => {
            e.preventDefault();
            if (state.isLoading) return;
            const totalPages = Math.ceil(state.swapsData.length / PAGE_SIZE);
            if (state.currentPage < totalPages) {
                state.currentPage++;
                await updateSwapsTable({ resetPage: false, refreshData: false });
            }
        });
    }
};

document.addEventListener('DOMContentLoaded', async () => {
    WebSocketManager.initialize();
    setupEventListeners();
    await updateSwapsTable({ resetPage: true, refreshData: true });
    const autoRefreshInterval = setInterval(async () => {
        await updateSwapsTable({ resetPage: false, refreshData: true });
    }, 10000);  // 30 seconds
});
