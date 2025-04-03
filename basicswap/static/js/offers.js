let latestPrices = null;
let lastRefreshTime = null;
let currentPage = 1;
let jsonData = [];
let originalJsonData = [];
let currentSortColumn = 0;
let currentSortDirection = 'desc';
let filterTimeout = null;
let isPaginationInProgress = false;

const isSentOffers = window.offersTableConfig.isSentOffers;
const CACHE_DURATION = window.config.cacheConfig.defaultTTL;
const wsPort = window.config.wsPort;
const itemsPerPage = window.config.itemsPerPage;

const offersBody = document.getElementById('offers-body');
const filterForm = document.getElementById('filterForm');
const prevPageButton = document.getElementById('prevPage');
const nextPageButton = document.getElementById('nextPage');
const currentPageSpan = document.getElementById('currentPage');
const totalPagesSpan = document.getElementById('totalPages');
const lastRefreshTimeSpan = document.getElementById('lastRefreshTime');
const newEntriesCountSpan = document.getElementById('newEntriesCount');

window.tableRateModule = {

    cache: {},
    processedOffers: new Set(),

    getCachedValue(key) {
        const cachedItem = localStorage.getItem(key);
        if (cachedItem) {
            const parsedItem = JSON.parse(cachedItem);
            if (Date.now() < parsedItem.expiry) {
                return parsedItem.value;
            } else {
                localStorage.removeItem(key);
            }
        }
        return null;
    },

    setCachedValue(key, value, resourceType = null) {
        const ttl = resourceType ?
            window.config.cacheConfig.ttlSettings[resourceType] ||
            window.config.cacheConfig.defaultTTL :
            900000;

        const item = {
            value: value,
            expiry: Date.now() + ttl,
        };
        localStorage.setItem(key, JSON.stringify(item));
    },

    setFallbackValue(coinSymbol, value) {
        this.setCachedValue(`fallback_${coinSymbol}_usd`, value, 'fallback');
    },

    isNewOffer(offerId) {
        if (this.processedOffers.has(offerId)) {
            return false;
        }
        this.processedOffers.add(offerId);
        return true;
    },

    formatUSD(value) {
        if (Math.abs(value) < 0.000001) {
            return value.toExponential(8) + ' USD';
        } else if (Math.abs(value) < 0.01) {
            return value.toFixed(8) + ' USD';
        } else {
            return value.toFixed(2) + ' USD';
        }
    },

    formatNumber(value, decimals) {
        if (Math.abs(value) < 0.000001) {
            return value.toExponential(decimals);
        } else if (Math.abs(value) < 0.01) {
            return value.toFixed(decimals);
        } else {
            return value.toFixed(Math.min(2, decimals));
        }
    },

    getFallbackValue(coinSymbol) {
        if (!coinSymbol) return null;
        const normalizedSymbol = coinSymbol.toLowerCase() === 'part' ? 'particl' : coinSymbol.toLowerCase();
        const cachedValue = this.getCachedValue(`fallback_${normalizedSymbol}_usd`);
        return cachedValue;
    },

    initializeTable() {
        document.querySelectorAll('.coinname-value').forEach(coinNameValue => {
            const coinFullNameOrSymbol = coinNameValue.getAttribute('data-coinname');
            if (!coinFullNameOrSymbol || coinFullNameOrSymbol === 'Unknown') {
                return;
            }
            coinNameValue.classList.remove('hidden');
            if (!coinNameValue.textContent.trim()) {
                coinNameValue.textContent = 'N/A';
            }
        });

        document.querySelectorAll('.usd-value').forEach(usdValue => {
            if (!usdValue.textContent.trim()) {
                usdValue.textContent = 'N/A';
            }
        });

        document.querySelectorAll('.profit-loss').forEach(profitLoss => {
            if (!profitLoss.textContent.trim() || profitLoss.textContent === 'Calculating...') {
                profitLoss.textContent = 'N/A';
            }
        });
    },

    init() {
        this.initializeTable();
    }
};

function initializeTableRateModule() {
    if (typeof window.tableRateModule !== 'undefined') {
        tableRateModule = window.tableRateModule;
        return true;
    } else {
        return false;
    }
}

function continueInitialization() {
    updateCoinFilterImages();
    fetchOffers().then(() => {
        applyFilters();
        if (!isSentOffers) {
            return;
        }
    });

    const listingLabel = document.querySelector('span[data-listing-label]');
    if (listingLabel) {
        listingLabel.textContent = isSentOffers ? 'Total Listings: ' : 'Network Listings: ';
    }
}

function initializeTooltips() {
    if (window.TooltipManager) {
        window.TooltipManager.initializeTooltips();
    }
}

function getValidOffers() {
    if (!jsonData) {
        return [];
    }

    const filteredData = filterAndSortData();
    return filteredData;
}

function saveFilterSettings() {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);

    const storageKey = isSentOffers ? 'sentOffersTableSettings' : 'networkOffersTableSettings';

    localStorage.setItem(storageKey, JSON.stringify({
        coin_to: filters.coin_to,
        coin_from: filters.coin_from,
        status: filters.status,
        sent_from: filters.sent_from,
        sortColumn: currentSortColumn,
        sortDirection: currentSortDirection
    }));
}

function coinMatches(offerCoin, filterCoin) {
    if (!offerCoin || !filterCoin || filterCoin === 'any') return true;

    offerCoin = offerCoin.toLowerCase();
    filterCoin = filterCoin.toLowerCase();

    if (offerCoin === filterCoin) return true;

    if ((offerCoin === 'firo' || offerCoin === 'zcoin') &&
        (filterCoin === 'firo' || filterCoin === 'zcoin')) {
        return true;
    }

    if ((offerCoin === 'bitcoincash' && filterCoin === 'bitcoin cash') ||
        (offerCoin === 'bitcoin cash' && filterCoin === 'bitcoincash')) {
        return true;
    }

    const particlVariants = ['particl', 'particl anon', 'particl blind'];
    if (filterCoin === 'particl' && particlVariants.includes(offerCoin)) {
        return true;
    }

    if (particlVariants.includes(filterCoin)) {
        return offerCoin === filterCoin;
    }

    return false;
}

function filterAndSortData() {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);

    saveFilterSettings();

    let filteredData = [...originalJsonData];

    const sentFromFilter = filters.sent_from || 'any';
    filteredData = filteredData.filter(offer => {
        const isMatch = sentFromFilter === 'public' ? offer.is_public : 
                        sentFromFilter === 'private' ? !offer.is_public : 
                        true;
        return isMatch;
    });

    filteredData = filteredData.filter(offer => {
        if (!isSentOffers && isOfferExpired(offer)) {
            return false;
        }

        if (filters.coin_to && filters.coin_to !== 'any') {
            const coinToSelect = document.getElementById('coin_to');
            const selectedOption = coinToSelect?.querySelector(`option[value="${filters.coin_to}"]`);
            const coinName = selectedOption?.textContent.trim();
            
            if (coinName && !coinMatches(offer.coin_to, coinName)) {
                return false;
            }
        }

        if (filters.coin_from && filters.coin_from !== 'any') {
            const coinFromSelect = document.getElementById('coin_from');
            const selectedOption = coinFromSelect?.querySelector(`option[value="${filters.coin_from}"]`);
            const coinName = selectedOption?.textContent.trim();
            
            if (coinName && !coinMatches(offer.coin_from, coinName)) {
                return false;
            }
        }

        if (isSentOffers && filters.status && filters.status !== 'any') {
            const isExpired = offer.expire_at <= Math.floor(Date.now() / 1000);
            const isRevoked = Boolean(offer.is_revoked);

            let statusMatch = false;
            switch (filters.status) {
                case 'active': 
                    statusMatch = !isExpired && !isRevoked;
                    break;
                case 'expired': 
                    statusMatch = isExpired && !isRevoked;
                    break;
                case 'revoked': 
                    statusMatch = isRevoked;
                    break;
            }

            if (!statusMatch) {
                return false;
            }
        }

        return true;
    });

    if (currentSortColumn !== null && currentSortDirection !== null) {
        filteredData.sort((a, b) => {
            let aValue, bValue;

            switch(currentSortColumn) {
                case 0: // Time column
                    aValue = a.created_at;
                    bValue = b.created_at;
                    break;
                case 1: // Details column (usually address)
                    aValue = a.addr_from || '';
                    bValue = b.addr_from || '';
                    break;
                case 2: // Taker Amount column
                    aValue = parseFloat(a.amount_to) || 0;
                    bValue = parseFloat(b.amount_to) || 0;
                    break;
                case 3: // Swap column (could sort by coin names)
                    aValue = a.coin_from + a.coin_to;
                    bValue = b.coin_from + b.coin_to;
                    break;
                case 4: // Orderbook column
                    aValue = parseFloat(a.amount_from) || 0;
                    bValue = parseFloat(b.amount_from) || 0;
                    break;
                case 5: // Rate column
                    aValue = parseFloat(a.rate) || 0;
                    bValue = parseFloat(b.rate) || 0;
                    break;
                default:
                    aValue = a.created_at;
                    bValue = b.created_at;
            }

            if (typeof aValue === 'number' && typeof bValue === 'number') {
                return currentSortDirection === 'asc' ? aValue - bValue : bValue - aValue;
            }

            if (typeof aValue === 'string' && typeof bValue === 'string') {
                return currentSortDirection === 'asc' 
                    ? aValue.localeCompare(bValue) 
                    : bValue.localeCompare(aValue);
            }

            return currentSortDirection === 'asc' ? (aValue > bValue ? 1 : -1) : (bValue > aValue ? 1 : -1);
        });
    }

    return filteredData;
}

async function calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
    return new Promise((resolve) => {
        if (!fromCoin || !toCoin) {
            resolve(null);
            return;
        }

        const getPriceForCoin = (coin) => {
            if (!coin) return null;

            let normalizedCoin = coin.toLowerCase();

            if (window.CoinManager) {
                normalizedCoin = window.CoinManager.getPriceKey(coin) || normalizedCoin;
            } else {
                if (normalizedCoin === 'zcoin') normalizedCoin = 'firo';
                if (normalizedCoin === 'bitcoincash' || normalizedCoin === 'bitcoin cash') 
                    normalizedCoin = 'bitcoin-cash';
                if (normalizedCoin.includes('particl')) normalizedCoin = 'particl';
            }
            let price = null;
            if (latestPrices && latestPrices[normalizedCoin]) {
                price = latestPrices[normalizedCoin].usd;
            }
            return price;
        };

        const fromPriceUSD = getPriceForCoin(fromCoin);
        const toPriceUSD = getPriceForCoin(toCoin);

        if (!fromPriceUSD || !toPriceUSD || isNaN(fromPriceUSD) || isNaN(toPriceUSD)) {
            resolve(null);
            return;
        }

        const fromValueUSD = fromAmount * fromPriceUSD;
        const toValueUSD = toAmount * toPriceUSD;

        if (isNaN(fromValueUSD) || isNaN(toValueUSD) || fromValueUSD === 0 || toValueUSD === 0) {
            resolve(null);
            return;
        }

        let percentDiff;
        if (isOwnOffer) {
            percentDiff = ((toValueUSD / fromValueUSD) - 1) * 100;
        } else {
            percentDiff = ((fromValueUSD / toValueUSD) - 1) * 100;
        }

        if (isNaN(percentDiff)) {
            resolve(null);
            return;
        }

        resolve(percentDiff);
    });
}

function getEmptyPriceData() {
    return window.config.utils.getEmptyPriceData();
}

async function fetchLatestPrices() {
    try {

        const prices = await window.PriceManager.getPrices(window.isManualRefresh);
        window.isManualRefresh = false;
        return prices;
    } catch (error) {
        console.error('Error fetching prices:', error);
        return getEmptyPriceData();
    }
}

async function fetchOffers() {
    const refreshButton = document.getElementById('refreshOffers');
    const refreshIcon = document.getElementById('refreshIcon');
    const refreshText = document.getElementById('refreshText');

    try {
        if (!NetworkManager.isOnline()) {
            throw new Error('Network is offline');
        }

        if (refreshButton) {
            refreshButton.disabled = true;
            refreshIcon.classList.add('animate-spin');
            refreshText.textContent = 'Refreshing...';
            refreshButton.classList.add('opacity-75', 'cursor-wait');
        }

        const [offersResponse, pricesData] = await Promise.all([
            fetch(isSentOffers ? '/json/sentoffers' : '/json/offers'),
            fetchLatestPrices()
        ]);

        if (!offersResponse.ok) {
            throw new Error(`HTTP error! status: ${offersResponse.status}`);
        }

        const data = await offersResponse.json();
        const processedData = Array.isArray(data) ? data : Object.values(data);

        jsonData = formatInitialData(processedData);
        originalJsonData = [...jsonData];

        latestPrices = pricesData || getEmptyPriceData();

        CacheManager.set('offers_cached', jsonData, 'offers');

        await updateOffersTable();
        updatePaginationInfo();

    } catch (error) {
        console.error('[Debug] Error fetching offers:', error);
        NetworkManager.handleNetworkError(error);

        const cachedOffers = CacheManager.get('offers_cached');
        if (cachedOffers?.value) {
            jsonData = cachedOffers.value;
            originalJsonData = [...jsonData];
            await updateOffersTable();
        }
        ui.displayErrorMessage('Failed to fetch offers. Please try again later.');
    } finally {
        if (refreshButton) {
            refreshButton.disabled = false;
            refreshIcon.classList.remove('animate-spin');
            refreshText.textContent = 'Refresh';
            refreshButton.classList.remove('opacity-75', 'cursor-wait');
        }
    }
}

function formatInitialData(data) {
    return data.map(offer => ({
        offer_id: String(offer.offer_id || ''),
        swap_type: String(offer.swap_type || 'N/A'),
        addr_from: String(offer.addr_from || ''),
        addr_to: String(offer.addr_to || ''),
        coin_from: String(offer.coin_from || ''),
        coin_to: String(offer.coin_to || ''),
        amount_from: String(offer.amount_from || '0'),
        amount_to: String(offer.amount_to || '0'),
        rate: String(offer.rate || '0'),
        created_at: Number(offer.created_at || 0),
        expire_at: Number(offer.expire_at || 0),
        is_own_offer: Boolean(offer.is_own_offer),
        amount_negotiable: Boolean(offer.amount_negotiable),
        is_revoked: Boolean(offer.is_revoked),
        is_public: offer.is_public !== undefined ? Boolean(offer.is_public) : false,
        unique_id: `${offer.offer_id}_${offer.created_at}_${offer.coin_from}_${offer.coin_to}`
    }));
}

function updateConnectionStatus(status) {
    const dot = document.getElementById('status-dot');
    const text = document.getElementById('status-text');

    if (!dot || !text) {
        return;
    }

    switch(status) {
        case 'connected':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-green-500 mr-2';
            text.textContent = 'Connected';
            text.className = 'text-sm text-green-500';
            break;
        case 'disconnected':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-red-500 mr-2';
            text.textContent = 'Disconnected - Reconnecting...';
            text.className = 'text-sm text-red-500';
            break;
        case 'error':
            dot.className = 'w-2.5 h-2.5 rounded-full bg-yellow-500 mr-2';
            text.textContent = 'Connection Error';
            text.className = 'text-sm text-yellow-500';
            break;
        default:
            dot.className = 'w-2.5 h-2.5 rounded-full bg-gray-500 mr-2';
            text.textContent = 'Connecting...';
            text.className = 'text-sm text-gray-500';
    }
}

function updateRowTimes() {
    requestAnimationFrame(() => {
        const rows = document.querySelectorAll('[data-offer-id]');
        rows.forEach(row => {
            const offerId = row.getAttribute('data-offer-id');
            const offer = jsonData.find(o => o.offer_id === offerId);
            if (!offer) return;

            const newPostedTime = formatTime(offer.created_at, true);
            const newExpiresIn = formatTimeLeft(offer.expire_at);

            const postedElement = row.querySelector('.text-xs:first-child');
            const expiresElement = row.querySelector('.text-xs:last-child');

            if (postedElement && postedElement.textContent !== `Posted: ${newPostedTime}`) {
                postedElement.textContent = `Posted: ${newPostedTime}`;
            }
            if (expiresElement && expiresElement.textContent !== `Expires in: ${newExpiresIn}`) {
                expiresElement.textContent = `Expires in: ${newExpiresIn}`;
            }
        });
    });
}

function updateLastRefreshTime() {
    if (lastRefreshTimeSpan) {
        lastRefreshTimeSpan.textContent = lastRefreshTime ? new Date(lastRefreshTime).toLocaleTimeString() : 'Never';
    }
}

function stopRefreshAnimation() {
    const refreshButton = document.getElementById('refreshOffers');
    const refreshIcon = document.getElementById('refreshIcon');
    const refreshText = document.getElementById('refreshText');

    if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.classList.remove('opacity-75', 'cursor-wait');
    }
    if (refreshIcon) {
        refreshIcon.classList.remove('animate-spin');
    }
    if (refreshText) {
        refreshText.textContent = 'Refresh';
    }
}

function updatePaginationInfo() {
    const validOffers = getValidOffers();
    const totalItems = validOffers.length;
    const totalPages = Math.max(1, Math.ceil(totalItems / itemsPerPage));
    const previousPage = currentPage;

    if (previousPage !== currentPage) {
        debugPaginationChange('updatePaginationInfo', previousPage, currentPage);
    }

    if (currentPageSpan) currentPageSpan.textContent = totalPages > 0 ? currentPage : 0;
    if (totalPagesSpan) totalPagesSpan.textContent = totalPages;

    const showPrev = currentPage > 1;
    const showNext = currentPage < totalPages;

    if (prevPageButton) {
        prevPageButton.style.display = showPrev ? 'inline-flex' : 'none';
        prevPageButton.disabled = !showPrev;
    }

    if (nextPageButton) {
        nextPageButton.style.display = showNext ? 'inline-flex' : 'none';
        nextPageButton.disabled = !showNext;
    }

    if (newEntriesCountSpan) {
        newEntriesCountSpan.textContent = totalItems;
    }
}

function updatePaginationControls(totalPages) {
    prevPageButton.style.display = currentPage > 1 ? 'inline-flex' : 'none';
    nextPageButton.style.display = currentPage < totalPages ? 'inline-flex' : 'none';
    currentPageSpan.textContent = currentPage;
    totalPagesSpan.textContent = totalPages;
}

function updateProfitLoss(row, fromCoin, toCoin, fromAmount, toAmount, isOwnOffer) {
    const profitLossElement = row.querySelector('.profit-loss');
    if (!profitLossElement) {
        return;
    }

    if (!fromCoin || !toCoin) {
        profitLossElement.textContent = 'N/A';
        profitLossElement.className = 'profit-loss text-lg font-bold text-gray-300';
        return;
    }

    calculateProfitLoss(fromCoin, toCoin, fromAmount, toAmount, isOwnOffer)
        .then(percentDiff => {
            if (percentDiff === null || isNaN(percentDiff)) {
                profitLossElement.textContent = 'N/A';
                profitLossElement.className = 'profit-loss text-lg font-bold text-gray-300';
                return;
            }

            const formattedPercentDiff = percentDiff.toFixed(2);
            const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" :
                                     (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

            const colorClass = getProfitColorClass(percentDiff);
            profitLossElement.textContent = `${percentDiffDisplay}%`;
            profitLossElement.className = `profit-loss text-lg font-bold ${colorClass}`;

            const tooltipId = `percentage-tooltip-${row.getAttribute('data-offer-id')}`;
            const tooltipElement = document.getElementById(tooltipId);
            if (tooltipElement) {
                const tooltipContent = createTooltipContent(isSentOffers || isOwnOffer, fromCoin, toCoin, fromAmount, toAmount);
                tooltipElement.innerHTML = `
                    <div class="tooltip-content">
                        ${tooltipContent}
                    </div>
                    <div class="tooltip-arrow" data-popper-arrow></div>
                `;
            }
        })
        .catch(error => {
            profitLossElement.textContent = 'N/A';
            profitLossElement.className = 'profit-loss text-lg font-bold text-gray-300';
        });
}

function updateCoinFilterImages() {
    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');
    const coinToButton = document.getElementById('coin_to_button');
    const coinFromButton = document.getElementById('coin_from_button');

    function updateButtonImage(select, button) {
        const selectedOption = select.options[select.selectedIndex];
        const imagePath = selectedOption.getAttribute('data-image');
        if (imagePath && select.value !== 'any') {
            button.style.backgroundImage = `url(${imagePath})`;
            button.style.backgroundSize = '25px 25px';
            button.style.backgroundPosition = 'center';
            button.style.backgroundRepeat = 'no-repeat';
        } else {
            button.style.backgroundImage = 'none';
        }
        button.style.minWidth = '25px';
        button.style.minHeight = '25px';
    }

    updateButtonImage(coinToSelect, coinToButton);
    updateButtonImage(coinFromSelect, coinFromButton);
}

function updateClearFiltersButton() {
    const clearButton = document.getElementById('clearFilters');
    if (clearButton) {
        const hasFilters = hasActiveFilters();
        clearButton.classList.toggle('opacity-50', !hasFilters);
        clearButton.disabled = !hasFilters;

        if (hasFilters) {
            clearButton.classList.add('hover:bg-green-600', 'hover:text-white');
            clearButton.classList.remove('cursor-not-allowed');
        } else {
            clearButton.classList.remove('hover:bg-green-600', 'hover:text-white');
            clearButton.classList.add('cursor-not-allowed');
        }
    }
}

function cleanupRow(row) {
    if (!row) return;

    const tooltipTriggers = row.querySelectorAll('[data-tooltip-trigger-id]');
    tooltipTriggers.forEach(trigger => {
        if (window.TooltipManager) {
            window.TooltipManager.destroy(trigger);
        }
    });

    CleanupManager.removeListenersByElement(row);

    row.removeAttribute('data-offer-id');

    while (row.firstChild) {
        const child = row.firstChild;
        row.removeChild(child);
    }
}

function cleanupTable() {
    if (!offersBody) return;

    const existingRows = offersBody.querySelectorAll('tr');
    existingRows.forEach(row => cleanupRow(row));

    offersBody.innerHTML = '';

    if (window.TooltipManager) {
        window.TooltipManager.cleanup();
    }
}

function handleNoOffersScenario() {
    const formData = new FormData(filterForm);
    const filters = Object.fromEntries(formData);
    const hasActiveFilters = filters.coin_to !== 'any' ||
                            filters.coin_from !== 'any' ||
                            (filters.status && filters.status !== 'any');

    stopRefreshAnimation();

    const existingRows = offersBody.querySelectorAll('tr');
    existingRows.forEach(row => {
        cleanupRow(row);
    });

    if (hasActiveFilters) {
        offersBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-8">
                    <div class="flex items-center justify-center text-gray-500 dark:text-white">
                        No offers match the selected filters. Try different filter options or
                        <button onclick="clearFilters()" class="ml-1 text-blue-500 hover:text-blue-700 font-semibold">
                            clear filters
                        </button>
                    </div>
                </td>
            </tr>`;
    } else {
        offersBody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-8 text-gray-500 dark:text-white">
                    No active offers available.
                </td>
            </tr>`;
    }
}

async function updateOffersTable(options = {}) {
    try {

        if (isPaginationInProgress && !options.fromPaginationClick) {
            console.log('Skipping table update during pagination operation');
            return;
        }

        if (window.TooltipManager) {
            window.TooltipManager.cleanup();
        }

        const validOffers = getValidOffers();
        if (validOffers.length === 0) {
            handleNoOffersScenario();
            return;
        }

        const totalPages = Math.ceil(validOffers.length / itemsPerPage);

        if (!options.fromPaginationClick) {
            const oldPage = currentPage;
            currentPage = Math.max(1, Math.min(currentPage, totalPages));
            if (oldPage !== currentPage) {
                debugPaginationChange('updateOffersTable auto-adjust', oldPage, currentPage);
            }
        }

        const startIndex = (currentPage - 1) * itemsPerPage;
        const endIndex = Math.min(startIndex + itemsPerPage, validOffers.length);
        const itemsToDisplay = validOffers.slice(startIndex, endIndex);

        const fragment = document.createDocumentFragment();

        const BATCH_SIZE = 10;
        for (let i = 0; i < itemsToDisplay.length; i += BATCH_SIZE) {
            const batch = itemsToDisplay.slice(i, i + BATCH_SIZE);

            const batchPromises = batch.map(offer =>
                offer.addr_from ? IdentityManager.getIdentityData(offer.addr_from) : Promise.resolve(null)
            );

            const batchIdentities = await Promise.all(batchPromises);

            batch.forEach((offer, index) => {
                const row = createTableRow(offer, batchIdentities[index]);
                if (row) fragment.appendChild(row);
            });

            if (i + BATCH_SIZE < itemsToDisplay.length) {
                await new Promise(resolve => setTimeout(resolve, 16));
            }
        }

        if (offersBody) {
            const existingRows = offersBody.querySelectorAll('tr');
            existingRows.forEach(row => cleanupRow(row));
            offersBody.textContent = '';
            offersBody.appendChild(fragment);
        }

        initializeTooltips();

        requestAnimationFrame(() => {
            updateRowTimes();
            updatePaginationInfo();
            updateProfitLossDisplays();
            if (tableRateModule?.initializeTable) {
                tableRateModule.initializeTable();
            }
        });

        lastRefreshTime = Date.now();
        updateLastRefreshTime();

    } catch (error) {
        console.error('[Debug] Error in updateOffersTable:', error);
        handleTableError();
    }
}

function updateProfitLossDisplays() {
    const rows = document.querySelectorAll('[data-offer-id]');
    rows.forEach(row => {
        const offerId = row.getAttribute('data-offer-id');
        const offer = jsonData.find(o => o.offer_id === offerId);
        if (!offer) return;

        const fromAmount = parseFloat(offer.amount_from) || 0;
        const toAmount = parseFloat(offer.amount_to) || 0;
        updateProfitLoss(row, offer.coin_from, offer.coin_to, fromAmount, toAmount, offer.is_own_offer);

        const rateTooltipId = `tooltip-rate-${offerId}`;
        const rateTooltip = document.getElementById(rateTooltipId);
        if (rateTooltip) {
            const tooltipContent = createCombinedRateTooltip(offer, offer.coin_from, offer.coin_to, offer.is_own_offer);
            rateTooltip.innerHTML = tooltipContent;
        }
    });
}

function handleTableError() {
    offersBody.innerHTML = `
        <tr>
            <td colspan="8" class="text-center py-4 text-gray-500">
                <div class="flex flex-col items-center justify-center gap-2">
                    <span>An error occurred while updating the table.</span>
                    <span class="text-sm">The table will continue to function with cached data.</span>
                </div>
            </td>
        </tr>`;
}

function getIdentityInfo(address, identity) {
    if (!identity) {
        return {
            displayAddr: address ? `${address.substring(0, 10)}...` : 'Unspecified',
            fullAddress: address || '',
            label: '',
            note: '',
            automationOverride: 0,
            stats: {
                sentBidsSuccessful: 0,
                recvBidsSuccessful: 0,
                sentBidsRejected: 0,
                recvBidsRejected: 0,
                sentBidsFailed: 0,
                recvBidsFailed: 0
            }
        };
    }

    return {
        displayAddr: address ? `${address.substring(0, 10)}...` : 'Unspecified',
        fullAddress: address || '',
        label: identity.label || '',
        note: identity.note || '',
        automationOverride: identity.automation_override || 0,
        stats: {
            sentBidsSuccessful: identity.num_sent_bids_successful || 0,
            recvBidsSuccessful: identity.num_recv_bids_successful || 0,
            sentBidsRejected: identity.num_sent_bids_rejected || 0,
            recvBidsRejected: identity.num_recv_bids_rejected || 0,
            sentBidsFailed: identity.num_sent_bids_failed || 0,
            recvBidsFailed: identity.num_recv_bids_failed || 0
        }
    };
}

function createTableRow(offer, identity = null) {
   const row = document.createElement('tr');
   const uniqueId = `${offer.offer_id}_${offer.created_at}`;

   row.className = 'relative opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600';
   row.setAttribute('data-offer-id', uniqueId);

   const {
       coin_from: coinFrom,
       coin_to: coinTo,
       created_at: createdAt,
       expire_at: expireAt,
       amount_from: amountFrom,
       amount_to: amountTo,
       is_own_offer: isOwnOffer,
       is_revoked: isRevoked,
       is_public: isPublic
   } = offer;

   let coinFromSymbol, coinToSymbol;
   
   if (window.CoinManager) {
       coinFromSymbol = window.CoinManager.getSymbol(coinFrom) || coinFrom.toLowerCase();
       coinToSymbol = window.CoinManager.getSymbol(coinTo) || coinTo.toLowerCase();
   } else {
       coinFromSymbol = coinFrom.toLowerCase();
       coinToSymbol = coinTo.toLowerCase();
   }

   let coinFromDisplay, coinToDisplay;
   
   if (window.CoinManager) {
       coinFromDisplay = window.CoinManager.getDisplayName(coinFrom) || coinFrom;
       coinToDisplay = window.CoinManager.getDisplayName(coinTo) || coinTo;
   } else {
       coinFromDisplay = coinFrom;
       coinToDisplay = coinTo;
       if (coinFromDisplay.toLowerCase() === 'zcoin') coinFromDisplay = 'Firo';
       if (coinToDisplay.toLowerCase() === 'zcoin') coinToDisplay = 'Firo';
   }
   
   const postedTime = formatTime(createdAt, true);
   const expiresIn = formatTime(expireAt);
   const currentTime = Math.floor(Date.now() / 1000);
   const isActuallyExpired = currentTime > expireAt;
   const fromAmount = parseFloat(amountFrom) || 0;
   const toAmount = parseFloat(amountTo) || 0;

   row.innerHTML = `
       ${!isPublic ? createPrivateIndicator() : '<td class="w-0 p-0 m-0"></td>'}
       ${createTimeColumn(offer, postedTime, expiresIn)}
       ${createDetailsColumn(offer, identity)}
       ${createTakerAmountColumn(offer, coinTo, coinFrom)}
       ${createSwapColumn(offer, coinFromDisplay, coinToDisplay, coinFromSymbol, coinToSymbol)}
       ${createOrderbookColumn(offer, coinFrom)}
       ${createRateColumn(offer, coinFrom, coinTo)}
       ${createPercentageColumn(offer)}
       ${createActionColumn(offer, isActuallyExpired)}
       ${createTooltips(
           offer,
           isOwnOffer,
           coinFrom,
           coinTo,
           fromAmount,
           toAmount,
           postedTime,
           expiresIn,
           isActuallyExpired,
           Boolean(isRevoked),
           identity
       )}
   `;

   updateTooltipTargets(row, uniqueId);
   updateProfitLoss(row, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer);

   return row;
}

function createPrivateIndicator() {
    return `<td class="relative w-0 p-0 m-0">
        <div class="absolute top-0 bottom-0 left-0 w-1 bg-red-700" style="min-height: 100%;"></div>
    </td>`;
}

function createTimeColumn(offer, postedTime, expiresIn) {
    const now = Math.floor(Date.now() / 1000);
    const timeLeft = offer.expire_at - now;

    let strokeColor = '#10B981';
    if (timeLeft <= 300) {
        strokeColor = '#9CA3AF';
    } else if (timeLeft <= 1800) {
        strokeColor = '#3B82F6';
    }

    return `
        <td class="py-3 pl-1 pr-2 text-xs whitespace-nowrap">
            <div class="flex items-center">
                <div class="relative" data-tooltip-target="tooltip-active${escapeHtml(offer.offer_id)}">
                    <svg alt="" class="w-5 h-5 rounded-full mr-4 cursor-pointer" xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 24 24">
                        <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${strokeColor}" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="11"></circle>
                            <polyline points="12,6 12,12 18,12" stroke="${strokeColor}"></polyline>
                        </g>
                    </svg>
                </div>
                <div class="flex flex-col hidden xl:block">
                    <div class="text-xs whitespace-nowrap"><span class="bold">Posted:</span> ${escapeHtml(postedTime)}</div>
                    <div class="text-xs whitespace-nowrap"><span class="bold">Expires in:</span> ${escapeHtml(expiresIn)}</div>
                </div>
            </div>
        </td>
    `;
}

function truncateText(text, maxLength = 15) {
    if (typeof text !== 'string') return '';
    return text.length > maxLength
        ? text.slice(0, maxLength) + '...'
        : text;
}

function createDetailsColumn(offer, identity = null) {
    const addrFrom = offer.addr_from || '';
    const identityInfo = getIdentityInfo(addrFrom, identity);

    const showPublicPrivateTags = originalJsonData.some(o => o.is_public !== offer.is_public);

    const tagClass = offer.is_public
        ? 'bg-green-600 dark:bg-green-600'
        : 'bg-red-500 dark:bg-red-500';
    const tagText = offer.is_public ? 'Public' : 'Private';

    const displayIdentifier = truncateText(
        identityInfo.label || addrFrom || 'Unspecified'
    );

    const identifierTextClass = identityInfo.label
        ? 'dark:text-white'
        : 'monospace';

    return `
        <td class="py-8 px-4 text-xs text-left hidden xl:block">
            <div class="flex flex-col gap-2 relative">
                ${showPublicPrivateTags ? `<span class="inline-flex pl-6 pr-6 py-1 justify-center text-[10px] w-1/4 font-medium text-gray-100 rounded-md ${tagClass}">${tagText}</span>
                ` : ''}

                <a data-tooltip-target="tooltip-recipient-${escapeHtml(offer.offer_id)}" href="/identity/${escapeHtml(addrFrom)}" class="flex items-center">
                    <svg class="w-4 h-4 mr-2 text-gray-400 dark:text-white" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                     <path fill-rule="evenodd" d="M10 9a3 3 0 100-6 3 3 0 000 6zm-7 9a7 7 0 1114 0H3z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="${identifierTextClass}">
                        ${escapeHtml(displayIdentifier)}
                    </span>
                </a>
            </div>
        </td>
    `;
}

function createTakerAmountColumn(offer, coinTo) {
    const fromAmount = parseFloat(offer.amount_to);
    const toSymbol = getCoinSymbol(coinTo);
    return `
        <td class="py-0">
            <div class="py-3 px-4 text-left">
                <a data-tooltip-target="tooltip-wallet${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(toSymbol)}" class="items-center monospace">
                    <div class="pr-2">
                        <div class="text-sm font-semibold">${fromAmount.toFixed(4)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-400">${coinTo}</div>
                    </div>
                </a>
            </div>
        </td>
    `;
}

function createSwapColumn(offer, coinFromDisplay, coinToDisplay, coinFromSymbol, coinToSymbol) {
    const getImageFilename = (symbol, displayName) => {
        if (displayName.toLowerCase() === 'zcoin' || displayName.toLowerCase() === 'firo') {
            return 'Firo.png';
        }
        return `${displayName.replace(' ', '-')}.png`;
    };

    return `
        <td class="py-0 px-0 text-right text-sm">
            <a data-tooltip-target="tooltip-offer${offer.offer_id}" href="/offer/${offer.offer_id}">
                <div class="flex items-center justify-evenly monospace">
                    <span class="inline-flex mr-3 ml-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${getImageFilename(coinToSymbol, coinToDisplay)}" alt="${coinToDisplay}">
                    </span>
                    <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                        <path fill-rule="evenodd" d="M12.293 5.293a1 1 0 011.414 0l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-2.293-2.293a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                    </svg>
                    <span class="inline-flex ml-3 mr-3 align-middle items-center justify-center w-18 h-20 rounded">
                        <img class="h-12" src="/static/images/coins/${getImageFilename(coinFromSymbol, coinFromDisplay)}" alt="${coinFromDisplay}">
                    </span>
                </div>
            </a>
        </td>
    `;
}

function createOrderbookColumn(offer, coinFrom) {
    const toAmount = parseFloat(offer.amount_from);
    const fromSymbol = getCoinSymbol(coinFrom);
    return `
        <td class="p-0">
            <div class="py-3 px-4 text-right">
                <a data-tooltip-target="tooltip-wallet-maker${escapeHtml(offer.offer_id)}" href="/wallet/${escapeHtml(fromSymbol)}" class="items-center monospace">
                    <div class="pr-2">
                        <div class="text-sm font-semibold">${toAmount.toFixed(4)}</div>
                        <div class="text-sm text-gray-500 dark:text-gray-400">${coinFrom}</div>
                    </div>
                </a>
            </div>
        </td>
    `;
}

function createRateColumn(offer, coinFrom, coinTo) {
    const rate = parseFloat(offer.rate) || 0;
    const inverseRate = rate ? (1 / rate) : 0;

    const toSymbolKey = getPriceKey(coinTo);
    let toPriceUSD = latestPrices && latestPrices[toSymbolKey] ? latestPrices[toSymbolKey].usd : null;

    if (!toPriceUSD || isNaN(toPriceUSD)) {
        toPriceUSD = tableRateModule.getFallbackValue(toSymbolKey);
    }

    const rateInUSD = toPriceUSD && !isNaN(toPriceUSD) && !isNaN(rate) ? rate * toPriceUSD : null;
    const fromSymbol = getCoinSymbol(coinFrom);
    const toSymbol = getCoinSymbol(coinTo);

    return `
        <td class="py-3 semibold monospace text-xs text-right items-center rate-table-info">
            <div class="relative">
                <div class="flex flex-col items-end pr-3" data-tooltip-target="tooltip-rate-${offer.offer_id}">
                    <span class="text-sm bold text-gray-700 dark:text-white">
                        ${rateInUSD !== null ? `$${rateInUSD.toFixed(2)} USD` : 'N/A'}
                    </span>
                    <span class="bold text-gray-700 dark:text-white">
                        ${rate.toFixed(8)} ${toSymbol}/${fromSymbol}
                    </span>
                    <span class="semibold text-gray-400 dark:text-gray-300">
                        ${inverseRate.toFixed(8)} ${fromSymbol}/${toSymbol}
                    </span>
                </div>
            </div>
        </td>
    `;
}


function createPercentageColumn(offer) {
    return `
        <td class="py-3 px-2 bold text-sm text-center monospace items-center rate-table-info">
            <div class="relative" data-tooltip-target="percentage-tooltip-${offer.offer_id}">
                <div class="profittype">
                    <span class="profit-loss text-lg font-bold" data-offer-id="${offer.offer_id}">
                        Calculating...
                    </span>
                </div>
            </div>
        </td>
    `;
}

function createActionColumn(offer, isActuallyExpired = false) {
    const isRevoked = Boolean(offer.is_revoked);
    const isTreatedAsSentOffer = offer.is_own_offer;

    let buttonClass, buttonText;

    if (isRevoked) {
        buttonClass = 'bg-red-500 text-white hover:bg-red-600 transition duration-200';
        buttonText = 'Revoked';
    } else if (isActuallyExpired && isSentOffers) {
        buttonClass = 'bg-gray-400 text-white dark:border-gray-300 text-white hover:bg-red-700 transition duration-200';
        buttonText = 'Expired';
    } else if (isTreatedAsSentOffer) {
        buttonClass = 'bg-gray-300 bold text-white bold hover:bg-green-600 transition duration-200';
        buttonText = 'Edit';
    } else {
        buttonClass = 'bg-blue-500 text-white hover:bg-green-600 transition duration-200';
        buttonText = 'Swap';
    }

    return `
        <td class="py-6 px-2 text-center">
            <div class="flex justify-center items-center h-full">
                <a class="inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md ${buttonClass}"
                   href="/offer/${offer.offer_id}">
                    ${buttonText}
                </a>
            </div>
        </td>
    `;
}

function createTooltips(offer, treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount, postedTime, expiresIn, isActuallyExpired, isRevoked, identity = null) {
    const uniqueId = `${offer.offer_id}_${offer.created_at}`;

    const addrFrom = offer.addr_from || '';
    const identityInfo = getIdentityInfo(addrFrom, identity);

    const totalBids = identity ? (
        identityInfo.stats.sentBidsSuccessful +
        identityInfo.stats.recvBidsSuccessful +
        identityInfo.stats.sentBidsFailed +
        identityInfo.stats.recvBidsFailed +
        identityInfo.stats.sentBidsRejected +
        identityInfo.stats.recvBidsRejected
    ) : 0;

    const successRate = totalBids ? (
        ((identityInfo.stats.sentBidsSuccessful + identityInfo.stats.recvBidsSuccessful) / totalBids) * 100
    ).toFixed(1) : 0;

    const combinedRateTooltip = createCombinedRateTooltip(offer, coinFrom, coinTo, treatAsSentOffer);
    const percentageTooltipContent = createTooltipContent(treatAsSentOffer, coinFrom, coinTo, fromAmount, toAmount);

    return `
        <div id="tooltip-active-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">
                    <div class="text-xs"><span class="bold">Posted:</span> ${postedTime}</div>
                    <div class="text-xs"><span class="bold">Expires in:</span> ${expiresIn}</div>
                    ${isRevoked ? '<div class="text-xs text-red-300"><span class="bold">Status:</span> Revoked</div>' : ''}
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
        </div>

        <div id="tooltip-wallet-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">${treatAsSentOffer ? 'My' : ''} ${coinTo} Wallet</span>
            </div>
        </div>

        <div id="tooltip-offer-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white ${isRevoked ? 'bg-red-500' : (offer.is_own_offer ? 'bg-gray-300' : 'bg-green-700')} rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">
                    ${isRevoked ? 'Offer Revoked' : (offer.is_own_offer ? 'Edit Offer' : `Buy ${coinFrom}`)}
                </span>
            </div>
        </div>

        <div id="tooltip-wallet-maker-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="active-revoked-expired">
                <span class="bold">${treatAsSentOffer ? 'My' : ''} ${coinFrom} Wallet</span>
            </div>
        </div>

        <div id="tooltip-rate-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="tooltip-content">
                ${combinedRateTooltip}
            </div>
        </div>

        <div id="percentage-tooltip-${uniqueId}" role="tooltip" class="inline-block absolute hidden z-50 py-2 px-3 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip">
            <div class="tooltip-content">
                ${percentageTooltipContent}
            </div>
        </div>

        ${createRecipientTooltip(uniqueId, identityInfo, identity, successRate, totalBids)}
    `;
}

function createRecipientTooltip(uniqueId, identityInfo, identity, successRate, totalBids) {

    const getSuccessRateColor = (rate) => {
        if (rate >= 80) return 'text-green-600';
        if (rate >= 60) return 'text-yellow-600';
        return 'text-red-600';
    };


    const truncateText = (text, maxLength) => {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength) + '...';
    };

    return `
        <div id="tooltip-recipient-${uniqueId}" role="tooltip"
            class="fixed z-50 py-3 px-4 text-sm font-medium text-white bg-gray-400 rounded-lg shadow-sm opacity-0 transition-opacity duration-300 tooltip max-w-sm pointer-events-none">
            <div class="identity-info space-y-2">
                ${identityInfo.label ? `
                    <div class="border-b border-gray-400 pb-2">
                        <div class="text-white text-xs tracking-wide font-semibold">Label:</div>
                        <div class="text-white">${escapeHtml(identityInfo.label)}</div>
                    </div>
                ` : ''}

                <div class="space-y-1">
                    <div class="text-white text-xs tracking-wide font-semibold">Recipient Address:</div>
                    <div class="monospace text-xs break-all bg-gray-500 p-2 rounded-md text-white">
                        ${escapeHtml(identityInfo.fullAddress)}
                    </div>
                </div>

                ${identityInfo.note ? `
                    <div class="space-y-1 hidden">
                        <div class="text-white text-xs tracking-wide font-semibold">Note:</div>
                        <div class="text-white text-sm italic" title="${escapeHtml(identityInfo.note)}">
                            ${escapeHtml(truncateText(identityInfo.note, 150))}
                        </div>
                    </div>
                ` : ''}

                ${identity ? `
                    <div class= pt-2 mt-2">
                        <div class="text-white text-xs tracking-wide font-semibold mb-2">Swap History:</div>
                        <div class="grid grid-cols-2 gap-2">
                            <div class="text-center p-2 bg-gray-500 rounded-md">
                                <div class="text-lg font-bold ${getSuccessRateColor(successRate)}">${successRate}%</div>
                                <div class="text-xs text-white">Success Rate</div>
                            </div>
                            <div class="text-center p-2 bg-gray-500 rounded-md">
                                <div class="text-lg font-bold text-blue-500">${totalBids}</div>
                                <div class="text-xs text-white">Total Trades</div>
                            </div>
                        </div>
                        <div class="grid grid-cols-3 gap-2 mt-2 text-center text-xs">
                            <div>
                                <div class="text-green-600 font-semibold">
                                    ${identityInfo.stats.sentBidsSuccessful + identityInfo.stats.recvBidsSuccessful}
                                </div>
                                <div class="text-white">Successful</div>
                            </div>
                            <div>
                                <div class="text-yellow-600 font-semibold">
                                    ${identityInfo.stats.sentBidsRejected + identityInfo.stats.recvBidsRejected}
                                </div>
                                <div class="text-white">Rejected</div>
                            </div>
                            <div>
                                <div class="text-red-600 font-semibold">
                                    ${identityInfo.stats.sentBidsFailed + identityInfo.stats.recvBidsFailed}
                                </div>
                                <div class="text-white">Failed</div>
                            </div>
                        </div>
                    </div>
                ` : ''}
            </div>
            <div class="tooltip-arrow" data-popper-arrow></div>
        </div>`;
}

function createTooltipContent(isSentOffers, coinFrom, coinTo, fromAmount, toAmount, isOwnOffer) {
    if (!coinFrom || !coinTo) {
        return `<p class="font-bold mb-1">Unable to calculate profit/loss</p>
                <p>Invalid coin data.</p>`;
    }

    fromAmount = parseFloat(fromAmount) || 0;
    toAmount = parseFloat(toAmount) || 0;

    const getPriceKey = (coin) => {
        if (!coin) return null;
        
        const lowerCoin = coin.toLowerCase();

        if (lowerCoin === 'zcoin') return 'firo';

        if (lowerCoin === 'bitcoin cash' || lowerCoin === 'bitcoincash' || lowerCoin === 'bch') {

            if (latestPrices && latestPrices['bitcoin-cash']) {
                return 'bitcoin-cash';
            } else if (latestPrices && latestPrices['bch']) {
                return 'bch';
            }
            return 'bitcoin-cash';
        }

        if (lowerCoin === 'part' || lowerCoin === 'particl' || lowerCoin.includes('particl')) {
            return 'part';
        }

        if (window.config && window.config.coinMappings && window.config.coinMappings.nameToSymbol) {
            const symbol = window.config.coinMappings.nameToSymbol[coin];
            if (symbol) {
                if (symbol.toUpperCase() === 'BCH') {
                    if (latestPrices && latestPrices['bitcoin-cash']) {
                        return 'bitcoin-cash';
                    } else if (latestPrices && latestPrices['bch']) {
                        return 'bch';
                    }
                    return 'bitcoin-cash'; // Default
                }

                if (symbol.toUpperCase() === 'PART') {
                    return 'part';
                }

                return symbol.toLowerCase();
            }
        }
        return lowerCoin;
    };

    const fromSymbol = getPriceKey(coinFrom);
    const toSymbol = getPriceKey(coinTo);

    let fromPriceUSD = latestPrices && fromSymbol ? latestPrices[fromSymbol]?.usd : null;
    let toPriceUSD = latestPrices && toSymbol ? latestPrices[toSymbol]?.usd : null;

    if (!fromPriceUSD && window.tableRateModule) {
        fromPriceUSD = tableRateModule.getFallbackValue(fromSymbol);
    }
    if (!toPriceUSD && window.tableRateModule) {
        toPriceUSD = tableRateModule.getFallbackValue(toSymbol);
    }

    if (fromPriceUSD === null || toPriceUSD === null ||
        fromPriceUSD === undefined || toPriceUSD === undefined ||
        isNaN(fromPriceUSD) || isNaN(toPriceUSD)) {
        return `<p class="font-bold mb-1">Price Information Unavailable</p>
                <p>Current market prices are temporarily unavailable.</p>
                <p class="mt-2">You are ${isSentOffers ? 'selling' : 'buying'} ${fromAmount.toFixed(8)} ${coinFrom}
                for ${toAmount.toFixed(8)} ${coinTo}.</p>
                <p class="font-bold mt-2">Note:</p>
                <p>Profit/loss calculations will be available when price data is restored.</p>`;
    }

    const fromValueUSD = fromAmount * fromPriceUSD;
    const toValueUSD = toAmount * toPriceUSD;
    const profitUSD = toValueUSD - fromValueUSD;

    const marketRate = fromPriceUSD / toPriceUSD;
    const offerRate = toAmount / fromAmount;
    let percentDiff;

    if (isSentOffers || isOwnOffer) {
        percentDiff = ((toValueUSD / fromValueUSD) - 1) * 100;
    } else {
        percentDiff = ((fromValueUSD / toValueUSD) - 1) * 100;
    }

    const formattedPercentDiff = percentDiff.toFixed(2);
    const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" :
                             (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);

    const profitLabel = (isSentOffers || isOwnOffer) ? "Max Profit" : "Max Loss";
    const actionLabel = (isSentOffers || isOwnOffer) ? "selling" : "buying";
    const directionLabel = (isSentOffers || isOwnOffer) ? "receiving" : "paying";

    return `
        <p class="font-bold mb-1">Profit/Loss Calculation:</p>
        <p>You are ${actionLabel} ${fromAmount.toFixed(8)} ${coinFrom} ($${fromValueUSD.toFixed(2)} USD) <br/> and ${directionLabel} ${toAmount.toFixed(8)} ${coinTo} ($${toValueUSD.toFixed(2)} USD).</p>
        <p class="mt-1">Percentage difference: ${percentDiffDisplay}%</p>
        <p>${profitLabel}: ${profitUSD > 0 ? '' : '-'}$${Math.abs(profitUSD).toFixed(2)} USD</p>
        <p class="font-bold mt-2">Calculation:</p>
        <p>Percentage = ${(isSentOffers || isOwnOffer) ?
            "((To Amount in USD / From Amount in USD) - 1) * 100" :
            "((From Amount in USD / To Amount in USD) - 1) * 100"}</p>
        <p>USD ${profitLabel} = To Amount in USD - From Amount in USD</p>
        <p class="font-bold mt-1">Interpretation:</p>
        ${(isSentOffers || isOwnOffer) ? `
            <p><span class="text-green-500">Positive percentage:</span> You're selling above market rate (profitable)</p>
            <p><span class="text-red-500">Negative percentage:</span> You're selling below market rate (loss)</p>
        ` : `
            <p><span class="text-green-500">Positive percentage:</span> You're buying below market rate (savings)</p>
            <p><span class="text-red-500">Negative percentage:</span> You're buying above market rate (premium)</p>
        `}
        <p class="mt-1"><strong>Note:</strong> ${(isSentOffers || isOwnOffer) ?
            "As a seller, a positive percentage means <br/> you're selling for more than the current market value." :
            "As a buyer, a positive percentage indicates </br> potential savings compared to current market rates."}</p>
        <p class="mt-1"><strong>Market Rate:</strong> 1 ${coinFrom} = ${marketRate.toFixed(8)} ${coinTo}</p>
        <p><strong>Offer Rate:</strong> 1 ${coinFrom} = ${offerRate.toFixed(8)} ${coinTo}</p>
    `;
}

function createCombinedRateTooltip(offer, coinFrom, coinTo, treatAsSentOffer) {
    const rate = parseFloat(offer.rate) || 0;
    const inverseRate = rate ? (1 / rate) : 0;

    const getPriceKey = (coin) => {
        if (!coin) return null;
        
        const lowerCoin = coin.toLowerCase();

        if (lowerCoin === 'zcoin') return 'firo';

        if (lowerCoin === 'bitcoin cash' || lowerCoin === 'bitcoincash' || lowerCoin === 'bch') {
            if (latestPrices && latestPrices['bitcoin-cash']) {
                return 'bitcoin-cash';
            } else if (latestPrices && latestPrices['bch']) {
                return 'bch';
            }

            return 'bitcoin-cash';
        }

        if (lowerCoin === 'part' || lowerCoin === 'particl' || lowerCoin.includes('particl')) {
            return 'part';
        }

        if (window.config && window.config.coinMappings && window.config.coinMappings.nameToSymbol) {
            const symbol = window.config.coinMappings.nameToSymbol[coin];
            if (symbol) {
                if (symbol.toUpperCase() === 'BCH') {

                    if (latestPrices && latestPrices['bitcoin-cash']) {
                        return 'bitcoin-cash';
                    } else if (latestPrices && latestPrices['bch']) {
                        return 'bch';
                    }
                    return 'bitcoin-cash'; // Default
                }
                if (symbol.toUpperCase() === 'PART') {
                    return 'part';
                }
                return symbol.toLowerCase();
            }
        }
        return lowerCoin;
    };

    const fromSymbol = getPriceKey(coinFrom);
    const toSymbol = getPriceKey(coinTo);

    let fromPriceUSD = latestPrices && fromSymbol ? latestPrices[fromSymbol]?.usd : null;
    let toPriceUSD = latestPrices && toSymbol ? latestPrices[toSymbol]?.usd : null;

    if (!fromPriceUSD && window.tableRateModule) {
        fromPriceUSD = tableRateModule.getFallbackValue(fromSymbol);
    }
    if (!toPriceUSD && window.tableRateModule) {
        toPriceUSD = tableRateModule.getFallbackValue(toSymbol);
    }

    if (fromPriceUSD === null || toPriceUSD === null ||
        fromPriceUSD === undefined || toPriceUSD === undefined ||
        isNaN(fromPriceUSD) || isNaN(toPriceUSD)) {
        return `
            <p class="font-bold mb-1">Exchange Rate Information</p>
            <p>Market price data is temporarily unavailable.</p>
            <p class="font-bold mt-2">Current Offer Rates:</p>
            <p>1 ${coinFrom} = ${rate.toFixed(8)} ${coinTo}</p>
            <p>1 ${coinTo} = ${inverseRate.toFixed(8)} ${coinFrom}</p>
            <p class="font-bold mt-2">Note:</p>
            <p>Market comparison will be available when price data is restored.</p>
        `;
    }

    const rateInUSD = rate * toPriceUSD;
    const marketRate = fromPriceUSD / toPriceUSD;
    const percentDiff = marketRate ? ((rate - marketRate) / marketRate) * 100 : 0;
    const formattedPercentDiff = percentDiff.toFixed(2);
    const percentDiffDisplay = formattedPercentDiff === "0.00" ? "0.00" :
    (percentDiff > 0 ? `+${formattedPercentDiff}` : formattedPercentDiff);
    const aboveOrBelow = percentDiff > 0 ? "above" : percentDiff < 0 ? "below" : "at";
    const action = treatAsSentOffer ? "selling" : "buying";

    return `
        <p class="font-bold mb-1">Exchange Rate Explanation:</p>
        <p>This offer is ${action} ${coinFrom} for ${coinTo} <br/>at a rate that is ${percentDiffDisplay}% ${aboveOrBelow} market price.</p>
        <p class="font-bold mt-1">Exchange Rates:</p>
        <p>1 ${coinFrom} = ${rate.toFixed(8)} ${coinTo}</p>
        <p>1 ${coinTo} = ${inverseRate.toFixed(8)} ${coinFrom}</p>
        <p class="font-bold mt-2">USD Equivalent:</p>
        <p>1 ${coinFrom} = $${rateInUSD.toFixed(2)} USD</p>
        <p class="font-bold mt-2">Current market prices:</p>
        <p>${coinFrom}: $${fromPriceUSD.toFixed(2)} USD</p>
        <p>${coinTo}: $${toPriceUSD.toFixed(2)} USD</p>
        <p class="mt-1">Market rate: 1 ${coinFrom} = ${marketRate.toFixed(8)} ${coinTo}</p>
    `;
}

function updateTooltipTargets(row, uniqueId) {
    const tooltipElements = [
        { prefix: 'tooltip-active', selector: '[data-tooltip-target^="tooltip-active"]' },
        { prefix: 'tooltip-recipient', selector: '[data-tooltip-target^="tooltip-recipient"]' },
        { prefix: 'tooltip-wallet', selector: '[data-tooltip-target^="tooltip-wallet"]' },
        { prefix: 'tooltip-offer', selector: '[data-tooltip-target^="tooltip-offer"]' },
        { prefix: 'tooltip-wallet-maker', selector: '[data-tooltip-target^="tooltip-wallet-maker"]' },
        { prefix: 'tooltip-rate', selector: '[data-tooltip-target^="tooltip-rate"]' },
        { prefix: 'percentage-tooltip', selector: '[data-tooltip-target^="percentage-tooltip"]' }
    ];

    tooltipElements.forEach(({ prefix, selector }) => {
        const element = row.querySelector(selector);
        if (element) {
            element.setAttribute('data-tooltip-target', `${prefix}-${uniqueId}`);
        }
    });
}

function applyFilters() {
    if (filterTimeout) {
        clearTimeout(filterTimeout);
        filterTimeout = null;
    }

    try {
        filterTimeout = setTimeout(() => {
            currentPage = 1;
            jsonData = filterAndSortData();
            updateOffersTable();
            updateClearFiltersButton();
            filterTimeout = null;
        }, 250);
    } catch (error) {
        console.error('Error in filter timeout:', error);
        filterTimeout = null;
    }
}

function clearFilters() {
    filterForm.reset();

    const selectElements = filterForm.querySelectorAll('select');
    selectElements.forEach(select => {
        select.value = 'any';
        const event = new Event('change', { bubbles: true });
        select.dispatchEvent(event);
    });

    const statusSelect = document.getElementById('status');
    if (statusSelect) {
        statusSelect.value = 'any';
    }

    jsonData = [...originalJsonData];
    currentPage = 1;

    const storageKey = isSentOffers ? 'sentOffersTableSettings' : 'networkOffersTableSettings';
    localStorage.removeItem(storageKey);

    updateOffersTable();
    updateCoinFilterImages();
    updateClearFiltersButton();
}

function hasActiveFilters() {
    const selectElements = filterForm.querySelectorAll('select');
    let hasChangedFilters = false;

    selectElements.forEach(select => {
        if (select.value !== 'any') {
            hasChangedFilters = true;
        }
    });

    return hasChangedFilters;
}

function formatTimeLeft(timestamp) {
    return window.config.utils.formatTimeLeft(timestamp);
}

function getDisplayName(coinName) {
    if (window.CoinManager) {
        return window.CoinManager.getDisplayName(coinName) || coinName;
    }
    if (coinName.toLowerCase() === 'zcoin') {
        return 'Firo';
    }
    return window.config.coinMappings.nameToDisplayName[coinName] || coinName;
}

function getCoinSymbolLowercase(coin) {
    if (typeof coin === 'string') {
        if (coin.toLowerCase() === 'bitcoin cash') {
            return 'bitcoin-cash';
        }
        return (window.config.coinMappings.nameToSymbol[coin] || coin).toLowerCase();
    } else if (coin && typeof coin === 'object' && coin.symbol) {
        return coin.symbol.toLowerCase();
    } else {
        return 'unknown';
    }
}

function coinMatches(offerCoin, filterCoin) {
    if (window.CoinManager) {
        return window.CoinManager.coinMatches(offerCoin, filterCoin);
    }
    return window.config.coinMatches(offerCoin, filterCoin);
}

function getProfitColorClass(percentage) {
    const numericPercentage = parseFloat(percentage);
    if (numericPercentage > 0) return 'text-green-500';
    if (numericPercentage < 0) return 'text-red-500';
    if (numericPercentage === 0) return 'text-yellow-400';
    return 'text-white';
}

function isOfferExpired(offer) {
    if (isSentOffers) {
        return false;
    }
    const currentTime = Math.floor(Date.now() / 1000);
    const isExpired = offer.expire_at <= currentTime;
    return isExpired;
}

function formatTime(timestamp, addAgoSuffix = false) {
    return window.config.utils.formatTime(timestamp, addAgoSuffix);
}

function escapeHtml(unsafe) {
    return window.config.utils.escapeHtml(unsafe);
}

function getPriceKey(coin) {

    if (window.CoinManager) {
        return window.CoinManager.getPriceKey(coin);
    }

    if (!coin) return null;
    
    const lowerCoin = coin.toLowerCase();

    if (lowerCoin === 'zcoin') {
        return 'firo';
    }

    if (lowerCoin === 'bitcoin cash' || lowerCoin === 'bitcoincash' || lowerCoin === 'bch') {
        return 'bitcoin-cash';
    }

    if (lowerCoin === 'part' || lowerCoin === 'particl' || 
        lowerCoin.includes('particl')) {
        return 'particl';
    }

    return lowerCoin;
}

function getCoinSymbol(fullName) {

    if (window.CoinManager) {
        return window.CoinManager.getSymbol(fullName) || fullName;
    }

    return window.config.coinMappings.nameToSymbol[fullName] || fullName;
}

function initializeTableEvents() {
    const filterForm = document.getElementById('filterForm');
    if (filterForm) {
        CleanupManager.addListener(filterForm, 'submit', (e) => {
            e.preventDefault();
            applyFilters();
        });

        CleanupManager.addListener(filterForm, 'change', () => {
            applyFilters();
            updateClearFiltersButton();
        });
    }

    const coinToSelect = document.getElementById('coin_to');
    const coinFromSelect = document.getElementById('coin_from');
    const statusSelect = document.getElementById('status');
    const sentFromSelect = document.getElementById('sent_from');

    if (coinToSelect) {
        CleanupManager.addListener(coinToSelect, 'change', () => {
            applyFilters();
            updateCoinFilterImages();
        });
    }

    if (coinFromSelect) {
        CleanupManager.addListener(coinFromSelect, 'change', () => {
            applyFilters();
            updateCoinFilterImages();
        });
    }

    if (statusSelect) {
        CleanupManager.addListener(statusSelect, 'change', () => {
            applyFilters();
        });
    }

    if (sentFromSelect) {
        CleanupManager.addListener(sentFromSelect, 'change', () => {
            applyFilters();
        });
    }

    const clearFiltersBtn = document.getElementById('clearFilters');
    if (clearFiltersBtn) {
        CleanupManager.addListener(clearFiltersBtn, 'click', () => {
            clearFilters();
            updateCoinFilterImages();
        });
    }

    const refreshButton = document.getElementById('refreshOffers');
    if (refreshButton) {
        let lastRefreshTime = 0;
        const REFRESH_COOLDOWN = 6000;
        let countdownInterval;

        CleanupManager.addListener(refreshButton, 'click', async () => {
            const now = Date.now();
            if (now - lastRefreshTime < REFRESH_COOLDOWN) {
                console.log('Refresh rate limited. Please wait before refreshing again.');
                const startTime = now;
                const refreshText = document.getElementById('refreshText');

                refreshButton.classList.remove('bg-blue-600', 'hover:bg-green-600', 'border-blue-500', 'hover:border-green-600');
                refreshButton.classList.add('bg-red-600', 'border-red-500', 'cursor-not-allowed');

                if (countdownInterval) clearInterval(countdownInterval);

                countdownInterval = setInterval(() => {
                    const currentTime = Date.now();
                    const elapsedTime = currentTime - startTime;
                    const remainingTime = Math.ceil((REFRESH_COOLDOWN - elapsedTime) / 1000);

                    if (remainingTime <= 0) {
                        clearInterval(countdownInterval);
                        refreshText.textContent = 'Refresh';

                        refreshButton.classList.remove('bg-red-600', 'border-red-500', 'cursor-not-allowed');
                        refreshButton.classList.add('bg-blue-600', 'hover:bg-green-600', 'border-blue-500', 'hover:border-green-600');
                    } else {
                        refreshText.textContent = `Refresh (${remainingTime}s)`;
                    }
                }, 100);
                return;
            }

            console.log('Manual refresh initiated');
            lastRefreshTime = now;
            const refreshIcon = document.getElementById('refreshIcon');
            const refreshText = document.getElementById('refreshText');
            refreshButton.disabled = true;
            refreshIcon.classList.add('animate-spin');
            refreshText.textContent = 'Refreshing...';
            refreshButton.classList.add('opacity-75', 'cursor-wait');

            try {
                const cachedPrices = CacheManager.get('prices_coingecko');
                const previousPrices = cachedPrices ? cachedPrices.value : null;
                CacheManager.clear();
                window.isManualRefresh = true;
                const endpoint = isSentOffers ? '/json/sentoffers' : '/json/offers';
                const response = await fetch(endpoint);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                const newData = await response.json();
                const processedNewData = Array.isArray(newData) ? newData : Object.values(newData);
                jsonData = formatInitialData(processedNewData);
                originalJsonData = [...jsonData];
                const priceData = await fetchLatestPrices();
                if (!priceData && previousPrices) {
                    console.log('Using previous price data after failed refresh');
                    latestPrices = previousPrices;
                    await updateOffersTable();
                } else if (priceData) {
                    latestPrices = priceData;
                    await updateOffersTable();
                } else {
                    throw new Error('Unable to fetch price data');
                }
                updatePaginationInfo();
                lastRefreshTime = now;
                updateLastRefreshTime();

                console.log('Manual refresh completed successfully');

            } catch (error) {
                console.error('Error during manual refresh:', error);
                NetworkManager.handleNetworkError(error);
                ui.displayErrorMessage('Unable to refresh data. Previous data will be preserved.');

                const cachedData = CacheManager.get('prices_coingecko');
                if (cachedData?.value) {
                    latestPrices = cachedData.value;
                    await updateOffersTable();
                }
            } finally {
                window.isManualRefresh = false;
                refreshButton.disabled = false;
                refreshIcon.classList.remove('animate-spin');
                refreshText.textContent = 'Refresh';
                refreshButton.classList.remove('opacity-75', 'cursor-wait');

                refreshButton.classList.remove('bg-red-600', 'border-red-500', 'cursor-not-allowed');
                refreshButton.classList.add('bg-blue-600', 'hover:bg-green-600', 'border-blue-500', 'hover:border-green-600');

                if (countdownInterval) {
                    clearInterval(countdownInterval);
                }
            }
        });
    }

    const prevPageButton = document.getElementById('prevPage');
    const nextPageButton = document.getElementById('nextPage');

    if (prevPageButton) {
        CleanupManager.addListener(prevPageButton, 'click', async () => {
            if (currentPage > 1 && !isPaginationInProgress) {
                try {
                    isPaginationInProgress = true;
                    const oldPage = currentPage;
                    currentPage--;
                    await updateOffersTable({ fromPaginationClick: true });
                    updatePaginationInfo();
                } finally {
                    // Use setTimeout to prevent immediate re-triggers
                    setTimeout(() => {
                        isPaginationInProgress = false;
                    }, 100);
                }
            }
        });
    }

    if (nextPageButton) {
        CleanupManager.addListener(nextPageButton, 'click', async () => {
            const validOffers = getValidOffers();
            const totalPages = Math.ceil(validOffers.length / itemsPerPage);
            if (currentPage < totalPages && !isPaginationInProgress) {
                try {
                    isPaginationInProgress = true;
                    const oldPage = currentPage;
                    currentPage++;
                    await updateOffersTable({ fromPaginationClick: true });
                    updatePaginationInfo();
                } finally {
                    setTimeout(() => {
                        isPaginationInProgress = false;
                    }, 100);
                }
            }
        });
    }

    document.querySelectorAll('th[data-sortable="true"]').forEach(header => {
        CleanupManager.addListener(header, 'click', () => {
            const columnIndex = parseInt(header.getAttribute('data-column-index'));
            handleTableSort(columnIndex, header);
        });
    });
}

function handleTableSort(columnIndex, header) {
    if (currentSortColumn === columnIndex) {
        if (currentSortDirection === null) {
            currentSortDirection = 'desc';
        } else if (currentSortDirection === 'desc') {
            currentSortDirection = 'asc';
        } else if (currentSortDirection === 'asc') {
            currentSortColumn = null;
            currentSortDirection = null;
        }
    } else {
        currentSortColumn = columnIndex;
        currentSortDirection = 'desc';
    }

    document.querySelectorAll('th[data-sortable="true"]').forEach(th => {
        const columnSpan = th.querySelector('span:not(.sort-icon)');
        const icon = th.querySelector('.sort-icon');
        const thisColumnIndex = parseInt(th.getAttribute('data-column-index'));

        if (thisColumnIndex === columnIndex) {
            if (columnSpan) {
                columnSpan.classList.remove('text-gray-600', 'dark:text-gray-300');
                columnSpan.classList.add('text-blue-500', 'dark:text-blue-500');
            }
            if (icon) {
                icon.classList.remove('text-gray-600', 'dark:text-gray-400');
                icon.classList.add('text-blue-500', 'dark:text-blue-500');

                if (currentSortDirection === 'desc') {
                    icon.textContent = '↓';
                } else if (currentSortDirection === 'asc') {
                    icon.textContent = '↑';
                } else {
                    icon.textContent = '↓';
                    columnSpan.classList.remove('text-blue-500', 'dark:text-blue-500');
                    columnSpan.classList.add('text-gray-600', 'dark:text-gray-300');
                    icon.classList.remove('text-blue-500', 'dark:text-blue-500');
                    icon.classList.add('text-gray-600', 'dark:text-gray-400');
                }
            }
        } else {
            if (columnSpan) {
                columnSpan.classList.remove('text-blue-500', 'dark:text-blue-500');
                columnSpan.classList.add('text-gray-600', 'dark:text-gray-300');
            }
            if (icon) {
                icon.classList.remove('text-blue-500', 'dark:text-blue-500');
                icon.classList.add('text-gray-600', 'dark:text-gray-400');
                icon.textContent = '↓';
            }
        }
    });

    saveFilterSettings();

    if (window.sortTimeout) {
        clearTimeout(window.sortTimeout);
    }

    window.sortTimeout = setTimeout(() => {
        applyFilters();
    }, 100);
}

async function initializeTableAndData() {
    loadSavedSettings();
    updateClearFiltersButton();
    initializeTableEvents();
    initializeTooltips();
    updateCoinFilterImages();

    try {
        await fetchOffers();
        applyFilters();
    } catch (error) {
        console.error('Error loading initial data:', error);
        NetworkManager.handleNetworkError(error);
        ui.displayErrorMessage('Error loading data. Retrying in background...');
    }
}

function loadSavedSettings() {
    const storageKey = isSentOffers ? 'sentOffersTableSettings' : 'networkOffersTableSettings';
    const saved = localStorage.getItem(storageKey);

    if (saved) {
        const settings = JSON.parse(saved);

        ['coin_to', 'coin_from', 'status', 'sent_from'].forEach(id => {
            const element = document.getElementById(id);
            if (element && settings[id]) element.value = settings[id];
        });

        if (settings.sortColumn !== undefined) {
            currentSortColumn = settings.sortColumn;
            currentSortDirection = settings.sortDirection;
            updateSortIndicators();
        }
    }
}

function updateSortIndicators() {
    document.querySelectorAll('.sort-icon').forEach(icon => {
        icon.classList.remove('text-blue-500');
        icon.textContent = '↓';
    });

    const sortIcon = document.getElementById(`sort-icon-${currentSortColumn}`);
    if (sortIcon) {
        sortIcon.textContent = currentSortDirection === 'asc' ? '↑' : '↓';
        sortIcon.classList.add('text-blue-500');
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    try {
        if (typeof window.PriceManager === 'undefined') {
            console.error('PriceManager module not loaded');
            ui.displayErrorMessage('Price data unavailable. Some features may not work correctly.');
        }

        if (initializeTableRateModule()) {
            tableRateModule.init();
        }

        await initializeTableAndData();

        if (window.PriceManager) {
            window.PriceManager.addEventListener('priceUpdate', function(prices) {
                latestPrices = prices;
                updateProfitLossDisplays();
            });
        }

        if (window.WebSocketManager) {
            WebSocketManager.addMessageHandler('message', async (data) => {
                if (data.event === 'new_offer' || data.event === 'offer_revoked') {
                    console.log('WebSocket event received:', data.event);
                    try {

                        const previousPrices = latestPrices;

                        const offersResponse = await fetch(isSentOffers ? '/json/sentoffers' : '/json/offers');
                        if (!offersResponse.ok) {
                            throw new Error(`HTTP error! status: ${offersResponse.status}`);
                        }
                        
                        const newData = await offersResponse.json();
                        const processedNewData = Array.isArray(newData) ? newData : Object.values(newData);
                        jsonData = formatInitialData(processedNewData);
                        originalJsonData = [...jsonData];

                        let priceData;
                        if (window.PriceManager) {
                            priceData = await window.PriceManager.getPrices(true);
                        } else {
                            priceData = await fetchLatestPrices();
                        }
                        
                        if (priceData) {
                            latestPrices = priceData;
                            CacheManager.set('prices_coingecko', priceData, 'prices');
                        } else if (previousPrices) {
                            console.log('Using previous price data after failed refresh');
                            latestPrices = previousPrices;
                        }

                        await updateOffersTable();
 
                        updateProfitLossDisplays();

                        document.querySelectorAll('.usd-value').forEach(usdValue => {
                            const coinName = usdValue.getAttribute('data-coin');
                            if (coinName) {
                                const priceKey = getPriceKey(coinName);
                                const price = latestPrices[priceKey]?.usd;
                                if (price !== undefined && price !== null) {
                                    const amount = parseFloat(usdValue.getAttribute('data-amount') || '0');
                                    if (!isNaN(amount) && amount > 0) {
                                        const usdValue = amount * price;
                                        usdValue.textContent = tableRateModule.formatUSD(usdValue);
                                    }
                                }
                            }
                        });

                        updatePaginationInfo();

                        console.log('WebSocket-triggered refresh completed successfully');
                    } catch (error) {
                        console.error('Error during WebSocket-triggered refresh:', error);
                        NetworkManager.handleNetworkError(error);
                    }
                }
            });

            if (!WebSocketManager.isConnected()) {
                WebSocketManager.connect();
            }
        }

        document.querySelectorAll('th[data-sortable="true"]').forEach(header => {
            CleanupManager.addListener(header, 'click', () => {
                const columnIndex = parseInt(header.getAttribute('data-column-index'), 10);
                if (columnIndex !== null && !isNaN(columnIndex)) {
                    handleTableSort(columnIndex, header);
                }
            });
        });

        if (window.NetworkManager) {
            NetworkManager.addHandler('online', () => {
                updateConnectionStatus('connected');
                if (document.getElementById('error-overlay').classList.contains('hidden')) {
                    fetchOffers();
                }
            });

            NetworkManager.addHandler('offline', () => {
                updateConnectionStatus('disconnected');
            });
        }

        if (window.config.autoRefreshEnabled) {
            startAutoRefresh();
        }

        const filterForm = document.getElementById('filterForm');
        if (filterForm) {
            filterForm.querySelectorAll('select').forEach(select => {
                CleanupManager.addListener(select, 'change', () => {
                    applyFilters();
                    updateCoinFilterImages();
                    updateClearFiltersButton();
                });
            });
        }

        const clearFiltersBtn = document.getElementById('clearFilters');
        if (clearFiltersBtn) {
            CleanupManager.addListener(clearFiltersBtn, 'click', clearFilters);
        }

        const rowTimeInterval = setInterval(updateRowTimes, 30000);
        if (CleanupManager.registerResource) {
            CleanupManager.registerResource('rowTimeInterval', rowTimeInterval, () => {
                clearInterval(rowTimeInterval);
            });
        } else if (CleanupManager.addResource) {
            CleanupManager.addResource('rowTimeInterval', rowTimeInterval, () => {
                clearInterval(rowTimeInterval);
            });
        } else {

            window._cleanupIntervals = window._cleanupIntervals || [];
            window._cleanupIntervals.push(rowTimeInterval);
        }

    } catch (error) {
        console.error('Error during initialization:', error);
        ui.displayErrorMessage('Error initializing application. Please refresh the page.');
    }
});

async function cleanup() {
    console.log('Starting offers.js cleanup process');

    try {
        if (window.filterTimeout) {
            clearTimeout(window.filterTimeout);
            window.filterTimeout = null;
        }

        if (window.sortTimeout) {
            clearTimeout(window.sortTimeout);
            window.sortTimeout = null;
        }

        if (window.refreshInterval) {
            clearInterval(window.refreshInterval);
            window.refreshInterval = null;
        }

        if (window.countdownInterval) {
            clearInterval(window.countdownInterval);
            window.countdownInterval = null;
        }

        if (window._cleanupIntervals && Array.isArray(window._cleanupIntervals)) {
            window._cleanupIntervals.forEach(interval => {
                clearInterval(interval);
            });
            window._cleanupIntervals = [];
        }

        if (window.PriceManager) {
            if (typeof window.PriceManager.removeEventListener === 'function') {
                window.PriceManager.removeEventListener('priceUpdate');
            }
        }

        if (window.TooltipManager) {
            if (typeof window.TooltipManager.cleanup === 'function') {
                window.TooltipManager.cleanup();
            }
        }

        const filterForm = document.getElementById('filterForm');
        if (filterForm) {
            CleanupManager.removeListenersByElement(filterForm);
            
            filterForm.querySelectorAll('select').forEach(select => {
                CleanupManager.removeListenersByElement(select);
            });
        }

        const paginationButtons = document.querySelectorAll('#prevPage, #nextPage');
        paginationButtons.forEach(button => {
            CleanupManager.removeListenersByElement(button);
        });

        document.querySelectorAll('th[data-sortable="true"]').forEach(header => {
            CleanupManager.removeListenersByElement(header);
        });

        const offersBody = document.getElementById('offers-body');
        if (offersBody) {
            const rows = offersBody.querySelectorAll('tr');
            rows.forEach(row => {
                cleanupRow(row);
            });
            offersBody.innerHTML = '';
        }

        jsonData = null;
        originalJsonData = null;
        latestPrices = null;

        console.log('Offers.js cleanup completed');
    } catch (error) {
        console.error('Error during cleanup:', error);
    }
}

window.cleanup = cleanup;
