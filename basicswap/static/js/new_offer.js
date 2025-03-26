const DOM = {
    get: (id) => document.getElementById(id),
    getValue: (id) => {
        const el = document.getElementById(id);
        return el ? el.value : '';
    },
    setValue: (id, value) => {
        const el = document.getElementById(id);
        if (el) el.value = value;
    },
    addEvent: (id, event, handler) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener(event, handler);
    },
    query: (selector) => document.querySelector(selector),
    queryAll: (selector) => document.querySelectorAll(selector)
};

const Storage = {
    get: (key) => {
        try {
            return JSON.parse(localStorage.getItem(key));
        } catch(e) {
            console.warn(`Failed to retrieve item from storage: ${key}`, e);
            return null;
        }
    },
    set: (key, value) => {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch(e) {
            console.error(`Failed to save item to storage: ${key}`, e);
            return false;
        }
    },
    setRaw: (key, value) => {
        try {
            localStorage.setItem(key, value);
            return true;
        } catch(e) {
            console.error(`Failed to save raw item to storage: ${key}`, e);
            return false;
        }
    },
    getRaw: (key) => {
        try {
            return localStorage.getItem(key);
        } catch(e) {
            console.warn(`Failed to retrieve raw item from storage: ${key}`, e);
            return null;
        }
    }
};

const Ajax = {
    post: (url, data, onSuccess, onError) => {
        const xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function() {
            if (xhr.readyState !== XMLHttpRequest.DONE) return;
            if (xhr.status === 200) {
                if (onSuccess) {
                    try {
                        const response = xhr.responseText.startsWith('{') ? 
                            JSON.parse(xhr.responseText) : xhr.responseText;
                        onSuccess(response);
                    } catch (e) {
                        console.error('Failed to parse response:', e);
                        if (onError) onError('Invalid response format');
                    }
                }
            } else {
                console.error('Request failed:', xhr.statusText);
                if (onError) onError(xhr.statusText);
            }
        };
        xhr.open('POST', url);
        xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        xhr.send(data);
        return xhr;
    }
};

function handleNewOfferAddress() {
    const STORAGE_KEY = 'lastUsedAddressNewOffer';
    const selectElement = DOM.query('select[name="addr_from"]');
    const form = selectElement?.closest('form');

    if (!selectElement || !form) return;

    function loadInitialAddress() {
        const savedAddress = Storage.get(STORAGE_KEY);
        if (savedAddress) {
            try {
                selectElement.value = savedAddress.value;
            } catch (e) {
                selectFirstAddress();
            }
        } else {
            selectFirstAddress();
        }
    }

    function selectFirstAddress() {
        if (selectElement.options.length > 1) {
            const firstOption = selectElement.options[1];
            if (firstOption) {
                selectElement.value = firstOption.value;
                saveAddress(firstOption.value, firstOption.text);
            }
        }
    }

    function saveAddress(value, text) {
        Storage.set(STORAGE_KEY, { value, text });
    }

    form.addEventListener('submit', () => {
        saveAddress(selectElement.value, selectElement.selectedOptions[0].text);
    });

    selectElement.addEventListener('change', (event) => {
        saveAddress(event.target.value, event.target.selectedOptions[0].text);
    });

    loadInitialAddress();
}

const RateManager = {
    lookupRates: () => {
        const coinFrom = DOM.getValue('coin_from');
        const coinTo = DOM.getValue('coin_to');
        const ratesDisplay = DOM.get('rates_display');

        if (!coinFrom || !coinTo || !ratesDisplay) {
            console.log('Required elements for lookup_rates not found');
            return;
        }

        if (coinFrom === '-1' || coinTo === '-1') {
            alert('Coins from and to must be set first.');
            return;
        }

        const selectedCoin = (coinFrom === '15') ? '3' : coinFrom;

        ratesDisplay.innerHTML = '<p>Updating...</p>';

        const priceJsonElement = DOM.query(".pricejsonhidden");
        if (priceJsonElement) {
            priceJsonElement.classList.remove("hidden");
        }

        const params = 'coin_from=' + selectedCoin + '&coin_to=' + coinTo;

        Ajax.post('/json/rates', params, 
            (response) => {
                if (ratesDisplay) {
                    ratesDisplay.innerHTML = typeof response === 'string' ? 
                        response : '<pre><code>' + JSON.stringify(response, null, '  ') + '</code></pre>';
                }
            },
            (error) => {
                if (ratesDisplay) {
                    ratesDisplay.innerHTML = '<p>Error loading rates: ' + error + '</p>';
                }
            }
        );
    },
    
    getRateInferred: (event) => {
        if (event) event.preventDefault();

        const coinFrom = DOM.getValue('coin_from');
        const coinTo = DOM.getValue('coin_to');
        const rateElement = DOM.get('rate');

        if (!coinFrom || !coinTo || !rateElement) {
            console.log('Required elements for getRateInferred not found');
            return;
        }

        const params = 'coin_from=' + encodeURIComponent(coinFrom) + 
                      '&coin_to=' + encodeURIComponent(coinTo);

        DOM.setValue('rate', 'Loading...');

        Ajax.post('/json/rates', params, 
            (response) => {
                if (response.coingecko && response.coingecko.rate_inferred) {
                    DOM.setValue('rate', response.coingecko.rate_inferred);
                    RateManager.setRate('rate');
                } else {
                    DOM.setValue('rate', 'Error: No rate available');
                    console.error('Rate not available in response');
                }
            },
            (error) => {
                DOM.setValue('rate', 'Error: Rate lookup failed');
                console.error('Error fetching rate data:', error);
            }
        );
    },

    setRate: (valueChanged) => {
        const elements = {
            coinFrom: DOM.get('coin_from'),
            coinTo: DOM.get('coin_to'),
            amtFrom: DOM.get('amt_from'),
            amtTo: DOM.get('amt_to'),
            rate: DOM.get('rate'),
            rateLock: DOM.get('rate_lock'),
            swapType: DOM.get('swap_type')
        };

        if (!elements.coinFrom || !elements.coinTo || 
            !elements.amtFrom || !elements.amtTo || !elements.rate) {
            console.log('Required elements for setRate not found');
            return;
        }

        const values = {
            coinFrom: elements.coinFrom.value,
            coinTo: elements.coinTo.value,
            amtFrom: elements.amtFrom.value,
            amtTo: elements.amtTo.value,
            rate: elements.rate.value,
            lockRate: elements.rate.value == '' ? false : 
                     (elements.rateLock ? elements.rateLock.checked : false)
        };

        if (valueChanged === 'coin_from' || valueChanged === 'coin_to') {
            DOM.setValue('rate', '');
            return;
        }

        if (elements.swapType) {
            SwapTypeManager.setSwapTypeEnabled(
                values.coinFrom, 
                values.coinTo, 
                elements.swapType
            );
        }

        if (values.coinFrom == '-1' || values.coinTo == '-1') {
            return;
        }

        let params = 'coin_from=' + values.coinFrom + '&coin_to=' + values.coinTo;

        if (valueChanged == 'rate' || 
            (values.lockRate && valueChanged == 'amt_from') || 
            (values.amtTo == '' && valueChanged == 'amt_from')) {

            if (values.rate == '' || (values.amtFrom == '' && values.amtTo == '')) {
                return;
            } else if (values.amtFrom == '' && values.amtTo != '') {
                if (valueChanged == 'amt_from') {
                    return;
                }
                params += '&rate=' + values.rate + '&amt_to=' + values.amtTo;
            } else {
                params += '&rate=' + values.rate + '&amt_from=' + values.amtFrom;
            }
        } else if (values.lockRate && valueChanged == 'amt_to') {
            if (values.amtTo == '' || values.rate == '') {
                return;
            }
            params += '&amt_to=' + values.amtTo + '&rate=' + values.rate;
        } else {
            if (values.amtFrom == '' || values.amtTo == '') {
                return;
            }
            params += '&amt_from=' + values.amtFrom + '&amt_to=' + values.amtTo;
        }

        Ajax.post('/json/rate', params, 
            (response) => {
                if (response.hasOwnProperty('rate')) {
                    DOM.setValue('rate', response.rate);
                } else if (response.hasOwnProperty('amount_to')) {
                    DOM.setValue('amt_to', response.amount_to);
                } else if (response.hasOwnProperty('amount_from')) {
                    DOM.setValue('amt_from', response.amount_from);
                }
            },
            (error) => {
                console.error('Rate calculation failed:', error);
            }
        );
    }
};

function set_rate(valueChanged) {
    RateManager.setRate(valueChanged);
}

function lookup_rates() {
    RateManager.lookupRates();
}

function getRateInferred(event) {
    RateManager.getRateInferred(event);
}

const SwapTypeManager = {
    adaptor_sig_only_coins: ['6', '9', '8', '7', '13', '18', '17'],
    secret_hash_only_coins: ['11', '12'],

    setSwapTypeEnabled: (coinFrom, coinTo, swapTypeElement) => {
        if (!swapTypeElement) return;

        let makeHidden = false;
        coinFrom = String(coinFrom);
        coinTo = String(coinTo);

        if (SwapTypeManager.adaptor_sig_only_coins.includes(coinFrom) || 
            SwapTypeManager.adaptor_sig_only_coins.includes(coinTo)) {
            swapTypeElement.disabled = true;
            swapTypeElement.value = 'xmr_swap';
            makeHidden = true;
            swapTypeElement.classList.add('select-disabled');
        } else if (SwapTypeManager.secret_hash_only_coins.includes(coinFrom) || 
                  SwapTypeManager.secret_hash_only_coins.includes(coinTo)) {
            swapTypeElement.disabled = true;
            swapTypeElement.value = 'seller_first';
            makeHidden = true;
            swapTypeElement.classList.add('select-disabled');
        } else {
            swapTypeElement.disabled = false;
            swapTypeElement.classList.remove('select-disabled');
            swapTypeElement.value = 'xmr_swap';
        }

        let swapTypeHidden = DOM.get('swap_type_hidden');
        if (makeHidden) {
            if (!swapTypeHidden) {
                const form = DOM.get('form');
                if (form) {
                    swapTypeHidden = document.createElement('input');
                    swapTypeHidden.setAttribute('id', 'swap_type_hidden');
                    swapTypeHidden.setAttribute('type', 'hidden');
                    swapTypeHidden.setAttribute('name', 'swap_type');
                    form.appendChild(swapTypeHidden);
                }
            }
            if (swapTypeHidden) {
                swapTypeHidden.setAttribute('value', swapTypeElement.value);
            }
        } else if (swapTypeHidden) {
            swapTypeHidden.parentNode.removeChild(swapTypeHidden);
        }
    }
};

function set_swap_type_enabled(coinFrom, coinTo, swapTypeElement) {
    SwapTypeManager.setSwapTypeEnabled(coinFrom, coinTo, swapTypeElement);
}

const UIEnhancer = {
    handleErrorHighlighting: () => {
        const errMsgs = document.querySelectorAll('p.error_msg');

        const errorFieldMap = {
            'coin_to': ['coin_to', 'Coin To'],
            'coin_from': ['Coin From'],
            'amt_from': ['Amount From'],
            'amt_to': ['Amount To'],
            'amt_bid_min': ['Minimum Bid Amount'],
            'Select coin you send': ['coin_from', 'parentNode']
        };

        errMsgs.forEach(errMsg => {
            const text = errMsg.innerText;

            Object.entries(errorFieldMap).forEach(([field, keywords]) => {
                if (keywords.some(keyword => text.includes(keyword))) {
                    let element = DOM.get(field);

                    if (field === 'Select coin you send' && element) {
                        element = element.parentNode;
                    }

                    if (element) {
                        element.classList.add('error');
                    }
                }
            });
        });

        document.querySelectorAll('input.error, select.error').forEach(element => {
            element.addEventListener('focus', event => {
                event.target.classList.remove('error');
            });
        });
    },

    updateDisabledStyles: () => {
        document.querySelectorAll('select.disabled-select').forEach(select => {
            if (select.disabled) {
                select.classList.add('disabled-select-enabled');
            } else {
                select.classList.remove('disabled-select-enabled');
            }
        });

        document.querySelectorAll('input.disabled-input, input[type="checkbox"].disabled-input').forEach(input => {
            if (input.readOnly) {
                input.classList.add('disabled-input-enabled');
            } else {
                input.classList.remove('disabled-input-enabled');
            }
        });
    },

    setupCustomSelects: () => {
        const selectCache = {};

        function updateSelectCache(select) {
            if (!select || !select.options || select.selectedIndex === undefined) return;

            const selectedOption = select.options[select.selectedIndex];
            if (!selectedOption) return;

            const image = selectedOption.getAttribute('data-image');
            const name = selectedOption.textContent.trim();
            selectCache[select.id] = { image, name };
        }
        
        function setSelectData(select) {
            if (!select || !select.options || select.selectedIndex === undefined) return;

            const selectedOption = select.options[select.selectedIndex];
            if (!selectedOption) return;

            const image = selectedOption.getAttribute('data-image') || '';
            const name = selectedOption.textContent.trim();

            select.style.backgroundImage = image ? `url(${image}?${new Date().getTime()})` : '';

            const selectImage = select.nextElementSibling?.querySelector('.select-image');
            if (selectImage) {
                selectImage.src = image;
            }

            const selectNameElement = select.nextElementSibling?.querySelector('.select-name');
            if (selectNameElement) {
                selectNameElement.textContent = name;
            }

            updateSelectCache(select);
        }

        function setupCustomSelect(select) {
            if (!select) return;

            const options = select.querySelectorAll('option');
            const selectIcon = select.parentElement?.querySelector('.select-icon');
            const selectImage = select.parentElement?.querySelector('.select-image');
            
            if (!options || !selectIcon || !selectImage) return;
            
            options.forEach(option => {
                const image = option.getAttribute('data-image');
                if (image) {
                    option.style.backgroundImage = `url(${image})`;
                }
            });

            const storedValue = Storage.getRaw(select.name);
            if (storedValue && select.value == '-1') {
                select.value = storedValue;
            }

            select.addEventListener('change', () => {
                setSelectData(select);
                Storage.setRaw(select.name, select.value);
            });
            
            setSelectData(select);
            selectIcon.style.display = 'none';
            selectImage.style.display = 'none';
        }

        const selectIcons = document.querySelectorAll('.custom-select .select-icon');
        const selectImages = document.querySelectorAll('.custom-select .select-image');
        const selectNames = document.querySelectorAll('.custom-select .select-name');

        selectIcons.forEach(icon => icon.style.display = 'none');
        selectImages.forEach(image => image.style.display = 'none');
        selectNames.forEach(name => name.style.display = 'none');

        const customSelects = document.querySelectorAll('.custom-select select');
        customSelects.forEach(setupCustomSelect);
    }
};

function initializeApp() {
    handleNewOfferAddress();

    DOM.addEvent('get_rate_inferred_button', 'click', RateManager.getRateInferred);

    const coinFrom = DOM.get('coin_from');
    const coinTo = DOM.get('coin_to');
    const swapType = DOM.get('swap_type');

    if (coinFrom && coinTo && swapType) {
        SwapTypeManager.setSwapTypeEnabled(coinFrom.value, coinTo.value, swapType);

        coinFrom.addEventListener('change', function() {
            SwapTypeManager.setSwapTypeEnabled(this.value, coinTo.value, swapType);
            RateManager.setRate('coin_from');
        });

        coinTo.addEventListener('change', function() {
            SwapTypeManager.setSwapTypeEnabled(coinFrom.value, this.value, swapType);
            RateManager.setRate('coin_to');
        });
    }

    ['amt_from', 'amt_to', 'rate'].forEach(id => {
        DOM.addEvent(id, 'change', function() {
            RateManager.setRate(id);
        });

        DOM.addEvent(id, 'input', function() {
            RateManager.setRate(id);
        });
    });

    DOM.addEvent('rate_lock', 'change', function() {
        if (DOM.getValue('rate')) {
            RateManager.setRate('rate');
        }
    });

    DOM.addEvent('lookup_rates_button', 'click', RateManager.lookupRates);

    UIEnhancer.handleErrorHighlighting();
    UIEnhancer.updateDisabledStyles();
    UIEnhancer.setupCustomSelects();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}
