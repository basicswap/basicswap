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

function toPlainDecimal(value) {
    const num = typeof value === 'number' ? value : parseFloat(value);
    if (!isFinite(num)) return '';
    const s = String(num);
    if (!/[eE]/.test(s)) return s;
    const fixed = num.toFixed(20);
    return fixed.indexOf('.') >= 0
        ? fixed.replace(/0+$/, '').replace(/\.$/, '')
        : fixed;
}

const ErrorModal = {
    show: function(title, message) {
        const errorTitle = document.getElementById('errorTitle');
        const errorMessage = document.getElementById('errorMessage');
        const modal = document.getElementById('errorModal');

        if (errorTitle) errorTitle.textContent = title || 'Error';
        if (errorMessage) errorMessage.textContent = message || 'An error occurred';
        if (modal) modal.classList.remove('hidden');
    },

    hide: function() {
        const modal = document.getElementById('errorModal');
        if (modal) modal.classList.add('hidden');
    },

    init: function() {
        const errorOkBtn = document.getElementById('errorOk');
        if (errorOkBtn) {
            errorOkBtn.addEventListener('click', this.hide.bind(this));
        }
    }
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

    const NETWORK_KEY = 'lastUsedNetworkNewOffer';
    const networkSelect = DOM.query('select[name="addr_to"]');
    if (networkSelect) {
        const savedNetwork = Storage.get(NETWORK_KEY);
        if (savedNetwork && networkSelect.value === '-1' &&
            Array.from(networkSelect.options).some(o => o.value === savedNetwork.value)) {
            networkSelect.value = savedNetwork.value;
        }
        const saveNetwork = () => {
            const opt = networkSelect.selectedOptions[0];
            Storage.set(NETWORK_KEY, { value: networkSelect.value, text: opt ? opt.text : '' });
        };
        networkSelect.addEventListener('change', saveNetwork);
        form.addEventListener('submit', saveNetwork);
    }
}

const AddrFromSearch = {
    initialOptions: null,
    debounceTimer: null,
    requestSeq: 0,
    init: function() {
        const input = DOM.get('addr_from_search');
        const select = DOM.get('addr_from');
        if (!input || !select) return;
        this.initialOptions = Array.from(select.options).map(o => ({ value: o.value, text: o.text }));
        input.addEventListener('input', () => {
            clearTimeout(this.debounceTimer);
            this.debounceTimer = setTimeout(() => this.search(input.value.trim()), 300);
        });
    },
    search: function(query) {
        const select = DOM.get('addr_from');
        if (!select) return;
        if (!query) {
            this.render(select, this.initialOptions);
            return;
        }
        const seq = ++this.requestSeq;
        const params = 'use_type=offer_send_from&limit=50&search=' + encodeURIComponent(query);
        Ajax.post('/json/smsgaddresses', params, (resp) => {
            if (seq !== this.requestSeq) return;
            let results = [];
            try {
                const list = (typeof resp === 'string') ? JSON.parse(resp) : resp;
                if (Array.isArray(list)) {
                    results = list.map(a => ({ value: a.addr, text: a.addr + (a.note ? ' ' + a.note : '') }));
                }
            } catch (e) {
                results = [];
            }
            const options = [{ value: '-1', text: 'New Address' }].concat(results);
            this.render(select, options);
        });
    },
    render: function(select, options) {
        const current = select.value;
        select.innerHTML = '';
        let hasCurrent = false;
        options.forEach(o => {
            const opt = document.createElement('option');
            opt.value = o.value;
            opt.text = o.text;
            select.appendChild(opt);
            if (o.value === current) hasCurrent = true;
        });
        if (!hasCurrent && current && current !== '-1') {
            const opt = document.createElement('option');
            opt.value = current;
            opt.text = current;
            select.insertBefore(opt, select.options[1] || null);
            hasCurrent = true;
        }
        select.value = hasCurrent ? current : '-1';
    }
};

const AddrFromHint = {
    update: function() {
        const hint = DOM.get('addr-from-hint');
        const sel = DOM.get('addr_from');
        if (!hint || !sel) return;
        if (sel.value !== '-1') {
            hint.textContent = '';
            hint.className = 'text-xs mt-1';
            return;
        }
        hint.textContent = 'A new address will be created to identify this offer and receive its locked funds.';
        hint.className = 'text-xs mt-1 offer-hint-info';
    }
};

const FeeEstimate = {
    fee: null, 
    feeStr: null,
    pairKey: null,
    refresh: function() {
        const coinFrom = DOM.getValue('coin_from');
        const coinTo = DOM.getValue('coin_to');
        if (!coinFrom || coinFrom === '-1' || !coinTo || coinTo === '-1' || coinFrom === coinTo) {
            this.fee = null; this.feeStr = null; this.pairKey = null;
            return;
        }
        const key = coinFrom + ':' + coinTo;
        if (key === this.pairKey) return;
        this.pairKey = key;
        const params = 'coin_from=' + encodeURIComponent(coinFrom) +
            '&coin_to=' + encodeURIComponent(coinTo);
        Ajax.post('/json/offerfeeestimate', params, (resp) => {
            if (this.pairKey !== key) return;
            try {
                const obj = (typeof resp === 'string') ? JSON.parse(resp) : resp;
                const f = parseFloat(obj && obj.fee);
                if (isFinite(f)) { this.fee = f; this.feeStr = obj.fee; }
                else { this.fee = null; this.feeStr = null; }
            } catch (e) {
                this.fee = null; this.feeStr = null;
            }
            BalanceHint.update();
            AddrFromHint.update();
            OfferValidation.updateContinueState();
        }, () => {
            if (this.pairKey === key) { this.fee = null; this.feeStr = null; }
        });
    }
};
window.FeeEstimate = FeeEstimate;

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
                    DOM.setValue('rate', toPlainDecimal(response.coingecko.rate_inferred));
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

        const numOk = (v) => /^\d*\.?\d+$/.test(v);

        let params = 'coin_from=' + values.coinFrom + '&coin_to=' + values.coinTo;

        if (valueChanged == 'rate' ||
            (values.lockRate && valueChanged == 'amt_from') ||
            (values.amtTo == '' && valueChanged == 'amt_from')) {

            if (!numOk(values.rate) || (values.amtFrom == '' && values.amtTo == '')) {
                return;
            } else if (values.amtFrom == '' && values.amtTo != '') {
                if (valueChanged == 'amt_from' || !numOk(values.amtTo)) {
                    return;
                }
                params += '&rate=' + values.rate + '&amt_to=' + values.amtTo;
            } else {
                if (!numOk(values.amtFrom)) {
                    return;
                }
                params += '&rate=' + values.rate + '&amt_from=' + values.amtFrom;
            }
        } else if (values.lockRate && valueChanged == 'amt_to') {
            if (!numOk(values.amtTo) || !numOk(values.rate)) {
                return;
            }
            params += '&amt_to=' + values.amtTo + '&rate=' + values.rate;
        } else {
            if (!numOk(values.amtFrom) || !numOk(values.amtTo)) {
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
                if (window.OfferSummary) OfferSummary.update();
                if (typeof BalanceHint !== 'undefined') BalanceHint.update();
                if (typeof OfferValidation !== 'undefined') OfferValidation.updateContinueState();
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
    coins_without_segwit: ['11', '12'],

    setSwapTypeEnabled: (coinFrom, coinTo, swapTypeElement) => {
        if (!swapTypeElement) return;

        let makeHidden = false;
        coinFrom = String(coinFrom);
        coinTo = String(coinTo);

        if (
            SwapTypeManager.coins_without_segwit.includes(coinFrom) &&
            SwapTypeManager.coins_without_segwit.includes(coinTo)
        ) {
            swapTypeElement.disabled = true;
            swapTypeElement.value = 'seller_first';
            makeHidden = true;
            swapTypeElement.classList.add('select-disabled');
        } else {
            swapTypeElement.disabled = true;
            swapTypeElement.value = 'xmr_swap';
            makeHidden = true;
            swapTypeElement.classList.add('select-disabled');
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

const CoinPicker = {
    instances: [],
    imageFallback: '/static/images/other/coin.png',

    parseOption: (opt) => {
        const image = opt.getAttribute('data-image') || '';
        const balance = opt.getAttribute('data-balance');
        const pending = opt.getAttribute('data-pending');
        let label = opt.textContent.trim();
        const sep = ' - Balance:';
        if (label.includes(sep)) label = label.split(sep)[0].trim();
        return { value: opt.value, image, balance, pending, label };
    },

    makeIcon: (data) => {
        const img = document.createElement('img');
        img.className = 'coin-picker-icon';
        img.src = data.image || CoinPicker.imageFallback;
        img.alt = data.label;
        img.onerror = function() { this.onerror = null; this.src = CoinPicker.imageFallback; };
        return img;
    },

    makeText: (data, withBalance) => {
        const text = document.createElement('span');
        text.className = 'coin-picker-text';
        const name = document.createElement('span');
        name.className = 'coin-picker-name';
        name.textContent = data.label;
        text.appendChild(name);
        if (withBalance && data.balance !== null && data.balance !== undefined) {
            const bal = document.createElement('span');
            bal.className = 'coin-picker-balance';
            bal.textContent = 'Balance: ' + data.balance;
            text.appendChild(bal);

            const pendingNum = parseFloat(data.pending);
            if (!isNaN(pendingNum) && pendingNum > 0) {
                const pend = document.createElement('span');
                pend.className = 'coin-picker-pending';
                pend.textContent = '+' + data.pending + ' pending';
                text.appendChild(pend);
            }
        }
        return text;
    },

    renderButton: (inst) => {
        const opt = inst.select.options[inst.select.selectedIndex];
        const data = (opt && opt.value !== '-1') ? CoinPicker.parseOption(opt) : null;
        inst.button.innerHTML = '';

        const main = document.createElement('span');
        main.className = 'coin-picker-button-main';
        if (data) {
            main.appendChild(CoinPicker.makeIcon(data));
            main.appendChild(CoinPicker.makeText(data, false));
        } else {
            const ph = document.createElement('span');
            ph.className = 'coin-picker-placeholder';
            ph.textContent = inst.placeholder;
            main.appendChild(ph);
        }
        inst.button.appendChild(main);

        const chev = document.createElement('span');
        chev.className = 'coin-picker-chevron';
        chev.innerHTML = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>';
        inst.button.appendChild(chev);
    },

    renderList: (inst, filter) => {
        inst.list.innerHTML = '';
        const f = (filter || '').trim().toLowerCase();
        let shown = 0;

        let opts = Array.from(inst.select.options).filter(o => o.value !== '-1');
        if (inst.withBalance) {
            opts.sort((a, b) => {
                const ba = parseFloat(a.getAttribute('data-balance')) || 0;
                const bb = parseFloat(b.getAttribute('data-balance')) || 0;
                if (bb !== ba) return bb - ba;
                return CoinPicker.parseOption(a).label.localeCompare(
                    CoinPicker.parseOption(b).label);
            });
        }

        opts.forEach(opt => {
            const data = CoinPicker.parseOption(opt);
            if (f && !data.label.toLowerCase().includes(f)) return;
            shown++;

            const item = document.createElement('button');
            item.type = 'button';
            item.className = 'coin-picker-item';
            item.setAttribute('role', 'option');
            if (opt.value === inst.select.value) {
                item.classList.add('selected');
                item.setAttribute('aria-selected', 'true');
            }
            if (inst.withBalance) {
                const bal = parseFloat(data.balance);
                if (!isNaN(bal) && bal <= 0) item.classList.add('coin-picker-zero');
            }
            item.appendChild(CoinPicker.makeIcon(data));
            item.appendChild(CoinPicker.makeText(data, inst.withBalance));
            item.addEventListener('click', (e) => {
                e.preventDefault();
                CoinPicker.choose(inst, opt.value);
            });
            inst.list.appendChild(item);
        });

        if (shown === 0) {
            const empty = document.createElement('div');
            empty.className = 'coin-picker-empty';
            empty.textContent = 'No coins found';
            inst.list.appendChild(empty);
        }
    },

    choose: (inst, value) => {
        inst.select.value = value;
        CoinPicker.renderButton(inst);
        inst.button.classList.remove('coin-picker-error');
        try { Storage.setRaw(inst.select.name, value); } catch (e) {}
        inst.select.dispatchEvent(new Event('change', { bubbles: true }));
        CoinPicker.close(inst);
    },

    open: (inst) => {
        CoinPicker.instances.forEach(i => { if (i !== inst) CoinPicker.close(i); });
        CoinPicker.renderList(inst);
        inst.panel.style.display = 'block';
        inst.button.setAttribute('aria-expanded', 'true');
        inst.container.classList.add('open');
        inst.button.classList.remove('coin-picker-error');
        if (inst.search) {
            inst.search.value = '';
            setTimeout(() => inst.search.focus(), 0);
        }
    },

    close: (inst) => {
        inst.panel.style.display = 'none';
        inst.button.setAttribute('aria-expanded', 'false');
        inst.container.classList.remove('open');
    },

    toggle: (inst) => {
        if (inst.panel.style.display === 'none') {
            CoinPicker.open(inst);
        } else {
            CoinPicker.close(inst);
        }
    },

    refreshAll: () => {
        CoinPicker.instances.forEach(inst => {
            CoinPicker.renderButton(inst);
            if (inst.panel.style.display !== 'none') {
                CoinPicker.renderList(inst, inst.search ? inst.search.value : '');
            }
        });
    },

    fireRestored: () => {
        CoinPicker.instances.forEach(inst => {
            if (inst.restored) {
                inst.restored = false;
                inst.select.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });
    },

    build: (container) => {
        const select = container.querySelector('select');
        if (!select) return null;

        const withBalance = container.getAttribute('data-with-balance') === 'true';
        const placeholder = container.getAttribute('data-placeholder') || 'Select coin';

        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'coin-picker-button';
        button.setAttribute('aria-haspopup', 'listbox');
        button.setAttribute('aria-expanded', 'false');

        const panel = document.createElement('div');
        panel.className = 'coin-picker-panel';
        panel.setAttribute('role', 'listbox');
        panel.style.display = 'none';

        const searchWrap = document.createElement('div');
        searchWrap.className = 'coin-picker-search-wrap';
        const search = document.createElement('input');
        search.type = 'text';
        search.className = 'coin-picker-search';
        search.placeholder = 'Search coins...';
        search.setAttribute('aria-label', 'Search coins');
        searchWrap.appendChild(search);

        const list = document.createElement('div');
        list.className = 'coin-picker-list';

        panel.appendChild(searchWrap);
        panel.appendChild(list);
        container.appendChild(button);
        container.appendChild(panel);

        const inst = { container, select, button, panel, search, list, withBalance, placeholder };

        button.addEventListener('click', (e) => {
            e.preventDefault();
            CoinPicker.toggle(inst);
        });
        search.addEventListener('input', () => CoinPicker.renderList(inst, search.value));
        search.addEventListener('click', (e) => e.stopPropagation());

        CoinPicker.renderButton(inst);
        container.classList.add('coin-picker-ready');
        return inst;
    },

    init: function() {
        const containers = document.querySelectorAll('[data-coin-picker]');
        if (!containers.length) return;

        containers.forEach(container => {
            const inst = this.build(container);
            if (inst) this.instances.push(inst);
        });

        this.instances.forEach(inst => {
            const stored = Storage.getRaw(inst.select.name);
            if (stored && inst.select.value === '-1' &&
                Array.from(inst.select.options).some(o => o.value === stored)) {
                inst.select.value = stored;
                inst.restored = true;
                CoinPicker.renderButton(inst);
            }
        });

        document.addEventListener('click', (e) => {
            CoinPicker.instances.forEach(inst => {
                if (!inst.container.contains(e.target)) CoinPicker.close(inst);
            });
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                CoinPicker.instances.forEach(inst => CoinPicker.close(inst));
            }
        });
    }
};

const OfferSummary = {
    coinName: (selectId) => {
        const select = DOM.get(selectId);
        if (!select || select.selectedIndex < 0) return '';
        const opt = select.options[select.selectedIndex];
        if (!opt || opt.value === '-1') return '';
        return opt.textContent.split(' - Balance:')[0].trim();
    },

    selectedBalance: (selectId) => {
        const select = DOM.get(selectId);
        if (!select || select.selectedIndex < 0) return null;
        const opt = select.options[select.selectedIndex];
        if (!opt || opt.value === '-1') return null;
        const bal = opt.getAttribute('data-balance');
        return bal === null ? null : parseFloat(bal);
    },

    setText: (id, value) => {
        const el = DOM.get(id);
        if (el) el.textContent = value;
    },

    usdPrices: null,

    loadPrices: function() {
        if (!window.PriceManager || typeof PriceManager.getPrices !== 'function') return;
        try {
            Promise.resolve(PriceManager.getPrices()).then(prices => {
                if (prices) {
                    this.usdPrices = prices;
                    this.update();
                }
            }).catch(() => {});
        } catch (e) {}
    },

    usdFor: function(coinName, amount) {
        const amt = parseFloat(amount);
        if (!this.usdPrices || !coinName || isNaN(amt) || amt <= 0) return '';
        let key = coinName.toLowerCase().replace(/ /g, '-');
        if (window.CoinManager && typeof CoinManager.getPriceKey === 'function') {
            try { key = CoinManager.getPriceKey(coinName) || key; } catch (e) {}
        }
        const entry = this.usdPrices[key];
        const price = entry && (entry.usd !== undefined ? entry.usd : entry);
        if (typeof price !== 'number' || isNaN(price) || price <= 0) return '';
        const value = amt * price;
        const formatted = value >= 1 ? value.toLocaleString(undefined, {
            minimumFractionDigits: 2, maximumFractionDigits: 2 }) : value.toFixed(4);
        return '≈ $' + formatted;
    },

    update: function() {
        if (!DOM.get('offer-summary')) return;

        const sendCoin = this.coinName('coin_from');
        const getCoin = this.coinName('coin_to');
        const amtFrom = DOM.getValue('amt_from');
        const amtTo = DOM.getValue('amt_to');
        const rate = DOM.getValue('rate');
        const minBid = DOM.getValue('amt_bid_min');

        this.setText('summary-send-amt', amtFrom ? amtFrom : '—');
        this.setText('summary-send-coin', sendCoin || '');
        this.setText('summary-get-amt', amtTo ? amtTo : '—');
        this.setText('summary-get-coin', getCoin || '');

        if (rate && sendCoin && getCoin) {
            this.setText('summary-rate', `1 ${sendCoin} = ${rate} ${getCoin}`);
        } else if (rate) {
            this.setText('summary-rate', rate);
        } else {
            this.setText('summary-rate', '—');
        }

        this.setText('summary-min', (minBid && sendCoin) ? `${minBid} ${sendCoin}` : (minBid || '—'));

        this.setText('summary-send-usd', this.usdFor(sendCoin, amtFrom));
        this.setText('summary-get-usd', this.usdFor(getCoin, amtTo));

        this.setText('mobile-send', (amtFrom || '—') + (sendCoin ? ' ' + sendCoin : ''));
        this.setText('mobile-get', (amtTo || '—') + (getCoin ? ' ' + getCoin : ''));
    }
};

const OfferValidation = {
    isTradeStep: () => !!DOM.query('input[name="step1"]'),

    markError: (el) => {
        if (!el) return;
        el.classList.add('border-red-500', 'focus:border-red-500');
        const picker = el.closest ? el.closest('[data-coin-picker]') : null;
        if (picker) {
            const btn = picker.querySelector('.coin-picker-button');
            if (btn) btn.classList.add('coin-picker-error');
        }
    },

    clearErrors: () => {
        DOM.queryAll('.border-red-500').forEach(el => {
            el.classList.remove('border-red-500', 'focus:border-red-500');
        });
        DOM.queryAll('.coin-picker-error').forEach(el => {
            el.classList.remove('coin-picker-error');
        });
    },

    validateTrade: function(markErrors) {
        if (markErrors === undefined) markErrors = true;
        this.clearErrors();
        const coinFrom = DOM.get('coin_from');
        const coinTo = DOM.get('coin_to');
        const amtFrom = DOM.get('amt_from');
        const amtTo = DOM.get('amt_to');
        const rate = DOM.get('rate');
        const minBid = DOM.get('amt_bid_min');
        const problems = [];
        const mark = (el) => { if (markErrors) this.markError(el); };

        if (!coinFrom || coinFrom.value === '-1') {
            problems.push('Select the coin you send.');
            mark(coinFrom);
        }
        if (!coinTo || coinTo.value === '-1') {
            problems.push('Select the coin you get.');
            mark(coinTo);
        }
        if (coinFrom && coinTo && coinFrom.value !== '-1' && coinFrom.value === coinTo.value) {
            problems.push('The coins to send and get must be different.');
            mark(coinTo);
        }
        if (!amtFrom || !(parseFloat(amtFrom.value) > 0)) {
            problems.push('Enter the amount you send.');
            mark(amtFrom);
        }
        if (!amtTo || !(parseFloat(amtTo.value) > 0)) {
            problems.push('Enter the amount you get.');
            mark(amtTo);
        }
        if (!rate || !(parseFloat(rate.value) > 0)) {
            problems.push('Enter or accept the exchange rate.');
            mark(rate);
        }

        const balance = (window.OfferSummary)
            ? OfferSummary.selectedBalance('coin_from') : null;
        const sendValue = amtFrom ? parseFloat(amtFrom.value) : NaN;
        if (balance !== null && !isNaN(sendValue) && sendValue > balance) {
            problems.push('Amount exceeds your available balance (' + balance + ').');
            mark(amtFrom);
        }

        if (minBid && amtFrom) {
            const minV = parseFloat(minBid.value);
            if (!isNaN(minV) && !isNaN(sendValue) && minV > sendValue) {
                problems.push('Minimum purchase is larger than the amount you send.');
                mark(minBid);
            }
        }
        return problems;
    },

    updateContinueState: function() {
        if (!this.isTradeStep()) return;
        const ok = this.validateTrade(false).length === 0;
        document.querySelectorAll('button[name="continue"]').forEach(btn => {
            btn.disabled = !ok;
            btn.classList.toggle('opacity-50', !ok);
            btn.classList.toggle('cursor-not-allowed', !ok);
        });
    }
};

const BalanceHint = {
    update: function() {
        const hint = DOM.get('amt-from-balance-hint');
        if (!hint || !window.OfferSummary) return;
        const balance = OfferSummary.selectedBalance('coin_from');
        const coin = OfferSummary.coinName('coin_from');
        const sendValue = parseFloat(DOM.getValue('amt_from'));
        const fee = (window.FeeEstimate && typeof FeeEstimate.fee === 'number') ? FeeEstimate.fee : null;
        const feeStr = (window.FeeEstimate && FeeEstimate.feeStr) ? FeeEstimate.feeStr : null;
        const coinSuffix = coin ? ' ' + coin : '';
        if (balance === null || isNaN(sendValue) || sendValue <= 0) {
            hint.textContent = '';
            hint.className = 'text-xs mt-2';
            return;
        }
        if (sendValue > balance) {
            hint.textContent = 'Exceeds available balance (' + balance + coinSuffix + ').';
            hint.className = 'text-xs mt-2 offer-hint-danger';
        } else if (fee !== null && (sendValue + fee) > balance) {
            hint.textContent = 'This plus the swap network fee (~' + feeStr + coinSuffix + ') is more than your balance. Lower the amount.';
            hint.className = 'text-xs mt-2 offer-hint-warn';
        } else if (fee === null && sendValue >= balance * 0.9) {
            hint.textContent = 'Uses most of your balance — leave room for the swap network fee.';
            hint.className = 'text-xs mt-2 offer-hint-warn';
        } else {
            let msg = 'Within available balance (' + balance + coinSuffix + ').';
            if (feeStr) msg += '\nPlus ~' + feeStr + coinSuffix + ' swap network fee.';
            hint.textContent = msg;
            hint.className = 'text-xs mt-2 offer-hint-ok';
        }
    }
};

function swapTradeSides() {
    const coinFrom = DOM.get('coin_from');
    const coinTo = DOM.get('coin_to');
    if (!coinFrom || !coinTo) return;

    const cf = coinFrom.value;
    const ct = coinTo.value;
    coinFrom.value = ct;
    coinTo.value = cf;

    const amtFrom = DOM.get('amt_from');
    const amtTo = DOM.get('amt_to');
    if (amtFrom && amtTo) {
        const af = amtFrom.value;
        amtFrom.value = amtTo.value;
        amtTo.value = af;
    }

    try {
        Storage.setRaw(coinFrom.name, coinFrom.value);
        Storage.setRaw(coinTo.name, coinTo.value);
    } catch (e) {}
    if (window.CoinPicker) CoinPicker.refreshAll();

    DOM.setValue('rate', '');
    if (DOM.get('swap_type')) {
        SwapTypeManager.setSwapTypeEnabled(coinFrom.value, coinTo.value, DOM.get('swap_type'));
    }
    RateManager.setRate('amt_from');
    MarketRate.refresh();
    if (window.OfferSummary) OfferSummary.update();
}

const MarketRate = {
    inferred: null,
    pairKey: null,

    pair: () => {
        const cf = DOM.getValue('coin_from');
        const ct = DOM.getValue('coin_to');
        if (!cf || !ct || cf === '-1' || ct === '-1') return null;
        return { cf, ct, key: cf + ':' + ct };
    },

    refresh: function() {
        const p = this.pair();
        const hint = DOM.get('rate-market-hint');
        if (!p) {
            this.inferred = null;
            this.pairKey = null;
            if (hint) hint.textContent = '';
            return;
        }
        if (p.key === this.pairKey && this.inferred !== null) {
            this.render();
            return;
        }
        this.pairKey = p.key;
        this.inferred = null;
        Ajax.post('/json/rates', 'coin_from=' + encodeURIComponent(p.cf) +
            '&coin_to=' + encodeURIComponent(p.ct),
            (response) => {
                if (response && response.coingecko && response.coingecko.rate_inferred) {
                    this.inferred = parseFloat(response.coingecko.rate_inferred);
                    this.autofill();
                    this.render();
                }
            },
            () => {}
        );
    },

    autofill: function() {
        const rateEl = DOM.get('rate');
        if (!rateEl || !this.inferred) return;
        if (rateEl.value && rateEl.value.trim() !== '') return;
        rateEl.value = toPlainDecimal(this.inferred);
        RateManager.setRate('rate');
        if (window.OfferSummary) OfferSummary.update();
    },

    render: function() {
        const hint = DOM.get('rate-market-hint');
        if (!hint) return;
        const rate = parseFloat(DOM.getValue('rate'));
        if (!this.inferred || isNaN(rate) || rate <= 0) {
            hint.textContent = '';
            return;
        }
        const diff = ((rate - this.inferred) / this.inferred) * 100;
        const rounded = Math.round(diff * 10) / 10;
        if (Math.abs(rounded) < 0.1) {
            hint.textContent = 'At market rate';
            hint.className = 'text-xs mt-2 text-green-600 dark:text-green-400';
        } else {
            const dir = rounded > 0 ? 'above' : 'below';
            hint.textContent = Math.abs(rounded) + '% ' + dir + ' market';
            hint.className = 'text-xs mt-2 ' + (rounded > 0
                ? 'text-amber-600 dark:text-amber-400'
                : 'text-blue-600 dark:text-blue-400');
        }
    }
};

const DraftAutosave = {
    KEY: 'newOfferDraft',
    fields: ['amt_from', 'amt_to', 'rate', 'amt_bid_min'],

    isTradeStep: () => !!DOM.get('offer-summary'),

    save: function() {
        if (!this.isTradeStep()) return;
        const draft = {};
        this.fields.forEach(id => { draft[id] = DOM.getValue(id); });
        draft.coin_from = DOM.getValue('coin_from');
        draft.coin_to = DOM.getValue('coin_to');
        try { sessionStorage.setItem(this.KEY, JSON.stringify(draft)); } catch (e) {}
    },

    restore: function() {
        if (!this.isTradeStep()) return;
        let draft;
        try { draft = JSON.parse(sessionStorage.getItem(this.KEY)); } catch (e) { return; }
        if (!draft) return;

        this.fields.forEach(id => {
            const el = DOM.get(id);
            if (el && !el.value && draft[id]) el.value = draft[id];
        });

        ['coin_from', 'coin_to'].forEach(id => {
            const el = DOM.get(id);
            if (el && el.value === '-1' && draft[id] && draft[id] !== '-1' &&
                Array.from(el.options).some(o => o.value === draft[id])) {
                el.value = draft[id];
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }
        });
    },

    clear: function() {
        try { sessionStorage.removeItem(this.KEY); } catch (e) {}
    }
};

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
    }
};

function initializeApp() {
    handleNewOfferAddress();
    AddrFromSearch.init();

    CoinPicker.init();

    DOM.addEvent('get_rate_inferred_button', 'click', RateManager.getRateInferred);

    const coinFrom = DOM.get('coin_from');
    const coinTo = DOM.get('coin_to');
    const swapType = DOM.get('swap_type');

    if (coinFrom && coinTo) {
        if (swapType) {
            SwapTypeManager.setSwapTypeEnabled(coinFrom.value, coinTo.value, swapType);
        }

        coinFrom.addEventListener('change', function() {
            if (swapType) SwapTypeManager.setSwapTypeEnabled(this.value, coinTo.value, swapType);
            RateManager.setRate('coin_from');
            MarketRate.refresh();
            FeeEstimate.refresh();
        });

        coinTo.addEventListener('change', function() {
            if (swapType) SwapTypeManager.setSwapTypeEnabled(coinFrom.value, this.value, swapType);
            RateManager.setRate('coin_to');
            MarketRate.refresh();
            FeeEstimate.refresh();
        });
    }

    ['amt_from', 'amt_to', 'rate'].forEach(id => {
        DOM.addEvent(id, 'change', function() {
            RateManager.setRate(id);
            if (id === 'rate') MarketRate.render();
        });

        DOM.addEvent(id, 'input', function() {
            RateManager.setRate(id);
            if (id === 'rate') MarketRate.render();
        });
    });

    DOM.addEvent('rate_lock', 'change', function() {
        if (DOM.getValue('rate')) {
            RateManager.setRate('rate');
        }
    });

    DOM.addEvent('lookup_rates_button', 'click', RateManager.lookupRates);

    DOM.addEvent('swap-coins-btn', 'click', swapTradeSides);

    document.addEventListener('click', (e) => {
        const preset = e.target.closest('[data-set-value][data-target-name]');
        if (!preset) return;
        e.preventDefault();
        const target = document.querySelector('[name="' + preset.getAttribute('data-target-name') + '"]');
        if (target) {
            target.value = preset.getAttribute('data-set-value');
            target.dispatchEvent(new Event('change', { bubbles: true }));
        }
    });

    if (DOM.get('offer-summary')) {
        const refreshTrade = () => {
            OfferSummary.update();
            BalanceHint.update();
            AddrFromHint.update();
            OfferValidation.updateContinueState();
            DraftAutosave.save();
        };
        DOM.addEvent('addr_from', 'change', () => AddrFromHint.update());
        ['coin_from', 'coin_to', 'amt_from', 'amt_to', 'rate', 'amt_bid_min'].forEach(id => {
            DOM.addEvent(id, 'change', refreshTrade);
            DOM.addEvent(id, 'input', refreshTrade);
        });

        if (DOM.query('.offer-mobile-bar')) {
            document.body.classList.add('has-offer-mobile-bar');
        }

        DraftAutosave.restore();
        OfferSummary.update();
        OfferSummary.loadPrices();
        FeeEstimate.refresh();
        BalanceHint.update();
        AddrFromHint.update();
        OfferValidation.updateContinueState();
        MarketRate.refresh();

        document.addEventListener('click', (e) => {
            const target = e.target.closest('[data-set-offer-amount]');
            if (!target) return;
            setTimeout(() => {
                RateManager.setRate(target.getAttribute('data-input-id') || 'amt_from');
                refreshTrade();
            }, 0);
        });
    }

    const offerForm = DOM.get('form');
    if (offerForm) {
        offerForm.addEventListener('submit', (e) => {
            const submitter = e.submitter;

            if (submitter && submitter.name === 'submit_offer') {
                if (offerForm.dataset.submitting === '1') {
                    e.preventDefault();
                    return;
                }
                offerForm.dataset.submitting = '1';
                const icon = DOM.get('offer-confirm-icon');
                const spinner = DOM.get('offer-confirm-spinner');
                const label = DOM.get('offer-confirm-label');
                if (icon) icon.classList.add('hidden');
                if (spinner) spinner.classList.remove('hidden');
                if (label) label.textContent = 'Publishing…';
                if (submitter.classList) {
                    submitter.classList.add('opacity-75', 'cursor-not-allowed');
                }
                return;
            }

            if (!submitter || submitter.name !== 'continue') return;
            if (!OfferValidation.isTradeStep()) return;
            const problems = OfferValidation.validateTrade();
            if (problems.length > 0) {
                e.preventDefault();
                ErrorModal.show('Please complete your trade', problems.join('\n'));
            } else {
                DraftAutosave.clear();
            }
        });
    }

    if (DOM.get('copy-offer-link') || DOM.get('create-another-offer')) {
        DraftAutosave.clear();
    }
    const copyBtn = DOM.get('copy-offer-link');
    if (copyBtn) {
        const linkInput = DOM.get('offer-link');
        if (linkInput) {
            const path = copyBtn.getAttribute('data-offer-link') || linkInput.value || '';
            if (path.indexOf('http') !== 0) linkInput.value = window.location.origin + path;
        }
        copyBtn.addEventListener('click', () => {
            const path = copyBtn.getAttribute('data-offer-link') || '';
            const url = window.location.origin + path;
            const label = DOM.get('copy-offer-link-label');
            const done = () => { if (label) { label.textContent = 'Copied!'; setTimeout(() => { label.textContent = 'Copy link'; }, 2000); } };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(url).then(done).catch(() => {
                    const input = DOM.get('offer-link');
                    if (input) { input.select(); try { document.execCommand('copy'); done(); } catch (e) {} }
                });
            } else {
                const input = DOM.get('offer-link');
                if (input) { input.select(); try { document.execCommand('copy'); done(); } catch (e) {} }
            }
        });
    }

    UIEnhancer.handleErrorHighlighting();
    UIEnhancer.updateDisabledStyles();

    CoinPicker.fireRestored();

    ErrorModal.init();

    OfferModeToggle.init();
}

const OfferModeToggle = {
    init: function() {
        const select = DOM.get('offer_mode');
        if (!select) return;
        const update = () => {
            const mode = select.value;
            const fixedFields = DOM.get('offer_mode_fixed_total_fields');
            const standingFields = DOM.get('offer_mode_standing_fields');
            if (fixedFields) fixedFields.classList.toggle('hidden', mode !== 'fixed_total');
            if (standingFields) standingFields.classList.toggle('hidden', mode !== 'standing');
        };
        select.addEventListener('change', update);
        update();
    }
};

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

window.showErrorModal = ErrorModal.show.bind(ErrorModal);
window.hideErrorModal = ErrorModal.hide.bind(ErrorModal);
window.OfferSummary = OfferSummary;
window.CoinPicker = CoinPicker;
