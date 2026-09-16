const CoinPicker = {
    instances: [],
    imageFallback: '/static/images/other/coin.png',

    restoreValue: () => null,
    persistValue: () => {},

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
        CoinPicker.persistValue(inst.select.name, value);
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
            const stored = CoinPicker.restoreValue(inst.select.name);
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

window.CoinPicker = CoinPicker;
