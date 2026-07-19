(function () {
  'use strict';

  const POLL_INTERVAL = 5000;
  const NOT_PLACED = 'Not placed';
  const SETTINGS_KEY = 'smartbuy.settings';
  const TAB_KEY = 'smartbuy.tab';
  // Keep in sync with FEE_RESERVE_FRACTION in multibid.py.
  const FEE_RESERVE_FRACTION = 0.001;
  // Mirrors the minimum bid amount; a shortfall smaller than this cannot be re-bid.
  const MIN_BID_AMOUNT = 0.001;
  // Keep in sync with DEFAULT_MAX_BIDS in multibid.py.
  const DEFAULT_MAX_BIDS = 15;
  const SAVED_FIELDS = [
    'coin_from', 'coin_to', 'anchor', 'slip_percent', 'max_bids',
    'leg_timeout_mins', 'allow_self_bids', 'manual_offers'
  ].filter((id) => document.getElementById(id));

  const FAILED_STATES = new Set([
    NOT_PLACED,
    'Abandoned',
    'Error',
    'Expired',
    'Failed',
    'Failed, refunded',
    'Failed, swiped',
    'Rejected',
    'Timed-out',
    'Auto accept failed'
  ]);

  const DONE_STATES = new Set([
    'Completed'
  ]);

  const REFRESH_EVENTS = new Set(['new_offer', 'offer_created', 'offer_expired']);
  const BID_EVENTS = new Set(['bid_changed', 'swap_completed']);
  const REFRESH_DEBOUNCE = 1500;

  let activeSide = 'receive';
  let currentPlan = null;
  let retryPlanId = null;
  const historyPlans = new Map();
  // plan_id -> leg count when its retry fired; hides the button until the new leg lands.
  const pendingRetries = new Map();
  let bidByOffer = {};
  let pollTimer = null;
  let refreshTimer = null;
  let historyTimer = null;
  let showExcluded = false;
  const picks = new Set();

  const el = (id) => document.getElementById(id);

  const checked = (id) => Boolean(el(id) && el(id).checked);

  const pickBox = (offerId) => (checked('manual_offers')
    ? `<input type="checkbox" class="pick mr-2 align-middle" data-offer="${offerId}"${picks.has(offerId) ? ' checked' : ''}>`
    : '');

  const ownBadge = (own) => (own
    ? '<span class="ml-2 px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-100">Mine</span>'
    : '');

  const setPlaceEnabled = (enabled) => {
    const button = el('placeBtn');
    button.disabled = !enabled;
    button.classList.toggle('opacity-50', !enabled);
    button.classList.toggle('cursor-not-allowed', !enabled);
  };

  const postJson = async (url, body) => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok || data.error) {
      throw new Error(data.error || `Server error: ${response.status}`);
    }
    return data;
  };

  const TAB_ON = ['border-blue-500', 'text-blue-600', 'dark:text-blue-400'];
  const TAB_OFF = ['border-transparent', 'text-gray-500', 'dark:text-gray-400'];

  const showTab = (name) => {
    document.querySelectorAll('[data-sb-tab]').forEach((btn) => {
      const on = btn.dataset.sbTab === name;
      TAB_ON.forEach((c) => btn.classList.toggle(c, on));
      TAB_OFF.forEach((c) => btn.classList.toggle(c, !on));
    });
    el('sb-panel-buy').classList.toggle('hidden', name !== 'buy');
    el('sb-panel-history').classList.toggle('hidden', name !== 'history');
    if (name === 'history') {
      loadHistory();
    }
    try {
      sessionStorage.setItem(TAB_KEY, name);
    } catch {}
  };

  const showToggle = `
    <span class="sb-plan-toggle inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-white border border-gray-300 dark:border-gray-400">
      Show
    </span>`;

  const historyLegRow = (bid, planId, isLast) => {
    const edge = isLast ? ' border-b-2 border-blue-500' : '';
    return `
    <tr class="sb-legs sb-legs-${planId} text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600" data-plan-id="${planId}">
      <td class="py-3 pl-8 pr-3 border-l-4 border-blue-500${edge}">
        <div class="flex items-center min-w-max">
          <svg class="w-5 h-5 mr-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${PlanRows.getTimeStrokeColor(bid.expire_at)}" stroke-linejoin="round">
              <circle cx="12" cy="12" r="11"></circle>
              <polyline points="12,6 12,12 18,12"></polyline>
            </g>
          </svg>
          <div class="text-xs">${PlanRows.formatTime(bid.created_at)}</div>
        </div>
      </td>
      <td class="p-3 hidden lg:table-cell${edge}">
        <div class="font-mono text-xs opacity-75">
          <a href="/offer/${bid.offer_id}">Offer: ${bid.offer_id.slice(8, 20)}...</a>
        </div>
      </td>
      <td class="p-3${edge}">
        <div class="flex items-center min-w-max">
          <img class="w-8 h-8 mr-2" src="${PlanRows.coinImage(bid.coin_to)}" alt="${bid.coin_to}"
               onerror="this.src='/static/images/coins/default.png'">
          <div>
            <div class="text-sm font-medium monospace">${bid.amount_to}</div>
            <div class="text-xs opacity-75 monospace">${bid.coin_to}</div>
          </div>
        </div>
      </td>
      <td class="p-3${edge}">
        <div class="flex items-center min-w-max">
          <img class="w-8 h-8 mr-2" src="${PlanRows.coinImage(bid.coin_from)}" alt="${bid.coin_from}"
               onerror="this.src='/static/images/coins/default.png'">
          <div>
            <div class="text-sm font-medium monospace">${bid.amount_from}</div>
            <div class="text-xs opacity-75 monospace">${bid.coin_from}</div>
          </div>
        </div>
      </td>
      <td class="py-3 px-6${edge}">
        <div class="relative flex justify-center">
          <span class="w-full lg:w-7/8 xl:w-2/3 px-2.5 py-1 inline-flex items-center justify-center text-center rounded-full text-xs font-medium bold ${PlanRows.getStatusClass(bid.bid_state)}">${bid.bid_state}</span>
        </div>
      </td>
      <td class="py-3 pr-4${edge}">
        <div class="flex justify-center">
          <a href="/bid/${bid.bid_id}"
            class="inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md bg-blue-500 text-white border border-blue-500 hover:bg-blue-600 transition duration-200">
            View Bid
          </a>
        </div>
      </td>
    </tr>`;
  };

  const togglePlanLegs = (row) => {
    const toggle = row.querySelector('.sb-plan-toggle');
    const planId = row.dataset.planId;
    const existing = row.parentNode.querySelectorAll(`.sb-legs-${planId}`);
    if (existing.length) {
      existing.forEach((r) => r.remove());
      if (toggle) toggle.textContent = 'Show';
      return;
    }
    const plan = historyPlans.get(planId);
    if (!plan) return;
    row.insertAdjacentHTML('afterend', plan.bids.map((b, i) => historyLegRow(b, planId, i === plan.bids.length - 1)).join(''));
    if (toggle) toggle.textContent = 'Hide';
  };

  // Target less what has not failed; in-progress legs count.
  const planShortfall = (plan) => {
    const bids = plan.bids;
    // Hold until the retry's leg reaches /sentbids, so a refresh cannot double it.
    const pending = pendingRetries.get(plan.plan_id);
    if (pending !== undefined) {
      if (bids.length > pending) {
        pendingRetries.delete(plan.plan_id);
      } else {
        return null;
      }
    }
    const target = parseFloat(bids[0].plan_target);
    let unfilled;
    if (Number.isFinite(target)) {
      const filled = bids
        .filter((bid) => !FAILED_STATES.has(bid.bid_state))
        .reduce((total, bid) => total + parseFloat(bid.amount_from), 0);
      unfilled = target - filled;
    } else {
      // Legacy plans stored no target; sum failed legs once all have settled.
      if (bids.some((bid) => !PlanRows.PLAN_SETTLED_STATES.has(bid.bid_state))) {
        return null;
      }
      unfilled = bids
        .filter((bid) => FAILED_STATES.has(bid.bid_state))
        .reduce((total, bid) => total + parseFloat(bid.amount_from), 0);
    }
    if (unfilled < MIN_BID_AMOUNT) return null;
    return {
      amount: parseFloat(unfilled.toFixed(4)).toString(),
      coin_to: bids[0].coin_to,
      coin_from: bids[0].coin_from
    };
  };

  const retryButton = (plan) => {
    const short = planShortfall(plan);
    if (!short) return '';
    return `
      <button type="button" class="sb-retry inline-flex items-center gap-1 px-3 py-1 bg-purple-600 text-white text-xs font-medium bold rounded-md hover:bg-purple-700 focus:outline-none"
        data-plan-id="${plan.plan_id}" data-coin-to="${short.coin_to}" data-coin-from="${short.coin_from}" data-amount="${short.amount}">
        <svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clip-rule="evenodd"></path></svg>
        Retry ${short.amount} ${short.coin_from}
      </button>`;
  };

  const loadHistory = async () => {
    const body = el('sb-history-body');
    const message = (text, cls = 'text-gray-500 dark:text-gray-300') =>
      `<tr><td colspan="6" class="py-8 text-center text-sm ${cls}">${text}</td></tr>`;
    try {
      const res = await fetch('/json/sentbids', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          sort_by: 'created_at',
          sort_dir: 'desc',
          with_expired: true,
          state: -1,
          with_extra_info: true
        })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);

      const plans = PlanRows.groupBids(data).filter((item) => item.kind === 'plan');
      historyPlans.clear();
      plans.forEach((plan) => historyPlans.set(plan.plan_id, plan));
      if (plans.length === 0) {
        body.innerHTML = message('No Smart Buys yet.');
        return;
      }
      // A live refresh rebuilds the table, so re-open whatever legs were expanded.
      const open = new Set([...body.querySelectorAll('.sb-legs')].map((r) => r.dataset.planId));
      body.innerHTML = plans
        .map((plan) => PlanRows.createPlanRow(plan, {
          actionsHtml: showToggle,
          statusHtml: retryButton(plan)
        }))
        .join('');
      open.forEach((planId) => {
        const row = body.querySelector(`tr.plan-row[data-plan-id="${planId}"]`);
        if (row) togglePlanLegs(row);
      });
    } catch (e) {
      body.innerHTML = message(`Could not load history: ${e.message}`, 'text-red-500');
    }
  };

  const selected = (select) => select.options[select.selectedIndex];

  const selectCoin = (select, key) => {
    const opt = [...select.options].find((o) => o.value === key || o.text === key);
    if (opt) {
      select.value = opt.value;
    }
  };

  const retry = (btn) => {
    retryPlanId = btn.dataset.planId || null;
    selectCoin(el('coin_to'), btn.dataset.coinTo);
    selectCoin(el('coin_from'), btn.dataset.coinFrom);
    syncCoins();
    el('receive_amount').value = btn.dataset.amount || '';
    el('pay_amount').value = '';
    activeSide = 'receive';
    showTab('buy');
    preview();
  };

  const balanceOf = (select) => parseFloat(selected(select).dataset.balance) || 0;

  const syncCoin = (select, balanceId) => {
    const option = selected(select);
    el(balanceId).textContent = `${balanceOf(select)} ${option.text}`;
  };

  const applyBatchCap = () => {
    const input = el('max_bids');
    let caps = {};
    try {
      caps = JSON.parse(input.dataset.batchCaps || '{}');
    } catch {
      caps = {};
    }
    const cap = caps[el('coin_to').value];
    // A blank field falls back to the default, any other junk floors to 1.
    const raw = input.value.trim();
    let n = raw === '' ? DEFAULT_MAX_BIDS : Math.max(1, parseInt(raw, 10) || 1);
    if (cap) {
      n = Math.min(n, cap);
    }
    input.value = n;
    input.title = cap ? `${cap} max when paying this coin` : '';
  };

  const syncCoins = () => {
    syncCoin(el('coin_to'), 'pay_balance');
    syncCoin(el('coin_from'), 'receive_balance');
    applyBatchCap();
    CoinPicker.refreshAll();
  };

  // Hold the wait to 5-10 minutes; a blank or junk value falls back to 10.
  const clampTimeout = () => {
    const input = el('leg_timeout_mins');
    const n = parseInt(input.value.trim(), 10) || 10;
    input.value = Math.min(10, Math.max(5, n));
  };

  const saveSettings = () => {
    const saved = {};
    SAVED_FIELDS.forEach((id) => {
      saved[id] = el(id).type === 'checkbox' ? el(id).checked : el(id).value;
    });
    localStorage.setItem(SETTINGS_KEY, JSON.stringify(saved));
  };

  const restoreSettings = () => {
    const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || 'null');
    if (!saved) {
      return;
    }
    SAVED_FIELDS.forEach((id) => {
      const field = el(id);
      if (field.type === 'checkbox') {
        field.checked = Boolean(saved[id]);
      } else if (saved[id]) {
        field.value = saved[id];
      }
      // A coin the node no longer trades has no option to select.
      if (field.tagName === 'SELECT' && field.selectedIndex < 0) {
        field.selectedIndex = 0;
      }
    });
  };

  const showError = (message) => {
    el('planEmpty').classList.add('hidden');
    el('planBody').classList.add('hidden');
    const box = el('planError');
    box.textContent = message;
    box.classList.remove('hidden');
  };

  const statusClass = (state) => {
    if (FAILED_STATES.has(state)) {
      return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
    }
    if (DONE_STATES.has(state)) {
      return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
    }
    return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
  };

  const legRow = (leg) => {
    const bid = bidByOffer[leg.offer_id];
    const status = bid
      ? `<span class="px-3 py-1 inline-flex rounded-full text-xs font-medium whitespace-nowrap ${statusClass(bid.state)}">${bid.state}</span>`
      : '<span class="text-xs text-gray-400 dark:text-gray-500">Not bid yet</span>';
    const link = bid && bid.bid_id ? `/bid/${bid.bid_id}` : `/offer/${leg.offer_id}`;

    return `
      <tr class="text-gray-500 dark:text-gray-100 hover:bg-coolGray-100 dark:hover:bg-gray-700">
        <td class="py-3 pl-4">
          ${pickBox(leg.offer_id)}<a href="${link}" class="text-xs font-mono hover:text-blue-500">${leg.offer_id.slice(8, 20)}...</a>${ownBadge(leg.own)}
        </td>
        <td class="py-3 px-4 text-sm monospace">${leg.rate}</td>
        <td class="py-3 px-4 text-sm monospace text-right">${leg.amount} ${currentPlan.coin_from}</td>
        <td class="py-3 px-4 text-sm monospace text-right">${leg.cost} ${currentPlan.coin_to}</td>
        <td class="py-3 px-4 text-center">${status}</td>
      </tr>
    `;
  };

  // The offer is not being bid on, so its size is what it has, not what would be taken.
  const excludedRow = (offer) => `
    <tr class="text-gray-400 dark:text-gray-400 opacity-60 hover:bg-coolGray-100 dark:hover:bg-gray-700">
      <td class="py-3 pl-4">
        ${pickBox(offer.offer_id)}<a href="/offer/${offer.offer_id}" class="text-xs font-mono hover:text-blue-500">${offer.offer_id.slice(8, 20)}...</a>${ownBadge(offer.own)}
      </td>
      <td class="py-3 px-4 text-sm monospace">${offer.rate}</td>
      <td class="py-3 px-4 text-sm monospace text-right">up to ${offer.amount} ${currentPlan.coin_from}</td>
      <td class="py-3 px-4 text-sm monospace text-right">${offer.cost} ${currentPlan.coin_to}</td>
      <td class="py-3 px-4 text-center">
        <span class="px-3 py-1 inline-flex rounded-full text-xs font-medium whitespace-nowrap bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300">${offer.reason}</span>
      </td>
    </tr>
  `;

  const renderLegs = () => {
    const rows = currentPlan.legs.map((leg) => ({
      rate: parseFloat(leg.rate),
      html: legRow(leg)
    }));

    if (showExcluded) {
      currentPlan.excluded.forEach((offer) => {
        rows.push({ rate: parseFloat(offer.rate), html: excludedRow(offer) });
      });
      rows.sort((a, b) => a.rate - b.rate);
    }

    el('planLegs').innerHTML = rows.map((row) => row.html).join('');
  };

  const renderExcludedToggle = () => {
    const button = el('excludedBtn');
    const count = currentPlan ? currentPlan.excluded.length : 0;

    button.classList.toggle('hidden', count < 1);
    el('excludedBtnText').textContent = showExcluded
      ? `Hide skipped offers (${count})`
      : `Show skipped offers (${count})`;
  };

  const renderPlan = () => {
    const plan = currentPlan;

    el('planAvgRate').textContent = plan.avg_rate;
    el('planSpend').textContent = `${plan.total_spend} ${plan.coin_to}`;
    el('planNumBids').textContent = plan.num_bids;

    const vsMarket = el('planVsMarket');
    if (plan.pct_vs_market === null) {
      vsMarket.textContent = 'No market rate';
      vsMarket.className = 'text-lg font-semibold monospace text-gray-500 dark:text-gray-300';
    } else {
      const cheaper = plan.pct_vs_market <= 0;
      vsMarket.textContent = `${cheaper ? '' : '+'}${plan.pct_vs_market}%`;
      vsMarket.className = cheaper
        ? 'text-lg font-semibold monospace text-green-600 dark:text-green-400'
        : 'text-lg font-semibold monospace text-red-600 dark:text-red-400';
    }

    const unfilled = el('planUnfilled');
    if (parseFloat(plan.unfilled) > 0) {
      const units = plan.mode === 'spend' ? plan.coin_to : plan.coin_from;
      unfilled.textContent =
        `Only part of this can be filled at your limit. ${plan.unfilled} ${units} is left over. ` +
        `Raise the slippage, or ask for less.`;
      unfilled.classList.remove('hidden');
    } else {
      unfilled.classList.add('hidden');
    }

    el('planExhaustive').classList.toggle('hidden', plan.exhaustive);

    if (plan.num_bids > 0) {
      if (plan.mode === 'receive') {
        el('pay_amount').value = plan.total_spend;
      } else {
        el('receive_amount').value = plan.total_receive;
      }
    }

    renderLegs();
    renderExcludedToggle();

    el('planEmpty').classList.add('hidden');
    el('planError').classList.add('hidden');
    el('planResult').classList.add('hidden');
    el('planBody').classList.remove('hidden');
    setPlaceEnabled(plan.num_bids > 0);
  };

  const preview = async () => {
    const spending = activeSide === 'pay';
    const amount = el(spending ? 'pay_amount' : 'receive_amount').value.trim();
    if (!amount) {
      showError('Enter an amount to pay, or an amount to receive.');
      return;
    }

    const body = {
      coin_from: el('coin_from').value,
      coin_to: el('coin_to').value,
      anchor: el('anchor').value,
      slip_percent: el('slip_percent').value,
      max_bids: el('max_bids').value,
      allow_self_bids: checked('allow_self_bids')
    };
    body[spending ? 'spend_amount' : 'receive_amount'] = amount;

    if (checked('manual_offers') && picks.size) {
      body.manual_offers = [...picks];
    }

    el('previewBtn').disabled = true;
    try {
      const plan = await postJson('/json/bids/plan', body);
      currentPlan = plan;
      bidByOffer = {};

      if (checked('manual_offers') && picks.size === 0) {
        plan.legs.forEach((leg) => picks.add(leg.offer_id));
      }

      if (plan.num_bids < 1 && plan.excluded.length < 1) {
        showError('There are no offers to fill this from.');
        return;
      }

      if (plan.num_bids < 1) {
        showExcluded = true;
      }
      renderPlan();

      if (plan.num_bids < 1) {
        const box = el('planUnfilled');
        box.textContent =
          'No offers can fill this at your limit. Raise the slippage, or ask for less.';
        box.classList.remove('hidden');
      }
    } catch (error) {
      showError(error.message);
    } finally {
      el('previewBtn').disabled = false;
    }
  };

  const beforePlacing = () => currentPlan && Object.keys(bidByOffer).length === 0;

  const scheduleRefresh = () => {
    if (!beforePlacing()) {
      return;
    }
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(() => {
      const amount = el(activeSide === 'pay' ? 'pay_amount' : 'receive_amount').value.trim();
      if (amount && beforePlacing()) {
        preview();
      }
    }, REFRESH_DEBOUNCE);
  };

  // Only while the history tab is showing, coalescing one plan's burst of events.
  const scheduleHistoryRefresh = () => {
    if (el('sb-panel-history').classList.contains('hidden')) {
      return;
    }
    clearTimeout(historyTimer);
    historyTimer = setTimeout(loadHistory, REFRESH_DEBOUNCE);
  };

  const setupLiveOffers = () => {
    const wsm = window.WebSocketManager;
    if (!wsm) {
      return;
    }
    wsm.addMessageHandler('message', (data) => {
      if (!data) {
        return;
      }
      if (REFRESH_EVENTS.has(data.event)) {
        scheduleRefresh();
      }
      if (BID_EVENTS.has(data.event)) {
        scheduleHistoryRefresh();
      }
    });
    if (!wsm.isConnected()) {
      wsm.initialize();
    }
  };

  const summariseResult = () => {
    const bids = Object.values(bidByOffer);
    const failed = bids.filter((bid) => FAILED_STATES.has(bid.state));
    const live = bids.filter(
      (bid) => !FAILED_STATES.has(bid.state) && !DONE_STATES.has(bid.state)
    );

    let summary = `Placed ${bids.length - failed.length} of ${bids.length} bids.`;
    if (live.length > 0) {
      summary += ` ${live.length} still in progress.`;
    }
    if (failed.length > 0) {
      const lost = currentPlan.legs
        .filter((leg) => FAILED_STATES.has((bidByOffer[leg.offer_id] || {}).state))
        .reduce((sum, leg) => sum + parseFloat(leg.amount), 0);
      summary += ` ${failed.length} did not go through, leaving ${lost} ${currentPlan.coin_from} unfilled.` +
        ` Find the cheapest fill again to bid on what is left.`;
    }

    const box = el('planResult');
    box.textContent = summary;
    box.classList.remove('hidden');
  };

  const pollBidStates = async () => {
    const live = Object.values(bidByOffer).filter(
      (bid) => bid.bid_id && !DONE_STATES.has(bid.state) && !FAILED_STATES.has(bid.state)
    );
    if (live.length < 1) {
      clearInterval(pollTimer);
      pollTimer = null;
      return;
    }

    await Promise.all(live.map(async (bid) => {
      try {
        const response = await fetch(`/json/bids/${bid.bid_id}`, {
          headers: { 'Accept': 'application/json' }
        });
        const data = await response.json();
        if (data.bid_state) {
          bid.state = data.bid_state;
        }
      } catch (error) {
        console.error('Failed to poll bid', bid.bid_id, error);
      }
    }));

    renderLegs();
    summariseResult();
  };

  const openModal = (id) => el(id).classList.remove('hidden');
  const closeModal = (id) => el(id).classList.add('hidden');

  const placeBids = () => {
    if (!currentPlan) {
      return;
    }
    if (parseFloat(currentPlan.total_spend) > balanceOf(el('coin_to'))) {
      el('insufficientMessage').textContent =
        `This needs ${currentPlan.total_spend} ${currentPlan.coin_to}, but your balance is ` +
        `${selected(el('coin_to')).dataset.balance} ${currentPlan.coin_to}.`;
      openModal('insufficientModal');
      return;
    }
    el('confirmBids').textContent = currentPlan.num_bids;
    el('confirmPay').textContent = `${currentPlan.total_spend} ${currentPlan.coin_to}`;
    el('confirmFees').textContent = `${currentPlan.fees} ${currentPlan.coin_from}`;
    el('confirmNet').textContent = `${currentPlan.net_receive} ${currentPlan.coin_from}`;
    openModal('confirmModal');
  };

  const submitBids = async () => {
    setPlaceEnabled(false);
    el('placeBtnText').textContent = 'Placing...';

    try {
      const body = {
        legs: currentPlan.legs.map((leg) => ({
          offer_id: leg.offer_id,
          amount: leg.amount
        })),
        plan_leg_timeout: el('leg_timeout_mins').value
      };
      if (retryPlanId) {
        body.plan_id = retryPlanId;
      }
      const result = await postJson('/json/bids/bulk', body);
      if (retryPlanId && result.placed.length > 0) {
        const plan = historyPlans.get(retryPlanId);
        pendingRetries.set(retryPlanId, plan ? plan.bids.length : 0);
      }
      retryPlanId = null;

      bidByOffer = {};
      result.placed.forEach((bid) => {
        bidByOffer[bid.offer_id] = { bid_id: bid.bid_id, state: 'Sent' };
      });
      result.failed.forEach((bid) => {
        bidByOffer[bid.offer_id] = { bid_id: null, state: NOT_PLACED };
      });

      el('planTitle').textContent = 'Your bids';
      renderLegs();
      summariseResult();

      if (pollTimer) {
        clearInterval(pollTimer);
      }
      pollTimer = setInterval(pollBidStates, POLL_INTERVAL);
    } catch (error) {
      showError(error.message);
      setPlaceEnabled(true);
    } finally {
      el('placeBtnText').textContent = 'Place bids';
    }
  };

  const flip = () => {
    const payCoin = el('coin_to');
    const receiveCoin = el('coin_from');
    const wasPaying = payCoin.value;

    payCoin.value = receiveCoin.value;
    receiveCoin.value = wasPaying;

    retryPlanId = null;
    el('pay_amount').value = '';
    el('receive_amount').value = '';
    syncCoins();
    saveSettings();
  };

  const toggleExcluded = () => {
    showExcluded = !showExcluded;
    renderLegs();
    renderExcludedToggle();
  };

  document.addEventListener('DOMContentLoaded', () => {
    CoinPicker.init();
    restoreSettings();
    clampTimeout();
    syncCoins();
    setupLiveOffers();

    let startTab = 'buy';
    try {
      startTab = sessionStorage.getItem(TAB_KEY) || 'buy';
    } catch {}
    if (startTab === 'history') {
      showTab('history');
    } else {
      el('pay_amount').focus();
    }

    SAVED_FIELDS.forEach((id) => {
      el(id).addEventListener('change', () => {
        if (id === 'leg_timeout_mins') {
          clampTimeout();
        }
        syncCoins();
        saveSettings();
        if (currentPlan) {
          renderLegs();
        }
      });
    });

    ['coin_to', 'coin_from'].forEach((id) => {
      el(id).addEventListener('change', () => {
        retryPlanId = null;
      });
    });

    el('pay_amount').addEventListener('input', (e) => {
      activeSide = 'pay';
      e.target.value = e.target.value.replace(/(\.\d{8})\d+/, '$1');
      el('receive_amount').value = '';
    });
    el('receive_amount').addEventListener('input', (e) => {
      activeSide = 'receive';
      e.target.value = e.target.value.replace(/(\.\d{8})\d+/, '$1');
      el('pay_amount').value = '';
    });

    ['pay_amount', 'receive_amount', 'slip_percent', 'max_bids'].forEach((id) => {
      el(id).addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          picks.clear();
          preview();
        }
      });
    });

    document.querySelectorAll('.pct-btn').forEach((button) => {
      button.addEventListener('click', () => {
        const pct = parseInt(button.dataset.pct, 10);
        // Max leaves the lock-fee reserve, or the plan is rejected for spending 100%.
        const frac = pct >= 100 ? 1 - FEE_RESERVE_FRACTION : pct / 100;
        const amount = Math.trunc(balanceOf(el('coin_to')) * frac * 1e8) / 1e8;
        el('pay_amount').value = amount > 0 ? amount : '';
        el('receive_amount').value = '';
        activeSide = 'pay';
      });
    });

    el('planLegs').addEventListener('change', (event) => {
      const box = event.target;
      if (!box.classList.contains('pick')) {
        return;
      }
      if (box.checked) {
        picks.add(box.dataset.offer);
      } else {
        picks.delete(box.dataset.offer);
      }
      preview();
    });

    document.querySelectorAll('[data-sb-tab]').forEach((btn) => {
      btn.addEventListener('click', () => showTab(btn.dataset.sbTab));
    });

    el('sb-history-body').addEventListener('click', (e) => {
      const btn = e.target.closest('.sb-retry');
      if (btn) {
        retry(btn);
        return;
      }
      const row = e.target.closest('.plan-row');
      if (row) {
        togglePlanLegs(row);
      }
    });

    el('flipBtn').addEventListener('click', flip);
    el('previewBtn').addEventListener('click', () => {
      picks.clear();
      preview();
    });
    el('placeBtn').addEventListener('click', placeBids);
    el('excludedBtn').addEventListener('click', toggleExcluded);
    el('insufficientOk').addEventListener('click', () => closeModal('insufficientModal'));
    el('confirmCancel').addEventListener('click', () => closeModal('confirmModal'));
    el('confirmPlace').addEventListener('click', () => {
      closeModal('confirmModal');
      submitBids();
    });
  });

  window.addEventListener('beforeunload', () => {
    if (pollTimer) {
      clearInterval(pollTimer);
    }
    clearTimeout(refreshTimer);
    clearTimeout(historyTimer);
  });
})();
