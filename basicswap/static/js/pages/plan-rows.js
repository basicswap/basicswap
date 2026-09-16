// Shared rendering for Smart Buy plan rows, used by both /bids and /smartbuy.
window.PlanRows = (function () {
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

    const getTimeStrokeColor = (expireTime) => {
        const now = Math.floor(Date.now() / 1000);
        return expireTime > now ? '#10B981' : '#9CA3AF';
    };

    const coinImage = (coin) =>
        `/static/images/coins/${(coin || '').replace(' ', '-')}.png`;

    const getStatusClass = (status) => {
        switch (status) {
            case 'Completed':
                return 'bg-green-300 text-black dark:bg-green-600 dark:text-white';
            case 'Abandoned':
            case 'Expired':
            case 'Timed-out':
                return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-white';
            case 'Failed, refunded':
            case 'Failed, swiped':
                return 'bg-gray-200 text-black dark:bg-gray-400 dark:text-red-500';
            case 'Error':
            case 'Failed':
            case 'Rejected':
                return 'bg-red-300 text-black dark:bg-red-600 dark:text-white';
            default:
                return 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        }
    };

    // Bids sharing a plan_id collapse into one item, so a buy counts as one row.
    const groupBids = (bids) => {
        const items = [];
        const byPlan = new Map();

        bids.forEach((bid) => {
            if (!bid.plan_id) {
                items.push({ kind: 'bid', bid });
                return;
            }

            let plan = byPlan.get(bid.plan_id);
            if (!plan) {
                plan = { kind: 'plan', plan_id: bid.plan_id, bids: [] };
                byPlan.set(bid.plan_id, plan);
                // Takes the place of its first leg, so the sort the caller chose still holds.
                items.push(plan);
            }
            plan.bids.push(bid);
        });

        return items;
    };

    // Only a fully Completed swap is a good end; a redeemed leg is still live.
    const PLAN_SETTLED_STATES = new Set([
        'Completed',
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

    // Ended without filling, so its amount is left out of the buy's totals.
    const PLAN_FAILED_STATES = new Set([
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

    const planSummary = (plan) => {
        const bids = plan.bids;
        const filled = bids.filter((bid) => !PLAN_FAILED_STATES.has(bid.bid_state));
        const sum = (field) => filled.reduce((total, bid) => total + parseFloat(bid[field]), 0);
        // Show a total at the scale its legs came in at, trailing zeros and all.
        const like = (total, leg) => total.toFixed((leg.split('.')[1] || '').length);

        const send = like(sum('amount_to'), bids[0].amount_to);
        const receive = like(sum('amount_from'), bids[0].amount_from);
        // What the buy actually paid, which is not the mean of the legs' rates.
        const rate = parseFloat(receive) > 0 ? parseFloat(send) / parseFloat(receive) : 0;

        const live = bids.filter((bid) => !PLAN_SETTLED_STATES.has(bid.bid_state));

        return {
            send,
            receive,
            avgRate: like(rate, bids[0].bid_rate),
            state: live.length > 0
                ? `${live.length} of ${bids.length} in progress`
                : `${bids.length} bids settled`,
            coin_from: bids[0].coin_from,
            coin_to: bids[0].coin_to,
            created_at: Math.min(...bids.map((bid) => bid.created_at)),
            expire_at: Math.min(...bids.map((bid) => bid.expire_at))
        };
    };

    const showAction = `
        <span class="plan-toggle inline-block w-20 py-1 px-2 font-medium text-center text-sm rounded-md bg-gray-50 dark:bg-gray-700 text-gray-700 dark:text-white border border-gray-300 dark:border-gray-400">
            Show
        </span>`;

    const createPlanRow = (plan, options = {}) => {
        const summary = planSummary(plan);
        const timeColor = getTimeStrokeColor(summary.expire_at);
        const actionsHtml = options.actionsHtml !== undefined ? options.actionsHtml : showAction;
        // Failed legs are ignored, a retry may have covered them.
        const target = parseFloat(plan.bids[0].plan_target);
        const succeeded = Number.isFinite(target)
            ? parseFloat(summary.receive) >= target - 1e-8
              && plan.bids.every((bid) =>
                  PLAN_FAILED_STATES.has(bid.bid_state) || bid.bid_state === 'Completed')
            : plan.bids.every((bid) => bid.bid_state === 'Completed');
        const statusPill = succeeded
            ? 'bg-green-300 text-black dark:bg-green-600 dark:text-white'
            : 'bg-blue-300 text-black dark:bg-blue-500 dark:text-white';
        const statusHtml = options.statusHtml
            ? options.statusHtml
            : `<span class="w-full lg:w-7/8 xl:w-2/3 px-2.5 py-1 inline-flex items-center justify-center text-center rounded-full text-xs font-medium bold ${statusPill}">${summary.state}</span>`;

        return `
            <tr class="plan-row cursor-pointer text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600" data-plan-id="${plan.plan_id}">
                <!-- Time Column -->
                <td class="py-3 pl-6 pr-3">
                    <div class="flex items-center min-w-max">
                        <svg class="w-5 h-5 mr-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                            <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${timeColor}" stroke-linejoin="round">
                                <circle cx="12" cy="12" r="11"></circle>
                                <polyline points="12,6 12,12 18,12"></polyline>
                            </g>
                        </svg>
                        <div class="text-xs flex items-center">
                            ${formatTime(summary.created_at)}
                            <span class="ml-1 px-1.5 py-0.5 text-xs font-medium bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300 rounded">
                                Smart Buy
                            </span>
                        </div>
                    </div>
                </td>

                <!-- Details Column -->
                <td class="p-3 hidden lg:flex">
                    <div class="flex flex-col">
                        <div class="text-xs font-mono font-semibold text-gray-700 dark:text-white">
                            ${plan.bids.length} bids
                        </div>
                        <div class="font-mono text-xs opacity-75">
                            Rate: ${summary.avgRate} average
                        </div>
                    </div>
                </td>

                <!-- Send Coin Column -->
                <td class="p-3">
                    <div class="flex items-center min-w-max">
                        <img class="w-8 h-8 mr-2" src="${coinImage(summary.coin_to)}" alt="${summary.coin_to}"
                             onerror="this.src='/static/images/coins/default.png'">
                        <div>
                            <div class="text-sm font-medium monospace">${summary.send}</div>
                            <div class="text-xs opacity-75 monospace">${summary.coin_to}</div>
                        </div>
                    </div>
                </td>

                <!-- Receive Coin Column -->
                <td class="p-3">
                    <div class="flex items-center min-w-max">
                        <img class="w-8 h-8 mr-2" src="${coinImage(summary.coin_from)}" alt="${summary.coin_from}"
                             onerror="this.src='/static/images/coins/default.png'">
                        <div>
                            <div class="text-sm font-medium monospace">${summary.receive}</div>
                            <div class="text-xs opacity-75 monospace">${summary.coin_from}</div>
                        </div>
                    </div>
                </td>

                <!-- Status Column -->
                <td class="py-3 px-6">
                    <div class="relative flex justify-center">
                        ${statusHtml}
                    </div>
                </td>

                <!-- Actions Column -->
                <td class="py-3 pr-4">
                    <div class="flex justify-center">
                        ${actionsHtml}
                    </div>
                </td>
            </tr>
        `;
    };

    return {
        formatTime,
        getTimeStrokeColor,
        coinImage,
        getStatusClass,
        groupBids,
        planSummary,
        createPlanRow,
        PLAN_SETTLED_STATES
    };
})();
