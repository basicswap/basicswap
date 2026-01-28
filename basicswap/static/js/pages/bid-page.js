const BidPage = {
  bidId: null,
  bidStateInd: null,
  createdAtTimestamp: null,
  autoRefreshInterval: null,
  elapsedTimeInterval: null,
  AUTO_REFRESH_SECONDS: 60,
  refreshPaused: false,

  INACTIVE_STATES: [8, 17, 18, 19, 21, 22, 23, 25, 31], // Completed, Failed variants, Timed-out, Abandoned, Error, Rejected, Expired

  STATE_TOOLTIPS: {
    'Bid Sent': 'Your bid has been broadcast to the network',
    'Bid Receiving': 'Receiving partial bid message from the network',
    'Bid Received': 'Bid received and waiting for decision to accept or reject',
    'Bid Receiving accept': 'Receiving acceptance message from the other party',
    'Bid Accepted': 'Bid accepted. The atomic swap process is starting',
    'Bid Initiated': 'Swap initiated. First lock transaction is being created',
    'Bid Participating': 'Participating in the swap. Second lock transaction is being created',
    'Bid Completed': 'Swap completed successfully! Both parties received their coins',
    'Bid Script coin locked': 'Your coins are locked in the atomic swap contract on the script chain (e.g., BTC/LTC)',
    'Bid Script coin spend tx valid': 'The spend transaction for the script coin has been validated and is ready',
    'Bid Scriptless coin locked': 'The other party\'s coins are locked using adaptor signatures (e.g., XMR)',
    'Bid Script coin lock released': 'Secret key revealed. The script coin can now be claimed',
    'Bid Script tx redeemed': 'Script coin has been successfully claimed',
    'Bid Script pre-refund tx in chain': 'Pre-refund transaction detected. Swap may be failing',
    'Bid Scriptless tx redeemed': 'Scriptless coin (e.g., XMR) has been successfully claimed',
    'Bid Scriptless tx recovered': 'Scriptless coin recovered after swap failure',
    'Bid Failed, refunded': 'Swap failed but your coins have been refunded',
    'Bid Failed, swiped': 'Swap failed due to an unexpected issue. Please check the event log for details',
    'Bid Failed': 'Swap failed. Check events for details',
    'Bid Delaying': 'Brief delay between swap steps to ensure network propagation',
    'Bid Timed-out': 'Swap timed out waiting for the other party',
    'Bid Abandoned': 'Swap was manually abandoned. Locked coins will be refunded after timelock',
    'Bid Error': 'An error occurred. Check events for details',
    'Bid Rejected': 'Bid was rejected by the offer owner',
    'Bid Stalled (debug)': 'Debug mode: swap intentionally stalled for testing',
    'Bid Exchanged script lock tx sigs msg': 'Exchanging cryptographic signatures needed for lock transactions',
    'Bid Exchanged script lock spend tx msg': 'Exchanging signed spend transaction for locked coins',
    'Bid Request sent': 'Connection request sent to the other party',
    'Bid Request accepted': 'Connection request accepted',
    'Bid Expired': 'Bid expired before being accepted',
    'Bid Auto accept delay': 'Waiting for automation delay before auto-accepting',
    'Bid Auto accept failed': 'Automation failed to accept this bid',
    'Bid Connect request sent': 'Sent connection request to peer',
    'Bid Unknown bid state': 'Unknown state - please check the swap details',
  
    'ITX Sent': 'Initiate transaction has been broadcast to the network',
    'ITX Confirmed': 'Initiate transaction has been confirmed by miners',
    'ITX Redeemed': 'Initiate transaction has been successfully claimed',
    'ITX Refunded': 'Initiate transaction has been refunded',
    'ITX In Mempool': 'Initiate transaction is in the mempool (unconfirmed)',
    'ITX In Chain': 'Initiate transaction is included in a block',
    'PTX Sent': 'Participate transaction has been broadcast to the network',
    'PTX Confirmed': 'Participate transaction has been confirmed by miners',
    'PTX Redeemed': 'Participate transaction has been successfully claimed',
    'PTX Refunded': 'Participate transaction has been refunded',
    'PTX In Mempool': 'Participate transaction is in the mempool (unconfirmed)',
    'PTX In Chain': 'Participate transaction is included in a block'
  },

  EVENT_TOOLTIPS: {
    'Lock tx A published': 'First lock transaction broadcast to the blockchain network',
    'Lock tx A seen in mempool': 'First lock transaction detected in mempool (unconfirmed)',
    'Lock tx A seen in chain': 'First lock transaction included in a block',
    'Lock tx A confirmed in chain': 'First lock transaction has enough confirmations',
    'Lock tx B published': 'Second lock transaction broadcast to the blockchain network',
    'Lock tx B seen in mempool': 'Second lock transaction detected in mempool (unconfirmed)',
    'Lock tx B seen in chain': 'Second lock transaction included in a block',
    'Lock tx B confirmed in chain': 'Second lock transaction has enough confirmations',
    'Lock tx A spend tx published': 'Transaction to claim coins from first lock has been broadcast',
    'Lock tx A spend tx seen in chain': 'First lock spend transaction included in a block',
    'Lock tx B spend tx published': 'Transaction to claim coins from second lock has been broadcast',
    'Lock tx B spend tx seen in chain': 'Second lock spend transaction included in a block',
    'Failed to publish lock tx B': 'ERROR: Could not broadcast second lock transaction',
    'Failed to publish lock tx B spend': 'ERROR: Could not broadcast spend transaction for second lock',
    'Failed to publish lock tx B refund': 'ERROR: Could not broadcast refund transaction',
    'Detected invalid lock Tx B': 'ERROR: Second lock transaction is invalid or malformed',
    'Lock tx A pre-refund tx published': 'Pre-refund transaction broadcast. Swap is being cancelled',
    'Lock tx A refund spend tx published': 'Refund transaction for first lock has been broadcast',
    'Lock tx A refund swipe tx published': 'Other party claimed your refund (swiped)',
    'Lock tx B refund tx published': 'Refund transaction for second lock has been broadcast',
    'Lock tx A conflicting txn/s': 'WARNING: Conflicting transaction detected for first lock',
    'Lock tx A pre-refund tx seen in chain': 'Pre-refund transaction detected in blockchain',
    'Lock tx A refund spend tx seen in chain': 'Refund spend transaction detected in blockchain',
    'Initiate tx published': 'Secret-hash swap: Initiate transaction broadcast',
    'Initiate tx redeem tx published': 'Secret-hash swap: Initiate transaction claimed',
    'Initiate tx refund tx published': 'Secret-hash swap: Initiate transaction refunded',
    'Participate tx published': 'Secret-hash swap: Participate transaction broadcast',
    'Participate tx redeem tx published': 'Secret-hash swap: Participate transaction claimed',
    'Participate tx refund tx published': 'Secret-hash swap: Participate transaction refunded',
    'BCH mercy tx found': 'BCH specific: Mercy transaction detected',
    'Lock tx B mercy tx published': 'BCH specific: Mercy transaction broadcast',
    'Auto accepting': 'Automation is accepting this bid',
    'Failed auto accepting': 'Automation constraints prevented accepting this bid',
    'Debug tweak applied': 'Debug mode: A test tweak was applied'
  },

  STATE_PHASES: {
    1: { phase: 'negotiation', order: 1, label: 'Negotiation' },  // BID_SENT
    2: { phase: 'negotiation', order: 2, label: 'Negotiation' },  // BID_RECEIVING
    3: { phase: 'negotiation', order: 3, label: 'Negotiation' },  // BID_RECEIVED
    4: { phase: 'negotiation', order: 4, label: 'Negotiation' },  // BID_RECEIVING_ACC
    5: { phase: 'accepted', order: 5, label: 'Accepted' },        // BID_ACCEPTED
    6: { phase: 'locking', order: 6, label: 'Locking' },          // SWAP_INITIATED
    7: { phase: 'locking', order: 7, label: 'Locking' },          // SWAP_PARTICIPATING
    8: { phase: 'complete', order: 100, label: 'Complete' },      // SWAP_COMPLETED
    9: { phase: 'locking', order: 8, label: 'Locking' },          // XMR_SWAP_SCRIPT_COIN_LOCKED
    10: { phase: 'locking', order: 9, label: 'Locking' },         // XMR_SWAP_HAVE_SCRIPT_COIN_SPEND_TX
    11: { phase: 'locking', order: 10, label: 'Locking' },        // XMR_SWAP_NOSCRIPT_COIN_LOCKED
    12: { phase: 'redemption', order: 11, label: 'Redemption' },  // XMR_SWAP_LOCK_RELEASED
    13: { phase: 'redemption', order: 12, label: 'Redemption' },  // XMR_SWAP_SCRIPT_TX_REDEEMED
    14: { phase: 'failed', order: 90, label: 'Failed' },          // XMR_SWAP_SCRIPT_TX_PREREFUND
    15: { phase: 'redemption', order: 13, label: 'Redemption' },  // XMR_SWAP_NOSCRIPT_TX_REDEEMED
    16: { phase: 'failed', order: 91, label: 'Recovered' },       // XMR_SWAP_NOSCRIPT_TX_RECOVERED
    17: { phase: 'failed', order: 92, label: 'Failed' },          // XMR_SWAP_FAILED_REFUNDED
    18: { phase: 'failed', order: 93, label: 'Failed' },          // XMR_SWAP_FAILED_SWIPED
    19: { phase: 'failed', order: 94, label: 'Failed' },          // XMR_SWAP_FAILED
    20: { phase: 'locking', order: 7.5, label: 'Locking' },       // SWAP_DELAYING
    21: { phase: 'failed', order: 95, label: 'Failed' },          // SWAP_TIMEDOUT
    22: { phase: 'failed', order: 96, label: 'Abandoned' },       // BID_ABANDONED
    23: { phase: 'failed', order: 97, label: 'Error' },           // BID_ERROR
    25: { phase: 'failed', order: 98, label: 'Rejected' },        // BID_REJECTED
    27: { phase: 'accepted', order: 5.5, label: 'Accepted' },     // XMR_SWAP_MSG_SCRIPT_LOCK_TX_SIGS
    28: { phase: 'accepted', order: 5.6, label: 'Accepted' },     // XMR_SWAP_MSG_SCRIPT_LOCK_SPEND_TX
    29: { phase: 'negotiation', order: 0.5, label: 'Negotiation' }, // BID_REQUEST_SENT
    30: { phase: 'negotiation', order: 0.6, label: 'Negotiation' }, // BID_REQUEST_ACCEPTED
    31: { phase: 'failed', order: 99, label: 'Expired' },         // BID_EXPIRED
    32: { phase: 'negotiation', order: 3.5, label: 'Negotiation' }, // BID_AACCEPT_DELAY
    33: { phase: 'failed', order: 89, label: 'Failed' },          // BID_AACCEPT_FAIL
    34: { phase: 'negotiation', order: 0.4, label: 'Negotiation' }  // CONNECT_REQ_SENT
  },

  init: function(bidId, bidStateInd, createdAtTimestamp, stateTimeTimestamp) {
    this.bidId = bidId;
    this.bidStateInd = bidStateInd;
    this.createdAtTimestamp = createdAtTimestamp;
    this.stateTimeTimestamp = stateTimeTimestamp;
    this.tooltipCounter = 0;

    this.applyStateTooltips();
    this.applyEventTooltips();
    this.createProgressBar();
    this.startElapsedTimeUpdater();
    this.setupAutoRefresh();
  },

  isActiveState: function() {
    return !this.INACTIVE_STATES.includes(this.bidStateInd);
  },

  setupAutoRefresh: function() {
    if (!this.isActiveState()) {
      return;
    }

    const refreshBtn = document.getElementById('refresh');
    if (!refreshBtn) return;

    const originalSpan = refreshBtn.querySelector('span');
    if (!originalSpan) return;

    let countdown = this.AUTO_REFRESH_SECONDS;
    let isRefreshing = false;

    const updateCountdown = () => {
      if (this.refreshPaused || isRefreshing) return;

      originalSpan.textContent = `Auto-refresh in ${countdown}s`;
      countdown--;

      if (countdown < 0 && !isRefreshing) {
        isRefreshing = true;
        if (this.autoRefreshInterval) {
          clearInterval(this.autoRefreshInterval);
          this.autoRefreshInterval = null;
        }
        window.location.href = window.location.pathname + window.location.search;
      }
    };

    updateCountdown();
    this.autoRefreshInterval = setInterval(updateCountdown, 1000);

    refreshBtn.addEventListener('mouseenter', () => {
      this.refreshPaused = true;
      if (this.autoRefreshInterval) {
        clearInterval(this.autoRefreshInterval);
        this.autoRefreshInterval = null;
      }
      originalSpan.textContent = 'Click to refresh (paused)';
    });

    refreshBtn.addEventListener('mouseleave', () => {
      this.refreshPaused = false;
      countdown = this.AUTO_REFRESH_SECONDS;
      if (!this.autoRefreshInterval) {
        updateCountdown();
        this.autoRefreshInterval = setInterval(updateCountdown, 1000);
      }
    });
  },

  createTooltip: function(element, tooltipText) {
    if (window.TooltipManager && typeof window.TooltipManager.create === 'function') {
      try {
        const tooltipContent = `
          <div class="py-1 px-2 text-sm text-white">
            ${tooltipText}
          </div>
        `;
        window.TooltipManager.create(element, tooltipContent, {
          placement: 'top'
        });
        element.classList.add('cursor-help');
      } catch (e) {
        element.setAttribute('title', tooltipText);
        element.classList.add('cursor-help');
      }
    } else {
      element.setAttribute('title', tooltipText);
      element.classList.add('cursor-help');
    }
  },

  applyStateTooltips: function() {
    const sections = document.querySelectorAll('section');
    let oldStatesSection = null;

    sections.forEach(section => {
      const h4 = section.querySelector('h4');
      if (h4 && h4.textContent.includes('Old states')) {
        oldStatesSection = section.nextElementSibling;
      }
    });

    if (oldStatesSection) {
      const table = oldStatesSection.querySelector('table');
      if (table) {
        const rows = table.querySelectorAll('tr');
        rows.forEach(row => {
          const cells = row.querySelectorAll('td');
          if (cells.length >= 2) {
            const stateCell = cells[cells.length - 1];
            const stateText = stateCell.textContent.trim();
            const tooltip = this.STATE_TOOLTIPS[stateText];
            if (tooltip) {
              this.addHelpIcon(stateCell, tooltip);
            }
          }
        });
      }
    }

    const allRows = document.querySelectorAll('table tr');
    allRows.forEach(row => {
      const firstCell = row.querySelector('td');
      if (firstCell) {
        const labelText = firstCell.textContent.trim();
        if (labelText === 'Bid State') {
          const valueCell = row.querySelectorAll('td')[1];
          if (valueCell) {
            const stateText = valueCell.textContent.trim();
            const tooltip = this.STATE_TOOLTIPS[stateText] || this.STATE_TOOLTIPS['Bid ' + stateText];
            if (tooltip) {
              this.addHelpIcon(valueCell, tooltip);
            }
          }
        }
      }
    });
  },

  addHelpIcon: function(cell, tooltipText) {
    if (cell.querySelector('.help-icon')) return;

    const helpIcon = document.createElement('span');
    helpIcon.className = 'help-icon cursor-help inline-flex items-center justify-center w-4 h-4 ml-2 text-xs font-medium text-white bg-blue-500 dark:bg-blue-600 rounded-full hover:bg-blue-600 dark:hover:bg-blue-500';
    helpIcon.textContent = '?';
    helpIcon.style.fontSize = '10px';
    helpIcon.style.verticalAlign = 'middle';
    helpIcon.style.flexShrink = '0';

    cell.appendChild(helpIcon);

    setTimeout(() => {
      this.createTooltip(helpIcon, tooltipText);
    }, 50);
  },

  applyEventTooltips: function() {
    const sections = document.querySelectorAll('section');
    let eventsSection = null;

    sections.forEach(section => {
      const h4 = section.querySelector('h4');
      if (h4 && h4.textContent.includes('Events')) {
        eventsSection = section.nextElementSibling;
      }
    });

    if (eventsSection) {
      const table = eventsSection.querySelector('table');
      if (table) {
        const rows = table.querySelectorAll('tr');
        rows.forEach(row => {
          const cells = row.querySelectorAll('td');
          if (cells.length >= 2) {
            const eventCell = cells[cells.length - 1];
            const eventText = eventCell.textContent.trim();

            let tooltip = this.EVENT_TOOLTIPS[eventText];

            if (!tooltip) {
              for (const [key, value] of Object.entries(this.EVENT_TOOLTIPS)) {
                if (eventText.startsWith(key.replace(':', ''))) {
                  tooltip = value;
                  break;
                }
              }
            }

            if (!tooltip && eventText.startsWith('Warning:')) {
              tooltip = 'System warning - check message for details';
            }
            if (!tooltip && eventText.startsWith('Error:')) {
              tooltip = 'Error occurred - check message for details';
            }
            if (!tooltip && eventText.startsWith('Temporary RPC error')) {
              tooltip = 'Temporary error checking transaction. Will retry automatically';
            }

            if (tooltip) {
              this.addHelpIcon(eventCell, tooltip);
            }
          }
        });
      }
    }
  },

  createProgressBar: function() {
    const phaseInfo = this.STATE_PHASES[this.bidStateInd];
    if (!phaseInfo) return;

    let progressPercent = 0;
    const phase = phaseInfo.phase;

    if (phase === 'negotiation') progressPercent = 15;
    else if (phase === 'accepted') progressPercent = 30;
    else if (phase === 'locking') progressPercent = 55;
    else if (phase === 'redemption') progressPercent = 80;
    else if (phase === 'complete') progressPercent = 100;
    else if (phase === 'failed' || phase === 'error') progressPercent = 100;

    const bidStateRow = document.querySelector('td.bold');
    if (!bidStateRow) return;

    let targetRow = null;
    const rows = document.querySelectorAll('table tr');
    rows.forEach(row => {
      const firstTd = row.querySelector('td.bold');
      if (firstTd && firstTd.textContent.trim() === 'Bid State') {
        targetRow = row;
      }
    });

    if (!targetRow) return;

    const progressRow = document.createElement('tr');
    progressRow.className = 'opacity-100 text-gray-500 dark:text-gray-100';

    const isError = ['failed', 'error'].includes(phase);
    const isComplete = phase === 'complete';
    const barColor = isError ? 'bg-red-500' : (isComplete ? 'bg-green-500' : 'bg-blue-500');
    const phaseLabel = isError ? phaseInfo.label : (isComplete ? 'Complete' : `${phaseInfo.label} (${progressPercent}%)`);

    progressRow.innerHTML = `
      <td class="py-3 px-6 bold">Swap Progress</td>
      <td class="py-3 px-6">
        <div class="flex items-center gap-3">
          <div class="flex-1 bg-gray-200 dark:bg-gray-600 rounded-full h-2.5 max-w-xs">
            <div class="${barColor} h-2.5 rounded-full transition-all duration-500" style="width: ${progressPercent}%"></div>
          </div>
          <span class="text-sm font-medium text-gray-900 dark:text-white">${phaseLabel}</span>
        </div>
      </td>
    `;

    targetRow.parentNode.insertBefore(progressRow, targetRow.nextSibling);
  },

  startElapsedTimeUpdater: function() {
    if (!this.createdAtTimestamp) return;

    let createdAtRow = null;
    const rows = document.querySelectorAll('table tr');
    rows.forEach(row => {
      const firstTd = row.querySelector('td');
      if (firstTd && firstTd.textContent.includes('Created At')) {
        createdAtRow = row;
      }
    });

    if (!createdAtRow) return;

    const isCompleted = !this.isActiveState() && this.stateTimeTimestamp;

    const elapsedRow = document.createElement('tr');
    elapsedRow.className = 'opacity-100 text-gray-500 dark:text-gray-100 hover:bg-coolGray-200 dark:hover:bg-gray-600';

    const labelText = isCompleted ? 'Swap Duration' : 'Time Elapsed';
    const iconColor = isCompleted ? '#10B981' : '#3B82F6';

    elapsedRow.innerHTML = `
      <td class="flex items-center px-46 whitespace-nowrap">
        <svg alt="" class="w-5 h-5 rounded-full ml-5" xmlns="http://www.w3.org/2000/svg" height="20" width="20" viewBox="0 0 24 24">
          <g stroke-linecap="round" stroke-width="2" fill="none" stroke="${iconColor}" stroke-linejoin="round">
            <circle cx="12" cy="12" r="11"></circle>
            <polyline points="12,6 12,12 18,12" stroke="${iconColor}"></polyline>
          </g>
        </svg>
        <div class="py-3 pl-2 bold">
          <div>${labelText}</div>
        </div>
      </td>
      <td class="py-3 px-6" id="elapsed-time-display">Calculating...</td>
    `;
    createdAtRow.parentNode.insertBefore(elapsedRow, createdAtRow.nextSibling);

    const elapsedDisplay = document.getElementById('elapsed-time-display');

    if (isCompleted) {
      const duration = this.stateTimeTimestamp - this.createdAtTimestamp;
      elapsedDisplay.textContent = this.formatDuration(duration);
    } else {
      const updateElapsed = () => {
        const now = Math.floor(Date.now() / 1000);
        const elapsed = now - this.createdAtTimestamp;
        elapsedDisplay.textContent = this.formatDuration(elapsed);
      };

      updateElapsed();
      this.elapsedTimeInterval = setInterval(updateElapsed, 1000);
    }
  },

  formatDuration: function(seconds) {
    if (seconds < 60) {
      return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    }
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) {
      const remainingSeconds = seconds % 60;
      if (remainingSeconds > 0) {
        return `${minutes} min ${remainingSeconds} sec`;
      }
      return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
    }
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    if (hours < 24) {
      if (remainingMinutes > 0) {
        return `${hours} hr ${remainingMinutes} min`;
      }
      return `${hours} hour${hours !== 1 ? 's' : ''}`;
    }
    const days = Math.floor(hours / 24);
    const remainingHours = hours % 24;
    if (remainingHours > 0) {
      return `${days} day${days !== 1 ? 's' : ''} ${remainingHours} hr`;
    }
    return `${days} day${days !== 1 ? 's' : ''}`;
  }
};
