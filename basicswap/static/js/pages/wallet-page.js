(function() {
  'use strict';

  const WalletPage = {
    confirmCallback: null,
    triggerElement: null,
    currentCoinId: '',
    activeTooltip: null,

    init: function() {
      this.setupAddressCopy();
      this.setupConfirmModal();
      this.setupWithdrawalConfirmation();
      this.setupTransactionDisplay();
      this.setupWebSocketUpdates();
      this.setupTransactionPagination();
    },

    setupAddressCopy: function() {
      const copyableElements = [
        'main_deposit_address',
        'monero_main_address',
        'monero_sub_address',
        'stealth_address'
      ];
      
      copyableElements.forEach(id => {
        const element = document.getElementById(id);
        if (!element) return;
        
        element.classList.add('cursor-pointer', 'hover:bg-gray-100', 'dark:hover:bg-gray-600', 'transition-colors');
        
        if (!element.querySelector('.copy-icon')) {
          const copyIcon = document.createElement('span');
          copyIcon.className = 'copy-icon absolute right-2 inset-y-0 flex items-center text-gray-500 dark:text-gray-300';
          copyIcon.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>`;
          
          element.style.position = 'relative';
          element.style.paddingRight = '2.5rem';
          element.appendChild(copyIcon);
        }
        
        element.addEventListener('click', (e) => {
          const textToCopy = element.innerText.trim();
          
          this.copyToClipboard(textToCopy);
          
          element.classList.add('bg-blue-50', 'dark:bg-blue-900');

          this.showCopyFeedback(element);

          CleanupManager.setTimeout(() => {
            element.classList.remove('bg-blue-50', 'dark:bg-blue-900');
          }, 1000);
        });
      });
    },

    copyToClipboard: function(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          console.log('Address copied to clipboard');
        }).catch(err => {
          console.error('Failed to copy address:', err);
          this.fallbackCopyToClipboard(text);
        });
      } else {
        this.fallbackCopyToClipboard(text);
      }
    },

    fallbackCopyToClipboard: function(text) {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      textArea.style.top = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      
      try {
        document.execCommand('copy');
        console.log('Address copied to clipboard (fallback)');
      } catch (err) {
        console.error('Fallback: Failed to copy address', err);
      }
      
      document.body.removeChild(textArea);
    },

    showCopyFeedback: function(element) {
      if (this.activeTooltip && this.activeTooltip.parentNode) {
        this.activeTooltip.parentNode.removeChild(this.activeTooltip);
      }

      const popup = document.createElement('div');
      popup.className = 'copy-feedback-popup fixed z-50 bg-blue-600 text-white text-sm py-2 px-3 rounded-md shadow-lg';
      popup.innerText = 'Copied!';
      document.body.appendChild(popup);

      this.activeTooltip = popup;

      this.updateTooltipPosition(popup, element);

      const scrollHandler = () => {
        if (popup.parentNode) {
          requestAnimationFrame(() => {
            this.updateTooltipPosition(popup, element);
          });
        }
      };

      window.addEventListener('scroll', scrollHandler, { passive: true });

      popup.style.opacity = '0';
      popup.style.transition = 'opacity 0.2s ease-in-out';

      CleanupManager.setTimeout(() => {
        popup.style.opacity = '1';
      }, 10);

      CleanupManager.setTimeout(() => {
        window.removeEventListener('scroll', scrollHandler);
        popup.style.opacity = '0';

        CleanupManager.setTimeout(() => {
          if (popup.parentNode) {
            popup.parentNode.removeChild(popup);
          }
          if (this.activeTooltip === popup) {
            this.activeTooltip = null;
          }
        }, 200);
      }, 1500);
    },

    updateTooltipPosition: function(tooltip, element) {
      const rect = element.getBoundingClientRect();

      let top = rect.top - tooltip.offsetHeight - 8;
      const left = rect.left + rect.width / 2;

      if (top < 10) {
        top = rect.bottom + 8;
      }

      tooltip.style.top = `${top}px`;
      tooltip.style.left = `${left}px`;
      tooltip.style.transform = 'translateX(-50%)';
    },

    setupWithdrawalConfirmation: function() {
      
      const withdrawalClickHandler = (e) => {
        const target = e.target.closest('[data-confirm-withdrawal]');
        if (target) {
          e.preventDefault();

          this.triggerElement = target;

          this.confirmWithdrawal().catch(() => {
            
          });
        }
      };

      document.addEventListener('click', withdrawalClickHandler);

      if (window.CleanupManager) {
        CleanupManager.registerResource('walletWithdrawalClick', withdrawalClickHandler, () => {
          document.removeEventListener('click', withdrawalClickHandler);
        });
      }
    },

    setupConfirmModal: function() {
      const confirmYesBtn = document.getElementById('confirmYes');
      if (confirmYesBtn) {
        confirmYesBtn.addEventListener('click', () => {
          if (this.confirmCallback && typeof this.confirmCallback === 'function') {
            this.confirmCallback();
          }
          this.hideConfirmDialog();
        });
      }

      const confirmNoBtn = document.getElementById('confirmNo');
      if (confirmNoBtn) {
        confirmNoBtn.addEventListener('click', () => {
          this.hideConfirmDialog();
        });
      }

      const confirmModal = document.getElementById('confirmModal');
      if (confirmModal) {
        confirmModal.addEventListener('click', (e) => {
          if (e.target === confirmModal) {
            this.hideConfirmDialog();
          }
        });
      }
    },

    showConfirmDialog: function(title, message, callback) {
      return new Promise((resolve, reject) => {
        this.confirmCallback = () => {
          if (callback) callback();
          resolve();
        };
        this.confirmReject = reject;

        document.getElementById('confirmTitle').textContent = title;
        document.getElementById('confirmMessage').textContent = message;
        const modal = document.getElementById('confirmModal');
        if (modal) {
          modal.classList.remove('hidden');
        }
      });
    },

    hideConfirmDialog: function() {
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.add('hidden');
      }
      if (this.confirmReject) {
        this.confirmReject();
      }
      this.confirmCallback = null;
      this.confirmReject = null;
      return false;
    },

    confirmReseed: function() {
      this.triggerElement = document.activeElement;
      return this.showConfirmDialog(
        "Confirm Reseed Wallet",
        "Are you sure?\nBackup your wallet before and after.\nWon't detect used keys.\nShould only be used for new wallets.",
        () => {
          if (this.triggerElement) {
            const form = this.triggerElement.form;
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = this.triggerElement.name;
            hiddenInput.value = this.triggerElement.value;
            form.appendChild(hiddenInput);
            form.submit();
          }
        }
      );
    },

    confirmWithdrawal: function() {
      this.triggerElement = document.activeElement;
      return this.showConfirmDialog(
        "Confirm Withdrawal",
        "Are you sure you want to proceed with this withdrawal?",
        () => {
          if (this.triggerElement) {
            const form = this.triggerElement.form;
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = this.triggerElement.name;
            hiddenInput.value = this.triggerElement.value;
            form.appendChild(hiddenInput);
            form.submit();
          }
        }
      );
    },

    confirmCreateUTXO: function() {
      this.triggerElement = document.activeElement;
      return this.showConfirmDialog(
        "Confirm Create UTXO",
        "Are you sure you want to create this UTXO?",
        () => {
          if (this.triggerElement) {
            const form = this.triggerElement.form;
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = this.triggerElement.name;
            hiddenInput.value = this.triggerElement.value;
            form.appendChild(hiddenInput);
            form.submit();
          }
        }
      );
    },

    confirmUTXOResize: function() {
      this.triggerElement = document.activeElement;
      return this.showConfirmDialog(
        "Confirm UTXO Resize",
        "Are you sure you want to resize UTXOs?",
        () => {
          if (this.triggerElement) {
            const form = this.triggerElement.form;
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = this.triggerElement.name;
            hiddenInput.value = this.triggerElement.value;
            form.appendChild(hiddenInput);
            form.submit();
          }
        }
      );
    },

    setupTransactionDisplay: function() {
      
    },

    setupWebSocketUpdates: function() {
      if (window.BalanceUpdatesManager) {
        const coinId = this.getCoinIdFromPage();
        if (coinId) {
          this.currentCoinId = coinId;
          window.BalanceUpdatesManager.setup({
            contextKey: 'wallet_' + coinId,
            balanceUpdateCallback: this.handleBalanceUpdate.bind(this),
            swapEventCallback: this.handleSwapEvent.bind(this),
            errorContext: 'Wallet',
            enablePeriodicRefresh: true,
            periodicInterval: 60000
          });
        }
      }
    },

    getCoinIdFromPage: function() {
      const pathParts = window.location.pathname.split('/');
      const walletIndex = pathParts.indexOf('wallet');
      if (walletIndex !== -1 && pathParts[walletIndex + 1]) {
        return pathParts[walletIndex + 1];
      }
      return null;
    },

    handleBalanceUpdate: function(balanceData) {
      if (!balanceData || !Array.isArray(balanceData)) return;

      const coinId = this.currentCoinId;
      if (!coinId) return;

      const matchingCoins = balanceData.filter(coin =>
        coin.ticker && coin.ticker.toLowerCase() === coinId.toLowerCase()
      );

      matchingCoins.forEach(coinData => {
        const balanceElements = document.querySelectorAll('.coinname-value[data-coinname]');
        balanceElements.forEach(element => {
          const elementCoinName = element.getAttribute('data-coinname');
          if (elementCoinName === coinData.name) {
            const currentText = element.textContent;
            const ticker = coinData.ticker || coinId.toUpperCase();
            const newBalance = `${coinData.balance} ${ticker}`;
            if (currentText !== newBalance) {
              element.textContent = newBalance;
              console.log(`Updated balance: ${coinData.name} -> ${newBalance}`);
            }
          }
        });

        this.updatePendingForCoin(coinData);
      });

      this.refreshTransactions();
    },

    updatePendingForCoin: function(coinData) {
      const pendingAmount = parseFloat(coinData.pending || '0');


      const pendingElements = document.querySelectorAll('.inline-block.py-1.px-2.rounded-full.bg-green-100');

      pendingElements.forEach(el => {
        const text = el.textContent || '';

        if (text.includes('Pending:') && text.includes(coinData.ticker)) {
          if (pendingAmount > 0) {
            el.textContent = `Pending: +${coinData.pending} ${coinData.ticker}`;
            el.style.display = '';
          } else {
            el.style.display = 'none';
          }
        }
      });
    },

    refreshTransactions: function() {
      const txTable = document.querySelector('#transaction-history-section tbody');
      if (txTable) {
        const pathParts = window.location.pathname.split('/');
        const ticker = pathParts[pathParts.length - 1];

        fetch(`/json/wallettransactions/${ticker}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ page_no: 1 })
        })
        .then(response => response.json())
        .then(data => {
          if (data.transactions && data.transactions.length > 0) {
            const currentPageSpan = document.getElementById('currentPageTx');
            const totalPagesSpan = document.getElementById('totalPagesTx');
            if (currentPageSpan) currentPageSpan.textContent = data.page_no;
            if (totalPagesSpan) totalPagesSpan.textContent = data.total_pages;
          }
        })
        .catch(error => console.error('Error refreshing transactions:', error));
      }
    },

    handleSwapEvent: function(eventData) {
      if (window.BalanceUpdatesManager) {
        window.BalanceUpdatesManager.fetchBalanceData()
          .then(data => this.handleBalanceUpdate(data))
          .catch(error => console.error('Error updating balance after swap:', error));
      }
    },

    setupTransactionPagination: function() {
      const txContainer = document.getElementById('tx-container');
      if (!txContainer) return;

      const pathParts = window.location.pathname.split('/');
      const ticker = pathParts[pathParts.length - 1];

      let currentPage = 1;
      let totalPages = 1;
      let isLoading = false;

      const prevBtn = document.getElementById('prevPageTx');
      const nextBtn = document.getElementById('nextPageTx');
      const currentPageSpan = document.getElementById('currentPageTx');
      const totalPagesSpan = document.getElementById('totalPagesTx');
      const paginationControls = document.getElementById('tx-pagination-section');

      const copyToClipboard = (text, button) => {
        const showSuccess = () => {
          const originalHTML = button.innerHTML;
          button.innerHTML = `<svg class="w-4 h-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
          </svg>`;
          setTimeout(() => {
            button.innerHTML = originalHTML;
          }, 1500);
        };

        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(showSuccess).catch(err => {
            console.error('Clipboard API failed:', err);
            fallbackCopy(text, showSuccess);
          });
        } else {
          fallbackCopy(text, showSuccess);
        }
      };

      const fallbackCopy = (text, onSuccess) => {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
          document.execCommand('copy');
          onSuccess();
        } catch (err) {
          console.error('Fallback copy failed:', err);
        }
        document.body.removeChild(textArea);
      };

      const loadTransactions = async (page) => {
        if (isLoading) return;
        isLoading = true;

        try {
          const response = await fetch(`/json/wallettransactions/${ticker}`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ page_no: page })
          });

          const data = await response.json();

          if (data.error) {
            console.error('Error loading transactions:', data.error);
            return;
          }

          currentPage = data.page_no;
          totalPages = data.total_pages;

          currentPageSpan.textContent = currentPage;
          totalPagesSpan.textContent = totalPages;

          txContainer.innerHTML = '';

          if (data.transactions && data.transactions.length > 0) {
            data.transactions.forEach(tx => {
              const card = document.createElement('div');
              card.className = 'bg-white dark:bg-gray-600 rounded-lg border border-gray-200 dark:border-gray-500 p-4 hover:shadow-md transition-shadow';

              let typeClass = 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300';
              let amountClass = 'text-gray-700 dark:text-gray-200';
              let typeIcon = '';
              let amountPrefix = '';
              if (tx.type === 'Incoming') {
                typeClass = 'bg-green-100 text-green-600 dark:bg-green-900 dark:text-green-300';
                amountClass = 'text-green-600 dark:text-green-400';
                typeIcon = '↓';
                amountPrefix = '+';
              } else if (tx.type === 'Outgoing') {
                typeClass = 'bg-red-100 text-red-600 dark:bg-red-900 dark:text-red-300';
                amountClass = 'text-red-600 dark:text-red-400';
                typeIcon = '↑';
                amountPrefix = '-';
              }

              let confirmClass = 'text-gray-600 dark:text-gray-300';
              if (tx.confirmations === 0) {
                confirmClass = 'text-yellow-600 dark:text-yellow-400 font-medium';
              } else if (tx.confirmations >= 1 && tx.confirmations <= 5) {
                confirmClass = 'text-blue-600 dark:text-blue-400';
              } else if (tx.confirmations >= 6) {
                confirmClass = 'text-green-600 dark:text-green-400';
              }

              card.innerHTML = `
                <div class="flex flex-wrap items-center justify-between gap-2 mb-3">
                  <div class="flex items-center gap-3">
                    <span class="inline-flex items-center gap-1 py-1 px-2 rounded-full text-xs font-semibold ${typeClass}">
                      ${typeIcon} ${tx.type}
                    </span>
                    <span class="font-semibold ${amountClass}">
                      ${amountPrefix}${tx.amount} ${ticker.toUpperCase()}
                    </span>
                  </div>
                  <div class="flex items-center gap-4 text-sm">
                    <span class="${confirmClass}">${tx.confirmations} Confirmations</span>
                    <span class="text-gray-500 dark:text-gray-400">${tx.timestamp}</span>
                  </div>
                </div>
                ${tx.address ? `
                <div class="flex items-center gap-2 mb-2">
                  <span class="text-xs text-gray-500 dark:text-gray-400 w-16 flex-shrink-0">Address:</span>
                  <span class="font-mono text-xs text-gray-700 dark:text-gray-200 break-all flex-1">${tx.address}</span>
                  <button class="copy-address-btn p-1.5 hover:bg-gray-100 dark:hover:bg-gray-500 rounded flex-shrink-0 focus:outline-none focus:ring-0" title="Copy Address">
                    <svg class="w-4 h-4 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                    </svg>
                  </button>
                </div>
                ` : ''}
                <div class="flex items-center gap-2">
                  <span class="text-xs text-gray-500 dark:text-gray-400 w-16 flex-shrink-0">Txid:</span>
                  <span class="font-mono text-xs text-gray-700 dark:text-gray-200 break-all flex-1">${tx.txid}</span>
                  <button class="copy-txid-btn p-1.5 hover:bg-gray-100 dark:hover:bg-gray-500 rounded flex-shrink-0 focus:outline-none focus:ring-0" title="Copy Transaction ID">
                    <svg class="w-4 h-4 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                    </svg>
                  </button>
                </div>
              `;

              const copyAddressBtn = card.querySelector('.copy-address-btn');
              if (copyAddressBtn) {
                copyAddressBtn.addEventListener('click', () => copyToClipboard(tx.address, copyAddressBtn));
              }

              const copyTxidBtn = card.querySelector('.copy-txid-btn');
              if (copyTxidBtn) {
                copyTxidBtn.addEventListener('click', () => copyToClipboard(tx.txid, copyTxidBtn));
              }

              txContainer.appendChild(card);
            });

            if (totalPages > 1 && paginationControls) {
              paginationControls.style.display = 'block';
            } else if (paginationControls) {
              paginationControls.style.display = 'none';
            }
          } else {
            txContainer.innerHTML = '<div class="text-center py-8 text-gray-500 dark:text-gray-400">No transactions found</div>';
            if (paginationControls) paginationControls.style.display = 'none';
          }

          prevBtn.style.display = currentPage > 1 ? 'inline-flex' : 'none';
          nextBtn.style.display = currentPage < totalPages ? 'inline-flex' : 'none';

        } catch (error) {
          console.error('Error fetching transactions:', error);
        } finally {
          isLoading = false;
        }
      };

      if (prevBtn) {
        prevBtn.addEventListener('click', () => {
          if (currentPage > 1) {
            loadTransactions(currentPage - 1);
          }
        });
      }

      if (nextBtn) {
        nextBtn.addEventListener('click', () => {
          if (currentPage < totalPages) {
            loadTransactions(currentPage + 1);
          }
        });
      }

      loadTransactions(1);
    }
  };

  document.addEventListener('DOMContentLoaded', function() {
    WalletPage.init();
    
    if (window.BalanceUpdatesManager) {
      window.BalanceUpdatesManager.initialize();
    }
  });

  window.WalletPage = WalletPage;
  window.setupAddressCopy = WalletPage.setupAddressCopy.bind(WalletPage);
  window.showConfirmDialog = WalletPage.showConfirmDialog.bind(WalletPage);
  window.hideConfirmDialog = WalletPage.hideConfirmDialog.bind(WalletPage);
  window.confirmReseed = WalletPage.confirmReseed.bind(WalletPage);
  window.confirmWithdrawal = WalletPage.confirmWithdrawal.bind(WalletPage);
  window.confirmCreateUTXO = WalletPage.confirmCreateUTXO.bind(WalletPage);
  window.confirmUTXOResize = WalletPage.confirmUTXOResize.bind(WalletPage);
  window.copyToClipboard = WalletPage.copyToClipboard.bind(WalletPage);
  window.showCopyFeedback = WalletPage.showCopyFeedback.bind(WalletPage);

})();
