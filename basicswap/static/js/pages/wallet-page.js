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
      
      console.log('Balance updated:', balanceData);
    },

    handleSwapEvent: function(eventData) {
      
      console.log('Swap event:', eventData);
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
