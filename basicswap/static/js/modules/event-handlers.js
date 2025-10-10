(function() {
  'use strict';

  const EventHandlers = {
    
    confirmPopup: function(action = 'proceed', coinName = '') {
      const message = action === 'Accept' 
        ? 'Are you sure you want to accept this bid?'
        : coinName 
          ? `Are you sure you want to ${action} ${coinName}?`
          : 'Are you sure you want to proceed?';
      
      return confirm(message);
    },

    confirmReseed: function() {
      return confirm('Are you sure you want to reseed the wallet? This will generate new addresses.');
    },

    confirmWithdrawal: function() {
      
      if (window.WalletPage && typeof window.WalletPage.confirmWithdrawal === 'function') {
        return window.WalletPage.confirmWithdrawal();
      }
      return confirm('Are you sure you want to withdraw? Please verify the address and amount.');
    },

    confirmUTXOResize: function() {
      return confirm('Are you sure you want to create a UTXO? This will split your balance.');
    },

    confirmRemoveExpired: function() {
      return confirm('Are you sure you want to remove all expired offers and bids?');
    },

    fillDonationAddress: function(address, coinType) {
      
      let addressInput = null;

      addressInput = window.DOMCache
        ? window.DOMCache.get('address_to')
        : document.getElementById('address_to');

      if (!addressInput) {
        addressInput = document.querySelector('input[name^="to_"]');
      }

      if (!addressInput) {
        addressInput = document.querySelector('input[placeholder*="Address"]');
      }

      if (addressInput) {
        addressInput.value = address;
        console.log(`Filled donation address for ${coinType}: ${address}`);
      } else {
        console.error('EventHandlers: Address input not found');
      }
    },

    setAmmAmount: function(percent, inputId) {
      const amountInput = window.DOMCache
        ? window.DOMCache.get(inputId)
        : document.getElementById(inputId);

      if (!amountInput) {
        console.error('EventHandlers: AMM amount input not found:', inputId);
        return;
      }

      const balanceElement = amountInput.closest('form')?.querySelector('[data-balance]');
      const balance = balanceElement ? parseFloat(balanceElement.getAttribute('data-balance')) : 0;

      if (balance > 0) {
        const calculatedAmount = balance * percent;
        amountInput.value = calculatedAmount.toFixed(8);
      } else {
        console.warn('EventHandlers: No balance found for AMM amount calculation');
      }
    },

    setOfferAmount: function(percent, inputId) {
      const amountInput = window.DOMCache
        ? window.DOMCache.get(inputId)
        : document.getElementById(inputId);

      if (!amountInput) {
        console.error('EventHandlers: Offer amount input not found:', inputId);
        return;
      }

      const coinFromSelect = document.getElementById('coin_from');
      if (!coinFromSelect) {
        console.error('EventHandlers: coin_from select not found');
        return;
      }

      const selectedOption = coinFromSelect.options[coinFromSelect.selectedIndex];
      if (!selectedOption || selectedOption.value === '-1') {
        if (window.showErrorModal) {
          window.showErrorModal('Validation Error', 'Please select a coin first');
        } else {
          alert('Please select a coin first');
        }
        return;
      }

      const balance = selectedOption.getAttribute('data-balance');
      if (!balance) {
        console.error('EventHandlers: Balance not found for selected coin');
        return;
      }

      const floatBalance = parseFloat(balance);
      if (isNaN(floatBalance) || floatBalance <= 0) {
        if (window.showErrorModal) {
          window.showErrorModal('Invalid Balance', 'The selected coin has no available balance. Please select a coin with a positive balance.');
        } else {
          alert('Invalid balance for selected coin');
        }
        return;
      }

      const calculatedAmount = floatBalance * percent;
      amountInput.value = calculatedAmount.toFixed(8);
    },

    resetForm: function() {
      const form = document.querySelector('form[name="offer_form"]') || document.querySelector('form');
      if (form) {
        form.reset();
      }
    },

    hideConfirmModal: function() {
      if (window.DOMCache) {
        window.DOMCache.hide('confirmModal');
      } else {
        const modal = document.getElementById('confirmModal');
        if (modal) {
          modal.style.display = 'none';
        }
      }
    },

    lookup_rates: function() {
      
      if (window.lookup_rates && typeof window.lookup_rates === 'function') {
        window.lookup_rates();
      } else {
        console.error('EventHandlers: lookup_rates function not found');
      }
    },

    checkForUpdatesNow: function() {
      if (window.checkForUpdatesNow && typeof window.checkForUpdatesNow === 'function') {
        window.checkForUpdatesNow();
      } else {
        console.error('EventHandlers: checkForUpdatesNow function not found');
      }
    },

    testUpdateNotification: function() {
      if (window.testUpdateNotification && typeof window.testUpdateNotification === 'function') {
        window.testUpdateNotification();
      } else {
        console.error('EventHandlers: testUpdateNotification function not found');
      }
    },

    toggleNotificationDropdown: function(event) {
      if (window.toggleNotificationDropdown && typeof window.toggleNotificationDropdown === 'function') {
        window.toggleNotificationDropdown(event);
      } else {
        console.error('EventHandlers: toggleNotificationDropdown function not found');
      }
    },

    closeMessage: function(messageId) {
      if (window.DOMCache) {
        window.DOMCache.hide(messageId);
      } else {
        const messageElement = document.getElementById(messageId);
        if (messageElement) {
          messageElement.style.display = 'none';
        }
      }
    },

    initialize: function() {
      
      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-confirm]');
        if (target) {
          const action = target.getAttribute('data-confirm-action') || 'proceed';
          const coinName = target.getAttribute('data-confirm-coin') || '';
          
          if (!this.confirmPopup(action, coinName)) {
            e.preventDefault();
            return false;
          }
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-confirm-reseed]');
        if (target) {
          if (!this.confirmReseed()) {
            e.preventDefault();
            return false;
          }
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-confirm-utxo]');
        if (target) {
          if (!this.confirmUTXOResize()) {
            e.preventDefault();
            return false;
          }
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-confirm-remove-expired]');
        if (target) {
          if (!this.confirmRemoveExpired()) {
            e.preventDefault();
            return false;
          }
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-fill-donation]');
        if (target) {
          e.preventDefault();
          const address = target.getAttribute('data-address');
          const coinType = target.getAttribute('data-coin-type');
          this.fillDonationAddress(address, coinType);
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-set-amm-amount]');
        if (target) {
          e.preventDefault();
          const percent = parseFloat(target.getAttribute('data-set-amm-amount'));
          const inputId = target.getAttribute('data-input-id');
          this.setAmmAmount(percent, inputId);
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-set-offer-amount]');
        if (target) {
          e.preventDefault();
          const percent = parseFloat(target.getAttribute('data-set-offer-amount'));
          const inputId = target.getAttribute('data-input-id');
          this.setOfferAmount(percent, inputId);
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-reset-form]');
        if (target) {
          e.preventDefault();
          this.resetForm();
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-hide-modal]');
        if (target) {
          e.preventDefault();
          this.hideConfirmModal();
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-lookup-rates]');
        if (target) {
          e.preventDefault();
          this.lookup_rates();
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-check-updates]');
        if (target) {
          e.preventDefault();
          this.checkForUpdatesNow();
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-test-notification]');
        if (target) {
          e.preventDefault();
          const type = target.getAttribute('data-test-notification');
          if (type === 'update') {
            this.testUpdateNotification();
          } else {
            window.NotificationManager && window.NotificationManager.testToasts();
          }
        }
      });

      document.addEventListener('click', (e) => {
        const target = e.target.closest('[data-close-message]');
        if (target) {
          e.preventDefault();
          const messageId = target.getAttribute('data-close-message');
          this.closeMessage(messageId);
        }
      });
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      EventHandlers.initialize();
    });
  } else {
    EventHandlers.initialize();
  }

  window.EventHandlers = EventHandlers;
  
  window.confirmPopup = EventHandlers.confirmPopup.bind(EventHandlers);
  window.confirmReseed = EventHandlers.confirmReseed.bind(EventHandlers);
  window.confirmWithdrawal = EventHandlers.confirmWithdrawal.bind(EventHandlers);
  window.confirmUTXOResize = EventHandlers.confirmUTXOResize.bind(EventHandlers);
  window.confirmRemoveExpired = EventHandlers.confirmRemoveExpired.bind(EventHandlers);
  window.fillDonationAddress = EventHandlers.fillDonationAddress.bind(EventHandlers);
  window.setAmmAmount = EventHandlers.setAmmAmount.bind(EventHandlers);
  window.setOfferAmount = EventHandlers.setOfferAmount.bind(EventHandlers);
  window.resetForm = EventHandlers.resetForm.bind(EventHandlers);
  window.hideConfirmModal = EventHandlers.hideConfirmModal.bind(EventHandlers);
  window.toggleNotificationDropdown = EventHandlers.toggleNotificationDropdown.bind(EventHandlers);

})();
