(function() {
  'use strict';

  const AMMPage = {
    
    init: function() {
      this.loadDebugSetting();
      this.setupAutostartCheckbox();
      this.setupStartupValidation();
      this.setupDebugCheckbox();
      this.setupModals();
      this.setupClearStateButton();
      this.setupWebSocketBalanceUpdates();
      this.setupCleanup();
    },

    saveDebugSetting: function() {
      const debugCheckbox = document.getElementById('debug-mode');
      if (debugCheckbox) {
        localStorage.setItem('amm_debug_enabled', debugCheckbox.checked);
      }
    },

    loadDebugSetting: function() {
      const debugCheckbox = document.getElementById('debug-mode');
      if (debugCheckbox) {
        const savedSetting = localStorage.getItem('amm_debug_enabled');
        if (savedSetting !== null) {
          debugCheckbox.checked = savedSetting === 'true';
        }
      }
    },

    setupDebugCheckbox: function() {
      const debugCheckbox = document.getElementById('debug-mode');
      if (debugCheckbox) {
        debugCheckbox.addEventListener('change', this.saveDebugSetting.bind(this));
      }
    },

    saveAutostartSetting: function(checked) {
      const bodyData = `autostart=${checked ? 'true' : 'false'}`;

      fetch('/amm/autostart', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: bodyData
      })
      .then(response => response.json())
      .then(data => {
        if (data.success) {
          localStorage.setItem('amm_autostart_enabled', checked);

          if (data.autostart !== checked) {
            console.warn('WARNING: API returned different autostart value than expected!', {
              sent: checked,
              received: data.autostart
            });
          }
        } else {
          console.error('Failed to save autostart setting:', data.error);
          const autostartCheckbox = document.getElementById('autostart-amm');
          if (autostartCheckbox) {
            autostartCheckbox.checked = !checked;
          }
        }
      })
      .catch(error => {
        console.error('Error saving autostart setting:', error);
        const autostartCheckbox = document.getElementById('autostart-amm');
        if (autostartCheckbox) {
          autostartCheckbox.checked = !checked;
        }
      });
    },

    setupAutostartCheckbox: function() {
      const autostartCheckbox = document.getElementById('autostart-amm');
      if (autostartCheckbox) {
        autostartCheckbox.addEventListener('change', () => {
          this.saveAutostartSetting(autostartCheckbox.checked);
        });
      }
    },

    showErrorModal: function(title, message) {
      document.getElementById('errorTitle').textContent = title || 'Error';
      document.getElementById('errorMessage').textContent = message || 'An error occurred';
      const modal = document.getElementById('errorModal');
      if (modal) {
        modal.classList.remove('hidden');
      }
    },

    hideErrorModal: function() {
      const modal = document.getElementById('errorModal');
      if (modal) {
        modal.classList.add('hidden');
      }
    },

    showConfirmModal: function(title, message, callback) {
      document.getElementById('confirmTitle').textContent = title || 'Confirm Action';
      document.getElementById('confirmMessage').textContent = message || 'Are you sure?';
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.remove('hidden');
      }

      window.confirmCallback = callback;
    },

    hideConfirmModal: function() {
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.add('hidden');
      }
      window.confirmCallback = null;
    },

    setupModals: function() {
      const errorOkBtn = document.getElementById('errorOk');
      if (errorOkBtn) {
        errorOkBtn.addEventListener('click', this.hideErrorModal.bind(this));
      }

      const errorModal = document.getElementById('errorModal');
      if (errorModal) {
        errorModal.addEventListener('click', (e) => {
          if (e.target === errorModal) {
            this.hideErrorModal();
          }
        });
      }

      const confirmYesBtn = document.getElementById('confirmYes');
      if (confirmYesBtn) {
        confirmYesBtn.addEventListener('click', () => {
          if (window.confirmCallback && typeof window.confirmCallback === 'function') {
            window.confirmCallback();
          }
          this.hideConfirmModal();
        });
      }

      const confirmNoBtn = document.getElementById('confirmNo');
      if (confirmNoBtn) {
        confirmNoBtn.addEventListener('click', this.hideConfirmModal.bind(this));
      }

      const confirmModal = document.getElementById('confirmModal');
      if (confirmModal) {
        confirmModal.addEventListener('click', (e) => {
          if (e.target === confirmModal) {
            this.hideConfirmModal();
          }
        });
      }
    },

    setupStartupValidation: function() {
      const controlForm = document.querySelector('form[method="post"]');
      if (!controlForm) return;

      const startButton = controlForm.querySelector('input[name="start"]');
      if (!startButton) return;

      startButton.addEventListener('click', (e) => {
        e.preventDefault();
        this.performStartupValidation();
      });
    },

    performStartupValidation: function() {
      const feedbackDiv = document.getElementById('startup-feedback');
      const titleEl = document.getElementById('startup-title');
      const messageEl = document.getElementById('startup-message');
      const progressBar = document.getElementById('startup-progress-bar');

      feedbackDiv.classList.remove('hidden');

      const steps = [
        { message: 'Checking configuration...', progress: 20 },
        { message: 'Validating offers and bids...', progress: 40 },
        { message: 'Checking wallet balances...', progress: 60 },
        { message: 'Verifying API connection...', progress: 80 },
        { message: 'Starting AMM process...', progress: 100 }
      ];

      let currentStep = 0;

      const runNextStep = () => {
        if (currentStep >= steps.length) {
          this.submitStartForm();
          return;
        }

        const step = steps[currentStep];
        messageEl.textContent = step.message;
        progressBar.style.width = step.progress + '%';

        CleanupManager.setTimeout(() => {
          this.validateStep(currentStep).then(result => {
            if (result.success) {
              currentStep++;
              runNextStep();
            } else {
              this.showStartupError(result.error);
            }
          }).catch(error => {
            this.showStartupError('Validation failed: ' + error.message);
          });
        }, 500);
      };

      runNextStep();
    },

    validateStep: async function(stepIndex) {
      try {
        switch (stepIndex) {
          case 0:
            return await this.validateConfiguration();
          case 1:
            return await this.validateOffersAndBids();
          case 2:
            return await this.validateWalletBalances();
          case 3:
            return await this.validateApiConnection();
          case 4:
            return { success: true };
          default:
            return { success: true };
        }
      } catch (error) {
        return { success: false, error: error.message };
      }
    },

    validateConfiguration: async function() {
      const configData = window.ammTablesConfig?.configData;
      if (!configData) {
        return { success: false, error: 'No configuration found. Please save a configuration first.' };
      }

      if (!configData.min_seconds_between_offers || !configData.max_seconds_between_offers) {
        return { success: false, error: 'Missing timing configuration. Please check your settings.' };
      }

      return { success: true };
    },

    validateOffersAndBids: async function() {
      const configData = window.ammTablesConfig?.configData;
      if (!configData) {
        return { success: false, error: 'Configuration not available for validation.' };
      }

      const offers = configData.offers || [];
      const bids = configData.bids || [];
      const enabledOffers = offers.filter(o => o.enabled);
      const enabledBids = bids.filter(b => b.enabled);

      if (enabledOffers.length === 0 && enabledBids.length === 0) {
        return { success: false, error: 'No enabled offers or bids found. Please enable at least one offer or bid before starting.' };
      }

      for (const offer of enabledOffers) {
        if (!offer.amount_step) {
          return { success: false, error: `Offer "${offer.name}" is missing required Amount Step (privacy feature).` };
        }

        const amountStep = parseFloat(offer.amount_step);
        const amount = parseFloat(offer.amount);

        if (amountStep <= 0 || amountStep < 0.001) {
          return { success: false, error: `Offer "${offer.name}" has invalid Amount Step. Must be >= 0.001.` };
        }

        if (amountStep > amount) {
          return { success: false, error: `Offer "${offer.name}" Amount Step (${amountStep}) cannot be greater than offer amount (${amount}).` };
        }
      }

      return { success: true };
    },

    validateWalletBalances: async function() {
      const configData = window.ammTablesConfig?.configData;
      if (!configData) return { success: true };

      const offers = configData.offers || [];
      const enabledOffers = offers.filter(o => o.enabled);

      for (const offer of enabledOffers) {
        if (!offer.min_coin_from_amt || parseFloat(offer.min_coin_from_amt) <= 0) {
          return { success: false, error: `Offer "${offer.name}" needs a minimum coin amount to protect your wallet balance.` };
        }
      }

      return { success: true };
    },

    validateApiConnection: async function() {
      return { success: true };
    },

    showStartupError: function(errorMessage) {
      const feedbackDiv = document.getElementById('startup-feedback');
      feedbackDiv.classList.add('hidden');

      if (window.showErrorModal) {
        window.showErrorModal('AMM Startup Failed', errorMessage);
      } else {
        alert('AMM Startup Failed: ' + errorMessage);
      }
    },

    submitStartForm: function() {
      const feedbackDiv = document.getElementById('startup-feedback');
      const titleEl = document.getElementById('startup-title');
      const messageEl = document.getElementById('startup-message');

      titleEl.textContent = 'Starting AMM...';
      messageEl.textContent = 'AMM process is starting. Please wait...';

      const controlForm = document.querySelector('form[method="post"]');
      if (controlForm) {
        const formData = new FormData(controlForm);
        formData.append('start', 'Start');

        fetch(window.location.pathname, {
          method: 'POST',
          body: formData
        }).then(response => {
          if (response.ok) {
            window.location.reload();
          } else {
            throw new Error('Failed to start AMM');
          }
        }).catch(error => {
          this.showStartupError('Failed to start AMM: ' + error.message);
        });
      }
    },

    setupClearStateButton: function() {
      const clearStateBtn = document.getElementById('clearStateBtn');
      if (clearStateBtn) {
        clearStateBtn.addEventListener('click', () => {
          this.showConfirmModal(
            'Clear AMM State',
            'This will clear the AMM state file. All running offers/bids will be lost. Are you sure?',
            () => {
              const form = clearStateBtn.closest('form');
              if (form) {
                const hiddenInput = document.createElement('input');
                hiddenInput.type = 'hidden';
                hiddenInput.name = 'prune_state';
                hiddenInput.value = 'true';
                form.appendChild(hiddenInput);
                form.submit();
              }
            }
          );
        });
      }
    },

    setAmmAmount: function(percent, fieldId) {
      const amountInput = document.getElementById(fieldId);
      let coinSelect;

      let modalType = null;
      if (fieldId.includes('add-amm')) {
        const addModal = document.getElementById('add-amm-modal');
        modalType = addModal ? addModal.getAttribute('data-amm-type') : null;
      } else if (fieldId.includes('edit-amm')) {
        const editModal = document.getElementById('edit-amm-modal');
        modalType = editModal ? editModal.getAttribute('data-amm-type') : null;
      }

      if (fieldId.includes('add-amm')) {
        const isBidModal = modalType === 'bid';
        coinSelect = document.getElementById(isBidModal ? 'add-amm-coin-to' : 'add-amm-coin-from');
      } else if (fieldId.includes('edit-amm')) {
        const isBidModal = modalType === 'bid';
        coinSelect = document.getElementById(isBidModal ? 'edit-amm-coin-to' : 'edit-amm-coin-from');
      }

      if (!amountInput || !coinSelect) {
        console.error('Required elements not found');
        return;
      }

      const selectedOption = coinSelect.options[coinSelect.selectedIndex];
      if (!selectedOption) {
        if (window.showErrorModal) {
          window.showErrorModal('Validation Error', 'Please select a coin first');
        } else {
          alert('Please select a coin first');
        }
        return;
      }

      const balance = selectedOption.getAttribute('data-balance');
      if (!balance) {
        console.error('Balance not found for selected coin');
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

      const event = new Event('input', { bubbles: true });
      amountInput.dispatchEvent(event);
    },

    updateAmmModalBalances: function(balanceData) {
      const addModal = document.getElementById('add-amm-modal');
      const editModal = document.getElementById('edit-amm-modal');
      const addModalVisible = addModal && !addModal.classList.contains('hidden');
      const editModalVisible = editModal && !editModal.classList.contains('hidden');

      let modalType = null;
      if (addModalVisible) {
        modalType = addModal.getAttribute('data-amm-type');
      } else if (editModalVisible) {
        modalType = editModal.getAttribute('data-amm-type');
      }

      if (modalType === 'offer') {
        this.updateOfferDropdownBalances(balanceData);
      } else if (modalType === 'bid') {
        this.updateBidDropdownBalances(balanceData);
      }
    },

    setupWebSocketBalanceUpdates: function() {
      window.BalanceUpdatesManager.setup({
        contextKey: 'amm',
        balanceUpdateCallback: this.updateAmmModalBalances.bind(this),
        swapEventCallback: this.updateAmmModalBalances.bind(this),
        errorContext: 'AMM',
        enablePeriodicRefresh: true,
        periodicInterval: 120000
      });
    },

    updateAmmDropdownBalances: function(balanceData) {
      const balanceMap = {};
      const pendingMap = {};
      balanceData.forEach(coin => {
        balanceMap[coin.name] = coin.balance;
        pendingMap[coin.name] = coin.pending || '0.0';
      });

      const dropdownIds = ['add-amm-coin-from', 'edit-amm-coin-from', 'add-amm-coin-to', 'edit-amm-coin-to'];

      dropdownIds.forEach(dropdownId => {
        const select = document.getElementById(dropdownId);
        if (!select) {
          return;
        }

        Array.from(select.options).forEach(option => {
          const coinName = option.value;
          const balance = balanceMap[coinName] || '0.0';
          const pending = pendingMap[coinName] || '0.0';

          option.setAttribute('data-balance', balance);
          option.setAttribute('data-pending-balance', pending);
        });
      });

      const addModal = document.getElementById('add-amm-modal');
      const editModal = document.getElementById('edit-amm-modal');
      const addModalVisible = addModal && !addModal.classList.contains('hidden');
      const editModalVisible = editModal && !editModal.classList.contains('hidden');

      let currentModalType = null;
      if (addModalVisible) {
        currentModalType = addModal.getAttribute('data-amm-type');
      } else if (editModalVisible) {
        currentModalType = editModal.getAttribute('data-amm-type');
      }

      if (currentModalType && window.ammTablesManager) {
        if (currentModalType === 'offer' && typeof window.ammTablesManager.refreshOfferDropdownBalanceDisplay === 'function') {
          window.ammTablesManager.refreshOfferDropdownBalanceDisplay();
        } else if (currentModalType === 'bid' && typeof window.ammTablesManager.refreshBidDropdownBalanceDisplay === 'function') {
          window.ammTablesManager.refreshBidDropdownBalanceDisplay();
        }
      }
    },

    updateOfferDropdownBalances: function(balanceData) {
      this.updateAmmDropdownBalances(balanceData);
    },

    updateBidDropdownBalances: function(balanceData) {
      this.updateAmmDropdownBalances(balanceData);
    },

    cleanupAmmBalanceUpdates: function() {
      window.BalanceUpdatesManager.cleanup('amm');

      if (window.ammDropdowns) {
        window.ammDropdowns.forEach(dropdown => {
          if (dropdown.parentNode) {
            dropdown.parentNode.removeChild(dropdown);
          }
        });
        window.ammDropdowns = [];
      }
    },

    setupCleanup: function() {
      if (window.CleanupManager) {
        window.CleanupManager.registerResource('ammBalanceUpdates', null, this.cleanupAmmBalanceUpdates.bind(this));
      }

      const beforeUnloadHandler = this.cleanupAmmBalanceUpdates.bind(this);
      window.addEventListener('beforeunload', beforeUnloadHandler);

      if (window.CleanupManager) {
        CleanupManager.registerResource('ammBeforeUnload', beforeUnloadHandler, () => {
          window.removeEventListener('beforeunload', beforeUnloadHandler);
        });
      }
    },

    cleanup: function() {
      const debugCheckbox = document.getElementById('amm_debug');
      const autostartCheckbox = document.getElementById('amm_autostart');
      const errorOkBtn = document.getElementById('errorOk');
      const confirmYesBtn = document.getElementById('confirmYes');
      const confirmNoBtn = document.getElementById('confirmNo');
      const startButton = document.getElementById('startAMM');
      const clearStateBtn = document.getElementById('clearAmmState');

      this.cleanupAmmBalanceUpdates();
    }
  };

  document.addEventListener('DOMContentLoaded', function() {
    AMMPage.init();

    if (window.BalanceUpdatesManager) {
      window.BalanceUpdatesManager.initialize();
    }
  });

  window.AMMPage = AMMPage;
  window.showErrorModal = AMMPage.showErrorModal.bind(AMMPage);
  window.hideErrorModal = AMMPage.hideErrorModal.bind(AMMPage);
  window.showConfirmModal = AMMPage.showConfirmModal.bind(AMMPage);
  window.hideConfirmModal = AMMPage.hideConfirmModal.bind(AMMPage);
  window.setAmmAmount = AMMPage.setAmmAmount.bind(AMMPage);

})();
