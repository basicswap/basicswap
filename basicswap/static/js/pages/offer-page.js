(function() {
  'use strict';

  const OfferPage = {
    xhr_rates: null,
    xhr_bid_params: null,

    init: function() {
      this.xhr_rates = new XMLHttpRequest();
      this.xhr_bid_params = new XMLHttpRequest();
      
      this.setupXHRHandlers();
      this.setupEventListeners();
      this.handleBidsPageAddress();
    },

    setupXHRHandlers: function() {
      this.xhr_rates.onload = () => {
        if (this.xhr_rates.status == 200) {
          const obj = JSON.parse(this.xhr_rates.response);
          const inner_html = '<h4 class="bold">Rates</h4><pre><code>' + JSON.stringify(obj, null, '  ') + '</code></pre>';
          const ratesDisplay = document.getElementById('rates_display');
          if (ratesDisplay) {
            ratesDisplay.innerHTML = inner_html;
          }
        }
      };

      this.xhr_bid_params.onload = () => {
        if (this.xhr_bid_params.status == 200) {
          const obj = JSON.parse(this.xhr_bid_params.response);
          const bidAmountSendInput = document.getElementById('bid_amount_send');
          if (bidAmountSendInput) {
            bidAmountSendInput.value = obj['amount_to'];
          }
          this.updateModalValues();
        }
      };
    },

    setupEventListeners: function() {
      const sendBidBtn = document.querySelector('button[name="sendbid"][value="Send Bid"]');
      if (sendBidBtn) {
        sendBidBtn.onclick = this.showConfirmModal.bind(this);
      }

      const modalCancelBtn = document.querySelector('#confirmModal .flex button:last-child');
      if (modalCancelBtn) {
        modalCancelBtn.onclick = this.hideConfirmModal.bind(this);
      }

      const mainCancelBtn = document.querySelector('button[name="cancel"]');
      if (mainCancelBtn) {
        mainCancelBtn.onclick = this.handleCancelClick.bind(this);
      }

      const validMinsInput = document.querySelector('input[name="validmins"]');
      if (validMinsInput) {
        validMinsInput.addEventListener('input', this.updateModalValues.bind(this));
      }

      const addrFromSelect = document.querySelector('select[name="addr_from"]');
      if (addrFromSelect) {
        addrFromSelect.addEventListener('change', this.updateModalValues.bind(this));
      }

      const errorOkBtn = document.getElementById('errorOk');
      if (errorOkBtn) {
        errorOkBtn.addEventListener('click', this.hideErrorModal.bind(this));
      }
    },

    lookup_rates: function() {
      const coin_from = document.getElementById('coin_from')?.value;
      const coin_to = document.getElementById('coin_to')?.value;

      if (!coin_from || !coin_to || coin_from === '-1' || coin_to === '-1') {
        alert('Coins from and to must be set first.');
        return;
      }

      const ratesDisplay = document.getElementById('rates_display');
      if (ratesDisplay) {
        ratesDisplay.innerHTML = '<h4>Rates</h4><p>Updating...</p>';
      }

      this.xhr_rates.open('POST', '/json/rates');
      this.xhr_rates.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
      this.xhr_rates.send(`coin_from=${coin_from}&coin_to=${coin_to}`);
    },

    resetForm: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');
      const bidRateInput = document.getElementById('bid_rate');
      const validMinsInput = document.querySelector('input[name="validmins"]');
      const amtVar = document.getElementById('amt_var')?.value === 'True';
      
      if (bidAmountSendInput) {
        bidAmountSendInput.value = amtVar ? '' : bidAmountSendInput.getAttribute('max');
      }
      if (bidAmountInput) {
        bidAmountInput.value = amtVar ? '' : bidAmountInput.getAttribute('max');
      }
      if (bidRateInput && !bidRateInput.disabled) {
        const defaultRate = document.getElementById('offer_rate')?.value || '';
        bidRateInput.value = defaultRate;
      }
      if (validMinsInput) {
        validMinsInput.value = "60";
      }
      if (!amtVar) {
        this.updateBidParams('rate');
      }
      this.updateModalValues();
      
      const errorMessages = document.querySelectorAll('.error-message');
      errorMessages.forEach(msg => msg.remove());

      const inputs = document.querySelectorAll('input');
      inputs.forEach(input => {
        input.classList.remove('border-red-500', 'focus:border-red-500');
      });
    },

    roundUpToDecimals: function(value, decimals) {
      const factor = Math.pow(10, decimals);
      return Math.ceil(value * factor) / factor;
    },

    updateBidParams: function(value_changed) {
      const coin_from = document.getElementById('coin_from')?.value;
      const coin_to = document.getElementById('coin_to')?.value;
      const coin_from_exp = parseInt(document.getElementById('coin_from_exp')?.value || '8');
      const coin_to_exp = parseInt(document.getElementById('coin_to_exp')?.value || '8');
      const amt_var = document.getElementById('amt_var')?.value;
      const rate_var = document.getElementById('rate_var')?.value;
      const bidAmountInput = document.getElementById('bid_amount');
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidRateInput = document.getElementById('bid_rate');
      const offerRateInput = document.getElementById('offer_rate');

      if (!coin_from || !coin_to || !amt_var || !rate_var) return;

      const rate = rate_var === 'True' && bidRateInput ?
        parseFloat(bidRateInput.value) || 0 :
        parseFloat(offerRateInput?.value || '0');

      if (!rate) return;

      if (value_changed === 'rate') {
        if (bidAmountSendInput && bidAmountInput) {
          const sendAmount = parseFloat(bidAmountSendInput.value) || 0;
          const receiveAmount = (sendAmount / rate).toFixed(coin_from_exp);
          bidAmountInput.value = receiveAmount;
        }
      } else if (value_changed === 'sending') {
        if (bidAmountSendInput && bidAmountInput) {
          const sendAmount = parseFloat(bidAmountSendInput.value) || 0;
          const receiveAmount = (sendAmount / rate).toFixed(coin_from_exp);
          bidAmountInput.value = receiveAmount;
        }
      } else if (value_changed === 'receiving') {
        if (bidAmountInput && bidAmountSendInput) {
          const receiveAmount = parseFloat(bidAmountInput.value) || 0;
          const sendAmount = this.roundUpToDecimals(receiveAmount * rate, coin_to_exp).toFixed(coin_to_exp);
          bidAmountSendInput.value = sendAmount;
        }
      }

      this.validateAmountsAfterChange();

      this.xhr_bid_params.open('POST', '/json/rate');
      this.xhr_bid_params.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
      this.xhr_bid_params.send(`coin_from=${coin_from}&coin_to=${coin_to}&rate=${rate}&amt_from=${bidAmountInput?.value || '0'}`);

      this.updateModalValues();
    },

    validateAmountsAfterChange: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');

      if (bidAmountSendInput) {
        const maxSend = parseFloat(bidAmountSendInput.getAttribute('max'));
        this.validateMaxAmount(bidAmountSendInput, maxSend);
      }
      if (bidAmountInput) {
        const maxReceive = parseFloat(bidAmountInput.getAttribute('max'));
        this.validateMaxAmount(bidAmountInput, maxReceive);
      }
    },

    validateMaxAmount: function(input, maxAmount) {
      if (!input) return;
      const value = parseFloat(input.value) || 0;
      if (value > maxAmount) {
        input.value = maxAmount;
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

    showConfirmModal: function() {
      const bidAmountSendInput = document.getElementById('bid_amount_send');
      const bidAmountInput = document.getElementById('bid_amount');
      const validMinsInput = document.querySelector('input[name="validmins"]');
      const addrFromSelect = document.querySelector('select[name="addr_from"]');

      let sendAmount = 0;
      let receiveAmount = 0;

      if (bidAmountSendInput && bidAmountSendInput.value) {
        sendAmount = parseFloat(bidAmountSendInput.value) || 0;
      }

      if (bidAmountInput && bidAmountInput.value) {
        receiveAmount = parseFloat(bidAmountInput.value) || 0;
      }

      if (sendAmount <= 0 || receiveAmount <= 0) {
        this.showErrorModal('Validation Error', 'Please enter valid amounts for both sending and receiving.');
        return false;
      }

      const coinFrom = document.getElementById('coin_from_name')?.value || '';
      const coinTo = document.getElementById('coin_to_name')?.value || '';
      const tlaFrom = document.getElementById('tla_from')?.value || '';
      const tlaTo = document.getElementById('tla_to')?.value || '';

      const validMins = validMinsInput ? validMinsInput.value : '60';

      const addrFrom = addrFromSelect ? addrFromSelect.value : '';

      const modalAmtReceive = document.getElementById('modal-amt-receive');
      const modalReceiveCurrency = document.getElementById('modal-receive-currency');
      const modalAmtSend = document.getElementById('modal-amt-send');
      const modalSendCurrency = document.getElementById('modal-send-currency');
      const modalAddrFrom = document.getElementById('modal-addr-from');
      const modalValidMins = document.getElementById('modal-valid-mins');

      if (modalAmtReceive) modalAmtReceive.textContent = receiveAmount.toFixed(8);
      if (modalReceiveCurrency) modalReceiveCurrency.textContent = ` ${tlaFrom}`;
      if (modalAmtSend) modalAmtSend.textContent = sendAmount.toFixed(8);
      if (modalSendCurrency) modalSendCurrency.textContent = ` ${tlaTo}`;
      if (modalAddrFrom) modalAddrFrom.textContent = addrFrom || 'Default';
      if (modalValidMins) modalValidMins.textContent = validMins;

      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.remove('hidden');
      }
      return false;
    },

    hideConfirmModal: function() {
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.add('hidden');
      }
      return false;
    },

    updateModalValues: function() {
      
    },

    handleBidsPageAddress: function() {
      const selectElement = document.querySelector('select[name="addr_from"]');
      const STORAGE_KEY = 'lastUsedAddressBids';

      if (!selectElement) return;

      const loadInitialAddress = () => {
        const savedAddressJSON = localStorage.getItem(STORAGE_KEY);
        if (savedAddressJSON) {
          try {
            const savedAddress = JSON.parse(savedAddressJSON);
            selectElement.value = savedAddress.value;
          } catch (e) {
            selectFirstAddress();
          }
        } else {
          selectFirstAddress();
        }
      };

      const selectFirstAddress = () => {
        if (selectElement.options.length > 1) {
          const firstOption = selectElement.options[1];
          if (firstOption) {
            selectElement.value = firstOption.value;
            this.saveAddress(firstOption.value, firstOption.text);
          }
        }
      };

      selectElement.addEventListener('change', (event) => {
        this.saveAddress(event.target.value, event.target.selectedOptions[0].text);
      });

      loadInitialAddress();
    },

    saveAddress: function(value, text) {
      const addressData = {
        value: value,
        text: text
      };
      localStorage.setItem('lastUsedAddressBids', JSON.stringify(addressData));
    },

    confirmPopup: function() {
      return confirm("Are you sure?");
    },

    handleCancelClick: function(event) {
      if (event) event.preventDefault();
      const pathParts = window.location.pathname.split('/');
      const offerId = pathParts[pathParts.indexOf('offer') + 1];
      window.location.href = `/offer/${offerId}`;
    },

    cleanup: function() {
    }
  };

  document.addEventListener('DOMContentLoaded', function() {
    OfferPage.init();

    if (window.CleanupManager) {
      CleanupManager.registerResource('offerPage', OfferPage, (page) => {
        if (page.cleanup) page.cleanup();
      });
    }
  });

  window.OfferPage = OfferPage;
  window.lookup_rates = OfferPage.lookup_rates.bind(OfferPage);
  window.resetForm = OfferPage.resetForm.bind(OfferPage);
  window.updateBidParams = OfferPage.updateBidParams.bind(OfferPage);
  window.validateMaxAmount = OfferPage.validateMaxAmount.bind(OfferPage);
  window.showConfirmModal = OfferPage.showConfirmModal.bind(OfferPage);
  window.hideConfirmModal = OfferPage.hideConfirmModal.bind(OfferPage);
  window.showErrorModal = OfferPage.showErrorModal.bind(OfferPage);
  window.hideErrorModal = OfferPage.hideErrorModal.bind(OfferPage);
  window.confirmPopup = OfferPage.confirmPopup.bind(OfferPage);
  window.handleBidsPageAddress = OfferPage.handleBidsPageAddress.bind(OfferPage);

})();
