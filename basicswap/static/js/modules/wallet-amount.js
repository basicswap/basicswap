(function() {
  'use strict';

  const WalletAmountManager = {
    
    coinConfigs: {
      1: { 
        types: ['plain', 'blind', 'anon'],
        hasSubfee: true,
        hasSweepAll: false
      },
      3: { 
        types: ['plain', 'mweb'],
        hasSubfee: true,
        hasSweepAll: false
      },
      6: { 
        types: ['default'],
        hasSubfee: false,
        hasSweepAll: true
      },
      9: { 
        types: ['default'],
        hasSubfee: false,
        hasSweepAll: true
      }
    },

    safeParseFloat: function(value) {
      const numValue = Number(value);
      
      if (!isNaN(numValue) && numValue > 0) {
        return numValue;
      }
      
      console.warn('WalletAmountManager: Invalid balance value:', value);
      return 0;
    },

    getBalance: function(coinId, balances, selectedType) {
      const cid = parseInt(coinId);
      
      if (cid === 1) {
        switch(selectedType) {
          case 'plain':
            return this.safeParseFloat(balances.main || balances.balance);
          case 'blind':
            return this.safeParseFloat(balances.blind);
          case 'anon':
            return this.safeParseFloat(balances.anon);
          default:
            return this.safeParseFloat(balances.main || balances.balance);
        }
      }
      
      if (cid === 3) {
        switch(selectedType) {
          case 'plain':
            return this.safeParseFloat(balances.main || balances.balance);
          case 'mweb':
            return this.safeParseFloat(balances.mweb);
          default:
            return this.safeParseFloat(balances.main || balances.balance);
        }
      }
      
      return this.safeParseFloat(balances.main || balances.balance);
    },

    calculateAmount: function(balance, percent, coinId) {
      const cid = parseInt(coinId);
      
      if (percent === 1) {
        return balance;
      }
      
      if (cid === 1) {
        return Math.max(0, Math.floor(balance * percent * 100000000) / 100000000);
      }
      
      const calculatedAmount = balance * percent;
      
      if (calculatedAmount < 0.00000001) {
        console.warn('WalletAmountManager: Calculated amount too small, setting to zero');
        return 0;
      }
      
      return calculatedAmount;
    },

    setAmount: function(percent, balances, coinId) {
      
      const amountInput = window.DOMCache
        ? window.DOMCache.get('amount')
        : document.getElementById('amount');
      const typeSelect = window.DOMCache
        ? window.DOMCache.get('withdraw_type')
        : document.getElementById('withdraw_type');

      if (!amountInput) {
        console.error('WalletAmountManager: Amount input not found');
        return;
      }
      
      const cid = parseInt(coinId);
      const selectedType = typeSelect ? typeSelect.value : 'plain';
      
      const balance = this.getBalance(cid, balances, selectedType);
      
      const calculatedAmount = this.calculateAmount(balance, percent, cid);
      
      const specialCids = [6, 9];
      if (specialCids.includes(cid) && percent === 1) {
        amountInput.setAttribute('data-hidden', 'true');
        amountInput.placeholder = 'Sweep All';
        amountInput.value = '';
        amountInput.disabled = true;
        
        const sweepAllCheckbox = window.DOMCache
          ? window.DOMCache.get('sweepall')
          : document.getElementById('sweepall');
        if (sweepAllCheckbox) {
          sweepAllCheckbox.checked = true;
        }
      } else {
        
        amountInput.value = calculatedAmount.toFixed(8);
        amountInput.setAttribute('data-hidden', 'false');
        amountInput.placeholder = '';
        amountInput.disabled = false;

        const sweepAllCheckbox = window.DOMCache
          ? window.DOMCache.get('sweepall')
          : document.getElementById('sweepall');
        if (sweepAllCheckbox) {
          sweepAllCheckbox.checked = false;
        }
      }
      
      const subfeeCheckbox = document.querySelector(`[name="subfee_${cid}"]`);
      if (subfeeCheckbox) {
        subfeeCheckbox.checked = (percent === 1);
      }
    },

    initialize: function() {
      
      const amountButtons = document.querySelectorAll('[data-set-amount]');
      
      amountButtons.forEach(button => {
        button.addEventListener('click', (e) => {
          e.preventDefault();
          
          const percent = parseFloat(button.getAttribute('data-set-amount'));
          const balancesJson = button.getAttribute('data-balances');
          const coinId = button.getAttribute('data-coin-id');
          
          if (!balancesJson || !coinId) {
            console.error('WalletAmountManager: Missing data attributes on button', button);
            return;
          }
          
          try {
            const balances = JSON.parse(balancesJson);
            this.setAmount(percent, balances, coinId);
          } catch (error) {
            console.error('WalletAmountManager: Failed to parse balances', error);
          }
        });
      });
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      WalletAmountManager.initialize();
    });
  } else {
    WalletAmountManager.initialize();
  }

  window.WalletAmountManager = WalletAmountManager;
  
  window.setAmount = function(percent, balance, coinId, balance2, balance3) {
    
    const balances = {
      main: balance || balance,
      balance: balance,
      blind: balance2,
      anon: balance3,
      mweb: balance2
    };
    WalletAmountManager.setAmount(percent, balances, coinId);
  };

})();
