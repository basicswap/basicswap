(function() {
  'use strict';

  const WalletsPage = {
    
    init: function() {
      this.setupWebSocketUpdates();
    },

    setupWebSocketUpdates: function() {
      if (window.WebSocketManager && typeof window.WebSocketManager.initialize === 'function') {
        window.WebSocketManager.initialize();
      }

      if (window.BalanceUpdatesManager) {
        window.BalanceUpdatesManager.setup({
          contextKey: 'wallets',
          balanceUpdateCallback: this.updateWalletBalances.bind(this),
          swapEventCallback: this.updateWalletBalances.bind(this),
          errorContext: 'Wallets',
          enablePeriodicRefresh: true,
          periodicInterval: 60000
        });

        if (window.WebSocketManager && typeof window.WebSocketManager.addMessageHandler === 'function') {
          const priceHandlerId = window.WebSocketManager.addMessageHandler('message', (data) => {
            if (data && data.event) {
              if (data.event === 'price_updated' || data.event === 'prices_updated') {
                clearTimeout(window.walletsPriceUpdateTimeout);
                window.walletsPriceUpdateTimeout = CleanupManager.setTimeout(() => {
                  if (window.WalletManager && typeof window.WalletManager.updatePrices === 'function') {
                    window.WalletManager.updatePrices(true);
                  }
                }, 500);
              }
            }
          });
          window.walletsPriceHandlerId = priceHandlerId;
        }
      }
    },

    updateWalletBalances: function(balanceData) {
      if (balanceData) {
        balanceData.forEach(coin => {
          this.updateWalletDisplay(coin);
        });

        CleanupManager.setTimeout(() => {
          if (window.WalletManager && typeof window.WalletManager.updatePrices === 'function') {
            window.WalletManager.updatePrices(true);
          }
        }, 250);
      } else {
        window.BalanceUpdatesManager.fetchBalanceData()
          .then(data => this.updateWalletBalances(data))
          .catch(error => {
            console.error('Error updating wallet balances:', error);
          });
      }
    },

    updateWalletDisplay: function(coinData) {
      if (coinData.name === 'Particl') {
        this.updateSpecificBalance('Particl', 'Balance:', coinData.balance, coinData.ticker || 'PART');
      } else if (coinData.name === 'Particl Anon') {
        this.updateSpecificBalance('Particl', 'Anon Balance:', coinData.balance, coinData.ticker || 'PART');
        this.removePendingBalance('Particl', 'Anon Balance:');
        if (coinData.pending && parseFloat(coinData.pending) > 0) {
          this.updatePendingBalance('Particl', 'Anon Balance:', coinData.pending, coinData.ticker || 'PART', 'Anon Pending:', coinData);
        }
      } else if (coinData.name === 'Particl Blind') {
        this.updateSpecificBalance('Particl', 'Blind Balance:', coinData.balance, coinData.ticker || 'PART');
        this.removePendingBalance('Particl', 'Blind Balance:');
        if (coinData.pending && parseFloat(coinData.pending) > 0) {
          this.updatePendingBalance('Particl', 'Blind Balance:', coinData.pending, coinData.ticker || 'PART', 'Blind Unconfirmed:', coinData);
        }
      } else {
        this.updateSpecificBalance(coinData.name, 'Balance:', coinData.balance, coinData.ticker || coinData.name);

        if (coinData.name !== 'Particl Anon' && coinData.name !== 'Particl Blind' && coinData.name !== 'Litecoin MWEB') {
          if (coinData.pending && parseFloat(coinData.pending) > 0) {
            this.updatePendingDisplay(coinData);
          } else {
            this.removePendingDisplay(coinData.name);
          }
        }
      }
    },

    updateSpecificBalance: function(coinName, labelText, balance, ticker, isPending = false) {
      const balanceElements = document.querySelectorAll('.coinname-value[data-coinname]');

      balanceElements.forEach(element => {
        const elementCoinName = element.getAttribute('data-coinname');

        if (elementCoinName === coinName) {
          const parentDiv = element.closest('.flex.mb-2.justify-between.items-center');
          const labelElement = parentDiv ? parentDiv.querySelector('h4') : null;

          if (labelElement) {
            const currentLabel = labelElement.textContent.trim();

            if (currentLabel === labelText) {
              if (isPending) {
                const cleanBalance = balance.toString().replace(/^\+/, '');
                element.textContent = `+${cleanBalance} ${ticker}`;
              } else {
                element.textContent = `${balance} ${ticker}`;
              }
            }
          }
        }
      });
    },

    updatePendingDisplay: function(coinData) {
      const walletContainer = this.findWalletContainer(coinData.name);
      if (!walletContainer) return;

      const existingPendingElements = walletContainer.querySelectorAll('.flex.mb-2.justify-between.items-center');
      let staticPendingElement = null;
      let staticUsdElement = null;

      existingPendingElements.forEach(element => {
        const labelElement = element.querySelector('h4');
        if (labelElement) {
          const labelText = labelElement.textContent;
          if (labelText.includes('Pending:') && !labelText.includes('USD')) {
            staticPendingElement = element;
          } else if (labelText.includes('Pending USD value:')) {
            staticUsdElement = element;
          }
        }
      });

      if (staticPendingElement && staticUsdElement) {
        const pendingSpan = staticPendingElement.querySelector('.coinname-value');
        if (pendingSpan) {
          const cleanPending = coinData.pending.toString().replace(/^\+/, '');
          pendingSpan.textContent = `+${cleanPending} ${coinData.ticker || coinData.name}`;
        }

        let initialUSD = '$0.00';
        if (window.WalletManager && window.WalletManager.coinPrices) {
          const coinId = coinData.name.toLowerCase().replace(' ', '-');
          const price = window.WalletManager.coinPrices[coinId];
          if (price && price.usd) {
            const cleanPending = coinData.pending.toString().replace(/^\+/, '');
            const usdValue = (parseFloat(cleanPending) * price.usd).toFixed(2);
            initialUSD = `$${usdValue}`;
          }
        }

        const usdDiv = staticUsdElement.querySelector('.usd-value');
        if (usdDiv) {
          usdDiv.textContent = initialUSD;
        }
        return;
      }

      let pendingContainer = walletContainer.querySelector('.pending-container');

      if (!pendingContainer) {
        const balanceContainer = walletContainer.querySelector('.flex.mb-2.justify-between.items-center');
        if (!balanceContainer) return;

        pendingContainer = document.createElement('div');
        pendingContainer.className = 'pending-container';
        balanceContainer.parentNode.insertBefore(pendingContainer, balanceContainer.nextSibling);
      }

      pendingContainer.innerHTML = '';

      const pendingDiv = document.createElement('div');
      pendingDiv.className = 'flex mb-2 justify-between items-center';

      const cleanPending = coinData.pending.toString().replace(/^\+/, '');

      pendingDiv.innerHTML = `
        <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">Pending:</h4>
        <span class="coinname-value text-sm font-medium text-green-600 dark:text-green-400" data-coinname="${coinData.name}">+${cleanPending} ${coinData.ticker || coinData.name}</span>
      `;

      pendingContainer.appendChild(pendingDiv);

      let initialUSD = '$0.00';
      if (window.WalletManager && window.WalletManager.coinPrices) {
        const coinId = coinData.name.toLowerCase().replace(' ', '-');
        const price = window.WalletManager.coinPrices[coinId];
        if (price && price.usd) {
          const usdValue = (parseFloat(cleanPending) * price.usd).toFixed(2);
          initialUSD = `$${usdValue}`;
        }
      }

      const usdDiv = document.createElement('div');
      usdDiv.className = 'flex mb-2 justify-between items-center';
      usdDiv.innerHTML = `
        <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">Pending USD value:</h4>
        <div class="usd-value text-sm font-medium text-green-600 dark:text-green-400">${initialUSD}</div>
      `;

      pendingContainer.appendChild(usdDiv);
    },

    removePendingDisplay: function(coinName) {
      const walletContainer = this.findWalletContainer(coinName);
      if (!walletContainer) return;

      const pendingContainer = walletContainer.querySelector('.pending-container');
      if (pendingContainer) {
        pendingContainer.remove();
      }
    },

    findWalletContainer: function(coinName) {
      const balanceElements = document.querySelectorAll('.coinname-value[data-coinname]');
      for (const element of balanceElements) {
        if (element.getAttribute('data-coinname') === coinName) {
          return element.closest('.bg-white, .dark\\:bg-gray-500');
        }
      }
      return null;
    },

    removePendingBalance: function(coinName, balanceType) {
      const balanceElements = document.querySelectorAll('.coinname-value[data-coinname]');

      balanceElements.forEach(element => {
        const elementCoinName = element.getAttribute('data-coinname');

        if (elementCoinName === coinName) {
          const parentDiv = element.closest('.flex.mb-2.justify-between.items-center');
          const labelElement = parentDiv ? parentDiv.querySelector('h4') : null;

          if (labelElement) {
            const currentLabel = labelElement.textContent.trim();

            if (currentLabel.includes('Pending:') || currentLabel.includes('Unconfirmed:')) {
              const nextElement = parentDiv.nextElementSibling;
              if (nextElement && nextElement.querySelector('h4')?.textContent.includes('USD value:')) {
                nextElement.remove();
              }
              parentDiv.remove();
            }
          }
        }
      });
    },

    updatePendingBalance: function(coinName, balanceType, pendingAmount, ticker, pendingLabel, coinData) {
      const balanceElements = document.querySelectorAll('.coinname-value[data-coinname]');
      let targetElement = null;

      balanceElements.forEach(element => {
        const elementCoinName = element.getAttribute('data-coinname');
        if (elementCoinName === coinName) {
          const parentElement = element.closest('.flex.mb-2.justify-between.items-center');
          if (parentElement) {
            const labelElement = parentElement.querySelector('h4');
            if (labelElement && labelElement.textContent.includes(balanceType)) {
              targetElement = parentElement;
            }
          }
        }
      });

      if (!targetElement) return;

      let insertAfterElement = targetElement;
      let nextElement = targetElement.nextElementSibling;
      while (nextElement) {
        const labelElement = nextElement.querySelector('h4');
        if (labelElement) {
          const labelText = labelElement.textContent;
          if (labelText.includes('USD value:') && !labelText.includes('Pending') && !labelText.includes('Unconfirmed')) {
            insertAfterElement = nextElement;
            break;
          }
          if (labelText.includes('Balance:') || labelText.includes('Pending:') || labelText.includes('Unconfirmed:')) {
            break;
          }
        }
        nextElement = nextElement.nextElementSibling;
      }

      let pendingElement = insertAfterElement.nextElementSibling;
      while (pendingElement && !pendingElement.querySelector('h4')?.textContent.includes(pendingLabel)) {
        pendingElement = pendingElement.nextElementSibling;
        if (pendingElement && pendingElement.querySelector('h4')?.textContent.includes('Balance:')) {
          pendingElement = null;
          break;
        }
      }

      if (!pendingElement) {
        const newPendingDiv = document.createElement('div');
        newPendingDiv.className = 'flex mb-2 justify-between items-center';

        const cleanPending = pendingAmount.toString().replace(/^\+/, '');

        newPendingDiv.innerHTML = `
          <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">${pendingLabel}</h4>
          <span class="coinname-value text-sm font-medium text-green-600 dark:text-green-400" data-coinname="${coinName}">+${cleanPending} ${ticker}</span>
        `;

        insertAfterElement.parentNode.insertBefore(newPendingDiv, insertAfterElement.nextSibling);

        let initialUSD = '$0.00';
        if (window.WalletManager && window.WalletManager.coinPrices) {
          const coinId = coinName.toLowerCase().replace(' ', '-');
          const price = window.WalletManager.coinPrices[coinId];
          if (price && price.usd) {
            const usdValue = (parseFloat(cleanPending) * price.usd).toFixed(2);
            initialUSD = `$${usdValue}`;
          }
        }

        const usdDiv = document.createElement('div');
        usdDiv.className = 'flex mb-2 justify-between items-center';
        usdDiv.innerHTML = `
          <h4 class="text-sm font-semibold text-gray-700 dark:text-gray-300">${pendingLabel.replace(':', '')} USD value:</h4>
          <div class="usd-value text-sm font-medium text-green-600 dark:text-green-400">${initialUSD}</div>
        `;

        newPendingDiv.parentNode.insertBefore(usdDiv, newPendingDiv.nextSibling);
      } else {
        const pendingSpan = pendingElement.querySelector('.coinname-value');
        if (pendingSpan) {
          const cleanPending = pendingAmount.toString().replace(/^\+/, '');
          pendingSpan.textContent = `+${cleanPending} ${ticker}`;
        }
      }
    }
  };

  document.addEventListener('DOMContentLoaded', function() {
    WalletsPage.init();
  });

  window.WalletsPage = WalletsPage;

})();
