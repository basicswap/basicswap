
(function() {
  'use strict';

  const SettingsPage = {
    confirmCallback: null,
    triggerElement: null,

    originalConnectionTypes: {},

    init: function() {
      this.setupTabs();
      this.setupCoinHeaders();
      this.setupConfirmModal();
      this.setupNotificationSettings();
      this.setupMigrationIndicator();
      this.setupServerDiscovery();
    },

    setupTabs: function() {
      const tabButtons = document.querySelectorAll('.tab-button');
      const tabContents = document.querySelectorAll('.tab-content');

      const switchTab = (targetTab) => {
        tabButtons.forEach(btn => {
          if (btn.dataset.tab === targetTab) {
            btn.className = 'tab-button border-b-2 border-blue-500 text-blue-600 dark:text-blue-400 py-4 px-1 text-sm font-medium focus:outline-none focus:ring-0';
          } else {
            btn.className = 'tab-button border-b-2 border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600 py-4 px-1 text-sm font-medium focus:outline-none focus:ring-0';
          }
        });

        tabContents.forEach(content => {
          if (content.id === targetTab) {
            content.classList.remove('hidden');
          } else {
            content.classList.add('hidden');
          }
        });
      };

      tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
          switchTab(btn.dataset.tab);
        });
      });
    },

    setupCoinHeaders: function() {
      const coinHeaders = document.querySelectorAll('.coin-header');
      coinHeaders.forEach(header => {
        header.addEventListener('click', function() {
          const coinName = this.dataset.coin;
          const details = document.getElementById(`details-${coinName}`);
          const arrow = this.querySelector('.toggle-arrow');

          if (details.classList.contains('hidden')) {
            details.classList.remove('hidden');
            arrow.style.transform = 'rotate(180deg)';
          } else {
            details.classList.add('hidden');
            arrow.style.transform = 'rotate(0deg)';
          }
        });
      });
    },

    pendingModeSwitch: null,

    setupMigrationIndicator: function() {
      const connectionTypeSelects = document.querySelectorAll('select[name^="connection_type_"]');
      connectionTypeSelects.forEach(select => {
        const originalValue = select.dataset.originalValue || select.value;
        this.originalConnectionTypes[select.name] = originalValue;

        select.addEventListener('change', (e) => {
          const coinName = select.name.replace('connection_type_', '');
          const electrumSection = document.getElementById(`electrum-section-${coinName}`);
          const fundTransferSection = document.getElementById(`fund-transfer-section-${coinName}`);
          const originalValue = this.originalConnectionTypes[select.name];

          if (e.target.value === 'electrum') {
            if (electrumSection) {
              electrumSection.classList.remove('hidden');

              const clearnetTextarea = document.getElementById(`electrum_clearnet_${coinName}`);
              const onionTextarea = document.getElementById(`electrum_onion_${coinName}`);

              if (clearnetTextarea && !clearnetTextarea.value.trim()) {
                clearnetTextarea.value = electrumSection.dataset.defaultClearnet || '';
              }
              if (onionTextarea && !onionTextarea.value.trim()) {
                onionTextarea.value = electrumSection.dataset.defaultOnion || '';
              }
            }
            if (fundTransferSection) {
              fundTransferSection.classList.add('hidden');
            }
          } else {
            if (electrumSection) {
              electrumSection.classList.add('hidden');
            }
            if (fundTransferSection && originalValue === 'electrum') {
              fundTransferSection.classList.remove('hidden');
            }
          }
        });
      });

      this.setupWalletModeModal();

      const coinsForm = document.getElementById('coins-form');
      if (coinsForm) {
        coinsForm.addEventListener('submit', (e) => {
          const submitter = e.submitter;
          if (!submitter || !submitter.name.startsWith('apply_')) return;

          const coinName = submitter.name.replace('apply_', '');
          const select = document.querySelector(`select[name="connection_type_${coinName}"]`);
          if (!select) return;

          const original = this.originalConnectionTypes[select.name];
          const current = select.value;

          if (original && current && original !== current) {
            e.preventDefault();
            const direction = (original === 'rpc' && current === 'electrum') ? 'lite' : 'rpc';
            this.showWalletModeConfirmation(coinName, direction, submitter);
          }
        });
      }
    },

    setupWalletModeModal: function() {
      const confirmBtn = document.getElementById('walletModeConfirm');
      const cancelBtn = document.getElementById('walletModeCancel');

      if (confirmBtn) {
        confirmBtn.addEventListener('click', () => {
          this.hideWalletModeModal();
          if (this.pendingModeSwitch) {
            const { coinName, direction, submitter } = this.pendingModeSwitch;
            this.showMigrationModal(coinName.toUpperCase(), direction);
            const form = submitter.form;
            const hiddenInput = document.createElement('input');
            hiddenInput.type = 'hidden';
            hiddenInput.name = submitter.name;
            hiddenInput.value = submitter.value;
            form.appendChild(hiddenInput);
            form.submit();
          }
        });
      }

      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => {
          this.hideWalletModeModal();
          if (this.pendingModeSwitch) {
            const { coinName } = this.pendingModeSwitch;
            const select = document.querySelector(`select[name="connection_type_${coinName}"]`);
            if (select) {
              select.value = this.originalConnectionTypes[select.name];
            }
          }
          this.pendingModeSwitch = null;
        });
      }
    },

    showWalletModeConfirmation: function(coinName, direction, submitter) {
      const modal = document.getElementById('walletModeModal');
      const title = document.getElementById('walletModeTitle');
      const message = document.getElementById('walletModeMessage');
      const details = document.getElementById('walletModeDetails');

      if (!modal || !title || !message || !details) return;

      this.pendingModeSwitch = { coinName, direction, submitter };

      const displayName = coinName.charAt(0).toUpperCase() + coinName.slice(1).toLowerCase();

      if (direction === 'lite') {
        title.textContent = `Switch ${displayName} to Lite Wallet Mode`;
        message.textContent = 'Please confirm you want to switch to lite wallet mode.';
        details.innerHTML = `
          <p class="mb-2"><strong>Before switching:</strong></p>
          <ul class="list-disc list-inside space-y-1">
            <li>Active swaps must be completed first</li>
            <li>Wait for any pending transactions to confirm</li>
          </ul>
          <p class="mt-3 text-green-600 dark:text-green-400">
            <strong>Note:</strong> Your balance will remain accessible - same seed means same funds in both modes.
          </p>
        `;
      } else {
        title.textContent = `Switch ${displayName} to Full Node Mode`;
        message.textContent = 'Please confirm you want to switch to full node mode.';
        details.innerHTML = `
          <p class="mb-2"><strong>Switching to full node mode:</strong></p>
          <ul class="list-disc list-inside space-y-1">
            <li>Requires synced ${displayName} blockchain</li>
            <li>Your wallet addresses will be synced</li>
            <li>Active swaps must be completed first</li>
            <li>Restart required after switch</li>
          </ul>
          <p class="mt-3 text-green-600 dark:text-green-400">
            <strong>Note:</strong> Your balance will remain accessible - same seed means same funds in both modes.
          </p>
        `;
      }

      modal.classList.remove('hidden');
    },

    hideWalletModeModal: function() {
      const modal = document.getElementById('walletModeModal');
      if (modal) {
        modal.classList.add('hidden');
      }
    },

    showMigrationModal: function(coinName, direction) {
      const modal = document.getElementById('migrationModal');
      const title = document.getElementById('migrationTitle');
      const message = document.getElementById('migrationMessage');

      if (modal && title && message) {
        if (direction === 'lite') {
          title.textContent = `Migrating ${coinName} to Lite Wallet`;
          message.textContent = 'Checking wallet balance and migrating addresses. Please wait...';
        } else {
          title.textContent = `Switching ${coinName} to Full Node`;
          message.textContent = 'Syncing wallet indices. Please wait...';
        }
        modal.classList.remove('hidden');
      }
    },

    setupConfirmModal: function() {
      const confirmYesBtn = document.getElementById('confirmYes');
      if (confirmYesBtn) {
        confirmYesBtn.addEventListener('click', () => {
          if (typeof this.confirmCallback === 'function') {
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
    },

    showConfirmDialog: function(title, message, callback) {
      this.confirmCallback = callback;
      document.getElementById('confirmTitle').textContent = title;
      document.getElementById('confirmMessage').textContent = message;
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.remove('hidden');
      }
      return false;
    },

    hideConfirmDialog: function() {
      const modal = document.getElementById('confirmModal');
      if (modal) {
        modal.classList.add('hidden');
      }
      this.confirmCallback = null;
      return false;
    },

    confirmDisableCoin: function() {
      this.triggerElement = document.activeElement;
      return this.showConfirmDialog(
        "Confirm Disable Coin",
        "Are you sure you want to disable this coin?",
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

    setupNotificationSettings: function() {
      const notificationsTab = document.getElementById('notifications-tab');
      if (notificationsTab) {
        notificationsTab.addEventListener('click', () => {
          CleanupManager.setTimeout(() => this.syncNotificationSettings(), 100);
        });
      }

      document.addEventListener('change', (e) => {
        if (e.target.closest('#notifications')) {
          this.syncNotificationSettings();
        }
      });

      this.syncNotificationSettings();
    },

    syncNotificationSettings: function() {
      if (window.NotificationManager && typeof window.NotificationManager.updateSettings === 'function') {
        const backendSettings = {
          showNewOffers: document.getElementById('notifications_new_offers')?.checked || false,
          showNewBids: document.getElementById('notifications_new_bids')?.checked || false,
          showBidAccepted: document.getElementById('notifications_bid_accepted')?.checked || false,
          showBalanceChanges: document.getElementById('notifications_balance_changes')?.checked || false,
          showOutgoingTransactions: document.getElementById('notifications_outgoing_transactions')?.checked || false,
          showSwapCompleted: document.getElementById('notifications_swap_completed')?.checked || false,
          showUpdateNotifications: document.getElementById('check_updates')?.checked || false,
          notificationDuration: parseInt(document.getElementById('notifications_duration')?.value || '5') * 1000
        };

        window.NotificationManager.updateSettings(backendSettings);
      }
    },

    testUpdateNotification: function() {
      if (window.NotificationManager) {
        window.NotificationManager.createToast(
          'Update Available: v0.15.0',
          'update_available',
          {
            subtitle: 'Current: v0.14.6 • Click to view release (Test/Dummy)',
            releaseUrl: 'https://github.com/basicswap/basicswap/releases/tag/v0.15.0',
            releaseNotes: 'New version v0.15.0 is available. Click to view details on GitHub.'
          }
        );
      }
    },

    testLiveUpdateCheck: function(event) {
      const button = event?.target || event?.currentTarget || document.querySelector('[onclick*="testLiveUpdateCheck"]');
      if (!button) return;

      const originalText = button.textContent;
      button.textContent = 'Checking...';
      button.disabled = true;

      fetch('/json/checkupdates', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      })
      .then(response => response.json())
      .then(data => {
        if (window.NotificationManager) {
          const currentVer = data.current_version || 'Unknown';
          const latestVer = data.latest_version || currentVer;

          if (data.update_available) {
            window.NotificationManager.createToast(
              `Live Update Available: v${latestVer}`,
              'update_available',
              {
                latest_version: latestVer,
                current_version: currentVer,
                subtitle: `Current: v${currentVer} • Click to view release`,
                releaseUrl: `https://github.com/basicswap/basicswap/releases/tag/v${latestVer}`,
                releaseNotes: 'This is a real update check from GitHub API.'
              }
            );
          } else {
            window.NotificationManager.createToast(
              'No Updates Available',
              'success',
              {
                subtitle: `Current version v${currentVer} is up to date`
              }
            );
          }
        }
      })
      .catch(error => {
        console.error('Update check failed:', error);
        if (window.NotificationManager) {
          window.NotificationManager.createToast(
            'Update Check Failed',
            'error',
            {
              subtitle: 'Could not check for updates. See console for details.'
            }
          );
        }
      })
      .finally(() => {
        if (button) {
          button.textContent = originalText;
          button.disabled = false;
        }
      });
    },

    checkForUpdatesNow: function(event) {
      const button = event?.target || event?.currentTarget || document.querySelector('[data-check-updates]');
      if (!button) return;

      const originalText = button.textContent;
      button.textContent = 'Checking...';
      button.disabled = true;

      fetch('/json/checkupdates', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      })
      .then(response => response.json())
      .then(data => {
        if (data.error) {
          if (window.NotificationManager) {
            window.NotificationManager.createToast(
              'Update Check Failed',
              'error',
              {
                subtitle: data.error
              }
            );
          }
          return;
        }

        if (window.NotificationManager) {
          const currentVer = data.current_version || 'Unknown';
          const latestVer = data.latest_version || currentVer;

          if (data.update_available) {
            window.NotificationManager.createToast(
              `Update Available: v${latestVer}`,
              'update_available',
              {
                latest_version: latestVer,
                current_version: currentVer,
                subtitle: `Current: v${currentVer} • Click to view release`,
                releaseUrl: `https://github.com/basicswap/basicswap/releases/tag/v${latestVer}`,
                releaseNotes: `New version v${latestVer} is available. Click to view details on GitHub.`
              }
            );
          } else {
            window.NotificationManager.createToast(
              'You\'re Up to Date!',
              'success',
              {
                subtitle: `Current version v${currentVer} is the latest`
              }
            );
          }
        }
      })
      .catch(error => {
        console.error('Update check failed:', error);
        if (window.NotificationManager) {
          window.NotificationManager.createToast(
            'Update Check Failed',
            'error',
            {
              subtitle: 'Network error. Please try again later.'
            }
          );
        }
      })
      .finally(() => {
        if (button) {
          button.textContent = originalText;
          button.disabled = false;
        }
      });
    }
  };

  SettingsPage.setupServerDiscovery = function() {
    const discoverBtns = document.querySelectorAll('.discover-servers-btn');
    discoverBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const coin = btn.dataset.coin;
        this.discoverServers(coin, btn);
      });
    });

    const closeBtns = document.querySelectorAll('.close-discovered-btn');
    closeBtns.forEach(btn => {
      btn.addEventListener('click', () => {
        const coin = btn.dataset.coin;
        const panel = document.getElementById(`discovered-servers-${coin}`);
        if (panel) panel.classList.add('hidden');
      });
    });
  };

  SettingsPage.discoverServers = function(coin, button) {
    const originalHtml = button.innerHTML;
    button.innerHTML = `<svg class="w-3.5 h-3.5 mr-1 animate-spin inline-block" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Discovering...`;
    button.disabled = true;

    const panel = document.getElementById(`discovered-servers-${coin}`);
    const listContainer = document.getElementById(`discovered-list-${coin}`);

    fetch('/json/electrumdiscover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ coin: coin, ping: true })
    })
    .then(response => response.json())
    .then(data => {
      if (data.error) {
        listContainer.innerHTML = `<div class="text-sm text-red-500">${data.error}</div>`;
      } else {
        let html = '';

        if (data.current_server) {
          html += `
            <div class="flex items-center mb-4 p-3 bg-gray-100 dark:bg-gray-600 border border-gray-200 dark:border-gray-500 rounded-lg">
              <span class="w-2 h-2 bg-green-500 rounded-full mr-3 animate-pulse"></span>
              <span class="text-sm text-gray-900 dark:text-white">
                Connected to: <span class="font-mono font-medium">${data.current_server.host}:${data.current_server.port}</span>
              </span>
            </div>`;
        }

        if (data.clearnet_servers && data.clearnet_servers.length > 0) {
          html += `
            <div class="mb-4">
              <div class="text-sm font-semibold text-gray-900 dark:text-white mb-2 pb-2 border-b border-gray-200 dark:border-gray-600">
                Clearnet
              </div>
              <div class="space-y-1">`;
          data.clearnet_servers.forEach(srv => {
            const statusClass = srv.online ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500';
            const statusText = srv.online ? (srv.latency_ms ? srv.latency_ms.toFixed(0) + 'ms' : 'online') : 'offline';
            const statusDot = srv.online ? 'bg-green-500' : 'bg-gray-400';
            html += `
                <div class="flex items-center justify-between py-2 px-3 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-lg cursor-pointer add-server-btn transition-colors border border-transparent hover:border-blue-500"
                     data-coin="${coin}" data-host="${srv.host}" data-port="${srv.port}" data-type="clearnet">
                  <div class="flex items-center flex-1 min-w-0">
                    <svg class="w-4 h-4 mr-2 text-blue-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                    </svg>
                    <span class="font-mono text-sm text-gray-900 dark:text-white truncate">${srv.host}:${srv.port}</span>
                  </div>
                  <div class="flex items-center ml-3">
                    <span class="w-2 h-2 ${statusDot} rounded-full mr-2"></span>
                    <span class="text-xs ${statusClass}">${statusText}</span>
                  </div>
                </div>`;
          });
          html += `
              </div>
            </div>`;
        }

        if (data.onion_servers && data.onion_servers.length > 0) {
          html += `
            <div class="mb-4">
              <div class="text-sm font-semibold text-gray-900 dark:text-white mb-2 pb-2 border-b border-gray-200 dark:border-gray-600">
                TOR (.onion)
              </div>
              <div class="space-y-1">`;
          data.onion_servers.forEach(srv => {
            const statusClass = srv.online ? 'text-green-600 dark:text-green-400' : 'text-gray-400 dark:text-gray-500';
            const statusText = srv.online ? (srv.latency_ms ? srv.latency_ms.toFixed(0) + 'ms' : 'online') : 'offline';
            const statusDot = srv.online ? 'bg-green-500' : 'bg-gray-400';
            html += `
                <div class="flex items-center justify-between py-2 px-3 hover:bg-gray-100 dark:hover:bg-gray-600 rounded-lg cursor-pointer add-server-btn transition-colors border border-transparent hover:border-blue-500"
                     data-coin="${coin}" data-host="${srv.host}" data-port="${srv.port}" data-type="onion">
                  <div class="flex items-center flex-1 min-w-0">
                    <svg class="w-4 h-4 mr-2 text-blue-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
                    </svg>
                    <span class="font-mono text-sm text-gray-900 dark:text-white truncate" title="${srv.host}">${srv.host.substring(0, 24)}...:${srv.port}</span>
                  </div>
                  <div class="flex items-center ml-3">
                    <span class="w-2 h-2 ${statusDot} rounded-full mr-2"></span>
                    <span class="text-xs ${statusClass}">${statusText}</span>
                  </div>
                </div>`;
          });
          html += `
              </div>
            </div>`;
        }

        if (!data.clearnet_servers?.length && !data.onion_servers?.length) {
          const serverName = data.current_server ? `${data.current_server.host}:${data.current_server.port}` : 'The connected server';
          html = `<div class="text-sm text-gray-500 dark:text-gray-400 py-4 text-center">No servers discovered. <span class="font-mono">${serverName}</span> does not return peer lists.</div>`;
        } else {
          html += `<div class="text-xs text-gray-500 dark:text-gray-400 pt-3 border-t border-gray-200 dark:border-gray-600">Click a server to add it to your list</div>`;
        }

        listContainer.innerHTML = html;

        listContainer.querySelectorAll('.add-server-btn').forEach(item => {
          item.addEventListener('click', () => {
            const host = item.dataset.host;
            const port = item.dataset.port;
            const type = item.dataset.type;
            const coinName = item.dataset.coin;

            const textareaId = type === 'onion' ?
              `electrum_onion_${coinName}` : `electrum_clearnet_${coinName}`;
            const textarea = document.getElementById(textareaId);

            if (textarea) {
              const serverLine = `${host}:${port}`;
              const currentValue = textarea.value.trim();

              if (currentValue.split('\n').some(line => line.trim() === serverLine)) {
                item.classList.add('bg-yellow-100', 'dark:bg-yellow-800/30');
                setTimeout(() => item.classList.remove('bg-yellow-100', 'dark:bg-yellow-800/30'), 500);
                return;
              }

              textarea.value = currentValue ? currentValue + '\n' + serverLine : serverLine;
              item.classList.add('bg-green-100', 'dark:bg-green-800/30');
              setTimeout(() => item.classList.remove('bg-green-100', 'dark:bg-green-800/30'), 500);
            }
          });
        });
      }

      panel.classList.remove('hidden');
    })
    .catch(err => {
      listContainer.innerHTML = `<div class="text-xs text-red-500">Failed to discover servers: ${err.message}</div>`;
      panel.classList.remove('hidden');
    })
    .finally(() => {
      button.innerHTML = originalHtml;
      button.disabled = false;
    });
  };

  SettingsPage.cleanup = function() {
  };

  document.addEventListener('DOMContentLoaded', function() {
    SettingsPage.init();

    if (window.CleanupManager) {
      CleanupManager.registerResource('settingsPage', SettingsPage, (page) => {
        if (page.cleanup) page.cleanup();
      });
    }
  });

  window.SettingsPage = SettingsPage;
  window.syncNotificationSettings = SettingsPage.syncNotificationSettings.bind(SettingsPage);
  window.testUpdateNotification = SettingsPage.testUpdateNotification.bind(SettingsPage);
  window.testLiveUpdateCheck = SettingsPage.testLiveUpdateCheck.bind(SettingsPage);
  window.checkForUpdatesNow = SettingsPage.checkForUpdatesNow.bind(SettingsPage);
  window.showConfirmDialog = SettingsPage.showConfirmDialog.bind(SettingsPage);
  window.hideConfirmDialog = SettingsPage.hideConfirmDialog.bind(SettingsPage);
  window.confirmDisableCoin = SettingsPage.confirmDisableCoin.bind(SettingsPage);

})();
