
(function() {
  'use strict';

  const SettingsPage = {
    confirmCallback: null,
    triggerElement: null,

    init: function() {
      this.setupTabs();
      this.setupCoinHeaders();
      this.setupConfirmModal();
      this.setupNotificationSettings();
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
