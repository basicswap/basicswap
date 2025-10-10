(function() {
  'use strict';

  const AMMConfigTabs = {
    
    init: function() {
      const jsonTab = document.getElementById('json-tab');
      const settingsTab = document.getElementById('settings-tab');
      const overviewTab = document.getElementById('overview-tab');
      const jsonContent = document.getElementById('json-content');
      const settingsContent = document.getElementById('settings-content');
      const overviewContent = document.getElementById('overview-content');

      if (!jsonTab || !settingsTab || !overviewTab || !jsonContent || !settingsContent || !overviewContent) {
        return;
      }

      const activeConfigTab = localStorage.getItem('amm_active_config_tab');

      const switchConfigTab = (tabId) => {
        jsonContent.classList.add('hidden');
        jsonContent.classList.remove('block');
        settingsContent.classList.add('hidden');
        settingsContent.classList.remove('block');
        overviewContent.classList.add('hidden');
        overviewContent.classList.remove('block');

        jsonTab.classList.remove('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
        settingsTab.classList.remove('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
        overviewTab.classList.remove('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');

        if (tabId === 'json-tab') {
          jsonContent.classList.remove('hidden');
          jsonContent.classList.add('block');
          jsonTab.classList.add('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
          localStorage.setItem('amm_active_config_tab', 'json-tab');
        } else if (tabId === 'settings-tab') {
          settingsContent.classList.remove('hidden');
          settingsContent.classList.add('block');
          settingsTab.classList.add('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
          localStorage.setItem('amm_active_config_tab', 'settings-tab');

          this.loadSettingsFromJson();
        } else if (tabId === 'overview-tab') {
          overviewContent.classList.remove('hidden');
          overviewContent.classList.add('block');
          overviewTab.classList.add('bg-gray-100', 'text-gray-900', 'dark:bg-gray-600', 'dark:text-white');
          localStorage.setItem('amm_active_config_tab', 'overview-tab');
        }
      };

      jsonTab.addEventListener('click', () => switchConfigTab('json-tab'));
      settingsTab.addEventListener('click', () => switchConfigTab('settings-tab'));
      overviewTab.addEventListener('click', () => switchConfigTab('overview-tab'));

      const returnToTab = localStorage.getItem('amm_return_to_tab');
      if (returnToTab && (returnToTab === 'json-tab' || returnToTab === 'settings-tab' || returnToTab === 'overview-tab')) {
        localStorage.removeItem('amm_return_to_tab');
        switchConfigTab(returnToTab);
      } else if (activeConfigTab === 'settings-tab') {
        switchConfigTab('settings-tab');
      } else if (activeConfigTab === 'overview-tab') {
        switchConfigTab('overview-tab');
      } else {
        switchConfigTab('json-tab');
      }

      const globalSettingsForm = document.getElementById('global-settings-form');
      if (globalSettingsForm) {
        globalSettingsForm.addEventListener('submit', () => {
          this.updateJsonFromSettings();
        });
      }

      this.setupCollapsibles();

      this.setupConfigForm();

      this.setupCreateDefaultButton();

      this.handleCreateDefaultRefresh();
    },

    loadSettingsFromJson: function() {
      const configTextarea = document.querySelector('textarea[name="config_content"]');
      if (!configTextarea) return;

      try {
        const configText = configTextarea.value.trim();
        if (!configText) return;

        const config = JSON.parse(configText);

        document.getElementById('min_seconds_between_offers').value = config.min_seconds_between_offers || 15;
        document.getElementById('max_seconds_between_offers').value = config.max_seconds_between_offers || 60;
        document.getElementById('main_loop_delay').value = config.main_loop_delay || 60;

        const minSecondsBetweenBidsEl = document.getElementById('min_seconds_between_bids');
        const maxSecondsBetweenBidsEl = document.getElementById('max_seconds_between_bids');
        const pruneStateDelayEl = document.getElementById('prune_state_delay');
        const pruneStateAfterSecondsEl = document.getElementById('prune_state_after_seconds');

        if (minSecondsBetweenBidsEl) minSecondsBetweenBidsEl.value = config.min_seconds_between_bids || 15;
        if (maxSecondsBetweenBidsEl) maxSecondsBetweenBidsEl.value = config.max_seconds_between_bids || 60;
        if (pruneStateDelayEl) pruneStateDelayEl.value = config.prune_state_delay || 120;
        if (pruneStateAfterSecondsEl) pruneStateAfterSecondsEl.value = config.prune_state_after_seconds || 604800;
        document.getElementById('auth').value = config.auth || '';
      } catch (error) {
        console.error('Error loading settings from JSON:', error);
      }
    },

    updateJsonFromSettings: function() {
      const configTextarea = document.querySelector('textarea[name="config_content"]');
      if (!configTextarea) return;

      try {
        const configText = configTextarea.value.trim();
        let config = {};

        if (configText) {
          config = JSON.parse(configText);
        }

        config.min_seconds_between_offers = parseInt(document.getElementById('min_seconds_between_offers').value) || 15;
        config.max_seconds_between_offers = parseInt(document.getElementById('max_seconds_between_offers').value) || 60;
        config.main_loop_delay = parseInt(document.getElementById('main_loop_delay').value) || 60;

        const minSecondsBetweenBidsEl = document.getElementById('min_seconds_between_bids');
        const maxSecondsBetweenBidsEl = document.getElementById('max_seconds_between_bids');
        const pruneStateDelayEl = document.getElementById('prune_state_delay');
        const pruneStateAfterSecondsEl = document.getElementById('prune_state_after_seconds');

        if (minSecondsBetweenBidsEl) config.min_seconds_between_bids = parseInt(minSecondsBetweenBidsEl.value) || 15;
        if (maxSecondsBetweenBidsEl) config.max_seconds_between_bids = parseInt(maxSecondsBetweenBidsEl.value) || 60;
        if (pruneStateDelayEl) config.prune_state_delay = parseInt(pruneStateDelayEl.value) || 120;
        if (pruneStateAfterSecondsEl) config.prune_state_after_seconds = parseInt(pruneStateAfterSecondsEl.value) || 604800;
        config.auth = document.getElementById('auth').value || '';

        configTextarea.value = JSON.stringify(config, null, 2);

        localStorage.setItem('amm_return_to_tab', 'settings-tab');
      } catch (error) {
        console.error('Error updating JSON from settings:', error);
        alert('Error updating configuration: ' + error.message);
      }
    },

    setupCollapsibles: function() {
      const collapsibleHeaders = document.querySelectorAll('.collapsible-header');

      if (collapsibleHeaders.length === 0) return;

      let collapsibleStates = {};
      try {
        const storedStates = localStorage.getItem('amm_collapsible_states');
        if (storedStates) {
          collapsibleStates = JSON.parse(storedStates);
        }
      } catch (e) {
        console.error('Error parsing stored collapsible states:', e);
        collapsibleStates = {};
      }

      const toggleCollapsible = (header) => {
        const targetId = header.getAttribute('data-target');
        const content = document.getElementById(targetId);
        const arrow = header.querySelector('svg');

        if (content) {
          if (content.classList.contains('hidden')) {
            content.classList.remove('hidden');
            arrow.classList.add('rotate-180');
            collapsibleStates[targetId] = 'open';
          } else {
            content.classList.add('hidden');
            arrow.classList.remove('rotate-180');
            collapsibleStates[targetId] = 'closed';
          }

          localStorage.setItem('amm_collapsible_states', JSON.stringify(collapsibleStates));
        }
      };

      collapsibleHeaders.forEach(header => {
        const targetId = header.getAttribute('data-target');
        const content = document.getElementById(targetId);
        const arrow = header.querySelector('svg');

        if (content) {
          if (collapsibleStates[targetId] === 'open') {
            content.classList.remove('hidden');
            arrow.classList.add('rotate-180');
          } else {
            content.classList.add('hidden');
            arrow.classList.remove('rotate-180');
            collapsibleStates[targetId] = 'closed';
          }
        }

        header.addEventListener('click', () => toggleCollapsible(header));
      });

      localStorage.setItem('amm_collapsible_states', JSON.stringify(collapsibleStates));
    },

    setupConfigForm: function() {
      const configForm = document.querySelector('form[method="post"]');
      const saveConfigBtn = document.getElementById('save_config_btn');

      if (configForm && saveConfigBtn) {
        configForm.addEventListener('submit', (e) => {
          if (e.submitter && e.submitter.name === 'save_config') {
            localStorage.setItem('amm_update_tables', 'true');
          }
        });

        if (localStorage.getItem('amm_update_tables') === 'true') {
          localStorage.removeItem('amm_update_tables');
          CleanupManager.setTimeout(() => {
            if (window.ammTablesManager && window.ammTablesManager.updateTables) {
              window.ammTablesManager.updateTables();
            }
          }, 500);
        }
      }
    },

    setupCreateDefaultButton: function() {
      const createDefaultBtn = document.getElementById('create_default_btn');
      const configForm = document.querySelector('form[method="post"]');

      if (createDefaultBtn && configForm) {
        createDefaultBtn.addEventListener('click', (e) => {
          e.preventDefault();

          const title = 'Create Default Configuration';
          const message = 'This will overwrite your current configuration with a default template.\n\nAre you sure you want to continue?';

          if (window.showConfirmModal) {
            window.showConfirmModal(title, message, () => {
              const hiddenInput = document.createElement('input');
              hiddenInput.type = 'hidden';
              hiddenInput.name = 'create_default';
              hiddenInput.value = 'true';
              configForm.appendChild(hiddenInput);

              localStorage.setItem('amm_create_default_refresh', 'true');

              configForm.submit();
            });
          } else {
            if (confirm('This will overwrite your current configuration with a default template.\n\nAre you sure you want to continue?')) {
              const hiddenInput = document.createElement('input');
              hiddenInput.type = 'hidden';
              hiddenInput.name = 'create_default';
              hiddenInput.value = 'true';
              configForm.appendChild(hiddenInput);

              localStorage.setItem('amm_create_default_refresh', 'true');
              configForm.submit();
            }
          }
        });
      }
    },

    handleCreateDefaultRefresh: function() {
      if (localStorage.getItem('amm_create_default_refresh') === 'true') {
        localStorage.removeItem('amm_create_default_refresh');

        CleanupManager.setTimeout(() => {
          window.location.href = window.location.pathname + window.location.search;
        }, 500);
      }
    },

    cleanup: function() {
    }
  };

  document.addEventListener('DOMContentLoaded', function() {
    AMMConfigTabs.init();

    if (window.CleanupManager) {
      CleanupManager.registerResource('ammConfigTabs', AMMConfigTabs, (tabs) => {
        if (tabs.cleanup) tabs.cleanup();
      });
    }
  });

  window.AMMConfigTabs = AMMConfigTabs;

})();
