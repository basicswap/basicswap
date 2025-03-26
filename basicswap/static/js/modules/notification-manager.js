const NotificationManager = (function() {

  const config = {
    showNewOffers: false,
    showNewBids: true,
    showBidAccepted: true
  };

  function ensureToastContainer() {
    let container = document.getElementById('ul_updates');
    if (!container) {
      const floating_div = document.createElement('div');
      floating_div.classList.add('floatright');
      container = document.createElement('ul');
      container.setAttribute('id', 'ul_updates');
      floating_div.appendChild(container);
      document.body.appendChild(floating_div);
    }
    return container;
  }

  const publicAPI = {
    initialize: function(options = {}) {
      Object.assign(config, options);

      if (window.CleanupManager) {
        window.CleanupManager.registerResource('notificationManager', this, (mgr) => {

          console.log('NotificationManager disposed');
        });
      }

      return this;
    },

    createToast: function(title, type = 'success') {
      const messages = ensureToastContainer();
      const message = document.createElement('li');
      message.innerHTML = `
        <div id="hide">
          <div id="toast-${type}" class="flex items-center p-4 mb-4 w-full max-w-xs text-gray-500 
            bg-white rounded-lg shadow" role="alert">
            <div class="inline-flex flex-shrink-0 justify-center items-center w-10 h-10 
              bg-blue-500 rounded-lg">
              <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" height="18" width="18" 
                viewBox="0 0 24 24">
                <g fill="#ffffff">
                  <path d="M8.5,20a1.5,1.5,0,0,1-1.061-.439L.379,12.5,2.5,10.379l6,6,13-13L23.621,
                    5.5,9.561,19.561A1.5,1.5,0,0,1,8.5,20Z"></path>
                </g>
              </svg>
            </div>
            <div class="uppercase w-40 ml-3 text-sm font-semibold text-gray-900">${title}</div>
            <button type="button" onclick="closeAlert(event)" class="ml-auto -mx-1.5 -my-1.5 
              bg-white text-gray-400 hover:text-gray-900 rounded-lg focus:ring-0 focus:outline-none 
              focus:ring-gray-300 p-1.5 hover:bg-gray-100 inline-flex h-8 w-8">
              <span class="sr-only">Close</span>
              <svg aria-hidden="true" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" 
                xmlns="http://www.w3.org/2000/svg">
                <path fill-rule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 
                  1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 
                  4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" 
                  clip-rule="evenodd"></path>
              </svg>
            </button>
          </div>
        </div>
      `;
      messages.appendChild(message);
    },

    handleWebSocketEvent: function(data) {
      if (!data || !data.event) return;
      let toastTitle;
      let shouldShowToast = false;

      switch (data.event) {
        case 'new_offer':
          toastTitle = `New network <a class="underline" href=/offer/${data.offer_id}>offer</a>`;
          shouldShowToast = config.showNewOffers;
          break;
        case 'new_bid':
          toastTitle = `<a class="underline" href=/bid/${data.bid_id}>New bid</a> on 
            <a class="underline" href=/offer/${data.offer_id}>offer</a>`;
          shouldShowToast = config.showNewBids;
          break;
        case 'bid_accepted':
          toastTitle = `<a class="underline" href=/bid/${data.bid_id}>Bid</a> accepted`;
          shouldShowToast = config.showBidAccepted;
          break;
      }

      if (toastTitle && shouldShowToast) {
        this.createToast(toastTitle);
      }
    },

    updateConfig: function(newConfig) {
      Object.assign(config, newConfig);
      return this;
    }
  };

  window.closeAlert = function(event) {
    let element = event.target;
    while (element.nodeName !== "BUTTON") {
      element = element.parentNode;
    }
    element.parentNode.parentNode.removeChild(element.parentNode);
  };

  return publicAPI;
})();

window.NotificationManager = NotificationManager;

document.addEventListener('DOMContentLoaded', function() {

  if (!window.notificationManagerInitialized) {
    window.NotificationManager.initialize(window.notificationConfig || {});
    window.notificationManagerInitialized = true;
  }
});

//console.log('NotificationManager initialized with methods:', Object.keys(NotificationManager));
console.log('NotificationManager initialized');
