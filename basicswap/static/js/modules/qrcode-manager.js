
(function() {
  'use strict';

  const QRCodeManager = {
    
    defaultOptions: {
      width: 200,
      height: 200,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L
    },

    initialize: function() {
      const qrElements = document.querySelectorAll('[data-qrcode]');
      
      qrElements.forEach(element => {
        this.generateQRCode(element);
      });
    },

    generateQRCode: function(element) {
      const address = element.getAttribute('data-address');
      const width = parseInt(element.getAttribute('data-width')) || this.defaultOptions.width;
      const height = parseInt(element.getAttribute('data-height')) || this.defaultOptions.height;
      
      if (!address) {
        console.error('QRCodeManager: No address provided for element', element);
        return;
      }

      element.innerHTML = '';

      try {
        new QRCode(element, {
          text: address,
          width: width,
          height: height,
          colorDark: this.defaultOptions.colorDark,
          colorLight: this.defaultOptions.colorLight,
          correctLevel: this.defaultOptions.correctLevel
        });
      } catch (error) {
        console.error('QRCodeManager: Failed to generate QR code', error);
      }
    },

    generateById: function(elementId, address, options = {}) {
      
      const element = window.DOMCache
        ? window.DOMCache.get(elementId)
        : document.getElementById(elementId);

      if (!element) {
        console.error('QRCodeManager: Element not found:', elementId);
        return;
      }

      element.setAttribute('data-address', address);

      if (options.width) element.setAttribute('data-width', options.width);
      if (options.height) element.setAttribute('data-height', options.height);

      this.generateQRCode(element);
    }
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      QRCodeManager.initialize();
    });
  } else {
    QRCodeManager.initialize();
  }

  window.QRCodeManager = QRCodeManager;

})();
