(function() {
  'use strict';

  const originalGetElementById = document.getElementById.bind(document);

  const DOMCache = {
    
    cache: {},

    get: function(id, forceRefresh = false) {
      if (!id) {
        console.warn('DOMCache: No ID provided');
        return null;
      }

      if (!forceRefresh && this.cache[id]) {
        
        if (document.body.contains(this.cache[id])) {
          return this.cache[id];
        } else {
          
          delete this.cache[id];
        }
      }

      const element = originalGetElementById(id);
      if (element) {
        this.cache[id] = element;
      }

      return element;
    },

    getMultiple: function(ids) {
      const elements = {};
      ids.forEach(id => {
        elements[id] = this.get(id);
      });
      return elements;
    },

    setValue: function(id, value) {
      const element = this.get(id);
      if (element) {
        element.value = value;
        return true;
      }
      console.warn(`DOMCache: Element not found: ${id}`);
      return false;
    },

    getValue: function(id, defaultValue = '') {
      const element = this.get(id);
      return element ? element.value : defaultValue;
    },

    setText: function(id, text) {
      const element = this.get(id);
      if (element) {
        element.textContent = text;
        return true;
      }
      console.warn(`DOMCache: Element not found: ${id}`);
      return false;
    },

    getText: function(id, defaultValue = '') {
      const element = this.get(id);
      return element ? element.textContent : defaultValue;
    },

    addClass: function(id, className) {
      const element = this.get(id);
      if (element) {
        element.classList.add(className);
        return true;
      }
      return false;
    },

    removeClass: function(id, className) {
      const element = this.get(id);
      if (element) {
        element.classList.remove(className);
        return true;
      }
      return false;
    },

    toggleClass: function(id, className) {
      const element = this.get(id);
      if (element) {
        element.classList.toggle(className);
        return true;
      }
      return false;
    },

    show: function(id) {
      const element = this.get(id);
      if (element) {
        element.style.display = '';
        return true;
      }
      return false;
    },

    hide: function(id) {
      const element = this.get(id);
      if (element) {
        element.style.display = 'none';
        return true;
      }
      return false;
    },

    exists: function(id) {
      return this.get(id) !== null;
    },

    clear: function(id) {
      if (id) {
        delete this.cache[id];
      } else {
        this.cache = {};
      }
    },

    size: function() {
      return Object.keys(this.cache).length;
    },

    validate: function() {
      const ids = Object.keys(this.cache);
      let removed = 0;

      ids.forEach(id => {
        const element = this.cache[id];
        if (!document.body.contains(element)) {
          delete this.cache[id];
          removed++;
        }
      });

      return removed;
    },

    createScope: function(elementIds) {
      const scope = {};
      
      elementIds.forEach(id => {
        Object.defineProperty(scope, id, {
          get: () => this.get(id),
          enumerable: true
        });
      });

      return scope;
    },

    batch: function(operations) {
      Object.keys(operations).forEach(id => {
        const ops = operations[id];
        const element = this.get(id);

        if (!element) {
          console.warn(`DOMCache: Element not found in batch operation: ${id}`);
          return;
        }

        if (ops.value !== undefined) element.value = ops.value;
        if (ops.text !== undefined) element.textContent = ops.text;
        if (ops.html !== undefined) element.innerHTML = ops.html;
        if (ops.class) element.classList.add(ops.class);
        if (ops.removeClass) element.classList.remove(ops.removeClass);
        if (ops.hide) element.style.display = 'none';
        if (ops.show) element.style.display = '';
        if (ops.disabled !== undefined) element.disabled = ops.disabled;
      });
    }
  };

  window.DOMCache = DOMCache;

  if (!window.$) {
    window.$ = function(id) {
      return DOMCache.get(id);
    };
  }

  document.getElementById = function(id) {
    return DOMCache.get(id);
  };

  document.getElementByIdOriginal = originalGetElementById;

  if (window.CleanupManager) {
    const validationInterval = CleanupManager.setInterval(() => {
      DOMCache.validate();
    }, 30000);

    CleanupManager.registerResource('domCacheValidation', validationInterval, () => {
      clearInterval(validationInterval);
    });
  }

})();
