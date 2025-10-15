(function() {
  'use strict';

  const FormValidator = {
    
    checkPasswordStrength: function(password) {
      const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password)
      };

      let score = 0;
      if (requirements.length) score += 25;
      if (requirements.uppercase) score += 25;
      if (requirements.lowercase) score += 25;
      if (requirements.number) score += 25;

      return {
        score: score,
        requirements: requirements,
        isStrong: score >= 60
      };
    },

    updatePasswordStrengthUI: function(password, elements) {
      const result = this.checkPasswordStrength(password);
      const { score, requirements } = result;

      if (!elements.bar || !elements.text) {
        console.warn('FormValidator: Missing strength UI elements');
        return result.isStrong;
      }

      elements.bar.style.width = `${score}%`;

      if (score === 0) {
        elements.bar.className = 'h-2 rounded-full transition-all duration-300 bg-gray-300 dark:bg-gray-500';
        elements.text.textContent = 'Enter password';
        elements.text.className = 'text-sm font-medium text-gray-500 dark:text-gray-400';
      } else if (score < 40) {
        elements.bar.className = 'h-2 rounded-full transition-all duration-300 bg-red-500';
        elements.text.textContent = 'Weak';
        elements.text.className = 'text-sm font-medium text-red-600 dark:text-red-400';
      } else if (score < 70) {
        elements.bar.className = 'h-2 rounded-full transition-all duration-300 bg-yellow-500';
        elements.text.textContent = 'Fair';
        elements.text.className = 'text-sm font-medium text-yellow-600 dark:text-yellow-400';
      } else if (score < 90) {
        elements.bar.className = 'h-2 rounded-full transition-all duration-300 bg-blue-500';
        elements.text.textContent = 'Good';
        elements.text.className = 'text-sm font-medium text-blue-600 dark:text-blue-400';
      } else {
        elements.bar.className = 'h-2 rounded-full transition-all duration-300 bg-green-500';
        elements.text.textContent = 'Strong';
        elements.text.className = 'text-sm font-medium text-green-600 dark:text-green-400';
      }

      if (elements.requirements) {
        this.updateRequirement(elements.requirements.length, requirements.length);
        this.updateRequirement(elements.requirements.uppercase, requirements.uppercase);
        this.updateRequirement(elements.requirements.lowercase, requirements.lowercase);
        this.updateRequirement(elements.requirements.number, requirements.number);
      }

      return result.isStrong;
    },

    updateRequirement: function(element, met) {
      if (!element) return;

      if (met) {
        element.className = 'flex items-center text-green-600 dark:text-green-400';
      } else {
        element.className = 'flex items-center text-gray-500 dark:text-gray-400';
      }
    },

    checkPasswordMatch: function(password1, password2, elements) {
      if (!elements) {
        return password1 === password2;
      }

      const { container, success, error } = elements;

      if (password2.length === 0) {
        if (container) container.classList.add('hidden');
        return false;
      }

      if (container) container.classList.remove('hidden');

      if (password1 === password2) {
        if (success) success.classList.remove('hidden');
        if (error) error.classList.add('hidden');
        return true;
      } else {
        if (success) success.classList.add('hidden');
        if (error) error.classList.remove('hidden');
        return false;
      }
    },

    validateEmail: function(email) {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(email);
    },

    validateRequired: function(value) {
      return value && value.trim().length > 0;
    },

    validateMinLength: function(value, minLength) {
      return value && value.length >= minLength;
    },

    validateMaxLength: function(value, maxLength) {
      return value && value.length <= maxLength;
    },

    validateNumeric: function(value) {
      return !isNaN(value) && !isNaN(parseFloat(value));
    },

    validateRange: function(value, min, max) {
      const num = parseFloat(value);
      return !isNaN(num) && num >= min && num <= max;
    },

    showError: function(element, message) {
      if (!element) return;

      element.classList.add('border-red-500', 'focus:border-red-500', 'focus:ring-red-500');
      element.classList.remove('border-gray-300', 'focus:border-blue-500', 'focus:ring-blue-500');

      let errorElement = element.parentElement.querySelector('.validation-error');
      if (!errorElement) {
        errorElement = document.createElement('p');
        errorElement.className = 'validation-error text-red-600 dark:text-red-400 text-sm mt-1';
        element.parentElement.appendChild(errorElement);
      }

      errorElement.textContent = message;
      errorElement.classList.remove('hidden');
    },

    clearError: function(element) {
      if (!element) return;

      element.classList.remove('border-red-500', 'focus:border-red-500', 'focus:ring-red-500');
      element.classList.add('border-gray-300', 'focus:border-blue-500', 'focus:ring-blue-500');

      const errorElement = element.parentElement.querySelector('.validation-error');
      if (errorElement) {
        errorElement.classList.add('hidden');
      }
    },

    validateForm: function(form, rules) {
      if (!form || !rules) return false;

      let isValid = true;

      Object.keys(rules).forEach(fieldName => {
        const field = form.querySelector(`[name="${fieldName}"]`);
        if (!field) return;

        const fieldRules = rules[fieldName];
        let fieldValid = true;
        let errorMessage = '';

        if (fieldRules.required && !this.validateRequired(field.value)) {
          fieldValid = false;
          errorMessage = fieldRules.requiredMessage || 'This field is required';
        }

        if (fieldValid && fieldRules.minLength && !this.validateMinLength(field.value, fieldRules.minLength)) {
          fieldValid = false;
          errorMessage = fieldRules.minLengthMessage || `Minimum ${fieldRules.minLength} characters required`;
        }

        if (fieldValid && fieldRules.maxLength && !this.validateMaxLength(field.value, fieldRules.maxLength)) {
          fieldValid = false;
          errorMessage = fieldRules.maxLengthMessage || `Maximum ${fieldRules.maxLength} characters allowed`;
        }

        if (fieldValid && fieldRules.email && !this.validateEmail(field.value)) {
          fieldValid = false;
          errorMessage = fieldRules.emailMessage || 'Invalid email format';
        }

        if (fieldValid && fieldRules.numeric && !this.validateNumeric(field.value)) {
          fieldValid = false;
          errorMessage = fieldRules.numericMessage || 'Must be a number';
        }

        if (fieldValid && fieldRules.range && !this.validateRange(field.value, fieldRules.range.min, fieldRules.range.max)) {
          fieldValid = false;
          errorMessage = fieldRules.rangeMessage || `Must be between ${fieldRules.range.min} and ${fieldRules.range.max}`;
        }

        if (fieldValid && fieldRules.custom) {
          const customResult = fieldRules.custom(field.value, form);
          if (!customResult.valid) {
            fieldValid = false;
            errorMessage = customResult.message || 'Invalid value';
          }
        }

        if (fieldValid) {
          this.clearError(field);
        } else {
          this.showError(field, errorMessage);
          isValid = false;
        }
      });

      return isValid;
    }
  };

  window.FormValidator = FormValidator;

})();
