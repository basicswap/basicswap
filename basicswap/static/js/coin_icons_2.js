// Define the function for setting up the custom select element
function setupCustomSelect(select) {
  const options = select.querySelectorAll('option');
  const selectIcon = select.parentElement.querySelector('.select-icon');
  const selectImage = select.parentElement.querySelector('.select-image');

  // Set the background image for each option that has a data-image attribute
  options.forEach(option => {
    const image = option.getAttribute('data-image');
    if (image) {
      option.style.backgroundImage = `url(${image})`;
    }
  });

  // Set the selected option based on the stored value
  const storedValue = localStorage.getItem(select.name);
  if (storedValue) {
    const selectedOption = select.querySelector(`option[value="${storedValue}"]`);
    if (selectedOption) {
      select.value = storedValue;
      const image = selectedOption.getAttribute('data-image');
      if (image) {
        select.style.backgroundImage = `url(${image})`;
        selectImage.src = image;
      }
    }
  }

  // Update the select element and image when the user makes a selection
  select.addEventListener('change', () => {
    const selectedOption = select.options[select.selectedIndex];
    const image = selectedOption.getAttribute('data-image');
    if (image) {
      select.style.backgroundImage = `url(${image})`;
      selectImage.src = image;
    } else {
      select.style.backgroundImage = '';
      selectImage.src = '';
    }

    // Save the selected value to localStorage
    localStorage.setItem(select.name, select.value);
  });

  // Hide the select icon and image on page load
  selectIcon.style.display = 'none';
  selectImage.style.display = 'none';
}

// Call the setupCustomSelect function for each custom select element
const customSelects = document.querySelectorAll('.custom-select select');
customSelects.forEach(select => {
  setupCustomSelect(select);
});


