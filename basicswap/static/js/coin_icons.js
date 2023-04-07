// Define a cache object to store selected option data
const selectCache = {};

// Function to update the cache with the selected option data for a given select element
function updateSelectCache(select) {
  const selectedOption = select.options[select.selectedIndex];
  const image = selectedOption.getAttribute('data-image');
  const name = selectedOption.textContent.trim();
  selectCache[select.id] = { image, name };
}

// Function to set the selected option and associated image and name for a given select element


function setSelectData(select) {
  const selectedOption = select.options[select.selectedIndex];
  const image = selectedOption.getAttribute('data-image') || '/static/images/other/coin.png'; // set a default image URL
  const name = selectedOption.textContent.trim();
  if (image) {
    select.style.backgroundImage = `url(${image})`;
    select.nextElementSibling.querySelector('.select-image').src = image;
  } else {
    select.style.backgroundImage = '';
    select.nextElementSibling.querySelector('.select-image').src = '';
  }
  select.nextElementSibling.querySelector('.select-name').textContent = name;
  updateSelectCache(select);
}


// Function to get the selected option data from cache for a given select element
function getSelectData(select) {
  return selectCache[select.id] || {};
}

// Update all custom select elements on the page
const selects = document.querySelectorAll('.custom-select .select');
selects.forEach((select) => {
  // Set the initial select data based on the cached data (if available) or the selected option (if any)
  const cachedData = getSelectData(select);
  if (cachedData.image) {
    select.style.backgroundImage = `url(${cachedData.image})`;
    select.nextElementSibling.querySelector('.select-image').src = cachedData.image;
  }
  if (cachedData.name) {
    select.nextElementSibling.querySelector('.select-name').textContent = cachedData.name;
  }
  if (select.selectedIndex >= 0) {
    setSelectData(select);
  }

  // Add event listener to update select data when an option is selected
  select.addEventListener('change', () => {
    setSelectData(select);
  });
});

// Hide the select image and name on page load
const selectIcons = document.querySelectorAll('.custom-select .select-icon');
const selectImages = document.querySelectorAll('.custom-select .select-image');
const selectNames = document.querySelectorAll('.custom-select .select-name');
selectIcons.forEach((icon) => {
  icon.style.display = 'none';
});
selectImages.forEach((image) => {
  image.style.display = 'none';
});
selectNames.forEach((name) => {
  name.style.display = 'none';
});
