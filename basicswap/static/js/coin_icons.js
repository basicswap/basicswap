document.addEventListener('DOMContentLoaded', () => {

    const selectCache = {};

    function updateSelectCache(select) {
        const selectedOption = select.options[select.selectedIndex];
        const image = selectedOption.getAttribute('data-image');
        const name = selectedOption.textContent.trim();
        selectCache[select.id] = { image, name };
    }

    function setSelectData(select) {
        const selectedOption = select.options[select.selectedIndex];
        const image = selectedOption.getAttribute('data-image') || '';
        const name = selectedOption.textContent.trim();
        select.style.backgroundImage = image ? `url(${image}?${new Date().getTime()})` : '';
        
        const selectImage = select.nextElementSibling.querySelector('.select-image');
        if (selectImage) {
            selectImage.src = image;
        }

        const selectNameElement = select.nextElementSibling.querySelector('.select-name');
        if (selectNameElement) {
            selectNameElement.textContent = name;
        }

        updateSelectCache(select);
    }

    const selectIcons = document.querySelectorAll('.custom-select .select-icon');
    const selectImages = document.querySelectorAll('.custom-select .select-image');
    const selectNames = document.querySelectorAll('.custom-select .select-name');

    selectIcons.forEach(icon => icon.style.display = 'none');
    selectImages.forEach(image => image.style.display = 'none');
    selectNames.forEach(name => name.style.display = 'none');

    function setupCustomSelect(select) {
        const options = select.querySelectorAll('option');
        const selectIcon = select.parentElement.querySelector('.select-icon');
        const selectImage = select.parentElement.querySelector('.select-image');

        options.forEach(option => {
            const image = option.getAttribute('data-image');
            if (image) {
                option.style.backgroundImage = `url(${image})`;
            }
        });

        const storedValue = localStorage.getItem(select.name);
        if (storedValue && select.value == '-1') {
            select.value = storedValue;
        }

        select.addEventListener('change', () => {
            setSelectData(select);
            localStorage.setItem(select.name, select.value);
        });

        setSelectData(select);
        selectIcon.style.display = 'none';
        selectImage.style.display = 'none';
    }

    const customSelects = document.querySelectorAll('.custom-select select');
    customSelects.forEach(setupCustomSelect);
});