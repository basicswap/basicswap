document.addEventListener('DOMContentLoaded', function() {
    const burger = document.querySelectorAll('.navbar-burger');
    const menu = document.querySelectorAll('.navbar-menu');

    if (burger.length && menu.length) {
        for (var i = 0; i < burger.length; i++) {
            burger[i].addEventListener('click', function() {
                for (var j = 0; j < menu.length; j++) {
                    menu[j].classList.toggle('hidden');
                }
            });
        }
    }

    const close = document.querySelectorAll('.navbar-close');
    const backdrop = document.querySelectorAll('.navbar-backdrop');

    if (close.length) {
        for (var k = 0; k < close.length; k++) {
            close[k].addEventListener('click', function() {
                for (var j = 0; j < menu.length; j++) {
                    menu[j].classList.toggle('hidden');
                }
            });
        }
    }

    if (backdrop.length) {
        for (var l = 0; l < backdrop.length; l++) {
            backdrop[l].addEventListener('click', function() {
                for (var j = 0; j < menu.length; j++) {
                    menu[j].classList.toggle('hidden');
                }
            });
        }
    }

    const tooltipManager = TooltipManager.initialize();
    tooltipManager.initializeTooltips();
    setupShutdownModal();
    setupDarkMode();
    toggleImages();
});

function setupShutdownModal() {
    const shutdownButtons = document.querySelectorAll('.shutdown-button');
    const shutdownModal = document.getElementById('shutdownModal');
    const closeModalButton = document.getElementById('closeShutdownModal');
    const confirmShutdownButton = document.getElementById('confirmShutdown');
    const shutdownWarning = document.getElementById('shutdownWarning');

    function updateShutdownButtons() {
        const activeSwaps = parseInt(shutdownButtons[0].getAttribute('data-active-swaps') || '0');
        shutdownButtons.forEach(button => {
            if (activeSwaps > 0) {
                button.classList.add('shutdown-disabled');
                button.setAttribute('data-disabled', 'true');
                button.setAttribute('title', 'Caution: Swaps in progress');
            } else {
                button.classList.remove('shutdown-disabled');
                button.removeAttribute('data-disabled');
                button.removeAttribute('title');
            }
        });
    }

    function closeAllDropdowns() {

        const openDropdowns = document.querySelectorAll('.dropdown-menu:not(.hidden)');
        openDropdowns.forEach(dropdown => {
            if (dropdown.style.display !== 'none') {
                dropdown.style.display = 'none';
            }
        });

        if (window.Dropdown && window.Dropdown.instances) {
            window.Dropdown.instances.forEach(instance => {
                if (instance._visible) {
                    instance.hide();
                }
            });
        }
    }

    function showShutdownModal() {
        closeAllDropdowns();

        const activeSwaps = parseInt(shutdownButtons[0].getAttribute('data-active-swaps') || '0');
        if (activeSwaps > 0) {
            shutdownWarning.classList.remove('hidden');
            confirmShutdownButton.textContent = 'Yes, Shut Down Anyway';
        } else {
            shutdownWarning.classList.add('hidden');
            confirmShutdownButton.textContent = 'Yes, Shut Down';
        }
        shutdownModal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    function hideShutdownModal() {
        shutdownModal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    if (shutdownButtons.length) {
        shutdownButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                showShutdownModal();
            });
        });
    }

    if (closeModalButton) {
        closeModalButton.addEventListener('click', hideShutdownModal);
    }

    if (confirmShutdownButton) {
        confirmShutdownButton.addEventListener('click', function() {
            const shutdownToken = document.querySelector('.shutdown-button')
                .getAttribute('href').split('/').pop();
            window.location.href = '/shutdown/' + shutdownToken;
        });
    }

    if (shutdownModal) {
        shutdownModal.addEventListener('click', function(e) {
            if (e.target === this) {
                hideShutdownModal();
            }
        });
    }

    if (shutdownButtons.length) {
        updateShutdownButtons();
    }
}

function setupDarkMode() {
    const themeToggle = document.getElementById('theme-toggle');
    const themeToggleDarkIcon = document.getElementById('theme-toggle-dark-icon');
    const themeToggleLightIcon = document.getElementById('theme-toggle-light-icon');

    if (themeToggleDarkIcon && themeToggleLightIcon) {
        if (localStorage.getItem('color-theme') === 'dark' ||
            (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            themeToggleLightIcon.classList.remove('hidden');
        } else {
            themeToggleDarkIcon.classList.remove('hidden');
        }
    }

    function setTheme(theme) {
        if (theme === 'light') {
            document.documentElement.classList.remove('dark');
            localStorage.setItem('color-theme', 'light');
        } else {
            document.documentElement.classList.add('dark');
            localStorage.setItem('color-theme', 'dark');
        }
    }

    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            if (localStorage.getItem('color-theme') === 'dark') {
                setTheme('light');
            } else {
                setTheme('dark');
            }

            if (themeToggleDarkIcon && themeToggleLightIcon) {
                themeToggleDarkIcon.classList.toggle('hidden');
                themeToggleLightIcon.classList.toggle('hidden');
            }

            toggleImages();
        });
    }
}

function toggleImages() {
    var html = document.querySelector('html');
    var darkImages = document.querySelectorAll('.dark-image');
    var lightImages = document.querySelectorAll('.light-image');

    if (html && html.classList.contains('dark')) {
        toggleImageDisplay(darkImages, 'block');
        toggleImageDisplay(lightImages, 'none');
    } else {
        toggleImageDisplay(darkImages, 'none');
        toggleImageDisplay(lightImages, 'block');
    }
}

function toggleImageDisplay(images, display) {
    images.forEach(function(img) {
        img.style.display = display;
    });
}
