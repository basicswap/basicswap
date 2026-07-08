(function() {
    const VALID_OFFER_MODES = ['legacy', 'one_time', 'fixed_total', 'standing'];
    const MIN_OFFER_VALID_SECONDS = 600;
    const MIN_AMOUNT_STEP = 0.001;

    function isPositiveNumber(value) {
        const n = parseFloat(value);
        return !isNaN(n) && n > 0;
    }

    function validateOffer(offer) {
        const errors = [];

        if (!offer.name || !String(offer.name).trim()) {
            errors.push('Name is required and cannot be empty.');
        }

        if (!offer.coin_from || !offer.coin_to) {
            errors.push('Please select both Coin From and Coin To.');
        } else if (offer.coin_from === offer.coin_to) {
            errors.push('Coin From and Coin To must be different.');
        }

        if (!isPositiveNumber(offer.amount)) {
            errors.push('Amount must be greater than zero.');
        }

        const amount = parseFloat(offer.amount);

        if (offer.amount_step !== undefined && offer.amount_step !== null && offer.amount_step !== '') {
            const step = parseFloat(offer.amount_step);
            if (isNaN(step)) {
                errors.push('Offer Size Increment must be a valid number.');
            } else if (step < MIN_AMOUNT_STEP) {
                errors.push('Offer Size Increment must be at least ' + MIN_AMOUNT_STEP + '.');
            } else if (!isNaN(amount) && step > amount) {
                errors.push('Offer Size Increment cannot be greater than the offer amount.');
            }
        }

        if (offer.offer_valid_seconds !== undefined && offer.offer_valid_seconds !== null && offer.offer_valid_seconds !== '') {
            const seconds = parseInt(offer.offer_valid_seconds);
            if (isNaN(seconds) || seconds < MIN_OFFER_VALID_SECONDS) {
                errors.push('Offer valid seconds must be at least ' + MIN_OFFER_VALID_SECONDS + ' (10 minutes).');
            }
        }

        const mode = offer.offer_mode || 'standing';
        if (VALID_OFFER_MODES.indexOf(mode) === -1) {
            errors.push('Invalid offer mode.');
        }

        if (mode === 'standing') {
            if (!isPositiveNumber(offer.min_coin_from_amt)) {
                errors.push('Standing offers require a Minimum Balance greater than 0 to act as a wallet floor.');
            }
        }

        if (mode === 'fixed_total') {
            const total = parseFloat(offer.total_to_sell);
            if (isNaN(total) || (!isNaN(amount) && total < amount)) {
                errors.push('Total to Sell must be at least the offer amount.');
            }
        }

        return { valid: errors.length === 0, errors: errors };
    }

    function validateBid(bid) {
        const errors = [];

        if (!bid.name || !String(bid.name).trim()) {
            errors.push('Name is required and cannot be empty.');
        }

        if (!bid.coin_from || !bid.coin_to) {
            errors.push('Please select both Coin From and Coin To.');
        } else if (bid.coin_from === bid.coin_to) {
            errors.push('Coin From and Coin To must be different.');
        }

        if (!isPositiveNumber(bid.amount)) {
            errors.push('Amount must be greater than zero.');
        }

        return { valid: errors.length === 0, errors: errors };
    }

    window.AmmTemplateValidation = {
        VALID_OFFER_MODES: VALID_OFFER_MODES,
        MIN_OFFER_VALID_SECONDS: MIN_OFFER_VALID_SECONDS,
        MIN_AMOUNT_STEP: MIN_AMOUNT_STEP,
        validateOffer: validateOffer,
        validateBid: validateBid
    };
})();
