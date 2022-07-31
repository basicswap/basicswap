
window.addEventListener('DOMContentLoaded', (event) => {
    let err_msgs = document.querySelectorAll('p.error_msg');
    for (let i=0; i < err_msgs.length; i++) {
        err_msg = err_msgs[i].innerText
        if (err_msg.indexOf('coin_to') >= 0 || err_msg.indexOf('Coin To') >= 0) {
            e = document.getElementById('coin_to');
            e.classList.add('error');
        }
        if (err_msg.indexOf('Coin From') >= 0) {
            e = document.getElementById('coin_from');
            e.classList.add('error');
        }
        if (err_msg.indexOf('Amount From') >= 0) {
            e = document.getElementById('amt_from');
            e.classList.add('error');
        }
        if (err_msg.indexOf('Amount To') >= 0) {
            e = document.getElementById('amt_to');
            e.classList.add('error');
        }
        if (err_msg.indexOf('Minimum Bid Amount') >= 0) {
            e = document.getElementById('amt_bid_min');
            e.classList.add('error');
        }
    }
});
