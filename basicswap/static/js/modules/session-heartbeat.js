(function () {
  var timeoutMin = window.BSX_SESSION_TIMEOUT_MIN || 15;
  var throttleMs = Math.max(10000, Math.floor((timeoutMin * 60 * 1000) / 3));
  var lastSent = 0;

  function sendHeartbeat() {
    lastSent = Date.now();
    fetch("/json/heartbeat", {
      method: "POST",
      credentials: "same-origin",
      keepalive: true,
    })
      .then(function (r) {
        if (r.status === 401) {
          document.cookie =
            "basicswap_login_next=" +
            encodeURIComponent(
              window.location.pathname + window.location.search
            ) +
            "; path=/; samesite=lax";
          window.location.href = "/login";
        }
      })
      .catch(function () {});
  }

  function onActivity() {
    if (document.hidden) {
      return;
    }
    if (Date.now() - lastSent >= throttleMs) {
      sendHeartbeat();
    }
  }

  var events = ["mousedown", "keydown", "touchstart", "scroll", "wheel"];
  events.forEach(function (ev) {
    window.addEventListener(ev, onActivity, { passive: true, capture: true });
  });
})();
