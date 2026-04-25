// CSP-safe UI helpers. No frameworks; runs once at DOMContentLoaded.
(function () {
  "use strict";

  document.addEventListener("DOMContentLoaded", function () {
    // Confirm dialog on destructive forms (data-confirm="message").
    var forms = document.querySelectorAll("form[data-confirm]");
    for (var i = 0; i < forms.length; i++) {
      forms[i].addEventListener("submit", function (ev) {
        var msg = this.getAttribute("data-confirm") || "Are you sure?";
        if (!window.confirm(msg)) {
          ev.preventDefault();
        }
      });
    }
  });
})();
