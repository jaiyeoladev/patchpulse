// Progressive enhancement only — every page works without JavaScript.
(function () {
  "use strict";

  // Select-all checkbox for bulk actions.
  document.querySelectorAll("[data-select-all]").forEach(function (box) {
    box.addEventListener("change", function () {
      var table = box.closest("table");
      if (!table) return;
      table.querySelectorAll('input[name="ids"]').forEach(function (cb) { cb.checked = box.checked; });
    });
  });

  // Show only the inputs relevant to the chosen bulk action.
  document.querySelectorAll("[data-bulk-action]").forEach(function (select) {
    var form = select.form;
    function sync() {
      form.querySelectorAll("[data-bulk-field]").forEach(function (el) {
        el.hidden = el.getAttribute("data-bulk-field") !== select.value;
      });
    }
    select.addEventListener("change", sync);
    sync();
  });

  // Confirmation prompts for destructive buttons.
  document.querySelectorAll("[data-confirm]").forEach(function (el) {
    el.addEventListener("click", function (e) {
      if (!window.confirm(el.getAttribute("data-confirm"))) e.preventDefault();
    });
  });

  // Print button on the report page.
  document.querySelectorAll("[data-print]").forEach(function (el) {
    el.addEventListener("click", function () { window.print(); });
  });

  // Close the "More" menu when clicking elsewhere.
  document.addEventListener("click", function (e) {
    document.querySelectorAll("details.menu[open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });
  });
})();
