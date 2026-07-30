/* DevShield — bascule mode clair / sombre
   Placer ce script juste après <head> si possible (avant le rendu du CSS)
   pour éviter un flash de mauvais thème au chargement. */
(function () {
  var saved = localStorage.getItem("devshield-theme");
  var theme = saved || "light";
  document.documentElement.setAttribute("data-theme", theme);

  window.addEventListener("DOMContentLoaded", function () {
    var toggle = document.getElementById("theme-toggle");
    if (!toggle) return;

    function paint() {
      var current = document.documentElement.getAttribute("data-theme");
      toggle.querySelectorAll("[data-theme-option]").forEach(function (btn) {
        btn.classList.toggle("is-active", btn.getAttribute("data-theme-option") === current);
      });
    }
    paint();

    toggle.querySelectorAll("[data-theme-option]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var choice = btn.getAttribute("data-theme-option");
        document.documentElement.setAttribute("data-theme", choice);
        localStorage.setItem("devshield-theme", choice);
        paint();
      });
    });
  });
})();