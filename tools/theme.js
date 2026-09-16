(() => {
  "use strict";
  const key = "oss-security-timeline-theme";
  const button = document.getElementById("theme-toggle");
  if (!button) return;

  function apply(theme) {
    document.documentElement.dataset.theme = theme;
    button.textContent = theme === "light" ? "☀ 낮" : "☾ 밤";
    button.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
    window.dispatchEvent(new Event("themechange"));
  }

  let saved = "dark";
  try {
    saved = localStorage.getItem(key) || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  } catch (_error) {
    saved = "dark";
  }
  apply(saved === "light" ? "light" : "dark");

  button.addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    apply(next);
    try { localStorage.setItem(key, next); } catch (_error) { /* local-only preference */ }
  });
})();
