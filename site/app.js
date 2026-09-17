(() => {
  const root = document.documentElement;
  const button = document.getElementById("theme-toggle");
  const saved = localStorage.getItem("oss-timeline-preview-theme");
  const initial = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const apply = (theme) => {
    root.dataset.theme = theme;
    button.textContent = theme === "light" ? "☀" : "☾";
  };
  apply(initial);
  button.addEventListener("click", () => {
    const next = root.dataset.theme === "light" ? "dark" : "light";
    localStorage.setItem("oss-timeline-preview-theme", next);
    apply(next);
  });
})();
