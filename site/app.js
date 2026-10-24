(() => {
  const toggle = document.querySelector(".menuToggle");
  const menu = document.querySelector(".menuPanel");
  const glyph = toggle?.querySelector("span");

  function setMenu(open) {
    if (!toggle || !menu || !glyph) return;
    menu.classList.toggle("menuPanelOpen", open);
    menu.setAttribute("aria-hidden", String(!open));
    toggle.setAttribute("aria-expanded", String(open));
    toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
    glyph.textContent = open ? "×" : "☰";
    document.body.classList.toggle("menu-is-open", open);
  }

  toggle?.addEventListener("click", () => setMenu(toggle.getAttribute("aria-expanded") !== "true"));
  menu?.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => setMenu(false)));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setMenu(false);
  });

  const raw = typeof window.CHRONTINAL_APP_URL === "string" ? window.CHRONTINAL_APP_URL.trim() : "";
  if (!raw) return;

  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) return;
    const base = url.href.replace(/\/$/, "");
    document.querySelectorAll("[data-app-path]").forEach((link) => {
      link.href = base + link.dataset.appPath;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
    });
    const note = document.getElementById("connection-note");
    if (note) note.textContent = "The interactive SOC opens in a separate tab.";
  } catch {
    // Keep the explanatory in-page destination when the URL is not valid.
  }
})();
