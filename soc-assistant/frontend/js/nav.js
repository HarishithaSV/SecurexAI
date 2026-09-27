/**
 * nav.js — renders the shared top navigation bar into any element with
 * id="app-nav", and highlights the active page.
 */
function renderNav(activePage) {
  const nav = document.getElementById("app-nav");
  if (!nav) return;

  const links = [
    { href: "/index.html", label: "Dashboard", key: "dashboard" },
    { href: "/pages/alerts.html", label: "Alerts", key: "alerts" },
    { href: "/pages/rules.html", label: "Sigma Rules & MITRE", key: "rules" },
  ];

  nav.innerHTML = `
    <div class="nav-brand">
      <span class="nav-logo">&#128737;</span>
      <span>SecurexA <small>SOC Assistant</small></span>
    </div>
    <div class="nav-links">
      ${links
        .map(
          (l) => `<a href="${l.href}" class="${l.key === activePage ? "active" : ""}">${l.label}</a>`
        )
        .join("")}
    </div>
    <div class="nav-status" id="nav-status">
      <span class="status-dot" id="status-dot"></span>
      <span id="status-text">Checking backend...</span>
    </div>
  `;

  fetch(`${window.location.origin.includes("5000") ? window.location.origin : "http://localhost:5000"}/api/dashboard/health`)
    .then((r) => (r.ok ? r.json() : Promise.reject()))
    .then(() => {
      document.getElementById("status-dot").classList.add("status-ok");
      document.getElementById("status-text").textContent = "Backend online";
    })
    .catch(() => {
      document.getElementById("status-dot").classList.add("status-down");
      document.getElementById("status-text").textContent = "Backend offline";
    });
}
