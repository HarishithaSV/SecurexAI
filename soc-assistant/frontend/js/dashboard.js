/**
 * dashboard.js — populates the dashboard page: KPI cards, breakdown charts
 * (simple CSS bar charts, no external chart library needed), and recent
 * alerts table.
 */
async function loadDashboard() {
  try {
    const stats = await Api.getDashboardStats();
    renderKpis(stats);
    renderBreakdown("level-breakdown", stats.by_level, (k) => `Level ${k}`);
    renderBreakdown("verdict-breakdown", stats.by_verdict, UI.verdictLabel);
    renderBreakdown("status-breakdown", stats.by_status, (k) => k.replace(/_/g, " "));
    renderRecentAlerts(stats.recent_alerts);
  } catch (err) {
    UI.toast(`Failed to load dashboard: ${err.message}`, true);
  }
}

function renderKpis(stats) {
  const total = stats.total_alerts || 0;
  const malicious = stats.by_verdict?.likely_malicious || 0;
  const suspicious = stats.by_verdict?.suspicious || 0;
  const open = (stats.by_status?.new || 0) + (stats.by_status?.triaged || 0) + (stats.by_status?.investigating || 0);

  document.getElementById("kpi-total").textContent = total;
  document.getElementById("kpi-malicious").textContent = malicious;
  document.getElementById("kpi-suspicious").textContent = suspicious;
  document.getElementById("kpi-open").textContent = open;
}

function renderBreakdown(containerId, data, labelFn) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";
  const entries = Object.entries(data || {});
  if (entries.length === 0) {
    container.appendChild(UI.el("p", "muted", "No data yet"));
    return;
  }
  const max = Math.max(...entries.map(([, v]) => v));
  entries
    .sort((a, b) => b[1] - a[1])
    .forEach(([key, value]) => {
      const row = UI.el("div", "bar-row");
      const label = UI.el("span", "bar-label", labelFn(key));
      const track = UI.el("div", "bar-track");
      const fill = UI.el("div", "bar-fill");
      fill.style.width = `${(value / max) * 100}%`;
      const count = UI.el("span", "bar-count", String(value));
      track.appendChild(fill);
      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(count);
      container.appendChild(row);
    });
}

function renderRecentAlerts(alerts) {
  const tbody = document.getElementById("recent-alerts-body");
  tbody.innerHTML = "";
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No alerts yet. Click "Ingest New Alerts" to pull from Wazuh/simulator.</td></tr>`;
    return;
  }
  alerts.forEach((a) => {
    const tr = UI.el("tr");
    tr.innerHTML = `
      <td>#${a.id}</td>
      <td>${a.rule_description}</td>
      <td>${a.agent_name}</td>
      <td><span class="${UI.levelBadgeClass(a.level)}">${a.level}</span></td>
      <td>${a.status.replace(/_/g, " ")}</td>
      <td>${UI.fmtTime(a.created_at)}</td>
    `;
    tr.addEventListener("click", () => {
      window.location.href = `/pages/alerts.html?id=${a.id}`;
    });
    tr.style.cursor = "pointer";
    tbody.appendChild(tr);
  });
}

async function handleIngest() {
  const btn = document.getElementById("ingest-btn");
  btn.disabled = true;
  btn.textContent = "Ingesting...";
  try {
    const result = await Api.ingestAlerts(10);
    UI.toast(`Ingested and triaged ${result.processed} new alert(s)`);
    await loadDashboard();
  } catch (err) {
    UI.toast(`Ingest failed: ${err.message}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Ingest New Alerts";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  renderNav("dashboard");
  loadDashboard();
  document.getElementById("ingest-btn").addEventListener("click", handleIngest);
  document.getElementById("refresh-btn").addEventListener("click", loadDashboard);
});
