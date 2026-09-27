/**
 * alerts.js — alerts list + detail view (Sigma matches, MITRE mapping,
 * AI/rule-based analysis, status changes, audit trail) for pages/alerts.html
 */
let currentAlerts = [];

async function loadAlertsList() {
  const statusFilter = document.getElementById("status-filter").value;
  const params = statusFilter ? { status: statusFilter } : {};
  try {
    const { alerts } = await Api.listAlerts(params);
    currentAlerts = alerts;
    renderAlertsTable(alerts);
  } catch (err) {
    UI.toast(`Failed to load alerts: ${err.message}`, true);
  }
}

function renderAlertsTable(alerts) {
  const tbody = document.getElementById("alerts-body");
  tbody.innerHTML = "";
  if (alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">No alerts match this filter.</td></tr>`;
    return;
  }
  alerts.forEach((a) => {
    const tr = UI.el("tr");
    const verdict = a.analysis?.verdict;
    const score = a.analysis?.severity_score;
    tr.innerHTML = `
      <td>#${a.id}</td>
      <td>${a.rule_description}</td>
      <td>${a.agent_name}</td>
      <td><span class="${UI.levelBadgeClass(a.level)}">${a.level}</span></td>
      <td>${a.sigma_match_count}</td>
      <td>${verdict ? `<span class="${UI.verdictBadgeClass(verdict)}">${UI.verdictLabel(verdict)} (${score})</span>` : '<span class="muted">pending</span>'}</td>
      <td>${a.status.replace(/_/g, " ")}</td>
    `;
    tr.style.cursor = "pointer";
    tr.addEventListener("click", () => openAlertDetail(a.id));
    tbody.appendChild(tr);
  });
}

async function openAlertDetail(id) {
  const modal = document.getElementById("alert-modal");
  modal.classList.add("open");
  modal.dataset.alertId = id;
  document.getElementById("modal-body").innerHTML = `<p class="muted">Loading...</p>`;

  try {
    const alert = await Api.getAlert(id);
    renderAlertDetail(alert);
  } catch (err) {
    document.getElementById("modal-body").innerHTML = `<p class="error">Failed to load: ${err.message}</p>`;
  }
}

function renderAlertDetail(alert) {
  const a = alert.analysis;
  const sigmaHtml = alert.sigma_matches.length
    ? alert.sigma_matches
        .map(
          (m) => `
        <div class="sigma-match">
          <div class="sigma-match-title">${m.sigma_title} <span class="badge">${m.sigma_level}</span></div>
          <div class="muted">Rule ID: ${m.sigma_rule_id}</div>
          ${m.mitre_techniques.length ? `<div class="mitre-tags">${m.mitre_techniques.map((t) => `<span class="tag">${t}</span>`).join("")}</div>` : ""}
        </div>`
        )
        .join("")
    : `<p class="muted">No Sigma rules matched this alert.</p>`;

  const analysisHtml = a
    ? `
      <div class="analysis-box">
        <div class="analysis-header">
          <span class="${UI.verdictBadgeClass(a.verdict)}">${UI.verdictLabel(a.verdict)}</span>
          <span class="severity-score">Severity: ${a.severity_score}/100</span>
          <span class="muted">via ${a.llm_provider}</span>
        </div>
        <p>${a.summary}</p>
        <strong>Recommended actions:</strong>
        <ul>${a.recommended_actions.map((act) => `<li>${act}</li>`).join("")}</ul>
      </div>`
    : `<p class="muted">Not yet analyzed.</p>`;

  document.getElementById("modal-body").innerHTML = `
    <h2>#${alert.id} — ${alert.rule_description}</h2>
    <div class="detail-grid">
      <div><strong>Agent:</strong> ${alert.agent_name} (${alert.agent_ip})</div>
      <div><strong>Level:</strong> <span class="${UI.levelBadgeClass(alert.level)}">${alert.level}</span></div>
      <div><strong>Timestamp:</strong> ${UI.fmtTime(alert.timestamp)}</div>
      <div><strong>Rule ID:</strong> ${alert.rule_id}</div>
    </div>

    <h3>AI / Analytic Triage</h3>
    ${analysisHtml}

    <h3>Sigma Rule Matches</h3>
    ${sigmaHtml}

    <h3>Raw Log</h3>
    <pre class="raw-log">${JSON.stringify(JSON.parse(alert.raw_log), null, 2)}</pre>

    <h3>Update Status</h3>
    <div class="status-actions">
      ${["new", "triaged", "investigating", "closed", "false_positive"]
        .map(
          (s) =>
            `<button class="btn-small ${alert.status === s ? "btn-active" : ""}" data-status="${s}">${s.replace(/_/g, " ")}</button>`
        )
        .join("")}
      <button id="reanalyze-btn" class="btn-secondary">Re-run Analysis</button>
    </div>
  `;

  UI.qsa("[data-status]").forEach((btn) =>
    btn.addEventListener("click", () => changeStatus(alert.id, btn.dataset.status))
  );
  document.getElementById("reanalyze-btn").addEventListener("click", () => reanalyze(alert.id));
}

async function changeStatus(id, status) {
  try {
    await Api.setAlertStatus(id, status);
    UI.toast(`Status updated to ${status}`);
    await openAlertDetail(id);
    await loadAlertsList();
  } catch (err) {
    UI.toast(`Failed to update status: ${err.message}`, true);
  }
}

async function reanalyze(id) {
  UI.toast("Re-running analysis...");
  try {
    await Api.reanalyzeAlert(id);
    await openAlertDetail(id);
    await loadAlertsList();
    UI.toast("Analysis updated");
  } catch (err) {
    UI.toast(`Reanalysis failed: ${err.message}`, true);
  }
}

function closeModal() {
  document.getElementById("alert-modal").classList.remove("open");
}

document.addEventListener("DOMContentLoaded", () => {
  renderNav("alerts");
  loadAlertsList();
  document.getElementById("status-filter").addEventListener("change", loadAlertsList);
  document.getElementById("refresh-alerts-btn").addEventListener("click", loadAlertsList);
  document.getElementById("modal-close").addEventListener("click", closeModal);
  document.getElementById("alert-modal").addEventListener("click", (e) => {
    if (e.target.id === "alert-modal") closeModal();
  });

  const params = new URLSearchParams(window.location.search);
  const id = params.get("id");
  if (id) openAlertDetail(id);
});
