/**
 * rules.js — lists loaded Sigma detection rules and the MITRE ATT&CK
 * technique reference table, for pages/rules.html
 */
async function loadRules() {
  try {
    const { rules } = await Api.listRules();
    renderRules(rules);
  } catch (err) {
    UI.toast(`Failed to load rules: ${err.message}`, true);
  }
}

function renderRules(rules) {
  const container = document.getElementById("rules-list");
  container.innerHTML = "";
  if (rules.length === 0) {
    container.innerHTML = `<p class="muted">No Sigma rules loaded. Add .yml files to backend/data/sigma_rules/</p>`;
    return;
  }
  rules.forEach((r) => {
    const card = UI.el("div", "rule-card");
    card.innerHTML = `
      <div class="rule-card-header">
        <strong>${r.title}</strong>
        <span class="badge badge-${r.level}">${r.level}</span>
      </div>
      <p class="muted">${r.description}</p>
      <div class="rule-meta">
        <span>ID: ${r.id}</span>
        <span>Category: ${r.logsource?.category || "n/a"}</span>
      </div>
      ${r.mitre_techniques.length ? `<div class="mitre-tags">${r.mitre_techniques.map((t) => `<span class="tag">${t}</span>`).join("")}</div>` : ""}
    `;
    container.appendChild(card);
  });
}

async function loadMitre() {
  try {
    const { techniques } = await Api.listMitreTechniques();
    renderMitre(techniques);
  } catch (err) {
    UI.toast(`Failed to load MITRE data: ${err.message}`, true);
  }
}

function renderMitre(techniques) {
  const tbody = document.getElementById("mitre-body");
  tbody.innerHTML = "";
  techniques.forEach((t) => {
    const tr = UI.el("tr");
    tr.innerHTML = `
      <td><a href="${t.url}" target="_blank" rel="noopener">${t.id}</a></td>
      <td>${t.name}</td>
      <td><span class="tag">${t.tactic}</span></td>
      <td class="muted">${t.description}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function handleReloadRules() {
  const btn = document.getElementById("reload-rules-btn");
  btn.disabled = true;
  btn.textContent = "Reloading...";
  try {
    const result = await Api.reloadRules();
    UI.toast(`Reloaded ${result.count} Sigma rules`);
    await loadRules();
  } catch (err) {
    UI.toast(`Reload failed: ${err.message}`, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Reload Rules from Disk";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  renderNav("rules");
  loadRules();
  loadMitre();
  document.getElementById("reload-rules-btn").addEventListener("click", handleReloadRules);
});
