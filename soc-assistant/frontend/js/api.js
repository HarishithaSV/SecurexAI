/**
 * api.js — thin fetch wrapper for the SOC Assistant backend REST API.
 * Kept isolated so the base URL / auth headers only need to change here.
 */
const API_BASE = window.location.origin.includes("5000")
  ? window.location.origin
  : "http://localhost:5000";

async function request(path, options = {}) {
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new Error(body.error || `Request failed: ${resp.status}`);
  }
  return resp.json();
}

const Api = {
  getDashboardStats: () => request("/api/dashboard/stats"),

  listAlerts: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/api/alerts${qs ? "?" + qs : ""}`);
  },
  getAlert: (id) => request(`/api/alerts/${id}`),
  setAlertStatus: (id, status) =>
    request(`/api/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),
  reanalyzeAlert: (id) =>
    request(`/api/alerts/${id}/reanalyze`, { method: "POST" }),
  ingestAlerts: (limit = 10) =>
    request("/api/alerts/ingest", {
      method: "POST",
      body: JSON.stringify({ limit }),
    }),

  listRules: () => request("/api/rules"),
  reloadRules: () => request("/api/rules/reload", { method: "POST" }),

  listMitreTechniques: () => request("/api/mitre/techniques"),
  getMitreTechnique: (id) => request(`/api/mitre/techniques/${id}`),

  getAuditLog: (alertId) => request(`/api/audit/${alertId}`),
};
