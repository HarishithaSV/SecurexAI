/**
 * ui.js — small shared DOM/formatting helpers used across pages.
 */
const UI = {
  el(tag, className, text) {
    const e = document.createElement(tag);
    if (className) e.className = className;
    if (text !== undefined) e.textContent = text;
    return e;
  },

  fmtTime(iso) {
    if (!iso) return "-";
    const d = new Date(iso);
    return d.toLocaleString();
  },

  levelBadgeClass(level) {
    const n = Number(level);
    if (n >= 12) return "badge badge-critical";
    if (n >= 9) return "badge badge-high";
    if (n >= 5) return "badge badge-medium";
    return "badge badge-low";
  },

  verdictBadgeClass(verdict) {
    switch (verdict) {
      case "likely_malicious":
        return "badge badge-critical";
      case "suspicious":
        return "badge badge-high";
      case "needs_review":
        return "badge badge-medium";
      case "benign":
        return "badge badge-low";
      default:
        return "badge";
    }
  },

  verdictLabel(verdict) {
    return (verdict || "pending").replace(/_/g, " ");
  },

  toast(message, isError = false) {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = UI.el("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }
    const toast = UI.el("div", `toast ${isError ? "toast-error" : "toast-success"}`, message);
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
  },

  qs(selector, root = document) {
    return root.querySelector(selector);
  },
  qsa(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
  },
};
