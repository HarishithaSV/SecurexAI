# Frontend — SecurexA SOC Assistant

A modular, dependency-free (no build step, no npm) vanilla HTML/CSS/JS
frontend for the SOC Assistant backend. Split into one HTML file per page and
one JS file per concern — nothing is a single monolithic script.

## Structure

```
frontend/
├── index.html              Dashboard page (KPIs, breakdowns, recent alerts)
├── pages/
│   ├── alerts.html          Alert list, filters, detail modal
│   └── rules.html           Loaded Sigma rules + MITRE ATT&CK reference table
├── css/
│   └── style.css            Single shared stylesheet (dark SOC-style theme)
└── js/
    ├── api.js                Fetch wrapper — the ONLY file that knows API URLs/paths
    ├── ui.js                 Shared helpers: badges, toasts, date formatting, DOM shortcuts
    ├── nav.js                Renders the shared top navbar + live backend health indicator
    ├── dashboard.js          Logic for index.html
    ├── alerts.js             Logic for pages/alerts.html
    └── rules.js              Logic for pages/rules.html
```

Each page loads scripts in this fixed order: `api.js` → `ui.js` → `nav.js` →
its own page script (e.g. `dashboard.js`). This keeps every module
independent and easy to reason about — `api.js` never touches the DOM,
`ui.js` never calls the network, and each page script only orchestrates the
two.

## How it talks to the backend

`js/api.js` auto-detects the API base URL: if the page itself is being
served from a port containing `5000` (i.e. served directly by the Flask app),
it uses `window.location.origin`; otherwise it defaults to
`http://localhost:5000`. This means the frontend works both:

1. **Served by Flask directly** (simplest — see backend/README.md, this is
   the default when you run `python run.py`), or
2. **Served standalone** by any static file server, pointed at a backend
   running elsewhere (see below).

If your backend runs on a different host/port, edit the `API_BASE` constant
at the top of `frontend/js/api.js`.

## Running the frontend standalone (optional)

You don't need this if you're using `python run.py` in the backend — it
already serves these files at `http://localhost:5000`. But if you want to
serve the frontend independently (e.g. from Nginx, or while developing UI
only):

```bash
cd frontend
python3 -m http.server 8080
```

Then open **http://localhost:8080**. Make sure the backend (`cd ../backend &&
python run.py`) is running on port 5000, and that `flask-cors` (already in
`requirements.txt`) is enabled — it is, by default, in `app.py` via
`CORS(app)`.

## Page-by-page guide

### `index.html` (Dashboard)
- 4 KPI cards: total alerts, likely-malicious count, suspicious count, open/unresolved count
- 3 CSS-bar breakdowns: by rule level, by AI verdict, by status
- Recent alerts table (click a row to jump into that alert's detail view)
- **"Ingest New Alerts"** button → `POST /api/alerts/ingest` → refreshes everything
- **"Refresh"** button → re-pulls `/api/dashboard/stats` without ingesting

### `pages/alerts.html` (Alerts)
- Status filter dropdown (`new / triaged / investigating / closed / false_positive`)
- Full alerts table with live Sigma-match-count and AI verdict/score columns
- Clicking a row (or visiting `alerts.html?id=<N>`) opens a detail modal showing:
  - Alert metadata (agent, level, timestamp, rule id)
  - AI/rule-based triage: verdict badge, severity score, summary, recommended actions, which engine produced it
  - All matched Sigma rules with their MITRE ATT&CK tags
  - Full raw log JSON (pretty-printed)
  - Status-change buttons and a "Re-run Analysis" button

### `pages/rules.html` (Sigma Rules & MITRE ATT&CK)
- Card list of every currently loaded Sigma rule (title, description, level,
  logsource category, MITRE tags)
- **"Reload Rules from Disk"** button → `POST /api/rules/reload` — use this
  after adding/editing `.yml` files in `backend/data/sigma_rules/` without
  restarting the whole server
- Full MITRE ATT&CK technique reference table (id links out to
  attack.mitre.org, name, tactic, description)

## Styling

`css/style.css` is a single shared dark-theme stylesheet using CSS custom
properties (`:root` variables) for colors, so re-theming (e.g. light mode, a
different accent color) only requires editing the variables at the top of
the file. No CSS framework/build step is used.

## Extending

- **Add a new page:** create `pages/<name>.html` following the pattern in
  `pages/alerts.html` (same `<link>`/`<script>` includes), add its own
  `js/<name>.js`, and add an entry to the `links` array in `js/nav.js`.
- **Add a new API call:** add a method to the `Api` object in `js/api.js` —
  every page script already has access to `Api.*` once the script tag is
  included.
