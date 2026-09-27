# SecurexA — AI-Powered SOC Assistant

An end-to-end Security Operations Center (SOC) assistant that ingests security
alerts (from a real **Wazuh** manager, or a built-in simulator), matches them
against **Sigma** detection rules, maps hits to **MITRE ATT&CK** techniques,
and produces an AI-generated (or deterministic rule-based) triage — severity
score, verdict, human-readable summary, and recommended response actions.
Everything is stored in **SQLite** and exposed through a **Flask** REST API,
with a modular vanilla-JS frontend dashboard.

```
┌─────────────┐     ┌───────────────┐     ┌───────────────┐     ┌─────────────┐
│   Wazuh /   │ --> │  Sigma Rule   │ --> │  MITRE ATT&CK │ --> │  LLM / Rule │
│  Simulator  │     │    Engine     │     │    Mapper     │     │   Triage    │
└─────────────┘     └───────────────┘     └───────────────┘     └──────┬──────┘
                                                                        │
                                                                        v
                                                                  ┌───────────┐
                                                                  │  SQLite   │
                                                                  └─────┬─────┘
                                                                        │
                                                            ┌───────────┴───────────┐
                                                            │   Flask REST API      │
                                                            └───────────┬───────────┘
                                                                        │
                                                            ┌───────────┴───────────┐
                                                            │  Modular JS Frontend  │
                                                            └───────────────────────┘
```

## Project structure

```
soc-assistant/
├── backend/                     Flask application (see backend/README.md)
│   ├── app.py                   App factory, blueprint registration, static serving
│   ├── run.py                   Dev entrypoint (loads .env, seeds demo alerts, runs server)
│   ├── config.py                Central config (env-var driven)
│   ├── requirements.txt
│   ├── models/
│   │   └── database.py          SQLite schema + all queries (no ORM)
│   ├── services/
│   │   ├── wazuh_client.py      Live Wazuh API client + local alert simulator fallback
│   │   ├── sigma_engine.py      YAML Sigma rule loader + matching engine
│   │   ├── mitre_mapper.py      MITRE ATT&CK technique lookup/enrichment
│   │   ├── llm_service.py       Anthropic / OpenAI / rule-based triage engine
│   │   └── alert_processor.py   Orchestrates the full pipeline end-to-end
│   ├── routes/
│   │   ├── alerts.py            /api/alerts...
│   │   ├── analysis.py          /api/mitre..., /api/audit...
│   │   ├── rules.py             /api/rules...
│   │   └── dashboard.py         /api/dashboard...
│   ├── data/
│   │   ├── sigma_rules/         8 sample Sigma detection rules (.yml)
│   │   └── mitre_attack.json    Local MITRE ATT&CK technique subset
│   └── utils/logger.py
│
├── frontend/                     Static modular frontend (see frontend/README.md)
│   ├── index.html                Dashboard page
│   ├── pages/
│   │   ├── alerts.html           Alert list + detail modal
│   │   └── rules.html            Sigma rules + MITRE ATT&CK reference
│   ├── css/style.css
│   └── js/
│       ├── api.js                Fetch wrapper for the backend REST API
│       ├── ui.js                 Shared DOM/formatting helpers
│       ├── nav.js                Shared navigation bar + backend health check
│       ├── dashboard.js
│       ├── alerts.js
│       └── rules.js
│
├── .env.example                   Template for backend/.env
└── README.md                      This file
```

## Quick start (fastest path)

```bash
cd soc-assistant/backend
python3 -m venv venv && source venv/bin/activate      # optional but recommended
pip install -r requirements.txt
cp ../.env.example .env                                # optional, defaults work out of the box
python run.py --seed 15
```

Then open **http://localhost:5000** in your browser. The Flask app serves the
frontend directly, so no separate frontend server is required (though you can
run one — see `frontend/README.md`).

Full, detailed setup/run instructions (including live Wazuh + real LLM wiring)
are in:
- **backend/README.md** — backend setup, environment variables, API reference, Wazuh + LLM configuration
- **frontend/README.md** — frontend structure, how to run it standalone, how each page/module works

## Key design choices

- **Runs fully offline out of the box.** No Wazuh manager or LLM API key
  required — `WazuhClient` falls back to a realistic alert simulator, and
  `llm_service` falls back to a transparent, deterministic rule-based
  severity/verdict engine (`LLM_PROVIDER=none`, the default) when no LLM key
  is set/configured.
- **Modular, not a single file.** Backend is split into `models / services /
  routes / utils`; frontend is split into per-page HTML + per-concern JS
  modules + a shared stylesheet — nothing is a single monolithic script.
- **Real Sigma YAML rules.** Rules live as individual `.yml` files under
  `backend/data/sigma_rules/`, following the actual Sigma spec (title,
  logsource, detection blocks, condition, MITRE ATT&CK tags). Drop in more
  `.yml` files and click "Reload Rules from Disk" in the UI (or `POST
  /api/rules/reload`) — no code changes needed.
- **Swappable LLM provider.** `LLM_PROVIDER=anthropic|openai|none` in
  `.env`; the analysis interface returned to the rest of the app is identical
  regardless of provider.
- **Swappable Wazuh backend.** Set `WAZUH_API_URL` / `WAZUH_API_USER` /
  `WAZUH_API_PASSWORD` to point at a real Wazuh Manager REST API; leave blank
  to use the simulator.

## Typical workflow

1. Click **"Ingest New Alerts"** on the dashboard (or `POST /api/alerts/ingest`) —
   pulls alerts from Wazuh/simulator, runs them through Sigma matching, MITRE
   mapping, and AI/rule-based triage, and stores everything.
2. Go to **Alerts** — filter by status, click any row to see full detail:
   matched Sigma rules, mapped ATT&CK techniques, AI summary + severity score
   + recommended actions, raw log JSON, and status/workflow buttons.
3. Go to **Sigma Rules & MITRE ATT&CK** to see every loaded detection rule and
   the full local ATT&CK technique reference table.
4. Update alert status as you triage (`new → triaged → investigating →
   closed / false_positive`) — every change is written to the audit log
   (`GET /api/audit/<alert_id>`).
