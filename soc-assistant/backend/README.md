# Backend — SecurexA SOC Assistant

Flask REST API implementing the full alert pipeline: Wazuh ingestion → Sigma
rule matching → MITRE ATT&CK mapping → LLM/rule-based triage → SQLite storage.

## 1. Requirements

- Python 3.10+
- pip

## 2. Installation

```bash
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 3. Configuration

Copy the example env file and edit as needed. **Nothing is required** — every
setting has a safe fallback so the app runs fully offline/standalone.

```bash
cp ../.env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `SECRET_KEY` | `dev-secret-change-me` | Flask secret key |
| `FLASK_DEBUG` | `1` | `1` for auto-reload dev server, `0` for production-like run |
| `HOST` / `PORT` | `0.0.0.0` / `5000` | Bind address |
| `DB_PATH` | `data/soc_assistant.db` | SQLite file path |
| `WAZUH_API_URL` | *(empty)* | Wazuh Manager API base URL, e.g. `https://manager:55000`. Leave empty to use the built-in simulator. |
| `WAZUH_API_USER` / `WAZUH_API_PASSWORD` | *(empty)* | Wazuh API credentials |
| `WAZUH_VERIFY_SSL` | `0` | Set `1` to verify the Wazuh manager's TLS cert |
| `LLM_PROVIDER` | `none` | `none` (rule-based fallback) \| `anthropic` \| `openai` |
| `ANTHROPIC_API_KEY` / `ANTHROPIC_MODEL` | *(empty)* / `claude-sonnet-4-6` | Used when `LLM_PROVIDER=anthropic` |
| `OPENAI_API_KEY` / `OPENAI_MODEL` | *(empty)* / `gpt-4o-mini` | Used when `LLM_PROVIDER=openai` |
| `SIGMA_RULES_DIR` | `data/sigma_rules` | Folder scanned for `.yml`/`.yaml` Sigma rules |
| `MITRE_DATA_PATH` | `data/mitre_attack.json` | Local MITRE ATT&CK technique dataset |

### Connecting a real Wazuh Manager

1. Set `WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD` in `.env`
   (Wazuh's REST API, documented at
   https://documentation.wazuh.com/current/user-manual/api/).
2. Restart the app. `WazuhClient` will authenticate and pull from
   `GET /alerts` on each ingest call.
3. If the live call fails for any reason (network, auth, etc.) the app
   automatically and transparently falls back to the simulator and logs the
   error — the pipeline never breaks.

### Connecting a real LLM

Set `LLM_PROVIDER=anthropic` (or `openai`) and the matching API key. The
`services/llm_service.py` module sends the alert + Sigma matches + MITRE
context as JSON and asks for a structured JSON verdict back. If the call
fails or no key is set, it transparently falls back to
`_rule_based_analysis()` — a fully deterministic, explainable scoring model
(rule level + Sigma match severity + MITRE tactic weighting) so the platform
always produces a usable triage result.

## 4. Running

```bash
python run.py                 # seeds 15 simulated alerts on startup, then serves
python run.py --seed 0        # skip seeding, start with an empty DB
python run.py --seed 50       # seed a larger demo dataset
```

The server starts at **http://localhost:5000** and also serves the frontend
(`../frontend`) directly, so visiting that URL in a browser gives you the
full dashboard immediately.

Alternatively, without the seeding convenience wrapper:

```bash
python app.py
```

### Running with a production WSGI server

The Flask dev server (used above) is fine for local/demo use. For anything
resembling production:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
```

## 5. Database

SQLite, zero external dependencies, schema auto-created on first run
(`models/database.py::init_db`, called from `create_app()`). Tables:

- **alerts** — one row per ingested alert (source id, rule info, agent,
  level, raw JSON log, status, timestamps)
- **sigma_matches** — one row per Sigma rule that matched a given alert
  (rule id/title/level, matched MITRE technique IDs, matched field values)
- **analyses** — one row per triage run for an alert (severity score,
  verdict, summary, recommended actions, which LLM provider produced it) —
  new rows are added on re-analysis so history is preserved; the API always
  returns the latest
- **audit_log** — every ingestion, analysis, status change, and reanalysis
  event, with timestamps, for traceability

To fully reset: stop the server and delete the file at `DB_PATH`
(`data/soc_assistant.db` by default) — it will be recreated empty on next
start.

## 6. Sigma rules

Real Sigma-spec YAML files live in `data/sigma_rules/`. Eight sample rules
ship with the project covering: PowerShell encoded command execution,
LSASS/Mimikatz credential dumping, suspicious scheduled tasks, new local
admin accounts, C2 outbound connections, web directory traversal, brute
force + success, and system binary modification.

The engine (`services/sigma_engine.py`) supports the common subset of the
Sigma grammar: field equality, `|contains` / `|startswith` / `|endswith`
modifiers, list values (OR), multiple named detection blocks combined with
`and` / `and not` / `all of` / `1 of` conditions, and `attack.tXXXX[.YYY]`
tags for automatic MITRE ATT&CK technique extraction.

**To add your own rule:** drop a new `.yml` file into `data/sigma_rules/`
following the same structure, then either restart the server or call
`POST /api/rules/reload` (also available as a button in the UI).

## 7. API Reference

All responses are JSON. Base URL: `http://localhost:5000`.

### Dashboard
| Method | Path | Description |
|---|---|---|
| GET | `/api/dashboard/health` | Liveness check |
| GET | `/api/dashboard/stats` | Totals, breakdowns by level/status/verdict, 10 most recent alerts |

### Alerts
| Method | Path | Description |
|---|---|---|
| GET | `/api/alerts?status=&limit=&offset=` | List alerts (each includes latest analysis + Sigma match count) |
| GET | `/api/alerts/<id>` | Full alert detail: raw log, Sigma matches, latest analysis |
| POST | `/api/alerts/<id>/status` | Body `{"status": "new\|triaged\|investigating\|closed\|false_positive"}` |
| POST | `/api/alerts/<id>/reanalyze` | Re-runs Sigma + MITRE + LLM triage for an existing alert |
| POST | `/api/alerts/ingest` | Body `{"limit": 10}` — pulls from Wazuh/simulator and processes new alerts through the full pipeline |

### Sigma rules
| Method | Path | Description |
|---|---|---|
| GET | `/api/rules` | List all currently loaded Sigma rules |
| POST | `/api/rules/reload` | Re-scan `SIGMA_RULES_DIR` from disk |

### MITRE ATT&CK
| Method | Path | Description |
|---|---|---|
| GET | `/api/mitre/techniques` | List the full local ATT&CK technique reference |
| GET | `/api/mitre/techniques/<id>` | e.g. `/api/mitre/techniques/T1059.001` |

### Audit
| Method | Path | Description |
|---|---|---|
| GET | `/api/audit/<alert_id>` | Full chronological audit trail for one alert |

### Example: manually ingest 5 alerts and inspect one

```bash
curl -X POST http://localhost:5000/api/alerts/ingest -H "Content-Type: application/json" -d '{"limit":5}'
curl http://localhost:5000/api/alerts/1
```

## 8. Extending

- **More Sigma rules:** add `.yml` files to `data/sigma_rules/` (real
  community Sigma rules from https://github.com/SigmaHQ/sigma will mostly
  work as long as they use the supported condition/modifier subset above).
- **Fuller MITRE ATT&CK coverage:** replace `data/mitre_attack.json` with a
  larger extracted subset of the official ATT&CK STIX bundle (id → name /
  tactic / url / description), or point `MITRE_DATA_PATH` at your own file.
- **New alert sources:** implement a new client alongside
  `services/wazuh_client.py` with a `fetch_recent_alerts(limit)` method
  returning the same normalized alert dict shape, and swap it into
  `services/alert_processor.py`.
