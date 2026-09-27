"""
Orchestrates the full alert pipeline: Wazuh -> Sigma -> MITRE -> LLM triage -> DB
"""
from models import database as db
from services.wazuh_client import wazuh_client
from services.sigma_engine import sigma_engine
from services.mitre_mapper import mitre_mapper
from services.llm_service import analyze_alert
from utils.logger import get_logger

logger = get_logger("alert_processor")


def _flatten_event_fields(alert: dict) -> dict:
    fields = {}
    raw = alert.get("raw_log", {}) or {}
    data = raw.get("data", {}) if isinstance(raw, dict) else {}
    fields.update(data)
    fields.setdefault("process_name", data.get("process_name", ""))
    return fields


def process_new_alert(alert: dict) -> dict:
    if alert.get("source_id") and db.alert_exists(alert["source_id"]):
        logger.info("Alert %s already processed, skipping", alert["source_id"])
        return None

    alert_id = db.insert_alert(alert)
    db.log_action(alert_id, "ingested", f"source_id={alert.get('source_id')}")

    event_fields = _flatten_event_fields(alert)
    sigma_matches = sigma_engine.evaluate(event_fields)
    for match in sigma_matches:
        db.insert_sigma_match(alert_id, match)

    all_technique_ids = sorted({t for m in sigma_matches for t in m["mitre_techniques"]})
    mitre_info = mitre_mapper.enrich(all_technique_ids)

    analysis = analyze_alert(alert, sigma_matches, mitre_info)
    analysis["mitre_techniques"] = all_technique_ids
    db.insert_analysis(alert_id, analysis)
    db.log_action(alert_id, "analyzed", f"verdict={analysis['verdict']} score={analysis['severity_score']}")

    db.update_alert_status(alert_id, "triaged")

    return {
        "alert_id": alert_id,
        "sigma_matches": sigma_matches,
        "mitre_techniques": mitre_info,
        "analysis": analysis,
    }


def ingest_and_process_batch(limit: int = 20) -> list:
    raw_alerts = wazuh_client.fetch_recent_alerts(limit=limit)
    results = []
    for alert in raw_alerts:
        result = process_new_alert(alert)
        if result:
            results.append(result)
    logger.info("Processed %d new alerts out of %d fetched", len(results), len(raw_alerts))
    return results


def reanalyze_alert(alert_id: int) -> dict:
    alert = db.get_alert(alert_id)
    if not alert:
        raise ValueError(f"Alert {alert_id} not found")

    event_fields = _flatten_event_fields(alert)
    sigma_matches = sigma_engine.evaluate(event_fields)

    all_technique_ids = sorted({t for m in sigma_matches for t in m["mitre_techniques"]})
    mitre_info = mitre_mapper.enrich(all_technique_ids)

    analysis = analyze_alert(alert, sigma_matches, mitre_info)
    analysis["mitre_techniques"] = all_technique_ids
    db.insert_analysis(alert_id, analysis)
    db.log_action(alert_id, "reanalyzed", f"verdict={analysis['verdict']} score={analysis['severity_score']}")

    return {
        "alert_id": alert_id,
        "sigma_matches": sigma_matches,
        "mitre_techniques": mitre_info,
        "analysis": analysis,
    }
