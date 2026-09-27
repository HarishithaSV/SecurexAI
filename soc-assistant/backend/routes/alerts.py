from flask import Blueprint, request, jsonify

from models import database as db
from services.alert_processor import ingest_and_process_batch, reanalyze_alert

alerts_bp = Blueprint("alerts", __name__, url_prefix="/api/alerts")


@alerts_bp.get("")
def list_alerts():
    status = request.args.get("status")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))
    alerts = db.list_alerts(status=status, limit=limit, offset=offset)
    for a in alerts:
        analysis = db.get_latest_analysis(a["id"])
        a["analysis"] = analysis
        a["sigma_match_count"] = len(db.get_sigma_matches(a["id"]))
    return jsonify({"alerts": alerts, "count": len(alerts)})


@alerts_bp.get("/<int:alert_id>")
def get_alert(alert_id):
    alert = db.get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    alert["sigma_matches"] = db.get_sigma_matches(alert_id)
    alert["analysis"] = db.get_latest_analysis(alert_id)
    return jsonify(alert)


@alerts_bp.post("/<int:alert_id>/status")
def set_status(alert_id):
    body = request.get_json(force=True) or {}
    status = body.get("status")
    valid = {"new", "triaged", "investigating", "closed", "false_positive"}
    if status not in valid:
        return jsonify({"error": f"status must be one of {sorted(valid)}"}), 400
    if not db.get_alert(alert_id):
        return jsonify({"error": "Alert not found"}), 404
    db.update_alert_status(alert_id, status)
    db.log_action(alert_id, "status_change", f"new_status={status}", actor="analyst")
    return jsonify({"ok": True, "alert_id": alert_id, "status": status})


@alerts_bp.post("/<int:alert_id>/reanalyze")
def reanalyze(alert_id):
    try:
        result = reanalyze_alert(alert_id)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 404
    return jsonify(result)


@alerts_bp.post("/ingest")
def ingest():
    body = request.get_json(silent=True) or {}
    limit = int(body.get("limit", 10))
    results = ingest_and_process_batch(limit=limit)
    return jsonify({"processed": len(results), "results": results})
