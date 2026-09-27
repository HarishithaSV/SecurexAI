from flask import Blueprint, jsonify

from models import database as db
from services.mitre_mapper import mitre_mapper

analysis_bp = Blueprint("analysis", __name__, url_prefix="/api")


@analysis_bp.get("/mitre/techniques")
def list_mitre_techniques():
    return jsonify({"techniques": mitre_mapper.all_techniques()})


@analysis_bp.get("/mitre/techniques/<technique_id>")
def get_mitre_technique(technique_id):
    info = mitre_mapper.get(technique_id)
    if not info:
        return jsonify({"error": "Technique not found"}), 404
    return jsonify({"id": technique_id.upper(), **info})


@analysis_bp.get("/audit/<int:alert_id>")
def get_audit_log(alert_id):
    with db.get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE alert_id = ? ORDER BY created_at ASC",
            (alert_id,),
        ).fetchall()
    return jsonify({"audit_log": [dict(r) for r in rows]})
