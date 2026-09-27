from flask import Blueprint, jsonify

from models import database as db

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


@dashboard_bp.get("/stats")
def stats():
    return jsonify(db.get_dashboard_stats())


@dashboard_bp.get("/health")
def health():
    return jsonify({"status": "ok"})
