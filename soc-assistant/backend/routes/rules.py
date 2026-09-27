from flask import Blueprint, jsonify

from services.sigma_engine import sigma_engine

rules_bp = Blueprint("rules", __name__, url_prefix="/api/rules")


@rules_bp.get("")
def list_rules():
    return jsonify({"rules": sigma_engine.list_rules()})


@rules_bp.post("/reload")
def reload_rules():
    sigma_engine.load_rules()
    return jsonify({"ok": True, "count": len(sigma_engine.rules)})
