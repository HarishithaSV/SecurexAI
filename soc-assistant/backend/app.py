"""
Flask application factory for SOC Assistant.
"""
from flask import Flask, send_from_directory
from flask_cors import CORS
import os

from config import config
from models.database import init_db
from routes.alerts import alerts_bp
from routes.analysis import analysis_bp
from routes.rules import rules_bp
from routes.dashboard import dashboard_bp
from utils.logger import get_logger

logger = get_logger("app")

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")


def create_app():
    app = Flask(__name__, static_folder=None)
    app.config.from_object(config)
    CORS(app)

    init_db()
    logger.info("Database initialized at %s", config.DB_PATH)

    app.register_blueprint(alerts_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(rules_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def serve_index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:path>")
    def serve_static(path):
        full_path = os.path.join(FRONTEND_DIR, path)
        if os.path.exists(full_path):
            return send_from_directory(FRONTEND_DIR, path)
        return send_from_directory(FRONTEND_DIR, "index.html")

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
