"""
Central configuration for the SOC Assistant backend.
All values can be overridden via environment variables (see .env.example).
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    DEBUG = os.environ.get("FLASK_DEBUG", "1") == "1"
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))

    DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "data" / "soc_assistant.db"))

    WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "")
    WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "")
    WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
    WAZUH_VERIFY_SSL = os.environ.get("WAZUH_VERIFY_SSL", "0") == "1"

    LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "none")
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    SIGMA_RULES_DIR = os.environ.get(
        "SIGMA_RULES_DIR", str(BASE_DIR / "data" / "sigma_rules")
    )
    MITRE_DATA_PATH = os.environ.get(
        "MITRE_DATA_PATH", str(BASE_DIR / "data" / "mitre_attack.json")
    )


config = Config()
