"""
Convenience entrypoint: loads .env, initializes DB, optionally seeds demo
alerts on first run, then starts the Flask dev server.

Usage:
    python run.py
    python run.py --seed 25
"""
import argparse
import os
import sys

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(__file__))

from app import create_app
from config import config
from services.alert_processor import ingest_and_process_batch
from utils.logger import get_logger

logger = get_logger("run")


def main():
    parser = argparse.ArgumentParser(description="Run SOC Assistant backend")
    parser.add_argument("--seed", type=int, default=15,
                         help="Number of alerts to ingest on startup (0 to skip)")
    args = parser.parse_args()

    app = create_app()

    if args.seed > 0:
        logger.info("Seeding %d alerts on startup...", args.seed)
        results = ingest_and_process_batch(limit=args.seed)
        logger.info("Seeded %d alerts.", len(results))

    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)


if __name__ == "__main__":
    main()
