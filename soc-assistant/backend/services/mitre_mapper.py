"""
MITRE ATT&CK lookup/mapping service.
"""
import json
import os

from config import config
from utils.logger import get_logger

logger = get_logger("mitre_mapper")


class MitreMapper:
    def __init__(self, path: str = None):
        self.path = path or config.MITRE_DATA_PATH
        self.techniques = {}
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            logger.warning("MITRE data file not found at %s", self.path)
            self.techniques = {}
            return
        with open(self.path, "r", encoding="utf-8") as f:
            self.techniques = json.load(f)
        logger.info("Loaded %d MITRE ATT&CK techniques", len(self.techniques))

    def get(self, technique_id: str):
        return self.techniques.get(technique_id.upper())

    def enrich(self, technique_ids):
        enriched = []
        for tid in technique_ids:
            info = self.get(tid)
            if info:
                enriched.append({"id": tid.upper(), **info})
            else:
                enriched.append({"id": tid.upper(), "name": "Unknown technique",
                                  "tactic": "Unknown", "url": "", "description": ""})
        return enriched

    def all_techniques(self):
        return [{"id": tid, **info} for tid, info in self.techniques.items()]


mitre_mapper = MitreMapper()
