"""
Lightweight Sigma rule engine (practical subset of the Sigma spec).
"""
import os
import glob
import yaml

from config import config
from utils.logger import get_logger

logger = get_logger("sigma_engine")


class SigmaRule:
    def __init__(self, raw: dict, path: str):
        self.path = path
        self.id = raw.get("id", os.path.basename(path))
        self.title = raw.get("title", "Untitled rule")
        self.description = raw.get("description", "")
        self.level = raw.get("level", "medium")
        self.logsource = raw.get("logsource", {})
        self.detection = raw.get("detection", {})
        self.tags = raw.get("tags", [])
        self.mitre_techniques = [
            t[len("attack."):].upper()
            for t in self.tags
            if t.lower().startswith("attack.t") and t[7].lower() == "t"
        ]

    def matches(self, event_fields: dict):
        condition = self.detection.get("condition", "selection")
        block_results = {}
        matched_fields_total = {}

        for block_name, block_def in self.detection.items():
            if block_name == "condition":
                continue
            ok, matched = self._eval_block(block_def, event_fields)
            block_results[block_name] = ok
            if ok:
                matched_fields_total.update(matched)

        try:
            result = self._eval_condition(condition, block_results)
        except Exception as exc:
            logger.warning("Failed evaluating condition '%s' for rule %s: %s",
                            condition, self.id, exc)
            result = False

        return result, matched_fields_total

    @staticmethod
    def _eval_block(block_def, event_fields: dict):
        matched = {}
        if isinstance(block_def, list):
            for sub in block_def:
                ok, m = SigmaRule._eval_block(sub, event_fields)
                if ok:
                    return True, m
            return False, {}

        for raw_field, expected in block_def.items():
            field, _, modifier = raw_field.partition("|")
            actual = event_fields.get(field)
            if actual is None:
                return False, {}
            actual_str = str(actual).lower()

            values = expected if isinstance(expected, list) else [expected]
            values = [str(v).lower() for v in values]

            if modifier == "contains":
                ok = any(v in actual_str for v in values)
            elif modifier == "startswith":
                ok = any(actual_str.startswith(v) for v in values)
            elif modifier == "endswith":
                ok = any(actual_str.endswith(v) for v in values)
            else:
                ok = actual_str in values

            if not ok:
                return False, {}
            matched[field] = actual

        return True, matched

    @staticmethod
    def _eval_condition(condition: str, block_results: dict) -> bool:
        cond = condition.strip()

        if cond.startswith("all of ") or cond.startswith("1 of "):
            prefix = cond.split(" of ")[1].replace("*", "")
            relevant = [v for k, v in block_results.items() if k.startswith(prefix)]
            if cond.startswith("all of "):
                return all(relevant) if relevant else False
            return any(relevant) if relevant else False

        expr = cond
        for name in sorted(block_results.keys(), key=len, reverse=True):
            expr = expr.replace(name, f"block_results['{name}']")
        try:
            return bool(eval(expr, {"__builtins__": {}}, {"block_results": block_results}))
        except Exception:
            return any(block_results.values())


class SigmaEngine:
    def __init__(self, rules_dir: str = None):
        self.rules_dir = rules_dir or config.SIGMA_RULES_DIR
        self.rules = []
        self.load_rules()

    def load_rules(self):
        self.rules = []
        pattern = os.path.join(self.rules_dir, "*.yml")
        for path in glob.glob(pattern) + glob.glob(pattern.replace(".yml", ".yaml")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw = yaml.safe_load(f)
                self.rules.append(SigmaRule(raw, path))
            except Exception as exc:
                logger.error("Failed to load sigma rule %s: %s", path, exc)
        logger.info("Loaded %d Sigma rules from %s", len(self.rules), self.rules_dir)

    def evaluate(self, event_fields: dict):
        matches = []
        for rule in self.rules:
            ok, matched_fields = rule.matches(event_fields)
            if ok:
                matches.append(
                    {
                        "id": rule.id,
                        "title": rule.title,
                        "level": rule.level,
                        "mitre_techniques": rule.mitre_techniques,
                        "matched_fields": matched_fields,
                    }
                )
        return matches

    def list_rules(self):
        return [
            {
                "id": r.id,
                "title": r.title,
                "description": r.description,
                "level": r.level,
                "logsource": r.logsource,
                "mitre_techniques": r.mitre_techniques,
                "tags": r.tags,
            }
            for r in self.rules
        ]


sigma_engine = SigmaEngine()
