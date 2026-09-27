"""
LLM-powered alert analysis service (anthropic | openai | rule-based fallback).
"""
import json
import re

from config import config
from utils.logger import get_logger

logger = get_logger("llm_service")

SYSTEM_PROMPT = """You are a senior SOC (Security Operations Center) analyst assistant.
You are given a security alert, any matched Sigma detection rules, and mapped MITRE
ATT&CK techniques. Produce a JSON object ONLY (no markdown, no prose outside JSON) with
these exact keys:
{
  "severity_score": <integer 0-100>,
  "verdict": "<one of: likely_malicious, suspicious, benign, needs_review>",
  "summary": "<2-4 sentence analyst-style summary of what happened and why it matters>",
  "recommended_actions": ["<action 1>", "<action 2>", "..."]
}
Base your severity score on: rule level, number/criticality of Sigma matches, MITRE
tactic severity (Credential Access/Command and Control/Persistence are high),
and whether the pattern suggests confirmed compromise vs. reconnaissance/noise.
"""


def _build_user_prompt(alert: dict, sigma_matches: list, mitre_info: list) -> str:
    return json.dumps(
        {
            "alert": {
                "rule_description": alert.get("rule_description"),
                "level": alert.get("level"),
                "agent_name": alert.get("agent_name"),
                "agent_ip": alert.get("agent_ip"),
                "timestamp": alert.get("timestamp"),
                "raw_log": alert.get("raw_log"),
            },
            "sigma_matches": sigma_matches,
            "mitre_techniques": mitre_info,
        },
        default=str,
    )


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
        raise


def _call_anthropic(system: str, user: str) -> dict:
    import anthropic

    client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
    resp = client.messages.create(
        model=config.ANTHROPIC_MODEL,
        max_tokens=800,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = "".join(block.text for block in resp.content if block.type == "text")
    return _extract_json(text)


def _call_openai(system: str, user: str) -> dict:
    from openai import OpenAI

    client = OpenAI(api_key=config.OPENAI_API_KEY)
    resp = client.chat.completions.create(
        model=config.OPENAI_MODEL,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    text = resp.choices[0].message.content
    return _extract_json(text)


_TACTIC_WEIGHT = {
    "Credential Access": 30,
    "Command and Control": 28,
    "Persistence": 20,
    "Defense Evasion": 15,
    "Initial Access": 18,
    "Execution": 15,
}

_SIGMA_LEVEL_WEIGHT = {"critical": 35, "high": 25, "medium": 12, "low": 5}


def _rule_based_analysis(alert: dict, sigma_matches: list, mitre_info: list) -> dict:
    score = min(int(alert.get("level", 0)) * 3, 40)

    for m in sigma_matches:
        score += _SIGMA_LEVEL_WEIGHT.get(str(m.get("level", "")).lower(), 5)

    tactics = {t.get("tactic") for t in mitre_info}
    for tactic in tactics:
        score += _TACTIC_WEIGHT.get(tactic, 5)

    score = max(0, min(score, 100))

    if score >= 75:
        verdict = "likely_malicious"
    elif score >= 45:
        verdict = "suspicious"
    elif score >= 20:
        verdict = "needs_review"
    else:
        verdict = "benign"

    rule_names = ", ".join(m["title"] for m in sigma_matches) or "no Sigma rule matches"
    technique_names = ", ".join(f"{t['id']} ({t['name']})" for t in mitre_info) or "none mapped"

    summary = (
        f"Alert '{alert.get('rule_description', 'Unknown')}' from agent "
        f"{alert.get('agent_name', 'unknown')} triggered at severity level "
        f"{alert.get('level', 'N/A')}. Detection engine matched: {rule_names}. "
        f"Mapped ATT&CK techniques: {technique_names}. "
        f"Computed composite risk score is {score}/100, yielding a '{verdict}' verdict "
        f"based on rule severity, Sigma match criticality, and tactic weighting."
    )

    if score >= 75:
        actions = [
            "Isolate affected host from the network immediately",
            "Escalate to incident response team",
            "Collect forensic memory/disk image before remediation",
            "Reset credentials for any implicated accounts",
        ]
    elif score >= 45:
        actions = [
            "Assign to an analyst for manual triage within SLA",
            "Correlate with related alerts on the same host/user",
            "Review process/command-line ancestry for the event",
        ]
    elif score >= 20:
        actions = [
            "Monitor for recurrence",
            "Validate against known-good baseline activity",
        ]
    else:
        actions = ["No action required; log for trend analysis"]

    return {
        "severity_score": score,
        "verdict": verdict,
        "summary": summary,
        "recommended_actions": actions,
    }


def analyze_alert(alert: dict, sigma_matches: list, mitre_info: list) -> dict:
    provider = config.LLM_PROVIDER.lower()
    user_prompt = _build_user_prompt(alert, sigma_matches, mitre_info)

    try:
        if provider == "anthropic" and config.ANTHROPIC_API_KEY:
            result = _call_anthropic(SYSTEM_PROMPT, user_prompt)
            result["llm_provider"] = "anthropic"
            return _normalize(result)
        if provider == "openai" and config.OPENAI_API_KEY:
            result = _call_openai(SYSTEM_PROMPT, user_prompt)
            result["llm_provider"] = "openai"
            return _normalize(result)
    except Exception as exc:
        logger.error("LLM provider '%s' failed (%s); falling back to rule-based analyzer",
                      provider, exc)

    result = _rule_based_analysis(alert, sigma_matches, mitre_info)
    result["llm_provider"] = "rule_based"
    return _normalize(result)


def _normalize(result: dict) -> dict:
    result["severity_score"] = int(result.get("severity_score", 0))
    result["severity_score"] = max(0, min(result["severity_score"], 100))
    result.setdefault("verdict", "needs_review")
    result.setdefault("summary", "")
    result.setdefault("recommended_actions", [])
    return result
