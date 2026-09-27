"""
Wazuh integration layer with local simulator fallback.
"""
import random
import uuid
from datetime import datetime, timedelta

import requests

from config import config
from utils.logger import get_logger

logger = get_logger("wazuh_client")


class WazuhClient:
    def __init__(self):
        self.base_url = config.WAZUH_API_URL.rstrip("/") if config.WAZUH_API_URL else ""
        self.user = config.WAZUH_API_USER
        self.password = config.WAZUH_API_PASSWORD
        self.verify_ssl = config.WAZUH_VERIFY_SSL
        self._token = None
        self.live = bool(self.base_url and self.user and self.password)
        if self.live:
            logger.info("Wazuh client configured for live API at %s", self.base_url)
        else:
            logger.info("No Wazuh API configured -- using local alert simulator")

    def _authenticate(self):
        resp = requests.post(
            f"{self.base_url}/security/user/authenticate",
            auth=(self.user, self.password),
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]

    def _headers(self):
        if not self._token:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    def fetch_recent_alerts(self, limit: int = 20):
        if self.live:
            try:
                return self._fetch_live_alerts(limit)
            except Exception as exc:
                logger.error("Wazuh live fetch failed (%s); falling back to simulator", exc)
                return self._simulate_alerts(limit)
        return self._simulate_alerts(limit)

    def _fetch_live_alerts(self, limit):
        resp = requests.get(
            f"{self.base_url}/alerts",
            headers=self._headers(),
            params={"limit": limit, "sort": "-timestamp"},
            verify=self.verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()
        items = resp.json().get("data", {}).get("affected_items", [])
        return [self._normalize_wazuh_alert(a) for a in items]

    @staticmethod
    def _normalize_wazuh_alert(raw: dict) -> dict:
        rule = raw.get("rule", {})
        agent = raw.get("agent", {})
        return {
            "source_id": raw.get("id", str(uuid.uuid4())),
            "rule_id": str(rule.get("id", "")),
            "rule_description": rule.get("description", ""),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip", "unknown"),
            "level": rule.get("level", 0),
            "timestamp": raw.get("timestamp", datetime.utcnow().isoformat()),
            "raw_log": raw,
        }

    _SCENARIOS = [
        {
            "rule_description": "Multiple authentication failures followed by success",
            "rule_id": "5710",
            "level": 10,
            "fields": {
                "event_type": "authentication_success",
                "process_name": "sshd",
                "logon_attempts": 7,
                "src_ip": "185.220.101.{}",
                "user": "root",
            },
        },
        {
            "rule_description": "PowerShell encoded command execution detected",
            "rule_id": "92050",
            "level": 12,
            "fields": {
                "event_type": "process_creation",
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA==",
                "parent_process": "explorer.exe",
                "user": "corp\\jsmith",
            },
        },
        {
            "rule_description": "Suspicious scheduled task creation for persistence",
            "rule_id": "92100",
            "level": 9,
            "fields": {
                "event_type": "process_creation",
                "process_name": "schtasks.exe",
                "command_line": "schtasks /create /sc onlogon /tn Updater /tr C:\\\\Users\\\\Public\\\\svc.exe",
                "parent_process": "cmd.exe",
                "user": "corp\\svc-backup",
            },
        },
        {
            "rule_description": "Mimikatz-like credential dumping tool execution",
            "rule_id": "92200",
            "level": 15,
            "fields": {
                "event_type": "process_creation",
                "process_name": "rundll32.exe",
                "command_line": "rundll32.exe C:\\\\Windows\\\\Temp\\\\comsvcs.dll, MiniDump 624 lsass.dmp full",
                "parent_process": "cmd.exe",
                "user": "corp\\administrator",
            },
        },
        {
            "rule_description": "Outbound connection to known malicious C2 IP",
            "rule_id": "100050",
            "level": 13,
            "fields": {
                "event_type": "network_connection",
                "process_name": "svchost.exe",
                "dst_ip": "45.153.160.{}",
                "dst_port": 443,
                "user": "SYSTEM",
            },
        },
        {
            "rule_description": "File integrity monitoring: system binary modified",
            "rule_id": "550",
            "level": 7,
            "fields": {
                "event_type": "file_change",
                "file_path": "/usr/bin/sudo",
                "md5_before": "a94a8fe5",
                "md5_after": "0be0d783",
                "user": "root",
            },
        },
        {
            "rule_description": "Web server directory traversal attempt",
            "rule_id": "31151",
            "level": 8,
            "fields": {
                "event_type": "web_attack",
                "process_name": "nginx",
                "url": "/download?file=../../../../etc/passwd",
                "src_ip": "103.21.244.{}",
                "user": "-",
            },
        },
        {
            "rule_description": "New local administrator account created",
            "rule_id": "70123",
            "level": 8,
            "fields": {
                "event_type": "account_management",
                "process_name": "net.exe",
                "command_line": "net user backdoor P@ssw0rd123 /add & net localgroup administrators backdoor /add",
                "user": "corp\\helpdesk1",
            },
        },
    ]

    AGENTS = [
        ("web-prod-01", "10.0.1.15"),
        ("dc-01", "10.0.0.5"),
        ("workstation-jsmith", "10.0.5.42"),
        ("db-prod-02", "10.0.1.30"),
        ("mail-gateway", "10.0.2.10"),
    ]

    def _simulate_alerts(self, limit: int):
        alerts = []
        now = datetime.utcnow()
        for i in range(limit):
            scenario = random.choice(self._SCENARIOS)
            agent_name, agent_ip = random.choice(self.AGENTS)
            fields = dict(scenario["fields"])
            for k, v in fields.items():
                if isinstance(v, str) and "{}" in v:
                    fields[k] = v.format(random.randint(2, 254))
            ts = now - timedelta(minutes=random.randint(0, 240))
            alerts.append(
                {
                    "source_id": str(uuid.uuid4()),
                    "rule_id": scenario["rule_id"],
                    "rule_description": scenario["rule_description"],
                    "agent_name": agent_name,
                    "agent_ip": agent_ip,
                    "level": scenario["level"],
                    "timestamp": ts.isoformat(),
                    "raw_log": {
                        "rule": {
                            "id": scenario["rule_id"],
                            "description": scenario["rule_description"],
                            "level": scenario["level"],
                        },
                        "agent": {"name": agent_name, "ip": agent_ip},
                        "data": fields,
                        "timestamp": ts.isoformat(),
                    },
                }
            )
        return alerts


wazuh_client = WazuhClient()
