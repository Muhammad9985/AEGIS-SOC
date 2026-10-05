"""
AEGIS-SOC Detection & Behavioral Correlation Engine
Evaluates live events against Sigma-grade rules, triggers alerts, and correlates attack kill-chains.
"""
from typing import Dict, Any, List, Optional
import re
import uuid
from datetime import datetime
from backend.database import insert_alert, get_connection

class DetectionEngine:
    def __init__(self):
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": "SIGMA-WIN-001",
                "title": "Ransomware - Volume Shadow Copy Deletion",
                "severity": "CRITICAL",
                "category": "Impact",
                "mitre_tactic": "Impact",
                "mitre_technique": "T1490 - Inhibit System Recovery",
                "matcher": lambda e: (
                    ("vssadmin" in e["command_line"].lower() and "delete" in e["command_line"].lower() and "shadows" in e["command_line"].lower()) or
                    ("wmic" in e["command_line"].lower() and "shadowcopy" in e["command_line"].lower() and "delete" in e["command_line"].lower()) or
                    ("wbadmin" in e["command_line"].lower() and "delete" in e["command_line"].lower())
                ),
                "description": "Adversary attempting to delete shadow copies to inhibit system recovery prior to ransomware encryption."
            },
            {
                "id": "SIGMA-WIN-002",
                "title": "Credential Access - LSASS Memory Dumping via Procdump / Tool",
                "severity": "CRITICAL",
                "category": "Credential Access",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1003.001 - OS Credential Dumping: LSASS Memory",
                "matcher": lambda e: (
                    (e["event_id"] == 10 and "lsass.exe" in e["process_name"].lower()) or
                    ("lsass" in e["command_line"].lower() and ("procdump" in e["command_line"].lower() or "comsvcs.dll" in e["command_line"].lower() or "rundll32" in e["command_line"].lower())) or
                    ("sekurlsa" in e["command_line"].lower() or "mimikatz" in e["command_line"].lower())
                ),
                "description": "Detected process attempting to read or dump LSASS memory to extract plaintext passwords or Kerberos tickets."
            },
            {
                "id": "SIGMA-WIN-003",
                "title": "Defense Evasion - LOLBAS Certutil Download Cradle",
                "severity": "HIGH",
                "category": "Defense Evasion",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "T1218 - System Binary Proxy Execution",
                "matcher": lambda e: (
                    "certutil" in e["process_name"].lower() and ("-urlcache" in e["command_line"].lower() or "-split" in e["command_line"].lower())
                ),
                "description": "Certutil.exe was used to download a remote payload using proxy execution to evade perimeter inspection."
            },
            {
                "id": "SIGMA-WIN-004",
                "title": "Execution - Obfuscated PowerShell Download Cradle",
                "severity": "HIGH",
                "category": "Execution",
                "mitre_tactic": "Execution",
                "mitre_technique": "T1059.001 - Command and Scripting: PowerShell",
                "matcher": lambda e: (
                    "powershell" in e["process_name"].lower() and (
                        ("downloadstring" in e["command_line"].lower() and "webclient" in e["command_line"].lower()) or
                        ("-enc" in e["command_line"].lower() and len(e["command_line"]) > 80) or
                        ("invoke-expression" in e["command_line"].lower() and "http" in e["command_line"].lower())
                    )
                ),
                "description": "PowerShell command executing a dynamic uncompiled script payload directly from memory."
            },
            {
                "id": "SIGMA-WIN-005",
                "title": "Persistence - Malicious Registry Run Key Added",
                "severity": "HIGH",
                "category": "Persistence",
                "mitre_tactic": "Persistence",
                "mitre_technique": "T1547.001 - Boot or Logon Autostart Execution",
                "matcher": lambda e: (
                    e["event_id"] == 13 and "currentversion\\run" in e.get("raw_data", {}).get("TargetObject", "").lower()
                ),
                "description": "An autostart registry entry was configured under HKLM/HKCU Run keys to maintain persistence."
            },
            {
                "id": "SIGMA-WIN-006",
                "title": "Lateral Movement - Remote WMI Process Creation",
                "severity": "HIGH",
                "category": "Lateral Movement",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique": "T1047 - Windows Management Instrumentation",
                "matcher": lambda e: (
                    "wmic" in e["process_name"].lower() and "/node:" in e["command_line"].lower() and "process" in e["command_line"].lower() and "call" in e["command_line"].lower()
                ),
                "description": "Adversary executing commands across remote internal network endpoints using WMI."
            },
            {
                "id": "SIGMA-WIN-007",
                "title": "Command & Control - Cobalt Strike / Metasploit Beaconing Pattern",
                "severity": "CRITICAL",
                "category": "Command and Control",
                "mitre_tactic": "Command and Control",
                "mitre_technique": "T1071.001 - Web Protocols: Beaconing",
                "matcher": lambda e: (
                    e["event_id"] == 3 and e.get("dest_port") in [4444, 8080, 8443, 1337, 4443] and
                    ("rundll32.exe" in e["process_name"].lower() or "svchost.exe" in e["process_name"].lower() or "powershell.exe" in e["process_name"].lower())
                ),
                "description": "Suspicious outbound interactive socket initiated by a system binary on known offensive C2 ports."
            },
            {
                "id": "SIGMA-WIN-008",
                "title": "Privilege Escalation - Special Privileges Assigned to Local Administrator",
                "severity": "MEDIUM",
                "category": "Privilege Escalation",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "T1078.001 - Default Accounts",
                "matcher": lambda e: (
                    e["event_id"] == 4672 and "administrator" in e["user"].lower() and e["severity"] != "INFO"
                ),
                "description": "User session obtained sensitive administrative privileges (SeDebugPrivilege / SeTcbPrivilege)."
            }
        ]

    def evaluate(self, event: Dict[str, Any], event_db_id: int) -> Optional[Dict[str, Any]]:
        """
        Evaluate an event against loaded detection signatures.
        """
        for rule in self.rules:
            try:
                if rule["matcher"](event):
                    alert_data = {
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "category": rule["category"],
                        "description": rule["description"],
                        "mitre_tactic": rule["mitre_tactic"],
                        "mitre_technique": rule["mitre_technique"],
                        "host": event["computer"],
                        "user": event["user"],
                        "process": event["process_name"],
                        "event_ref_id": event_db_id,
                        "timestamp": event["timestamp"],
                        "status": "NEW",
                        "ai_triage_verdict": f"Autonomous trigger via {rule['id']}. MITRE: {rule['mitre_technique']}.",
                        "ai_confidence": 0.98 if rule["severity"] == "CRITICAL" else 0.88
                    }
                    alert_id = insert_alert(alert_data)
                    alert_data["id"] = alert_id
                    return alert_data
            except Exception:
                continue
        return None

# Singleton detection engine
engine = DetectionEngine()
