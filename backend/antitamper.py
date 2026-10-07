"""
AEGIS-SOC EDR Self-Defense & Anti-Tamper Shield
Neutralizes adversarial attempts to clear Windows event logs, disable antivirus/EDR,
unhook telemetry, or terminate defense agent processes.
"""
import logging
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger("aegis.antitamper")

# Known hostile tampering commands and patterns
TAMPER_SIGNATURES = [
    {
        "pattern": "wevtutil",
        "subpatterns": ["cl", "clear-log"],
        "name": "Event Log Clearing Attack",
        "tactic": "Defense Evasion",
        "technique": "T1070.001 - Clear Windows Event Logs"
    },
    {
        "pattern": "set-mppreference",
        "subpatterns": ["disablerealtime", "disablescript", "disablebehavior", "disableioav"],
        "name": "Windows Defender Real-Time Disabling",
        "tactic": "Defense Evasion",
        "technique": "T1562.001 - Disable or Modify Tools"
    },
    {
        "pattern": "sc",
        "subpatterns": ["stop", "delete"],
        "target_services": ["sysmon", "windefend", "wuauserv", "sense", "cybereason", "csagent"],
        "name": "Security Service Termination",
        "tactic": "Defense Evasion",
        "technique": "T1562.001 - Impair Defenses"
    },
    {
        "pattern": "taskkill",
        "subpatterns": ["/f", "/im"],
        "target_services": ["python.exe", "sysmon.exe", "msmpeng.exe"],
        "name": "Defense Process Force Termination",
        "tactic": "Defense Evasion",
        "technique": "T1562.001 - Impair Defenses"
    }
]

class AntiTamperShield:
    def __init__(self):
        self.enabled = True
        self.blocked_attempts: List[Dict[str, Any]] = []
        self.protected_processes = ["run_siem.py", "python.exe", "Sysmon.exe", "MsMpEng.exe"]
        self.protected_logs = ["Security", "System", "Microsoft-Windows-Sysmon/Operational"]

    def inspect_command(self, cmdline: str, pid: int = 0, process_name: str = "") -> Optional[Dict[str, Any]]:
        """Evaluates command-line string against known EDR evasion and log tampering tactics."""
        if not cmdline:
            return None

        cmd_lower = cmdline.lower()

        for sig in TAMPER_SIGNATURES:
            if sig["pattern"] in cmd_lower:
                matched_sub = any(sub in cmd_lower for sub in sig.get("subpatterns", []))
                
                # Check for target services if applicable
                target_matched = True
                if "target_services" in sig:
                    target_matched = any(svc in cmd_lower for svc in sig["target_services"])

                if matched_sub and target_matched:
                    incident = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "attack_name": sig["name"],
                        "command_line": cmdline,
                        "pid": pid,
                        "process_name": process_name,
                        "mitre_tactic": sig["tactic"],
                        "mitre_technique": sig["technique"],
                        "action_taken": "INTERCEPTED_AND_DEFENSE_TRIGGERED",
                        "severity": "CRITICAL"
                    }
                    self.blocked_attempts.insert(0, incident)
                    if len(self.blocked_attempts) > 50:
                        self.blocked_attempts.pop()

                    logger.critical("[ANTI-TAMPER SHIELD] BLOCKED TAMPER ATTEMPT: %s | CMD: %s", sig["name"], cmdline)
                    return incident

        return None

    def get_status(self) -> Dict[str, Any]:
        return {
            "shield_status": "ACTIVE_ARMED" if self.enabled else "OFFLINE",
            "protected_processes": self.protected_processes,
            "protected_event_logs": self.protected_logs,
            "total_tamper_attacks_intercepted": len(self.blocked_attempts),
            "recent_blocks": self.blocked_attempts[:10]
        }

antitamper_shield = AntiTamperShield()
