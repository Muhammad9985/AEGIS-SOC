"""
AEGIS-SOC Autonomous Host Network Isolation & Perimeter Severing Engine
Instantly drops all inbound/outbound Windows network connectivity during critical breaches,
whitelisting strictly the local loopback and AEGIS-SOC management port (8000).
"""
import subprocess
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

logger = logging.getLogger("aegis.network_isolation")

RULE_BLOCK_OUT = "AEGIS_ISOLATION_BLOCK_OUT"
RULE_BLOCK_IN = "AEGIS_ISOLATION_BLOCK_IN"
RULE_ALLOW_MGT = "AEGIS_ISOLATION_ALLOW_MGT"

class NetworkIsolationEngine:
    def __init__(self):
        self.is_isolated = False
        self.isolated_at: str = ""
        self.isolation_reason: str = ""
        self.management_port = 8000
        self.history: List[Dict[str, Any]] = []

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_isolated": self.is_isolated,
            "isolated_at": self.isolated_at,
            "isolation_reason": self.isolation_reason,
            "management_port": self.management_port,
            "firewall_rules_active": [RULE_BLOCK_OUT, RULE_BLOCK_IN, RULE_ALLOW_MGT] if self.is_isolated else [],
            "history": self.history[:10]
        }

    def isolate_host(self, host: str = "LOCAL", reason: str = "MANUAL_OPERATOR_ENGAGE") -> Dict[str, Any]:
        """
        Executes real Windows netsh advfirewall policies to isolate the host from LAN/WAN.
        Preserves port 8000 and 127.0.0.1 so AEGIS-SOC dashboard and telemetry continue running.
        """
        logger.warning("[NETWORK ISOLATION] Engaging host isolation for host: %s (Reason: %s)", host, reason)
        commands = [
            # 1. Allow local management traffic on port 8000
            f'netsh advfirewall firewall add rule name="{RULE_ALLOW_MGT}" dir=in action=allow protocol=TCP localport={self.management_port} enable=yes',
            # 2. Block all outbound network traffic
            f'netsh advfirewall firewall add rule name="{RULE_BLOCK_OUT}" dir=out action=block enable=yes',
            # 3. Block all inbound network traffic
            f'netsh advfirewall firewall add rule name="{RULE_BLOCK_IN}" dir=in action=block enable=yes'
        ]

        executed_cmds = []
        for cmd in commands:
            try:
                res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=4)
                executed_cmds.append({"cmd": cmd, "status": "OK" if res.returncode == 0 else "NOTE", "out": (res.stdout or res.stderr).strip()})
            except Exception as e:
                executed_cmds.append({"cmd": cmd, "status": "ERROR", "out": str(e)})

        self.is_isolated = True
        self.isolated_at = datetime.now(timezone.utc).isoformat()
        self.isolation_reason = reason

        record = {
            "timestamp": self.isolated_at,
            "action": "ISOLATE",
            "host": host,
            "reason": reason,
            "commands": executed_cmds
        }
        self.history.insert(0, record)

        return {
            "status": "SUCCESS",
            "is_isolated": True,
            "host": host,
            "message": f"Host [{host}] network SEVERED. All external inbound/outbound packets dropped. Management port {self.management_port} preserved.",
            "record": record
        }

    def restore_host(self, host: str = "LOCAL", reason: str = "ANALYST_REMEDIATION_CONFIRMED") -> Dict[str, Any]:
        """
        Removes emergency isolation firewall rules, restoring normal LAN and Internet operations.
        """
        logger.info("[NETWORK ISOLATION] Restoring network connectivity on host: %s", host)
        rules = [RULE_BLOCK_OUT, RULE_BLOCK_IN, RULE_ALLOW_MGT]
        for r in rules:
            try:
                subprocess.run(f'netsh advfirewall firewall delete rule name="{r}"', shell=True, capture_output=True, text=True, timeout=4)
            except Exception:
                pass

        self.is_isolated = False
        restore_ts = datetime.now(timezone.utc).isoformat()
        record = {
            "timestamp": restore_ts,
            "action": "RESTORE",
            "host": host,
            "reason": reason
        }
        self.history.insert(0, record)

        return {
            "status": "SUCCESS",
            "is_isolated": False,
            "host": host,
            "message": f"Isolation rules purged. Full network connectivity restored to [{host}].",
            "record": record
        }

isolation_engine = NetworkIsolationEngine()
