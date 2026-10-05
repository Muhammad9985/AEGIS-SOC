"""
AEGIS-SOC Configuration Module
Central settings, thresholds, and paths for the Windows SIEM & Autonomous SOC platform.
"""
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "aegis_siem.db"

# Server configuration
HOST = "0.0.0.0"
PORT = 8000

# Telemetry settings
DEFAULT_POLL_INTERVAL_SEC = 2.0
MAX_LIVE_BUFFER_EVENTS = 2000

# DEFCON Threat Levels
DEFCON_LEVELS = {
    1: {"name": "DEFCON 1", "desc": "Active Hostile Intrusion / Active Ransomware / Breach In Progress", "color": "#EF4444"},
    2: {"name": "DEFCON 2", "desc": "Credential Dumping or Lateral Movement Detected", "color": "#F97316"},
    3: {"name": "DEFCON 3", "desc": "Suspicious Defense Evasion or Script Execution", "color": "#F59E0B"},
    4: {"name": "DEFCON 4", "desc": "Anomalous Reconnaissance or Failed Logons Observed", "color": "#3B82F6"},
    5: {"name": "DEFCON 5", "desc": "Normal Operations - All Sensor Channels Green", "color": "#10B981"}
}

# MITRE ATT&CK Tactics
MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact"
]
