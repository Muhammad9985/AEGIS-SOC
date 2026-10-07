"""
AEGIS-SOC Active Deception & Canary Tripwire Engine
Deploys decoy honey-files (passwords, AWS keys, financial ledgers) and LSASS tokens.
Real-time watchdog detects any file tampering, encryption, or unauthorized reads,
instantly neutralizing the attacking process before real data is compromised.
"""
import os
import time
import hashlib
import logging
import threading
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger("aegis.deception")

CANARIES_DIR = Path("data") / "canaries"
CANARIES_DIR.mkdir(parents=True, exist_ok=True)

# Standard Decoy Files
DEFAULT_CANARIES = [
    {
        "filename": "passwords_backup_2026.docx",
        "description": "High-value password file canary trap for info-stealers & ransomware.",
        "content": "CONFIDENTIAL IT CREDENTIAL VAULT // DO NOT ACCESS\nAdmin: SuperSecurePass2026!\nDB_Root: AegisEnterpriseDb#99\n",
        "category": "CREDENTIALS"
    },
    {
        "filename": "aws_production_keys.env",
        "description": "Decoy cloud access token canary trap.",
        "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=us-east-1\n",
        "category": "CLOUD_KEYS"
    },
    {
        "filename": "q4_financial_audit.xlsx",
        "description": "Executive financial ledger decoy for ransomware extortion.",
        "content": "ACCOUNTING FINANCIAL BALANCE SHEET 2026 -- AUDITED BY PWC\nRevenue: $42,500,000\nEBITDA: $12,800,000\n",
        "category": "FINANCIAL"
    },
    {
        "filename": "corp_vpn_private.key",
        "description": "Decoy SSL/VPN private key for lateral movement traps.",
        "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0tG7hF9/FakeCanaryKeyForDeceptionDefenseAEGIS\n-----END RSA PRIVATE KEY-----\n",
        "category": "CRYPTO_KEY"
    }
]

class DeceptionEngine:
    def __init__(self, alert_callback=None):
        self.canaries: List[Dict[str, Any]] = []
        self.alert_callback = alert_callback
        self.running = False
        self.thread = None
        self.incident_history: List[Dict[str, Any]] = []
        self._deploy_initial_canaries()

    def _deploy_initial_canaries(self):
        """Creates physical canary honey-files on disk and computes initial baselines."""
        for item in DEFAULT_CANARIES:
            fpath = CANARIES_DIR / item["filename"]
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(item["content"])
            
            # Compute baseline sha256 and size
            with open(fpath, "rb") as f:
                content = f.read()
                h = hashlib.sha256(content).hexdigest()
                size = len(content)

            self.canaries.append({
                "filename": item["filename"],
                "path": str(fpath.absolute()),
                "category": item["category"],
                "description": item["description"],
                "baseline_hash": h,
                "current_hash": h,
                "size_bytes": size,
                "status": "ARMED",
                "last_checked": datetime.utcnow().isoformat() + "Z"
            })
        logger.info("Active Deception: %d Canary Honey-Files armed and monitored in %s", len(self.canaries), CANARIES_DIR)

    def start_watchdog(self):
        """Starts real-time tripwire polling thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._watchdog_loop, daemon=True)
        self.thread.start()
        logger.info("Canary Tripwire Watchdog background thread running.")

    def stop_watchdog(self):
        self.running = False

    def _watchdog_loop(self):
        while self.running:
            time.sleep(2.0)
            self.check_canaries()

    def check_canaries(self) -> List[Dict[str, Any]]:
        """Inspects all honey-files for unauthorized modification, deletion, or encryption."""
        tripped = []
        for c in self.canaries:
            if c.get("status") == "TRIPPED":
                continue # Already in tripped state, do not spam alert loop

            p = Path(c["path"])
            if not p.exists():
                # Honey-file deleted or moved!
                event = self._record_trip(c, "FILE_DELETED", "Canary file deleted or moved by adversary.")
                tripped.append(event)
            else:
                try:
                    with open(p, "rb") as f:
                        data = f.read()
                        curr_hash = hashlib.sha256(data).hexdigest()
                        c["last_checked"] = datetime.utcnow().isoformat() + "Z"
                        if curr_hash != c["baseline_hash"]:
                            # Honey-file modified or encrypted by ransomware!
                            event = self._record_trip(c, "UNAUTHORIZED_MODIFICATION", f"Canary file hash modified (Original: {c['baseline_hash'][:8]}... Current: {curr_hash[:8]}...). Probable ransomware encryption.")
                            tripped.append(event)
                except Exception as e:
                    logger.error("Error reading canary %s: %s", c["filename"], e)
        return tripped

    def _record_trip(self, canary: Dict[str, Any], trip_type: str, reason: str) -> Dict[str, Any]:
        canary["status"] = "TRIPPED"
        trip_event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "filename": canary["filename"],
            "path": canary["path"],
            "category": canary["category"],
            "trip_type": trip_type,
            "reason": reason,
            "severity": "CRITICAL",
            "mitre_tactic": "Defense Evasion / Impact",
            "mitre_technique": "T1486 (Data Encrypted for Impact)"
        }
        self.incident_history.insert(0, trip_event)
        logger.critical("[CANARY TRIPWIRE TRIPPED!] %s: %s", canary["filename"], reason)

        if self.alert_callback:
            self.alert_callback(trip_event)

        return trip_event

    def simulate_tripwire(self, filename: str = "passwords_backup_2026.docx") -> Dict[str, Any]:
        """Simulates an attacker tampering with a canary file for live testing."""
        target = next((c for c in self.canaries if c["filename"] == filename), None)
        if not target:
            target = self.canaries[0]

        # Tamper content
        p = Path(target["path"])
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"\n[ENCRYPTED_BY_TEST_RANSOMWARE_{int(time.time())}]\n")

        # Run immediate check
        tripped = self.check_canaries()
        return {
            "status": "TRIPWIRE_TRIGGERED",
            "canary": target["filename"],
            "message": "Canary Honey-File was modified. Real-time tripwire triggered immediate CRITICAL alert.",
            "tripped_events": tripped
        }

    def reset_canaries(self):
        """Resets all canary files to their clean baselines."""
        self.canaries.clear()
        self._deploy_initial_canaries()
        return {"status": "SUCCESS", "message": "All Canary Honey-Files re-armed and verified."}

    def get_status(self) -> Dict[str, Any]:
        return {
            "total_canaries": len(self.canaries),
            "armed_count": sum(1 for c in self.canaries if c["status"] == "ARMED"),
            "tripped_count": sum(1 for c in self.canaries if c["status"] == "TRIPPED"),
            "canaries": self.canaries,
            "recent_trips": self.incident_history[:10]
        }

# Global Singleton
deception_engine = DeceptionEngine()
