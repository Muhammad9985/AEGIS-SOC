"""
AEGIS-SOC Digital Forensics & Incident Response (DFIR) Engine
Captures forensic snapshots, process memory metadata, open handles, DLL modules,
and network sockets into a secure evidence vault before threat neutralization.
"""
import os
import json
import logging
import psutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

logger = logging.getLogger("aegis.dfir")

VAULT_DIR = Path("data") / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

class DFIREngine:
    def __init__(self):
        self.artifacts: List[Dict[str, Any]] = []
        self._load_existing_artifacts()

    def _load_existing_artifacts(self):
        """Loads previously saved forensic manifests from disk."""
        for p in VAULT_DIR.glob("*.json"):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.artifacts.append(data)
            except Exception:
                pass
        self.artifacts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        logger.info("DFIR Engine loaded %d existing forensic evidence artifacts from vault.", len(self.artifacts))

    def capture_process_forensics(self, pid: int, process_name: str = "", reason: str = "SOAR_PRE_TERMINATION") -> Dict[str, Any]:
        """
        Extracts comprehensive digital forensic artifacts from an active PID
        including lineage, loaded DLLs, memory maps, and open sockets.
        """
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        artifact_id = f"DFIR_{ts}_{pid}"
        
        forensic_data = {
            "artifact_id": artifact_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "pid": pid,
            "process_name": process_name,
            "reason": reason,
            "status": "CAPTURED",
            "cmdline": "",
            "exe_path": "",
            "cwd": "",
            "username": "",
            "parent": {},
            "memory_info": {},
            "open_connections": [],
            "loaded_modules": [],
            "open_files": [],
            "sha256": ""
        }

        try:
            if pid and psutil.pid_exists(pid):
                p = psutil.Process(pid)
                forensic_data["process_name"] = p.name()
                
                try:
                    forensic_data["cmdline"] = " ".join(p.cmdline())
                except Exception:
                    pass

                try:
                    forensic_data["exe_path"] = p.exe()
                except Exception:
                    pass

                try:
                    forensic_data["cwd"] = p.cwd()
                except Exception:
                    pass

                try:
                    forensic_data["username"] = p.username()
                except Exception:
                    pass

                try:
                    mem = p.memory_info()
                    forensic_data["memory_info"] = {
                        "rss_mb": round(mem.rss / (1024 * 1024), 2),
                        "vms_mb": round(mem.vms / (1024 * 1024), 2),
                    }
                except Exception:
                    pass

                try:
                    parent = p.parent()
                    if parent:
                        forensic_data["parent"] = {
                            "pid": parent.pid,
                            "name": parent.name()
                        }
                except Exception:
                    pass

                # Network connections
                try:
                    for conn in p.connections(kind="inet"):
                        forensic_data["open_connections"].append({
                            "type": "TCP" if conn.type == 1 else "UDP",
                            "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                            "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                            "status": conn.status
                        })
                except Exception:
                    pass

                # Loaded modules
                try:
                    for m in p.memory_maps()[:25]:
                        forensic_data["loaded_modules"].append(m.path)
                except Exception:
                    pass

                # Open files
                try:
                    for f in p.open_files()[:20]:
                        forensic_data["open_files"].append(f.path)
                except Exception:
                    pass

        except Exception as e:
            logger.warning("Partial forensic capture on PID %s: %s", pid, e)
            forensic_data["capture_note"] = str(e)

        # Persist to disk
        artifact_file = VAULT_DIR / f"{artifact_id}.json"
        try:
            with open(artifact_file, "w", encoding="utf-8") as f:
                json.dump(forensic_data, f, indent=2)
            forensic_data["vault_file"] = str(artifact_file.absolute())
        except Exception as e:
            logger.error("Failed to save DFIR artifact: %s", e)

        self.artifacts.insert(0, forensic_data)
        logger.info("[DFIR EVIDENCE SECURED] Captured memory and forensic artifact %s for PID %s", artifact_id, pid)
        return forensic_data

    def list_artifacts(self) -> List[Dict[str, Any]]:
        return self.artifacts

    def get_artifact(self, artifact_id: str) -> Optional[Dict[str, Any]]:
        return next((a for a in self.artifacts if a.get("artifact_id") == artifact_id), None)

# Global Singleton
dfir_engine = DFIREngine()
