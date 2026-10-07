"""
AEGIS-SOC Threat Hunting & KQL Analytical Query Engine
Enables SOC operators and threat hunters to execute complex queries,
search event telemetries, and aggregate threat statistics.
"""
import time
import logging
from typing import Dict, Any, List, Optional
from backend.database import get_connection

logger = logging.getLogger("aegis.hunting")

PREBUILT_HUNT_QUERIES = [
    {
        "name": "Ransomware Pre-Encryption Shadow Copy Wiping",
        "category": "RANSOMWARE",
        "description": "Hunts for adversaries attempting to wipe volume shadow copies prior to disk encryption.",
        "query": "process_name in ('vssadmin.exe', 'wmic.exe') and command_line contains 'shadow'",
        "mitre": "T1490 (Inhibit System Recovery)"
    },
    {
        "name": "LSASS Memory Dump & Credential Theft",
        "category": "CREDENTIAL_ACCESS",
        "description": "Detects tools reading or dumping LSASS memory to harvest plaintext credentials and NTLM hashes.",
        "query": "event_id in (1, 10) and (process_name in ('procdump.exe', 'mimikatz.exe') or command_line contains 'lsass')",
        "mitre": "T1003.001 (OS Credential Dumping)"
    },
    {
        "name": "LOLBAS Proxy Execution & Ingress Cradles",
        "category": "DEFENSE_EVASION",
        "description": "Hunts for native Microsoft binaries leveraged to download and execute remote payloads.",
        "query": "process_name in ('certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'rundll32.exe')",
        "mitre": "T1218 (System Binary Proxy Execution)"
    },
    {
        "name": "Obfuscated / Base64 Encoded PowerShell",
        "category": "EXECUTION",
        "description": "Hunts for command-line arguments using encoded flags to bypass AMSI and script inspect.",
        "query": "process_name == 'powershell.exe' and (command_line contains '-enc' or command_line contains '-w hidden')",
        "mitre": "T1059.001 (PowerShell Scripting)"
    },
    {
        "name": "High-Risk Non-Standard C2 Outbound Sockets",
        "category": "COMMAND_AND_CONTROL",
        "description": "Hunts for beaconing traffic over common adversary C2 ports (4444, 8888, 1337, 9001).",
        "query": "event_id == 3 and dest_port in (4444, 8888, 1337, 9001)",
        "mitre": "T1071 (Application Layer Protocol)"
    },
    {
        "name": "Persistence via Windows Service & Registry Run",
        "category": "PERSISTENCE",
        "description": "Detects attempts to install persistent services or modify startup Run keys.",
        "query": "event_id in (13, 7045) or command_line contains 'CurrentVersion\\Run'",
        "mitre": "T1547.001 (Boot or Logon Autostart Execution)"
    }
]

class HuntingEngine:
    def execute_query(self, query_str: str, limit: int = 100) -> Dict[str, Any]:
        """
        Executes a threat hunting query against the analytical events database.
        Parses intuitive field criteria into optimized SQL queries.
        """
        start_time = time.time()
        conn = get_connection()
        cursor = conn.cursor()

        sql_where = []
        sql_params = []
        query_clean = query_str.strip()

        if query_clean and query_clean.upper() != "*":
            # Simple translation of field conditions
            tokens = query_clean.split(" and ")
            for token in tokens:
                t = token.strip()
                if "contains" in t:
                    parts = t.split("contains")
                    field = parts[0].strip()
                    val = parts[1].strip().strip("'\"")
                    # Whitelist fields
                    if field in ("command_line", "process_name", "user", "computer", "channel", "mitre_tactic"):
                        sql_where.append(f"{field} LIKE ?")
                        sql_params.append(f"%{val}%")
                elif "==" in t or "=" in t:
                    op = "==" if "==" in t else "="
                    parts = t.split(op)
                    field = parts[0].strip()
                    val = parts[1].strip().strip("'\"")
                    if field in ("event_id", "dest_port", "severity", "process_name", "computer", "user", "channel"):
                        sql_where.append(f"{field} = ?")
                        sql_params.append(val)
                elif " in " in t:
                    parts = t.split(" in ")
                    field = parts[0].strip()
                    val_group = parts[1].strip().strip("()")
                    items = [x.strip().strip("'\"") for x in val_group.split(",")]
                    if field in ("process_name", "event_id", "severity", "dest_port", "computer"):
                        placeholders = ",".join("?" for _ in items)
                        sql_where.append(f"{field} IN ({placeholders})")
                        sql_params.extend(items)
                else:
                    # Free text wildcard search across multiple fields
                    search_term = t.strip("'\"")
                    sql_where.append("(process_name LIKE ? OR command_line LIKE ? OR computer LIKE ? OR user LIKE ?)")
                    term_fmt = f"%{search_term}%"
                    sql_params.extend([term_fmt, term_fmt, term_fmt, term_fmt])

        where_clause = f"WHERE {' AND '.join(sql_where)}" if sql_where else ""
        query_sql = f"SELECT * FROM events {where_clause} ORDER BY timestamp DESC LIMIT ?"
        sql_params.append(limit)

        try:
            cursor.execute(query_sql, sql_params)
            rows = [dict(r) for r in cursor.fetchall()]
        except Exception as e:
            logger.error("Hunting query execution failed: %s", e)
            return {
                "status": "ERROR",
                "error": str(e),
                "query": query_str,
                "execution_ms": round((time.time() - start_time) * 1000, 2),
                "count": 0,
                "results": []
            }

        # Calculate breakdown statistics
        process_stats = {}
        severity_stats = {}
        for r in rows:
            p = r.get("process_name") or "unknown"
            s = r.get("severity") or "INFO"
            process_stats[p] = process_stats.get(p, 0) + 1
            severity_stats[s] = severity_stats.get(s, 0) + 1

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "status": "SUCCESS",
            "query": query_str,
            "count": len(rows),
            "execution_ms": elapsed_ms,
            "process_breakdown": dict(sorted(process_stats.items(), key=lambda x: x[1], reverse=True)[:8]),
            "severity_breakdown": severity_stats,
            "results": rows
        }

    def get_prebuilt_queries(self) -> List[Dict[str, Any]]:
        return PREBUILT_HUNT_QUERIES

# Global Singleton
hunting_engine = HuntingEngine()
