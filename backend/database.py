"""
AEGIS-SOC Analytical Database
Embedded SQLite in WAL mode with full indexing for sub-millisecond query latency.
"""
import sqlite3
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.config import DB_PATH

logger = logging.getLogger("aegis.database")

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Fast write-ahead logging & optimizations
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;") # 64MB cache
    conn.execute("PRAGMA temp_store = MEMORY;")
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        channel TEXT NOT NULL,
        event_id INTEGER NOT NULL,
        computer TEXT NOT NULL,
        user TEXT,
        process_name TEXT,
        process_id INTEGER,
        parent_process TEXT,
        command_line TEXT,
        src_ip TEXT,
        dest_ip TEXT,
        dest_port INTEGER,
        hashes TEXT,
        severity TEXT DEFAULT 'INFO',
        raw_json TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_eid ON events(event_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_comp ON events(computer);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_proc ON events(process_name);")

    # 2. Alerts Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL, -- CRITICAL, HIGH, MEDIUM, LOW, INFO
        category TEXT,
        description TEXT,
        mitre_tactic TEXT,
        mitre_technique TEXT,
        host TEXT NOT NULL,
        user TEXT,
        process TEXT,
        event_ref_id INTEGER,
        timestamp TEXT NOT NULL,
        status TEXT DEFAULT 'NEW', -- NEW, TRIAGED, ESCALATED, RESOLVED, FALSE_POSITIVE
        ai_triage_verdict TEXT,
        ai_confidence REAL DEFAULT 0.0
    );
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity);")

    # 3. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        kill_chain_stage TEXT,
        affected_host TEXT NOT NULL,
        status TEXT DEFAULT 'OPEN', -- OPEN, CONTAINED, RESOLVED
        alert_count INTEGER DEFAULT 1,
        root_cause TEXT,
        ai_summary TEXT,
        ai_remediation TEXT,
        attack_graph_json TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)

    # 4. SOAR Actions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS soar_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_type TEXT NOT NULL, -- ISOLATE_HOST, KILL_PID, QUARANTINE_FILE, BLOCK_IP, LOCK_ACCOUNT
        target TEXT NOT NULL,
        details TEXT,
        executed_by TEXT DEFAULT 'VALKYRIE-AI', -- VALKYRIE-AI or ANALYST
        timestamp TEXT NOT NULL,
        status TEXT DEFAULT 'COMPLETED'
    );
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully at %s", DB_PATH)

# Database helper functions
def insert_event(event_dict: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (
            timestamp, channel, event_id, computer, user, process_name, 
            process_id, parent_process, command_line, src_ip, dest_ip, 
            dest_port, hashes, severity, raw_json, mitre_tactic, mitre_technique
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_dict.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        event_dict.get("channel", "Security"),
        event_dict.get("event_id", 0),
        event_dict.get("computer", "DESKTOP-WIN11"),
        event_dict.get("user", "SYSTEM"),
        event_dict.get("process_name", ""),
        event_dict.get("process_id", 0),
        event_dict.get("parent_process", ""),
        event_dict.get("command_line", ""),
        event_dict.get("src_ip", ""),
        event_dict.get("dest_ip", ""),
        event_dict.get("dest_port", 0),
        event_dict.get("hashes", ""),
        event_dict.get("severity", "INFO"),
        json.dumps(event_dict.get("raw_data", {})),
        event_dict.get("mitre_tactic", ""),
        event_dict.get("mitre_technique", "")
    ))
    event_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return event_id

def insert_alert(alert_dict: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO alerts (
            title, severity, category, description, mitre_tactic,
            mitre_technique, host, user, process, event_ref_id,
            timestamp, status, ai_triage_verdict, ai_confidence
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_dict["title"],
        alert_dict["severity"],
        alert_dict.get("category", "Threat"),
        alert_dict.get("description", ""),
        alert_dict.get("mitre_tactic", ""),
        alert_dict.get("mitre_technique", ""),
        alert_dict.get("host", "DESKTOP-WIN11"),
        alert_dict.get("user", ""),
        alert_dict.get("process", ""),
        alert_dict.get("event_ref_id"),
        alert_dict.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        alert_dict.get("status", "NEW"),
        alert_dict.get("ai_triage_verdict", ""),
        alert_dict.get("ai_confidence", 0.95)
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_recent_events(limit: int = 100, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    if severity and severity.upper() != "ALL":
        cursor.execute("SELECT * FROM events WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity.upper(), limit))
    else:
        cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_event_by_id(event_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_incident_summary() -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'")
    critical_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
    high_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM soar_actions")
    total_soar_actions = cursor.fetchone()[0]

    # Mitre tactic stats
    cursor.execute("""
        SELECT mitre_tactic, COUNT(*) as cnt 
        FROM alerts 
        WHERE mitre_tactic IS NOT NULL AND mitre_tactic != ''
        GROUP BY mitre_tactic 
        ORDER BY cnt DESC
    """)
    tactic_counts = {r["mitre_tactic"]: r["cnt"] for r in cursor.fetchall()}

    conn.close()
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "total_soar_actions": total_soar_actions,
        "tactic_counts": tactic_counts
    }

def record_soar_action(action_type: str, target: str, details: str, executed_by: str = "VALKYRIE-AI") -> int:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO soar_actions (action_type, target, details, executed_by, timestamp, status)
        VALUES (?, ?, ?, ?, ?, 'COMPLETED')
    """, (action_type, target, details, executed_by, datetime.utcnow().isoformat() + "Z"))
    action_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return action_id

def get_soar_actions(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM soar_actions ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
