"""
AEGIS-SOC Main API & Real-time WebSocket Hub
Unifies backend detection, autonomous AI agent, SOAR orchestration, and live streaming.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio
import json
import logging
from pathlib import Path

from backend.config import BASE_DIR, DEFCON_LEVELS
from backend.database import (
    init_db, get_recent_events, get_recent_alerts, 
    get_incident_summary, get_soar_actions, insert_event
)
from backend.normalizer import normalize_event
from backend.detection_engine import engine as detection_engine
from backend.ai_analyst import valkyrie_agent
from backend.soar import SOAREngine
from backend.simulator import simulator
from backend.sensor import sensor_service
from backend.threat_intel import threat_intel
from backend.deception import deception_engine
from backend.dfir import dfir_engine
from backend.hunting import hunting_engine
from backend.ransomware_shield import ransomware_shield
from backend.network_isolation import isolation_engine
from backend.antitamper import antitamper_shield
from backend.quarantine import quarantine_vault
from backend.bas_engine import bas_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("aegis.main")

# Initialize database
init_db()

app = FastAPI(title="AEGIS-SOC", version="1.0.0", description="Autonomous Windows SIEM & Neural SOC Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("Client connected. Total clients: %s", len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("Client disconnected. Total clients: %s", len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

# Autonomous Active Defense Setting
AUTO_SOAR_ENABLED = True

def trigger_autonomous_soar(alert: Dict[str, Any], event: Dict[str, Any]):
    """Automatically neutralizes critical threats if Auto-SOAR is enabled."""
    global AUTO_SOAR_ENABLED
    if not AUTO_SOAR_ENABLED or alert.get("severity") != "CRITICAL":
        return

    host = alert.get("host") or event.get("computer")
    pid = event.get("process_id") or 0
    proc_name = event.get("process_name") or alert.get("process") or ""
    title = alert.get("title", "")

    # Auto-Freeze and Terminate Malicious Process
    if pid and pid > 4:
        logger.warning("[AUTOPILOT SOAR] Auto-freezing and terminating rogue PID %s [%s] on %s", pid, proc_name, host)
        # 1. Instant thread freeze
        ransomware_shield.suspend_hostile_process(pid=pid, process_name=proc_name, reason=f"AUTOPILOT_CRITICAL: {title}")
        # 2. Terminate rogue process
        action_res = SOAREngine.terminate_process(pid=pid, process_name=proc_name, host=host, executed_by="VALKYRIE-AUTOPILOT")
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "SOAR_ACTION", "data": action_res}), loop)

    # Auto-Isolate on Active Ransomware / Cobalt Strike Breach
    if "Ransomware" in title or "Cobalt Strike" in title or "Canary" in title:
        logger.warning("[AUTOPILOT SOAR] Auto-isolating host %s due to %s", host, title)
        iso_res = isolation_engine.isolate_host(host=host, reason=f"AUTOPILOT_CONTAINMENT: {title}")
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "ISOLATION_UPDATE", "data": iso_res}), loop)

# Hook sensor to broadcast directly through asyncio loop
loop = None

def sensor_event_callback(msg: Dict[str, Any]):
    global loop
    if loop and loop.is_running():
        # EDR Anti-Tamper check on incoming telemetry
        event_data = msg.get("data", {})
        if isinstance(event_data, dict) and event_data.get("command_line"):
            tamper_incident = antitamper_shield.inspect_command(
                cmdline=event_data["command_line"],
                pid=event_data.get("process_id", 0),
                process_name=event_data.get("process_name", "")
            )
            if tamper_incident:
                tamper_alert = {
                    "title": f"EDR Anti-Tamper Block: {tamper_incident['attack_name']}",
                    "severity": "CRITICAL",
                    "category": "DEFENSE_EVASION",
                    "description": f"Blocked attempt to unhook defenses: {tamper_incident['command_line']}",
                    "mitre_tactic": tamper_incident["mitre_tactic"],
                    "mitre_technique": tamper_incident["mitre_technique"],
                    "host": event_data.get("computer", "LOCAL"),
                    "process": event_data.get("process_name", ""),
                    "timestamp": tamper_incident["timestamp"]
                }
                asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "ALERT", "data": tamper_alert}), loop)
                trigger_autonomous_soar(tamper_alert, event_data)

        asyncio.run_coroutine_threadsafe(manager.broadcast(msg), loop)
        if msg.get("type") == "ALERT":
            trigger_autonomous_soar(msg["data"], {})

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()
    sensor_service.callback = sensor_event_callback
    sensor_service.start()

    # Active Deception Canary Watchdog Hook
    def canary_alert_handler(trip_event: Dict[str, Any]):
        alert = {
            "title": f"Active Deception Breach: Canary Honey-File [{trip_event.get('filename')}] Modified!",
            "severity": "CRITICAL",
            "category": "ACTIVE_DECEPTION",
            "description": trip_event.get("reason", "Decoy honey-file altered by adversary"),
            "mitre_tactic": trip_event.get("mitre_tactic", "Impact"),
            "mitre_technique": trip_event.get("mitre_technique", "T1486"),
            "host": sensor_service.hostname,
            "process": "canary_watcher",
            "timestamp": trip_event.get("timestamp")
        }
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "ALERT", "data": alert}), loop)
            trigger_autonomous_soar(alert, {})

    deception_engine.alert_callback = canary_alert_handler
    deception_engine.start_watchdog()
    logger.info("AEGIS-SOC Real Windows Sensor & Deception Watchdog initialized.")

    # Periodic Live Graph Synchronization Task
    async def periodic_graph_sync():
        while True:
            await asyncio.sleep(6)
            try:
                if manager.active_connections:
                    graph_data = valkyrie_agent.build_attack_graph()
                    await manager.broadcast({"type": "GRAPH_UPDATE", "data": graph_data})
            except Exception as e:
                logger.debug("Periodic graph sync loop error: %s", e)

    asyncio.create_task(periodic_graph_sync())

@app.on_event("shutdown")
def shutdown_event():
    sensor_service.stop()
    deception_engine.stop_watchdog()

@app.post("/api/sensor/audit-now")
def trigger_sensor_audit():
    telemetry = sensor_service.force_audit()
    return {"status": "SUCCESS", "message": "Real Windows audit complete", "telemetry": telemetry}

@app.post("/api/sensor/test-detection")
def run_real_detection_test():
    """Executes a real benign administrative reconnaissance command on Windows to demonstrate live detection."""
    import subprocess
    try:
        proc = subprocess.run(
            ["whoami.exe", "/priv"],
            capture_output=True,
            text=True,
            timeout=5
        )
        telemetry = sensor_service.force_audit()
        return {
            "status": "SUCCESS",
            "command": "whoami.exe /priv",
            "output_preview": proc.stdout[:200] if proc.stdout else "",
            "message": "Real Windows process executed and harvested by AEGIS sensor."
        }
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

# --- REST Models ---
class IngestEventRequest(BaseModel):
    raw_event: Dict[str, Any]

class ChatRequest(BaseModel):
    prompt: str

class SOARRequest(BaseModel):
    action: str
    target: str
    process_name: Optional[str] = ""
    pid: Optional[int] = 0

class SimulateRequest(BaseModel):
    scenario: str # 'ransomware', 'credential_theft', 'normal'
    host: Optional[str] = "DESKTOP-WIN11-SEC"

class HuntQueryRequest(BaseModel):
    query: str
    limit: Optional[int] = 100

class DumpPIDRequest(BaseModel):
    pid: int
    process_name: Optional[str] = ""
    reason: Optional[str] = "MANUAL_OPERATOR_DUMP"

class TripTestRequest(BaseModel):
    filename: Optional[str] = "passwords_backup_2026.docx"

class IsolateHostRequest(BaseModel):
    host: Optional[str] = "LOCAL"
    reason: Optional[str] = "MANUAL_OPERATOR_ENGAGE"

class SuspendPIDRequest(BaseModel):
    pid: int
    process_name: Optional[str] = ""
    reason: Optional[str] = "MANUAL_OPERATOR_SUSPEND"

class QuarantineFileRequest(BaseModel):
    filepath: str
    reason: Optional[str] = "MANUAL_OPERATOR_QUARANTINE"

class BASRunTestRequest(BaseModel):
    scenario: str
    host: Optional[str] = "DESKTOP-SEC-HOST"

# --- REST Endpoints ---
@app.get("/api/status")
def get_system_status():
    summary = get_incident_summary()
    dossier = valkyrie_agent.generate_incident_dossier()
    defcon = dossier["defcon_level"]
    defcon_info = DEFCON_LEVELS.get(defcon, DEFCON_LEVELS[5])
    host_info = sensor_service.get_host_telemetry()
    return {
        "status": "ONLINE",
        "defcon": defcon,
        "defcon_info": defcon_info,
        "metrics": summary,
        "host_info": host_info,
        "active_incidents": 1 if defcon <= 2 else 0
    }

@app.get("/api/host-info")
def get_host_info():
    return sensor_service.get_host_telemetry()

@app.get("/api/events")
def list_events(limit: int = 100, severity: Optional[str] = None):
    return get_recent_events(limit=limit, severity=severity)

@app.get("/api/alerts")
def list_alerts(limit: int = 50):
    return get_recent_alerts(limit=limit)

@app.get("/api/dossier")
def get_dossier():
    return valkyrie_agent.generate_incident_dossier()

@app.get("/api/attack-graph")
def get_attack_graph():
    return valkyrie_agent.build_attack_graph()

@app.get("/api/soar/actions")
def get_soar_history():
    return get_soar_actions()

@app.post("/api/events/ingest")
async def ingest_event(payload: IngestEventRequest):
    norm = normalize_event(payload.raw_event)
    db_id = insert_event(norm)
    norm["id"] = db_id
    alert = detection_engine.evaluate(norm, db_id)
    
    await manager.broadcast({"type": "EVENT", "data": norm})
    if alert:
        await manager.broadcast({"type": "ALERT", "data": alert})
    return {"status": "INGESTED", "event_id": db_id, "alert": alert}

@app.post("/api/chat")
async def chat_with_valkyrie(payload: ChatRequest):
    response = valkyrie_agent.answer_query(payload.prompt)
    if response.get("action_taken"):
        await manager.broadcast({"type": "SOAR_ACTION", "data": response["action_taken"]})
    return response

@app.post("/api/soar/execute")
async def execute_soar(payload: SOARRequest):
    action = payload.action.upper()
    result = None
    if action == "ISOLATE_HOST":
        result = SOAREngine.isolate_host(payload.target, executed_by="ANALYST")
    elif action == "RESTORE_HOST":
        result = SOAREngine.restore_host(payload.target, executed_by="ANALYST")
    elif action == "KILL_PID":
        result = SOAREngine.terminate_process(payload.pid, payload.process_name or payload.target, executed_by="ANALYST")
    elif action == "BLOCK_IP":
        result = SOAREngine.block_c2_ip(payload.target, executed_by="ANALYST")
    elif action == "QUARANTINE_FILE":
        result = SOAREngine.quarantine_file(payload.target, executed_by="ANALYST")
    else:
        return {"status": "ERROR", "message": f"Unknown action: {action}"}

    await manager.broadcast({"type": "SOAR_ACTION", "data": result})
    return result

@app.post("/api/soar/toggle-auto")
def toggle_auto_soar():
    global AUTO_SOAR_ENABLED
    AUTO_SOAR_ENABLED = not AUTO_SOAR_ENABLED
    return {"status": "SUCCESS", "auto_soar_enabled": AUTO_SOAR_ENABLED}

@app.get("/api/soar/mode")
def get_soar_mode():
    return {"auto_soar_enabled": AUTO_SOAR_ENABLED}

@app.post("/api/simulate")
async def run_simulation(payload: SimulateRequest):
    results = []
    if payload.scenario == "ransomware":
        results = simulator.run_apt_scenario_ransomware(payload.host or "DESKTOP-WIN11-SEC")
    elif payload.scenario == "credential_theft":
        results = simulator.run_apt_scenario_credential_theft(payload.host or "SRV-DC01")
    else:
        results = [simulator.generate_normal_event()]

    # Broadcast newly created events and alerts
    for r in results:
        await manager.broadcast({"type": "EVENT", "data": r})
        if "alert" in r:
            await manager.broadcast({"type": "ALERT", "data": r["alert"]})
            trigger_autonomous_soar(r["alert"], r)

    return {"status": "SUCCESS", "scenario": payload.scenario, "events_generated": len(results)}

# --- Threat Intelligence Endpoints ---
@app.get("/api/threat-intel/lookup")
def lookup_threat_intel(indicator: str):
    return threat_intel.lookup(indicator)

# --- Active Deception & Canary Endpoints ---
@app.get("/api/deception/status")
def get_deception_status():
    return deception_engine.get_status()

@app.post("/api/deception/trip-test")
async def trigger_canary_trip_test(payload: TripTestRequest):
    res = deception_engine.simulate_tripwire(payload.filename or "passwords_backup_2026.docx")
    from datetime import datetime
    alert = {
        "title": f"Active Deception: Canary Honey-File [{payload.filename}] Tampered!",
        "severity": "CRITICAL",
        "category": "ACTIVE_DECEPTION",
        "description": "Adversary attempted unauthorized read/modify/encrypt operation against decoy honeypot file.",
        "mitre_tactic": "Defense Evasion / Impact",
        "mitre_technique": "T1486 (Data Encrypted for Impact)",
        "host": sensor_service.hostname,
        "process": "honeypot_tripwire.sys",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    await manager.broadcast({"type": "ALERT", "data": alert})
    trigger_autonomous_soar(alert, {})
    return res

@app.post("/api/deception/reset")
def reset_deception_canaries():
    return deception_engine.reset_canaries()

# --- Digital Forensics & Incident Response (DFIR) Evidence Vault ---
@app.get("/api/dfir/vault")
def list_dfir_vault():
    return dfir_engine.list_artifacts()

@app.get("/api/dfir/artifact/{artifact_id}")
def get_dfir_artifact_by_id(artifact_id: str):
    art = dfir_engine.get_artifact(artifact_id)
    if not art:
        return {"status": "NOT_FOUND", "message": f"Artifact {artifact_id} not found."}
    return art

@app.post("/api/dfir/dump-pid")
def dump_process_memory_forensics(payload: DumpPIDRequest):
    artifact = dfir_engine.capture_process_forensics(payload.pid, payload.process_name, payload.reason or "MANUAL_OPERATOR_DUMP")
    return {"status": "SUCCESS", "artifact": artifact}

# --- Threat Hunting & KQL Analytical Query Engine ---
@app.get("/api/hunting/prebuilt")
def get_hunting_prebuilt():
    return hunting_engine.get_prebuilt_queries()

@app.post("/api/hunting/query")
def execute_hunt_query(payload: HuntQueryRequest):
    return hunting_engine.execute_query(payload.query, payload.limit or 100)

# --- Multi-Agent Cognitive SOC Team ---
@app.get("/api/ai/agents")
def get_cognitive_ai_agents():
    return valkyrie_agent.get_multi_agent_hierarchy()

# --- Billion-Dollar Autonomous Defense & BAS Arena Endpoints ---
@app.get("/api/defense/isolation/status")
def get_isolation_status():
    return isolation_engine.get_status()

@app.post("/api/defense/isolation/engage")
async def engage_host_isolation(payload: IsolateHostRequest):
    res = isolation_engine.isolate_host(payload.host or "LOCAL", payload.reason or "MANUAL_OPERATOR_ENGAGE")
    await manager.broadcast({"type": "ISOLATION_UPDATE", "data": res})
    return res

@app.post("/api/defense/isolation/restore")
async def restore_host_isolation(payload: IsolateHostRequest):
    res = isolation_engine.restore_host(payload.host or "LOCAL", payload.reason or "ANALYST_REMEDIATION_CONFIRMED")
    await manager.broadcast({"type": "ISOLATION_UPDATE", "data": res})
    return res

@app.get("/api/defense/ransomware/status")
def get_ransomware_shield_status():
    return ransomware_shield.get_status()

@app.post("/api/defense/ransomware/suspend")
def suspend_ransomware_pid(payload: SuspendPIDRequest):
    return ransomware_shield.suspend_hostile_process(payload.pid, payload.process_name, payload.reason)

@app.post("/api/defense/ransomware/resume")
def resume_ransomware_pid(payload: SuspendPIDRequest):
    return ransomware_shield.resume_process(payload.pid)

@app.get("/api/defense/antitamper/status")
def get_antitamper_status():
    return antitamper_shield.get_status()

@app.get("/api/defense/quarantine/catalog")
def get_quarantine_catalog():
    return quarantine_vault.get_catalog()

@app.post("/api/defense/quarantine/isolate-file")
def isolate_quarantine_file(payload: QuarantineFileRequest):
    return quarantine_vault.quarantine_file(payload.filepath, payload.reason)

@app.get("/api/defense/bas/metrics")
def get_bas_metrics():
    return bas_engine.get_metrics()

@app.post("/api/defense/bas/run-test")
async def run_bas_test(payload: BASRunTestRequest):
    res = bas_engine.run_atomic_test(payload.scenario, payload.host or "DESKTOP-SEC-HOST")
    if res.get("status") == "SUCCESS":
        await manager.broadcast({"type": "BAS_INTERCEPTION", "data": res["result"]})
        # Broadcast the updated live battle attack graph with laser pulse flow!
        await manager.broadcast({"type": "GRAPH_UPDATE", "data": valkyrie_agent.build_attack_graph()})
    return res

# --- WebSocket Hub ---
@app.websocket("/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Send initial status
        dossier = valkyrie_agent.generate_incident_dossier()
        await websocket.send_text(json.dumps({
            "type": "INIT",
            "dossier": dossier,
            "graph": valkyrie_agent.build_attack_graph()
        }))
        while True:
            data = await websocket.receive_text()
            # Client can send ping or actions
            try:
                msg = json.loads(data)
                if msg.get("action") == "PING":
                    await websocket.send_text(json.dumps({"type": "PONG"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# --- Mount Static Frontend ---
FRONTEND_DIR = BASE_DIR / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
