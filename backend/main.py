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

    # Auto-Kill Malicious Process
    if pid and pid > 4:
        logger.warning("[AUTOPILOT SOAR] Auto-terminating rogue PID %s [%s] on %s", pid, proc_name, host)
        action_res = SOAREngine.terminate_process(pid=pid, process_name=proc_name, host=host, executed_by="VALKYRIE-AUTOPILOT")
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "SOAR_ACTION", "data": action_res}), loop)

    # Auto-Isolate on Active Ransomware / Breach
    if "Ransomware" in title or "Cobalt Strike" in title:
        logger.warning("[AUTOPILOT SOAR] Auto-isolating host %s due to %s", host, title)
        iso_res = SOAREngine.isolate_host(host=host, executed_by="VALKYRIE-AUTOPILOT")
        if loop and loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast({"type": "SOAR_ACTION", "data": iso_res}), loop)

# Hook sensor to broadcast directly through asyncio loop
loop = None

def sensor_event_callback(msg: Dict[str, Any]):
    global loop
    if loop and loop.is_running():
        asyncio.run_coroutine_threadsafe(manager.broadcast(msg), loop)
        if msg.get("type") == "ALERT":
            trigger_autonomous_soar(msg["data"], {})

@app.on_event("startup")
async def startup_event():
    global loop
    loop = asyncio.get_running_loop()
    sensor_service.callback = sensor_event_callback
    sensor_service.start()
    logger.info("AEGIS-SOC Real Windows Sensor initialized and linked to WebSocket.")

@app.on_event("shutdown")
def shutdown_event():
    sensor_service.stop()

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
