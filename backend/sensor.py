"""
AEGIS-SOC Real Live Windows Telemetry & Event Sensor
Directly hooks into native Windows Event Logs (System/Application via win32evtlog)
and live OS process and network socket telemetry (via psutil).
"""
import sys
import time
import socket
import platform
import threading
import logging
from datetime import datetime
from typing import Callable, Optional, Dict, Any, List

import psutil
try:
    import win32evtlog
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

from backend.normalizer import normalize_event
from backend.database import insert_event
from backend.detection_engine import engine as detection_engine

logger = logging.getLogger("aegis.sensor")

class RealWindowsSensor:
    def __init__(self, callback: Optional[Callable] = None):
        self.running = False
        self.callback = callback
        self.thread: Optional[threading.Thread] = None
        self.hostname = socket.gethostname()
        self.os_info = platform.platform()
        self.last_record_numbers = {"System": 0, "Application": 0}
        self.known_pids = set()

    def start(self):
        if self.running:
            return
        self.running = True
        # Initialize baseline known PIDs
        try:
            self.known_pids = set(psutil.pids())
        except Exception:
            self.known_pids = set()

        self.thread = threading.Thread(target=self._live_telemetry_loop, daemon=True)
        self.thread.start()
        logger.info("[LIVE SENSOR] Real Windows Telemetry Engine started for host %s (%s)", self.hostname, self.os_info)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
        logger.info("[LIVE SENSOR] Real Windows Telemetry Engine stopped.")

    def get_host_telemetry(self) -> Dict[str, Any]:
        """Returns real-time host status from the actual Windows operating system."""
        try:
            cpu_usage = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            pids = psutil.pids()
            connections = psutil.net_connections(kind='inet')
            return {
                "hostname": self.hostname,
                "os": self.os_info,
                "cpu_percent": cpu_usage,
                "ram_percent": mem.percent,
                "ram_used_gb": round(mem.used / (1024**3), 2),
                "ram_total_gb": round(mem.total / (1024**3), 2),
                "total_processes": len(pids),
                "active_connections": len(connections),
                "sensor_mode": "REAL_LIVE_WINDOWS"
            }
        except Exception as e:
            return {
                "hostname": self.hostname,
                "os": self.os_info,
                "error": str(e),
                "sensor_mode": "REAL_LIVE_WINDOWS"
            }

    def force_audit(self) -> Dict[str, Any]:
        """Forces an immediate sweep of all active processes, network sockets, and event logs."""
        try:
            self._harvest_live_processes()
            self._harvest_live_network_connections()
            if HAS_WIN32:
                self._harvest_windows_event_logs("System")
                self._harvest_windows_event_logs("Application")
        except Exception as e:
            logger.error("Force audit error: %s", e)
        return self.get_host_telemetry()

    def _live_telemetry_loop(self):
        """Continuously harvests real live Windows Event Logs and OS processes."""
        loop_counter = 0

        while self.running:
            try:
                loop_counter += 1

                # 1. Pull Real Windows Event Logs (System & Application channels)
                if HAS_WIN32:
                    self._harvest_windows_event_logs("System")
                    self._harvest_windows_event_logs("Application")

                # 2. Inspect Live Process Activity (New or Active Processes)
                self._harvest_live_processes()

                # 3. Sample Live Network Sockets
                if loop_counter % 3 == 0:
                    self._harvest_live_network_connections()

            except Exception as e:
                logger.error("[LIVE SENSOR ERROR] %s", e)

            time.sleep(2.0)

    def _harvest_windows_event_logs(self, channel: str):
        """Reads real live records from Windows Event Log."""
        try:
            h = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(h, flags, 0)
            win32evtlog.CloseEventLog(h)

            if not records:
                return

            # Process the latest 2 records
            for r in records[:2]:
                record_id = r.RecordNumber
                if self.last_record_numbers[channel] and record_id <= self.last_record_numbers[channel]:
                    continue

                event_id = r.EventID & 0xFFFF
                source_name = r.SourceName
                time_gen = str(r.TimeGenerated) if r.TimeGenerated else datetime.utcnow().isoformat()
                strings = r.StringInserts or ()
                details = " // ".join(str(s) for s in strings[:4]) if strings else f"Event from {source_name}"

                raw_event = {
                    "channel": f"Windows-{channel}",
                    "event_id": event_id,
                    "computer": r.ComputerName or self.hostname,
                    "user": "SYSTEM" if r.EventType == 4 else "LOCAL SERVICE",
                    "process_name": source_name,
                    "command_line": details[:350],
                    "timestamp": time_gen + "Z" if not time_gen.endswith("Z") else time_gen,
                    "raw_data": {
                        "RecordNumber": record_id,
                        "SourceName": source_name,
                        "EventType": r.EventType,
                        "Strings": strings[:5]
                    }
                }

                self.last_record_numbers[channel] = max(self.last_record_numbers[channel], record_id)
                self._dispatch_event(raw_event)

        except Exception as e:
            logger.debug("Event log read note (%s): %s", channel, e)

    def _harvest_live_processes(self):
        """Samples real live running processes from this Windows computer."""
        try:
            current_pids = set(psutil.pids())
            new_pids = current_pids - self.known_pids

            # If new processes were launched on Windows, process them
            target_pids = list(new_pids) if new_pids else []
            
            # If no new PIDs, periodically sample active processes for live visibility
            if not target_pids:
                all_pids = list(current_pids)
                if all_pids:
                    # Pick 1-2 active processes to report live heartbeat
                    import random
                    sample_pid = random.choice(all_pids)
                    target_pids = [sample_pid]

            self.known_pids = current_pids

            for pid in target_pids[:3]:
                if not psutil.pid_exists(pid) or pid <= 4:
                    continue
                try:
                    p = psutil.Process(pid)
                    p_info = p.as_dict(attrs=['pid', 'name', 'exe', 'cmdline', 'username', 'ppid'])
                    
                    cmd_line = " ".join(p_info.get('cmdline') or []) if p_info.get('cmdline') else (p_info.get('exe') or p_info.get('name') or '')
                    user = p_info.get('username') or 'SYSTEM'
                    
                    # Parent name
                    parent_name = ""
                    try:
                        if p_info.get('ppid') and psutil.pid_exists(p_info['ppid']):
                            parent_name = psutil.Process(p_info['ppid']).name()
                    except Exception:
                        pass

                    raw_event = {
                        "channel": "Microsoft-Windows-Sysmon/Operational",
                        "event_id": 1, # Process Creation
                        "computer": self.hostname,
                        "user": user,
                        "process_name": p_info.get('exe') or p_info.get('name') or 'unknown.exe',
                        "process_id": pid,
                        "parent_process": parent_name,
                        "command_line": cmd_line[:400],
                        "timestamp": datetime.utcnow().isoformat() + "Z",
                        "raw_data": {
                            "PID": pid,
                            "PPID": p_info.get('ppid'),
                            "Exe": p_info.get('exe')
                        }
                    }
                    self._dispatch_event(raw_event)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug("Process harvest note: %s", e)

    def _harvest_live_network_connections(self):
        """Samples real live outbound/listening network connections on this Windows host."""
        try:
            conns = psutil.net_connections(kind='inet')
            # Look for established external connections
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    rip = c.raddr.ip
                    rport = c.raddr.port
                    # Filter out local loopback 127.0.0.1
                    if rip not in ['127.0.0.1', '0.0.0.0', '::1']:
                        proc_name = "network.exe"
                        try:
                            if c.pid and psutil.pid_exists(c.pid):
                                proc_name = psutil.Process(c.pid).name()
                        except Exception:
                            pass

                        raw_event = {
                            "channel": "Microsoft-Windows-Sysmon/Operational",
                            "event_id": 3, # Network Connection Detected
                            "computer": self.hostname,
                            "user": "SYSTEM",
                            "process_name": proc_name,
                            "process_id": c.pid or 0,
                            "src_ip": c.laddr.ip if c.laddr else "127.0.0.1",
                            "dest_ip": rip,
                            "dest_port": rport,
                            "command_line": f"Active socket to {rip}:{rport} ({proc_name})",
                            "timestamp": datetime.utcnow().isoformat() + "Z",
                            "raw_data": {
                                "Status": c.status,
                                "LocalPort": c.laddr.port if c.laddr else 0
                            }
                        }
                        self._dispatch_event(raw_event)
                        break
        except Exception as e:
            logger.debug("Network harvest note: %s", e)

    def _dispatch_event(self, raw_dict: Dict[str, Any]):
        """Normalizes, evaluates against detection rules, and broadcasts."""
        norm = normalize_event(raw_dict)
        db_id = insert_event(norm)
        norm["id"] = db_id

        # Evaluate detection rules on real event
        alert = detection_engine.evaluate(norm, db_id)

        if self.callback:
            self.callback({"type": "EVENT", "data": norm})
            if alert:
                self.callback({"type": "ALERT", "data": alert})

sensor_service = RealWindowsSensor()
