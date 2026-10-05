"""
AEGIS-SOC Event Normalizer
Converts raw Windows Event Logs (EVTX/ETW/Sysmon/PowerShell) into unified OCSF/ECS compliant structures.
"""
from typing import Dict, Any
from datetime import datetime
import re

WINDOWS_SECURITY_EVENT_MAP = {
    4624: {"name": "Successful Logon", "severity": "INFO", "tactic": "Initial Access", "technique": "T1078 - Valid Accounts"},
    4625: {"name": "Failed Logon Attempt", "severity": "MEDIUM", "tactic": "Credential Access", "technique": "T1110 - Brute Force"},
    4672: {"name": "Special Privileges Assigned", "severity": "LOW", "tactic": "Privilege Escalation", "technique": "T1078 - Valid Accounts"},
    4698: {"name": "Scheduled Task Created", "severity": "HIGH", "tactic": "Persistence", "technique": "T1053.005 - Scheduled Task"},
    4720: {"name": "User Account Created", "severity": "MEDIUM", "tactic": "Persistence", "technique": "T1136 - Create Account"},
    4738: {"name": "User Account Modified", "severity": "MEDIUM", "tactic": "Persistence", "technique": "T1098 - Account Manipulation"},
    7045: {"name": "New Windows Service Installed", "severity": "HIGH", "tactic": "Persistence", "technique": "T1543.003 - Windows Service"},
    4776: {"name": "Domain Controller Credential Validation", "severity": "INFO", "tactic": "Credential Access", "technique": "T1110 - Brute Force"}
}

SYSMON_EVENT_MAP = {
    1: {"name": "Process Creation", "severity": "INFO", "tactic": "Execution", "technique": "T1059 - Command and Scripting Interpreter"},
    2: {"name": "Process Changed File Creation Time", "severity": "LOW", "tactic": "Defense Evasion", "technique": "T1070.006 - Timestomp"},
    3: {"name": "Network Connection Detected", "severity": "LOW", "tactic": "Command and Control", "technique": "T1071 - Application Layer Protocol"},
    7: {"name": "Image (DLL) Loaded", "severity": "INFO", "tactic": "Defense Evasion", "technique": "T1574 - Hijack Execution Flow"},
    8: {"name": "CreateRemoteThread Injected", "severity": "CRITICAL", "tactic": "Defense Evasion", "technique": "T1055 - Process Injection"},
    10: {"name": "ProcessAccess (LSASS/Target)", "severity": "HIGH", "tactic": "Credential Access", "technique": "T1003.001 - LSASS Memory"},
    11: {"name": "FileCreate (Dropped Binary)", "severity": "MEDIUM", "tactic": "Resource Development", "technique": "T1588 - Obtain Capabilities"},
    12: {"name": "Registry Object Added/Deleted", "severity": "LOW", "tactic": "Persistence", "technique": "T1112 - Modify Registry"},
    13: {"name": "Registry Value Set", "severity": "MEDIUM", "tactic": "Persistence", "technique": "T1547.001 - Registry Run Keys"},
    22: {"name": "DNSEvent (Query Resolved)", "severity": "INFO", "tactic": "Command and Control", "technique": "T1071.004 - DNS Beaconing"}
}

def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform raw event data into normalized AEGIS schema.
    """
    channel = raw.get("Channel") or raw.get("channel", "Security")
    event_id = int(raw.get("EventID") or raw.get("event_id", 0))
    ts = raw.get("TimeCreated") or raw.get("timestamp") or (datetime.utcnow().isoformat() + "Z")
    computer = raw.get("Computer") or raw.get("computer", "DESKTOP-SEC-NODE1")
    
    # Defaults
    severity = "INFO"
    tactic = ""
    technique = ""
    process_name = raw.get("process_name") or raw.get("Image", "")
    process_id = raw.get("process_id") or raw.get("ProcessId", 0)
    parent_process = raw.get("parent_process") or raw.get("ParentImage", "")
    command_line = raw.get("command_line") or raw.get("CommandLine", "")
    user = raw.get("user") or raw.get("User", "")
    src_ip = raw.get("src_ip") or raw.get("SourceIp", "")
    dest_ip = raw.get("dest_ip") or raw.get("DestinationIp", "")
    dest_port = raw.get("dest_port") or raw.get("DestinationPort", 0)
    hashes = raw.get("hashes") or raw.get("Hashes", "")

    # Check Windows Security Map
    if event_id in WINDOWS_SECURITY_EVENT_MAP:
        meta = WINDOWS_SECURITY_EVENT_MAP[event_id]
        severity = meta["severity"]
        tactic = meta["tactic"]
        technique = meta["technique"]
    
    # Check Sysmon Map
    elif "Sysmon" in channel and event_id in SYSMON_EVENT_MAP:
        meta = SYSMON_EVENT_MAP[event_id]
        severity = meta["severity"]
        tactic = meta["tactic"]
        technique = meta["technique"]

    # Check PowerShell ScriptBlock 4104
    elif event_id == 4104 or "PowerShell" in channel:
        severity = "MEDIUM"
        tactic = "Execution"
        technique = "T1059.001 - PowerShell Script"
        # Check for obfuscated payloads or AMSI bypass
        script_block = str(raw.get("ScriptBlockText", "") or command_line)
        if any(bad in script_block.lower() for bad in ["bypass", "hidden", "invoke-expression", "iex", "frombase64string", "downloadstring", "mimikatz", "rundll32"]):
            severity = "HIGH"
            technique = "T1027 - Obfuscated Files or Information"

    # Suspicious LOLBAS or Process Execution Heuristics
    lower_cmd = command_line.lower()
    lower_proc = process_name.lower()

    if any(lolbin in lower_proc for lolbin in ["certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "vssadmin.exe", "wmic.exe"]):
        severity = "HIGH"
        tactic = "Defense Evasion"
        technique = "T1218 - System Binary Proxy Execution"
    
    # Ransomware canary: vssadmin delete shadows
    if "vssadmin" in lower_cmd and "delete" in lower_cmd and "shadows" in lower_cmd:
        severity = "CRITICAL"
        tactic = "Impact"
        technique = "T1490 - Inhibit System Recovery"

    # Mimikatz or LSASS dump flags
    if "sekurlsa" in lower_cmd or "lsass" in lower_cmd and ("procdump" in lower_cmd or "rundll32" in lower_cmd):
        severity = "CRITICAL"
        tactic = "Credential Access"
        technique = "T1003.001 - OS Credential Dumping"

    return {
        "timestamp": ts,
        "channel": channel,
        "event_id": event_id,
        "computer": computer,
        "user": user or "SYSTEM",
        "process_name": process_name,
        "process_id": int(process_id) if process_id else 0,
        "parent_process": parent_process,
        "command_line": command_line,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": int(dest_port) if dest_port else 0,
        "hashes": hashes,
        "severity": severity,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "raw_data": raw
    }
