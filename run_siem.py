"""
AEGIS-SOC Launch Runner
Starts the backend FastAPI server and serves the Cyber War Room Dashboard.
"""
import sys
import uvicorn
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

BANNER = """
   ___    ____ _____ _____ ____       ____ ___   ____ 
  / _ \  | ____/ ___ |_   _/ ___|     / ___/ _ \ / ___|
 / /_\ \ |  _|| |  _   | | \___ \ ___| |  | | | | |    
/ /   \ \| |__| |_| |  | |  ___) |___| |__| |_| | |___ 
\/     \/|_____\____|  |_| |____/     \____\___/ \____|
                                                       
 >> Autonomous Windows Threat Defense & Neural SOC Platform <<
 [!] High-Throughput Event Engine Online
 [!] VALKYRIE AI Autonomous Analyst Ready
 [!] Sigma & Behavioral Detection Active
 [!] Cyber War Room UI: http://localhost:8000
"""

if __name__ == "__main__":
    print(BANNER)
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
