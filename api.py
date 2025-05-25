"""
FastAPI web interface for WiFi Marauder functionality.
"""
import subprocess
import select
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from kit.iface import detect_interfaces, toggle_monitor_mode
from kit.scan import ScanManager
from kit.attacks import build_deauth_cmd, start_deauth, stop_attack, build_packet, send_packet
from kit.crack import CrackManager
from kit.db import DatabaseManager
from kit.analytics import count_vendors, count_handshakes, count_attacks

app = FastAPI(
    title="WiFi Marauder API",
    openapi_url="/api/openapi.json",
    docs_url="/api/docs",
    redoc_url=None
)
# Serve web dashboard static files
app.mount("/static", StaticFiles(directory="web/static"), name="static")

@app.get("/", include_in_schema=False)
def get_dashboard():
    return FileResponse("web/index.html")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize managers
db = DatabaseManager()
scan_manager = ScanManager(db)
crack_manager = CrackManager(db)

# Processes
deauth_proc = None
handshake_proc = None
evilap_proc = None
fakeauth_proc = None
mdk4_proc = None
wash_proc = None
reaver_proc = None

class MonitorRequest(BaseModel):
    interface: str

class ScanRequest(BaseModel):
    interface: str
    duration: int

class DeauthRequest(BaseModel):
    interface: str
    bssid: str
    client: str = ""
    count: int = 5

class HandshakeRequest(BaseModel):
    interface: str
    bssid: str

class CrackRequest(BaseModel):
    handshake_file: str
    wordlist_file: str

class EvilAPRequest(BaseModel):
    essid: str
    password: str = ""

class FakeAuthRequest(BaseModel):
    interface: str
    bssid: str
    client: str = ""

class MDK4Request(BaseModel):
    interface: str
    bssid: str
    mode: str
    intensity: int = 5

@app.get("/interfaces", tags=["API"])
def api_interfaces():
    """List all detected wireless interfaces."""
    return {"interfaces": detect_interfaces()}

@app.post("/monitor-mode", tags=["API"])
def api_monitor_mode(req: MonitorRequest):
    """Enable monitor mode on the specified interface."""
    if not toggle_monitor_mode(req.interface):
        raise HTTPException(status_code=500, detail="Failed to enable monitor mode")
    return {"success": True}

@app.post("/scan/start")
def api_scan_start(req: ScanRequest):
    if not scan_manager.start(req.interface, req.duration):
        raise HTTPException(status_code=500, detail="Failed to start scan")
    return {"success": True}

@app.get("/scan/progress")
def api_scan_progress():
    elapsed, pct = scan_manager.progress()
    return {"elapsed": elapsed, "percent": pct}

@app.post("/scan/stop")
def api_scan_stop():
    scan_manager.stop()
    nets = scan_manager.record(scan_manager.interface) or []
    return {"networks": nets}

@app.get("/scan/logs")
def api_scan_logs():
    logs = db.get_scan_logs()
    return {"logs": logs}
@app.get("/scan/raw")
def api_scan_raw():
    """Return raw airodump-ng output log."""
    log_file = scan_manager.log_file
    if log_file and os.path.exists(log_file):
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            data = f.read()
        return {"raw": data}
    else:
        raise HTTPException(status_code=404, detail="Raw log not found")

@app.post("/attack/deauth/start")
def api_deauth_start(req: DeauthRequest):
    global deauth_proc
    deauth_proc = start_deauth(req.interface, req.bssid, req.client, req.count)
    return {"success": True}

@app.post("/attack/deauth/stop")
def api_deauth_stop():
    global deauth_proc
    stop_attack(deauth_proc)
    return {"success": True}

@app.post("/attack/handshake/start")
def api_handshake_start(req: HandshakeRequest):
    global handshake_proc
    handshake_proc = start_deauth(req.interface, req.bssid, '', 0)
    return {"success": True}

@app.post("/attack/handshake/stop")
def api_handshake_stop():
    global handshake_proc
    stop_attack(handshake_proc)
    return {"success": True}

@app.post("/attack/crack/start")
def api_crack_start(req: CrackRequest):
    if not crack_manager.start(req.handshake_file, req.wordlist_file):
        raise HTTPException(status_code=500, detail="Failed to start cracking")
    return {"success": True}

@app.get("/attack/crack/progress")
def api_crack_progress():
    attempts, total, key, done = crack_manager.progress()
    return {"attempts": attempts, "total": total, "key": key, "done": done}

@app.post("/attack/crack/stop")
def api_crack_stop():
    crack_manager.stop()
    return {"success": True}

@app.get("/attack/analytics")
def api_analytics():
    vendors = count_vendors(db.get_scan_logs(), lambda b: b)
    caps = db.get_all_captures()
    deauths = db.get_all_deauths()
    decoys = db.get_all_decoy_activities()
    return {
        "vendors": vendors,
        "handshakes": count_handshakes(caps),
        "attacks": count_attacks(deauths, caps, decoys)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)