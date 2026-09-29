import os
# pyrefly: ignore [missing-import]
import uvicorn
import yaml
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

from core.database import Database
from core.enricher import GeoIPEnricher
from core.alerter import AlertDispatcher
from core.engine import DetectionEngine
from core.simulator import AttackSimulator
from parsers import AutoLogParser

app = FastAPI(title="SOC Sentinel - Intrusion Detection & Log Analysis System", version="1.0.1")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core components
enricher = GeoIPEnricher()
database = Database()
alerter = AlertDispatcher()
engine = DetectionEngine(config_path="config/rules.yaml", db=database, alerter=alerter, enricher=enricher)
parser = AutoLogParser(enricher=enricher)
simulator = AttackSimulator(parser=parser, engine=engine)

# Static files
os.makedirs("static", exist_ok=True)
os.makedirs("static/css", exist_ok=True)
os.makedirs("static/js", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")


# Pydantic schemas for request validation
class IngestTextRequest(BaseModel):
    log_text: str
    source: Optional[str] = None  # "ssh", "web", "windows", or None for auto-detect

class UpdateStatusRequest(BaseModel):
    status: str  # "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"

class BlockIPRequest(BaseModel):
    ip: str
    reason: str
    severity: Optional[str] = "HIGH"

class UnblockIPRequest(BaseModel):
    ip: str

class DiscordTestRequest(BaseModel):
    webhook_url: str

class SaveRulesRequest(BaseModel):
    yaml_content: str


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join("static", "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h2>SOC Sentinel Dashboard initializing...</h2>")


@app.get("/api/stats")
async def get_stats():
    """Retrieve summarized SOC statistics, top attackers, and MITRE distributions."""
    return database.get_dashboard_stats()


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(100, ge=1, le=500),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None)
):
    """Retrieve security alerts with optional severity and triage status filters."""
    return database.get_alerts(limit=limit, severity=severity, status=status)


@app.post("/api/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, req: UpdateStatusRequest):
    """Update SOC triage status for a specific alert."""
    success = database.update_alert_status(alert_id, req.status)
    if not success:
        raise HTTPException(status_code=404, detail="Alert ID not found")
    return {"status": "success", "alert_id": alert_id, "new_status": req.status}


@app.get("/api/events")
async def get_events(
    limit: int = Query(100, ge=1, le=500),
    source_ip: Optional[str] = Query(None),
    log_source: Optional[str] = Query(None),
    status: Optional[str] = Query(None)
):
    """Retrieve normalized logs with filter capabilities."""
    return database.get_events(limit=limit, source_ip=source_ip, log_source=log_source, status=status)


@app.get("/api/blocklist")
async def get_blocklist():
    """Retrieve active and historical firewall blocked IP addresses."""
    return database.get_blocked_ips()


@app.post("/api/blocklist/block")
async def block_ip(req: BlockIPRequest):
    """Manually add an IP to the active firewall blocklist."""
    result = database.block_ip(req.ip, req.reason, req.severity)
    return {"status": "success", "blocked": result}


@app.post("/api/blocklist/unblock")
async def unblock_ip(req: UnblockIPRequest):
    """Unblock an IP address from the firewall."""
    success = database.unblock_ip(req.ip)
    if not success:
        raise HTTPException(status_code=404, detail="IP was not found in blocklist")
    return {"status": "success", "ip": req.ip}


@app.get("/api/blocklist/export")
async def export_blocklist():
    """Export an automated Linux bash script containing iptables commands to drop blocked IPs."""
    blocked = database.get_blocked_ips()
    active_ips = [b["ip"] for b in blocked if b["active"]]

    lines = [
        "#!/usr/bin/env bash",
        "# SOC Sentinel IDS - Automated Firewall Mitigation Rules",
        f"# Generated: {database.get_dashboard_stats()['total_alerts']} Total Alerts Tracked",
        "",
        "echo '[+] Applying SOC Sentinel Active Defense Firewall Rules...'",
        ""
    ]
    for ip in active_ips:
        lines.append(f"iptables -C INPUT -s {ip} -j DROP 2>/dev/null || iptables -A INPUT -s {ip} -j DROP")

    lines.append("")
    lines.append("echo '[✓] All malicious IP mitigation rules successfully enacted.'")
    return PlainTextResponse("\n".join(lines), media_type="text/x-shellscript")


@app.post("/api/ingest/text")
async def ingest_text(req: IngestTextRequest):
    """Parses and analyzes raw text log lines directly."""
    events = parser.parse_text(req.log_text, forced_source=req.source)
    if not events:
        return {"status": "warning", "message": "No valid log patterns recognized in input", "events_parsed": 0, "alerts_fired": 0}

    alerts = engine.process_events(events)
    return {
        "status": "success",
        "events_parsed": len(events),
        "alerts_fired": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    }


@app.post("/api/ingest/file")
async def ingest_file(file: UploadFile = File(...), source: Optional[str] = Form(None)):
    """Uploads and analyzes a .log, .txt, or Syslog file."""
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    events = parser.parse_text(text, forced_source=source if source != "auto" else None)
    alerts = engine.process_events(events)

    return {
        "status": "success",
        "filename": file.filename,
        "events_parsed": len(events),
        "alerts_fired": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    }


@app.get("/api/rules")
async def get_rules():
    """Returns raw YAML configuration content and parsed rules."""
    try:
        with open("config/rules.yaml", "r", encoding="utf-8") as f:
            raw = f.read()
        return {"yaml_content": raw, "rules": engine.rules, "settings": engine.settings}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/rules/save")
async def save_rules(req: SaveRulesRequest):
    """Validates and persists updated detection rules YAML configuration."""
    try:
        engine.reload_rules(req.yaml_content)
        return {"status": "success", "message": "Rules updated and reloaded into engine successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML structure: {str(e)}")


@app.post("/api/simulate/{scenario}")
async def run_simulation(scenario: str):
    """Executes a realistic cyber attack scenario against the detection pipeline."""
    scenarios = {
        "ssh_brute": simulator.simulate_ssh_bruteforce,
        "password_spray": simulator.simulate_password_spray,
        "compromise": simulator.simulate_compromise_after_brute,
        "impossible_travel": simulator.simulate_impossible_travel,
        "web_sqli_xss": simulator.simulate_web_sqli_and_xss,
        "web_directory_bust": simulator.simulate_web_directory_bust,
        "privilege_escalation": simulator.simulate_privilege_escalation
    }

    if scenario not in scenarios:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose from: {list(scenarios.keys())}")

    alerts = scenarios[scenario]()
    return {
        "status": "success",
        "scenario": scenario,
        "alerts_triggered": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    }


@app.post("/api/alerter/test-discord")
async def test_discord(req: DiscordTestRequest):
    """Sends a verification test embed to a specified Discord Webhook URL."""
    success = alerter.send_test_discord(req.webhook_url)
    if not success:
        raise HTTPException(status_code=400, detail="Failed to deliver message to Discord webhook")
    return {"status": "success", "message": "Discord test alert delivered successfully"}


@app.post("/api/clear")
async def clear_database():
    """Clears all stored events, alerts, and firewall entries for a fresh demonstration."""
    database.clear_all()
    # Reset engine memory
    engine.failures_by_ip.clear()
    engine.user_login_history.clear()
    engine.requests_404_by_ip.clear()
    engine.alert_cooldowns.clear()
    return {"status": "success", "message": "SOC Sentinel database and correlation cache cleared"}


if __name__ == "__main__":
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=True)
