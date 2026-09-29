import re
import json
from datetime import datetime
from typing import Optional
from core.models import NormalizedEvent
from core.enricher import GeoIPEnricher
from parsers.base import BaseLogParser


class WindowsLogParser(BaseLogParser):
    """
    Parser for Windows Security Event Logs and Sysmon records.
    Extracts Event ID 4625 (Logon Failure), 4624 (Logon Success), and 4672 (Admin Escalation).
    """

    def __init__(self, enricher: Optional[GeoIPEnricher] = None):
        self.enricher = enricher or GeoIPEnricher()

    def can_parse(self, sample_line: str) -> bool:
        indicators = ["Microsoft-Windows-Security-Auditing", "EventID", "4624", "4625", "4672", "WinEventLog"]
        return any(ind in sample_line for ind in indicators)

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        # 1. Try parsing JSON format (e.g. Winlogbeat or modern SIEM export)
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                event_id = str(data.get("EventID") or data.get("event_id") or data.get("winlog", {}).get("event_id"))
                ts_str = data.get("TimeCreated") or data.get("@timestamp")
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) if ts_str else datetime.utcnow()
                ip = data.get("IpAddress") or data.get("source_ip") or "127.0.0.1"
                user = data.get("TargetUserName") or data.get("user") or "SYSTEM"

                action = "login"
                status = "success"
                if event_id == "4625":
                    status = "failure"
                elif event_id == "4672":
                    action = "privilege_escalation"

                intel = self.enricher.enrich(ip)
                return NormalizedEvent(
                    timestamp=dt,
                    log_source="windows",
                    source_ip=ip,
                    user=user,
                    action=action,
                    status=status,
                    details={"event_id": event_id, "sub_status": data.get("SubStatus")},
                    raw_log=line,
                    geo_country=intel.country,
                    geo_country_code=intel.country_code,
                    geo_city=intel.city,
                    geo_lat=intel.lat,
                    geo_lon=intel.lon,
                    threat_score=intel.threat_score
                )
            except Exception:
                pass

        # 2. Structured text line format:
        # Example: 2026-09-29 10:14:02 WIN-DC01 Security-Auditing[4625]: An account failed to log on. User: administrator IP: 198.51.100.42
        dt = datetime.utcnow()
        ts_m = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
        if ts_m:
            try:
                dt = datetime.strptime(ts_m.group(1).replace("T", " "), "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass

        event_id_m = re.search(r"\[?(\d{4})\]?:", line)
        event_id = event_id_m.group(1) if event_id_m else "4625"

        ip_m = re.search(r"(?:IP|Address|Source Network Address):\s*([0-9\.]+)", line, re.IGNORECASE)
        ip = ip_m.group(1) if ip_m else "127.0.0.1"

        user_m = re.search(r"(?:User|Account Name|Target User):\s*([^\s,]+)", line, re.IGNORECASE)
        user = user_m.group(1) if user_m else "UnknownUser"

        status = "failure" if "failed" in line.lower() or event_id == "4625" else "success"
        action = "privilege_escalation" if event_id == "4672" else "login"

        intel = self.enricher.enrich(ip)
        return NormalizedEvent(
            timestamp=dt,
            log_source="windows",
            source_ip=ip,
            user=user,
            action=action,
            status=status,
            details={"event_id": event_id},
            raw_log=line,
            geo_country=intel.country,
            geo_country_code=intel.country_code,
            geo_city=intel.city,
            geo_lat=intel.lat,
            geo_lon=intel.lon,
            threat_score=intel.threat_score
        )
