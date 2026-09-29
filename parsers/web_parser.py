import re
import urllib.parse
from datetime import datetime
from typing import Optional
from core.models import NormalizedEvent
from core.enricher import GeoIPEnricher
from parsers.base import BaseLogParser


class WebLogParser(BaseLogParser):
    """
    Parser for Nginx & Apache web access logs in Combined and Common Log Format.
    Decodes URL encoding and identifies HTTP methods, paths, status codes, and User-Agents.
    """

    def __init__(self, enricher: Optional[GeoIPEnricher] = None):
        self.enricher = enricher or GeoIPEnricher()

        # Regex for Combined Log Format:
        # 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com" "Mozilla/4.08"
        self.regex_combined = re.compile(
            r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[\d\.]+)?(?:")?\s+(\d{3})\s+(\d+|-)(?:\s+"([^"]*)"\s+"([^"]*)")?'
        )

        # Regex for Common Log Format (fallback without referrer & user agent):
        self.regex_common = re.compile(
            r'^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)(?:\s+HTTP/[\d\.]+)?(?:")?\s+(\d{3})\s+(\d+|-)'
        )

    def can_parse(self, sample_line: str) -> bool:
        indicators = ["HTTP/1.0\"", "HTTP/1.1\"", "HTTP/2.0\"", "GET ", "POST ", "HEAD ", "OPTIONS "]
        return any(ind in sample_line for ind in indicators) and "[" in sample_line and "]" in sample_line

    def _parse_web_timestamp(self, ts_str: str) -> datetime:
        # Example: 29/Sep/2026:10:14:02 +0000 or without timezone
        try:
            # Clean possible brackets or extra whitespace
            clean_ts = ts_str.split()[0] if " " in ts_str else ts_str
            # Extract datetime before timezone offset if present
            if len(ts_str.split()) > 1:
                return datetime.strptime(ts_str[:20], "%d/%b/%Y:%H:%M:%S")
            return datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        except Exception:
            return datetime.utcnow()

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        match = self.regex_combined.match(line)
        has_extended = True
        if not match:
            match = self.regex_common.match(line)
            has_extended = False

        if not match:
            # Fallback simple extractor for malformed web requests
            simple_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*"([A-Z]+)\s+(/[^\s"]*).*"\s+(\d{3})', line)
            if simple_match:
                ip = simple_match.group(1)
                method = simple_match.group(2)
                raw_path = simple_match.group(3)
                status_code = int(simple_match.group(4))
                unquoted_path = urllib.parse.unquote_plus(raw_path)
                intel = self.enricher.enrich(ip)
                return NormalizedEvent(
                    timestamp=datetime.utcnow(),
                    log_source="web",
                    source_ip=ip,
                    user=None,
                    action="http_request",
                    status="success" if status_code < 400 else "failure",
                    details={
                        "method": method,
                        "path": unquoted_path,
                        "raw_path": raw_path,
                        "status_code": status_code,
                        "user_agent": "Unknown"
                    },
                    raw_log=line,
                    geo_country=intel.country,
                    geo_country_code=intel.country_code,
                    geo_city=intel.city,
                    geo_lat=intel.lat,
                    geo_lon=intel.lon,
                    threat_score=intel.threat_score
                )
            return None

        ip = match.group(1)
        raw_user = match.group(2)
        user = raw_user if raw_user != "-" else None
        ts_raw = match.group(3)
        dt = self._parse_web_timestamp(ts_raw)
        method = match.group(4)
        raw_path = match.group(5)
        status_code = int(match.group(6))
        bytes_sent = int(match.group(7)) if match.group(7) != "-" else 0

        referrer = match.group(8) if has_extended and match.lastindex >= 8 else None
        user_agent = match.group(9) if has_extended and match.lastindex >= 9 else None

        # Decode path to catch encoded attacks (e.g. %27 OR 1=1, %2e%2e%2f)
        try:
            unquoted_path = urllib.parse.unquote_plus(raw_path)
        except Exception:
            unquoted_path = raw_path

        intel = self.enricher.enrich(ip)
        return NormalizedEvent(
            timestamp=dt,
            log_source="web",
            source_ip=ip,
            user=user,
            action="http_request",
            status="success" if status_code < 400 else "failure",
            details={
                "method": method,
                "path": unquoted_path,
                "raw_path": raw_path,
                "status_code": status_code,
                "bytes_sent": bytes_sent,
                "referrer": referrer,
                "user_agent": user_agent or "Standard Client"
            },
            raw_log=line,
            geo_country=intel.country,
            geo_country_code=intel.country_code,
            geo_city=intel.city,
            geo_lat=intel.lat,
            geo_lon=intel.lon,
            threat_score=intel.threat_score
        )
