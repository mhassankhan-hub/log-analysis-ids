import re
from datetime import datetime
from typing import Optional
from core.models import NormalizedEvent
from core.enricher import GeoIPEnricher
from parsers.base import BaseLogParser


class SSHLogParser(BaseLogParser):
    """
    Parser for Linux SSH and authentication logs (/var/log/auth.log, /var/log/secure).
    Extracts failed/accepted logins, invalid users, and sudo privilege escalation commands.
    """

    def __init__(self, enricher: Optional[GeoIPEnricher] = None):
        self.enricher = enricher or GeoIPEnricher()

        # Regular expressions for SSH log events
        self.regex_failed_pwd = re.compile(
            r"Failed (?:password|none) for (?:invalid user )?([^\s]+) from ([\d\.]+|[0-9a-fA-F:]+) port (\d+) ssh2"
        )
        self.regex_accepted = re.compile(
            r"Accepted (?:password|publickey) for ([^\s]+) from ([\d\.]+|[0-9a-fA-F:]+) port (\d+) ssh2"
        )
        self.regex_invalid_user = re.compile(
            r"Invalid user ([^\s]+) from ([\d\.]+|[0-9a-fA-F:]+) port (\d+)"
        )
        self.regex_sudo = re.compile(
            r"sudo:\s+([^\s]+)\s+:.*?COMMAND=(.+)$"
        )
        self.regex_session_opened = re.compile(
            r"session opened for user ([^\s]+) by \(uid=\d+\)"
        )

    Tuple_Datetime_And_Remainder = None
    def _parse_timestamp(self, line: str) -> Tuple_Datetime_And_Remainder:
        pass

    def can_parse(self, sample_line: str) -> bool:
        indicators = ["sshd[", "sudo:", "pam_unix(", "authentication failure", "Failed password", "Accepted password"]
        return any(ind in sample_line for ind in indicators)

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        line = line.strip()
        if not line:
            return None

        # 1. Parse Timestamp
        # Standard syslog: Sep 29 10:14:02 hostname sshd[1234]: ...
        # Or ISO-8601: 2026-09-29T10:14:02.123456+00:00 hostname sshd[1234]: ...
        dt = None
        iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+", line)
        if iso_match:
            try:
                raw_ts = iso_match.group(1).replace("Z", "+00:00")
                if "." in raw_ts:
                    dt = datetime.fromisoformat(raw_ts)
                else:
                    dt = datetime.strptime(raw_ts[:19], "%Y-%m-%d %H:%M:%S" if " " in raw_ts else "%Y-%m-%dT%H:%M:%S")
            except Exception:
                dt = datetime.utcnow()
        else:
            syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+", line)
            if syslog_match:
                try:
                    current_year = datetime.utcnow().year
                    ts_str = f"{current_year} {syslog_match.group(1)}"
                    # Handle multiple spaces in day, e.g. "Sep  9 10:14:02"
                    ts_str = re.sub(r"\s+", " ", ts_str)
                    dt = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                except Exception:
                    dt = datetime.utcnow()

        if not dt:
            dt = datetime.utcnow()

        # 2. Match Failed Password
        match = self.regex_failed_pwd.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            port = int(match.group(3))
            intel = self.enricher.enrich(ip)
            return NormalizedEvent(
                timestamp=dt,
                log_source="ssh",
                source_ip=ip,
                user=user,
                action="login",
                status="failure",
                details={"port": port, "mechanism": "password", "reason": "invalid_credentials"},
                raw_log=line,
                geo_country=intel.country,
                geo_country_code=intel.country_code,
                geo_city=intel.city,
                geo_lat=intel.lat,
                geo_lon=intel.lon,
                threat_score=intel.threat_score
            )

        # 3. Match Accepted Password/Publickey
        match = self.regex_accepted.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            port = int(match.group(3))
            intel = self.enricher.enrich(ip)
            return NormalizedEvent(
                timestamp=dt,
                log_source="ssh",
                source_ip=ip,
                user=user,
                action="login",
                status="success",
                details={"port": port, "mechanism": "accepted_key_or_password"},
                raw_log=line,
                geo_country=intel.country,
                geo_country_code=intel.country_code,
                geo_city=intel.city,
                geo_lat=intel.lat,
                geo_lon=intel.lon,
                threat_score=intel.threat_score
            )

        # 4. Match Invalid User attempt
        match = self.regex_invalid_user.search(line)
        if match:
            user = match.group(1)
            ip = match.group(2)
            port = int(match.group(3))
            intel = self.enricher.enrich(ip)
            return NormalizedEvent(
                timestamp=dt,
                log_source="ssh",
                source_ip=ip,
                user=user,
                action="login",
                status="failure",
                details={"port": port, "reason": "non_existent_user"},
                raw_log=line,
                geo_country=intel.country,
                geo_country_code=intel.country_code,
                geo_city=intel.city,
                geo_lat=intel.lat,
                geo_lon=intel.lon,
                threat_score=intel.threat_score
            )

        # 5. Match Sudo command (privilege escalation)
        match = self.regex_sudo.search(line)
        if match:
            user = match.group(1)
            cmd = match.group(2).strip()
            # Localhost or terminal IP
            ip = "127.0.0.1"
            intel = self.enricher.enrich(ip)
            return NormalizedEvent(
                timestamp=dt,
                log_source="ssh",
                source_ip=ip,
                user=user,
                action="privilege_escalation",
                status="success",
                details={"command": cmd, "sudo": True},
                raw_log=line,
                geo_country=intel.country,
                geo_country_code=intel.country_code,
                geo_city=intel.city,
                geo_lat=intel.lat,
                geo_lon=intel.lon,
                threat_score=intel.threat_score
            )

        # 6. Generic SSH failure indicator
        if "authentication failure;" in line:
            ip_m = re.search(r"rhost=([^\s]+)", line)
            user_m = re.search(r"user=([^\s]+)", line)
            ip = ip_m.group(1) if ip_m else "127.0.0.1"
            user = user_m.group(1) if user_m else "unknown"
            intel = self.enricher.enrich(ip)
            return NormalizedEvent(
                timestamp=dt,
                log_source="ssh",
                source_ip=ip,
                user=user,
                action="login",
                status="failure",
                details={"raw_indicator": "pam_authentication_failure"},
                raw_log=line,
                geo_country=intel.country,
                geo_country_code=intel.country_code,
                geo_city=intel.city,
                geo_lat=intel.lat,
                geo_lon=intel.lon,
                threat_score=intel.threat_score
            )

        return None
