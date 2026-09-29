import re
import yaml
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from core.models import NormalizedEvent, Alert
from core.database import Database
from core.alerter import AlertDispatcher
from core.enricher import GeoIPEnricher


class DetectionEngine:
    """
    Stateful SOC Detection & Correlation Engine.
    Evaluates normalized event streams against configurable MITRE ATT&CK mapped rules.
    """

    def __init__(self, config_path: str = "config/rules.yaml", db: Optional[Database] = None,
                 alerter: Optional[AlertDispatcher] = None, enricher: Optional[GeoIPEnricher] = None):
        self.config_path = config_path
        self.db = db or Database()
        self.enricher = enricher or GeoIPEnricher()
        self.alerter = alerter or AlertDispatcher()

        # Load rules & settings
        self.rules: List[Dict[str, Any]] = []
        self.settings: Dict[str, Any] = {}
        self.load_config()

        # Stateful memory caches
        # ip -> list of (timestamp, user, raw_log)
        self.failures_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # user -> list of (timestamp, ip, lat, lon, country, city)
        self.user_login_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # ip -> list of (timestamp, path)
        self.requests_404_by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        # (ip, rule_id) -> last alert timestamp (to prevent alert flooding)
        self.alert_cooldowns: Dict[tuple, datetime] = {}

    def load_config(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f)
                self.settings = cfg.get("settings", {})
                self.rules = cfg.get("rules", [])
                self.alerter.update_config(cfg.get("alerts", {}))
        except Exception as e:
            print(f"[!] Warning: Could not load {self.config_path}: {e}")

    def reload_rules(self, new_yaml_content: Optional[str] = None):
        if new_yaml_content:
            cfg = yaml.safe_load(new_yaml_content)
            self.settings = cfg.get("settings", {})
            self.rules = cfg.get("rules", [])
            self.alerter.update_config(cfg.get("alerts", {}))
            with open(self.config_path, "w", encoding="utf-8") as f:
                yaml.dump(cfg, f, default_flow_style=False)
        else:
            self.load_config()

    def process_event(self, event: NormalizedEvent) -> List[Alert]:
        """
        Processes a single NormalizedEvent, stores it, tests all detection rules,
        triggers alerts, and initiates automated firewall mitigations.
        """
        # 1. Persist event to SQLite database
        self.db.insert_event(event)

        generated_alerts: List[Alert] = []

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            rule_id = rule["id"]
            cooldown_key = (event.source_ip, rule_id)
            cooldown_sec = self.settings.get("alert_cooldown_seconds", 60)

            # Check alert cooldown
            last_alert = self.alert_cooldowns.get(cooldown_key)
            if last_alert and (event.timestamp - last_alert).total_seconds() < cooldown_sec:
                continue

            alert = None
            if rule_id == "RULE-SSH-BRUTE-01":
                alert = self._check_brute_force(event, rule)
            elif rule_id == "RULE-SSH-SPRAY-01":
                alert = self._check_password_spray(event, rule)
            elif rule_id == "RULE-COMPROMISE-01":
                alert = self._check_compromise_after_brute(event, rule)
            elif rule_id == "RULE-ROOT-LOGIN-01":
                alert = self._check_root_login(event, rule)
            elif rule_id == "RULE-IMPOSSIBLE-TRAVEL-01":
                alert = self._check_impossible_travel(event, rule)
            elif rule_id == "RULE-WEB-SQLI-01":
                alert = self._check_web_sqli(event, rule)
            elif rule_id == "RULE-WEB-XSS-01":
                alert = self._check_web_xss(event, rule)
            elif rule_id == "RULE-WEB-TRAVERSAL-01":
                alert = self._check_web_traversal(event, rule)
            elif rule_id == "RULE-WEB-SENSITIVE-01":
                alert = self._check_web_sensitive_probe(event, rule)
            elif rule_id == "RULE-WEB-SCAN-01":
                alert = self._check_web_scan(event, rule)
            elif rule_id == "RULE-PRIV-ESC-01":
                alert = self._check_privilege_escalation(event, rule)

            if alert:
                self.alert_cooldowns[cooldown_key] = event.timestamp
                # Automated response check
                if alert.severity == "CRITICAL" or self.settings.get("auto_block_threshold_severity") == alert.severity:
                    self.db.block_ip(alert.source_ip, f"Auto-blocked by {alert.rule_name} ({alert.mitre_attack_id})", alert.severity)
                    alert.auto_blocked = True

                self.db.insert_alert(alert)
                self.alerter.dispatch(alert)
                generated_alerts.append(alert)

        return generated_alerts

    def process_events(self, events: List[NormalizedEvent]) -> List[Alert]:
        """Processes a batch of normalized events."""
        all_alerts = []
        for ev in events:
            alerts = self.process_event(ev)
            all_alerts.extend(alerts)
        return all_alerts

    # ---------------- Detection Logic Implementations ---------------- #

    def _check_brute_force(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source in ("ssh", "windows") and event.status == "failure":
            params = rule.get("params", {})
            threshold = params.get("threshold", 5)
            window_sec = params.get("window_seconds", 180)
            window = timedelta(seconds=window_sec)

            history = self.failures_by_ip[event.source_ip]
            history.append({"time": event.timestamp, "user": event.user, "log": event.raw_log})

            # Trim history outside window
            valid_entries = [e for e in history if (event.timestamp - e["time"]) <= window]
            self.failures_by_ip[event.source_ip] = valid_entries

            if len(valid_entries) >= threshold:
                users_targeted = list(set(e["user"] for e in valid_entries if e["user"]))
                return Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_attack_id=rule["mitre_attack_id"],
                    mitre_attack_tactic=rule["mitre_attack_tactic"],
                    mitre_attack_technique=rule["mitre_attack_technique"],
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    targeted_user=", ".join(users_targeted[:3]) if users_targeted else "unknown",
                    description=f"Detected {len(valid_entries)} failed authentications from {event.source_ip} within {window_sec}s.",
                    event_count=len(valid_entries),
                    evidence=valid_entries[-5:],
                    geo_country=event.geo_country,
                    geo_country_code=event.geo_country_code,
                    geo_city=event.geo_city,
                    geo_lat=event.geo_lat,
                    geo_lon=event.geo_lon
                )
        return None

    def _check_password_spray(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source in ("ssh", "windows") and event.status == "failure" and event.user:
            params = rule.get("params", {})
            distinct_threshold = params.get("distinct_users_threshold", 4)
            window_sec = params.get("window_seconds", 300)
            window = timedelta(seconds=window_sec)

            history = self.failures_by_ip[event.source_ip]
            valid_entries = [e for e in history if (event.timestamp - e["time"]) <= window and e.get("user")]
            unique_users = set(e["user"] for e in valid_entries)

            if len(unique_users) >= distinct_threshold:
                return Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_attack_id=rule["mitre_attack_id"],
                    mitre_attack_tactic=rule["mitre_attack_tactic"],
                    mitre_attack_technique=rule["mitre_attack_technique"],
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    targeted_user=f"{len(unique_users)} users: " + ", ".join(list(unique_users)[:4]),
                    description=f"IP {event.source_ip} attempted spraying passwords across {len(unique_users)} unique accounts.",
                    event_count=len(valid_entries),
                    evidence=valid_entries[-6:],
                    geo_country=event.geo_country,
                    geo_country_code=event.geo_country_code,
                    geo_city=event.geo_city,
                    geo_lat=event.geo_lat,
                    geo_lon=event.geo_lon
                )
        return None

    def _check_compromise_after_brute(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.status == "success" and event.action == "login":
            params = rule.get("params", {})
            min_failures = params.get("min_failures_before_success", 4)
            window_sec = params.get("window_seconds", 600)
            window = timedelta(seconds=window_sec)

            history = self.failures_by_ip.get(event.source_ip, [])
            valid_failures = [e for e in history if (event.timestamp - e["time"]) <= window]

            if len(valid_failures) >= min_failures:
                return Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_attack_id=rule["mitre_attack_id"],
                    mitre_attack_tactic=rule["mitre_attack_tactic"],
                    mitre_attack_technique=rule["mitre_attack_technique"],
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    targeted_user=event.user or "Unknown",
                    description=f"CRITICAL: User '{event.user}' successfully authenticated immediately after {len(valid_failures)} failed attempts from {event.source_ip}.",
                    event_count=len(valid_failures) + 1,
                    evidence=valid_failures[-4:] + [{"time": event.timestamp, "user": event.user, "log": event.raw_log}],
                    geo_country=event.geo_country,
                    geo_country_code=event.geo_country_code,
                    geo_city=event.geo_city,
                    geo_lat=event.geo_lat,
                    geo_lon=event.geo_lon
                )
        return None

    def _check_root_login(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.status == "success" and event.action == "login":
            user_lower = (event.user or "").lower()
            if user_lower in ("root", "administrator", "admin") and event.source_ip not in ("127.0.0.1", "::1", "localhost"):
                return Alert(
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    mitre_attack_id=rule["mitre_attack_id"],
                    mitre_attack_tactic=rule["mitre_attack_tactic"],
                    mitre_attack_technique=rule["mitre_attack_technique"],
                    timestamp=event.timestamp,
                    source_ip=event.source_ip,
                    targeted_user=event.user,
                    description=f"Direct administrative login for privileged account '{event.user}' from external IP {event.source_ip}.",
                    event_count=1,
                    evidence=[{"log": event.raw_log}],
                    geo_country=event.geo_country,
                    geo_country_code=event.geo_country_code,
                    geo_city=event.geo_city,
                    geo_lat=event.geo_lat,
                    geo_lon=event.geo_lon
                )
        return None

    def _check_impossible_travel(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.status == "success" and event.action == "login" and event.user:
            if event.geo_lat is not None and event.geo_lon is not None:
                params = rule.get("params", {})
                max_speed = params.get("max_speed_kmh", 850)

                history = self.user_login_history[event.user]
                for prev in reversed(history):
                    coord1 = (prev["lat"], prev["lon"])
                    coord2 = (event.geo_lat, event.geo_lon)
                    time1 = prev["time"]
                    time2 = event.timestamp

                    dist_km, speed_kmh = GeoIPEnricher.calculate_velocity_kmh(coord1, time1, coord2, time2)
                    time_diff_mins = abs((time2 - time1).total_seconds()) / 60.0

                    if dist_km > 500 and speed_kmh > max_speed:
                        # Record login event and alert
                        history.append({
                            "time": event.timestamp, "ip": event.source_ip,
                            "lat": event.geo_lat, "lon": event.geo_lon,
                            "country": event.geo_country, "city": event.geo_city
                        })
                        return Alert(
                            rule_id=rule["id"],
                            rule_name=rule["name"],
                            severity=rule["severity"],
                            mitre_attack_id=rule["mitre_attack_id"],
                            mitre_attack_tactic=rule["mitre_attack_tactic"],
                            mitre_attack_technique=rule["mitre_attack_technique"],
                            timestamp=event.timestamp,
                            source_ip=event.source_ip,
                            targeted_user=event.user,
                            description=(
                                f"IMPOSSIBLE TRAVEL: User '{event.user}' logged in from {event.geo_city}, {event.geo_country} "
                                f"only {time_diff_mins:.1f} mins after login from {prev.get('city')}, {prev.get('country')} "
                                f"(Distance: {dist_km:.0f}km, Required Speed: {speed_kmh:.0f}km/h > max {max_speed}km/h)."
                            ),
                            event_count=2,
                            evidence=[
                                {"previous_location": f"{prev.get('city')}, {prev.get('country')}", "ip": prev.get("ip"), "time": prev["time"].isoformat()},
                                {"current_location": f"{event.geo_city}, {event.geo_country}", "ip": event.source_ip, "time": event.timestamp.isoformat()}
                            ],
                            geo_country=event.geo_country,
                            geo_country_code=event.geo_country_code,
                            geo_city=event.geo_city,
                            geo_lat=event.geo_lat,
                            geo_lon=event.geo_lon
                        )

                # Append current valid login to history
                history.append({
                    "time": event.timestamp, "ip": event.source_ip,
                    "lat": event.geo_lat, "lon": event.geo_lon,
                    "country": event.geo_country, "city": event.geo_city
                })
        return None

    def _check_web_sqli(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source == "web":
            path = (event.details.get("path") or "") + " " + (event.details.get("raw_path") or "")
            params = rule.get("params", {})
            patterns = params.get("patterns", [])

            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return Alert(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        mitre_attack_id=rule["mitre_attack_id"],
                        mitre_attack_tactic=rule["mitre_attack_tactic"],
                        mitre_attack_technique=rule["mitre_attack_technique"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        targeted_user="Web Application",
                        description=f"SQL Injection payload signature detected in HTTP request: '{path[:100]}...'",
                        event_count=1,
                        evidence=[{"matched_pattern": pat, "request_path": path, "log": event.raw_log}],
                        geo_country=event.geo_country,
                        geo_country_code=event.geo_country_code,
                        geo_city=event.geo_city,
                        geo_lat=event.geo_lat,
                        geo_lon=event.geo_lon
                    )
        return None

    def _check_web_xss(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source == "web":
            path = (event.details.get("path") or "") + " " + (event.details.get("raw_path") or "")
            params = rule.get("params", {})
            patterns = params.get("patterns", [])

            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return Alert(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        mitre_attack_id=rule["mitre_attack_id"],
                        mitre_attack_tactic=rule["mitre_attack_tactic"],
                        mitre_attack_technique=rule["mitre_attack_technique"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        targeted_user="Web Application",
                        description=f"Cross-Site Scripting (XSS) payload identified in URI parameters.",
                        event_count=1,
                        evidence=[{"matched_pattern": pat, "request_path": path, "log": event.raw_log}],
                        geo_country=event.geo_country,
                        geo_country_code=event.geo_country_code,
                        geo_city=event.geo_city,
                        geo_lat=event.geo_lat,
                        geo_lon=event.geo_lon
                    )
        return None

    def _check_web_traversal(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source == "web":
            path = (event.details.get("path") or "") + " " + (event.details.get("raw_path") or "")
            params = rule.get("params", {})
            patterns = params.get("patterns", [])

            for pat in patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return Alert(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        mitre_attack_id=rule["mitre_attack_id"],
                        mitre_attack_tactic=rule["mitre_attack_tactic"],
                        mitre_attack_technique=rule["mitre_attack_technique"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        targeted_user="Web Server / OS Files",
                        description=f"Directory traversal / LFI exploit attempt attempting to escape webroot.",
                        event_count=1,
                        evidence=[{"matched_pattern": pat, "request_path": path, "log": event.raw_log}],
                        geo_country=event.geo_country,
                        geo_country_code=event.geo_country_code,
                        geo_city=event.geo_city,
                        geo_lat=event.geo_lat,
                        geo_lon=event.geo_lon
                    )
        return None

    def _check_web_sensitive_probe(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source == "web":
            path = (event.details.get("path") or "").lower()
            params = rule.get("params", {})
            sensitive_paths = params.get("sensitive_paths", [])

            for s_path in sensitive_paths:
                if s_path.lower() in path:
                    return Alert(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        mitre_attack_id=rule["mitre_attack_id"],
                        mitre_attack_tactic=rule["mitre_attack_tactic"],
                        mitre_attack_technique=rule["mitre_attack_technique"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        targeted_user="Configuration Secrets",
                        description=f"Unauthorized reconnaissance probe targeting sensitive endpoint: '{s_path}'",
                        event_count=1,
                        evidence=[{"target_endpoint": s_path, "log": event.raw_log}],
                        geo_country=event.geo_country,
                        geo_country_code=event.geo_country_code,
                        geo_city=event.geo_city,
                        geo_lat=event.geo_lat,
                        geo_lon=event.geo_lon
                    )
        return None

    def _check_web_scan(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        if event.log_source == "web":
            status_code = event.details.get("status_code", 200)
            if status_code in (404, 403):
                params = rule.get("params", {})
                threshold = params.get("threshold", 8)
                window_sec = params.get("window_seconds", 120)
                window = timedelta(seconds=window_sec)

                history = self.requests_404_by_ip[event.source_ip]
                history.append({"time": event.timestamp, "path": event.details.get("path")})

                valid_entries = [e for e in history if (event.timestamp - e["time"]) <= window]
                self.requests_404_by_ip[event.source_ip] = valid_entries

                if len(valid_entries) >= threshold:
                    return Alert(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        mitre_attack_id=rule["mitre_attack_id"],
                        mitre_attack_tactic=rule["mitre_attack_tactic"],
                        mitre_attack_technique=rule["mitre_attack_technique"],
                        timestamp=event.timestamp,
                        source_ip=event.source_ip,
                        targeted_user="Web Directory Structure",
                        description=f"Directory enumeration / vulnerability scanning detected: {len(valid_entries)} 404/403 errors within {window_sec}s.",
                        event_count=len(valid_entries),
                        evidence=valid_entries[-5:],
                        geo_country=event.geo_country,
                        geo_country_code=event.geo_country_code,
                        geo_city=event.geo_city,
                        geo_lat=event.geo_lat,
                        geo_lon=event.geo_lon
                    )
        return None

    def _check_privilege_escalation(self, event: NormalizedEvent, rule: Dict[str, Any]) -> Optional[Alert]:
        cmd = event.details.get("command", "")
        params = rule.get("params", {})
        sensitive_cmds = params.get("sensitive_commands", [])

        if event.action == "privilege_escalation" or any(re.search(sc, cmd, re.IGNORECASE) for sc in sensitive_cmds):
            return Alert(
                rule_id=rule["id"],
                rule_name=rule["name"],
                severity=rule["severity"],
                mitre_attack_id=rule["mitre_attack_id"],
                mitre_attack_tactic=rule["mitre_attack_tactic"],
                mitre_attack_technique=rule["mitre_attack_technique"],
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                targeted_user=event.user or "root",
                description=f"Privilege escalation activity detected: execution of '{cmd}' by user '{event.user}'.",
                event_count=1,
                evidence=[{"command": cmd, "log": event.raw_log}],
                geo_country=event.geo_country,
                geo_country_code=event.geo_country_code,
                geo_city=event.geo_city,
                geo_lat=event.geo_lat,
                geo_lon=event.geo_lon
            )
        return None
