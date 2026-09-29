import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from core.models import NormalizedEvent, Alert, BlockedIP


class Database:
    """SQLite Database Manager for SOC Sentinel events, alerts, and firewall rules."""

    def __init__(self, db_path: str = "soc_sentinel.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Normalized Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    log_source TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user TEXT,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details_json TEXT,
                    raw_log TEXT,
                    geo_country TEXT,
                    geo_country_code TEXT,
                    geo_city TEXT,
                    geo_lat REAL,
                    geo_lon REAL,
                    threat_score INTEGER DEFAULT 0
                )
            """)

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    mitre_attack_id TEXT NOT NULL,
                    mitre_attack_tactic TEXT NOT NULL,
                    mitre_attack_technique TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    source_ip TEXT NOT NULL,
                    targeted_user TEXT,
                    description TEXT NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    evidence_json TEXT,
                    geo_country TEXT,
                    geo_country_code TEXT,
                    geo_city TEXT,
                    geo_lat REAL,
                    geo_lon REAL,
                    status TEXT DEFAULT 'NEW',
                    auto_blocked BOOLEAN DEFAULT 0
                )
            """)

            # Blocked IPs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id TEXT PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    blocked_at DATETIME NOT NULL,
                    firewall_command TEXT NOT NULL,
                    active BOOLEAN DEFAULT 1
                )
            """)

            # Indexes for SOC queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_ip ON events(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(log_source)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(source_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity)")

            conn.commit()

    def insert_event(self, event: NormalizedEvent):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO events (
                    id, timestamp, log_source, source_ip, user, action, status,
                    details_json, raw_log, geo_country, geo_country_code, geo_city,
                    geo_lat, geo_lon, threat_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.id,
                event.timestamp.isoformat(),
                event.log_source,
                event.source_ip,
                event.user,
                event.action,
                event.status,
                json.dumps(event.details, default=str),
                event.raw_log,
                event.geo_country,
                event.geo_country_code,
                event.geo_city,
                event.geo_lat,
                event.geo_lon,
                event.threat_score
            ))
            conn.commit()

    def insert_events(self, events: List[NormalizedEvent]):
        with self._get_connection() as conn:
            records = [
                (
                    e.id,
                    e.timestamp.isoformat(),
                    e.log_source,
                    e.source_ip,
                    e.user,
                    e.action,
                    e.status,
                    json.dumps(e.details, default=str),
                    e.raw_log,
                    e.geo_country,
                    e.geo_country_code,
                    e.geo_city,
                    e.geo_lat,
                    e.geo_lon,
                    e.threat_score
                )
                for e in events
            ]
            conn.executemany("""
                INSERT OR REPLACE INTO events (
                    id, timestamp, log_source, source_ip, user, action, status,
                    details_json, raw_log, geo_country, geo_country_code, geo_city,
                    geo_lat, geo_lon, threat_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()

    def insert_alert(self, alert: Alert):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    id, rule_id, rule_name, severity, mitre_attack_id,
                    mitre_attack_tactic, mitre_attack_technique, timestamp,
                    source_ip, targeted_user, description, event_count,
                    evidence_json, geo_country, geo_country_code, geo_city,
                    geo_lat, geo_lon, status, auto_blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id,
                alert.rule_id,
                alert.rule_name,
                alert.severity,
                alert.mitre_attack_id,
                alert.mitre_attack_tactic,
                alert.mitre_attack_technique,
                alert.timestamp.isoformat(),
                alert.source_ip,
                alert.targeted_user,
                alert.description,
                alert.event_count,
                json.dumps(alert.evidence, default=str),
                alert.geo_country,
                alert.geo_country_code,
                alert.geo_city,
                alert.geo_lat,
                alert.geo_lon,
                alert.status,
                1 if alert.auto_blocked else 0
            ))
            conn.commit()

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM alerts WHERE 1=1"
            params = []
            if severity and severity != "ALL":
                query += " AND severity = ?"
                params.append(severity)
            if status and status != "ALL":
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            alerts = []
            for r in rows:
                item = dict(r)
                item["evidence"] = json.loads(item["evidence_json"]) if item["evidence_json"] else []
                alerts.append(item)
            return alerts

    def get_events(self, limit: int = 100, source_ip: Optional[str] = None,
                   log_source: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            query = "SELECT * FROM events WHERE 1=1"
            params = []
            if source_ip:
                query += " AND source_ip LIKE ?"
                params.append(f"%{source_ip}%")
            if log_source and log_source != "ALL":
                query += " AND log_source = ?"
                params.append(log_source)
            if status and status != "ALL":
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            events = []
            for r in rows:
                item = dict(r)
                item["details"] = json.loads(item["details_json"]) if item["details_json"] else {}
                events.append(item)
            return events

    def update_alert_status(self, alert_id: str, new_status: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))
            conn.commit()
            return cursor.rowcount > 0

    def block_ip(self, ip: str, reason: str, severity: str = "HIGH") -> Dict[str, Any]:
        with self._get_connection() as conn:
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            now = datetime.utcnow().isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO blocked_ips (id, ip, reason, severity, blocked_at, firewall_command, active)
                VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, 1)
            """, (ip, reason, severity, now, cmd))
            # Also mark alert as auto_blocked if exists
            conn.execute("UPDATE alerts SET auto_blocked = 1 WHERE source_ip = ?", (ip,))
            conn.commit()
            return {"ip": ip, "reason": reason, "command": cmd, "blocked_at": now, "active": True}

    def unblock_ip(self, ip: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.execute("UPDATE blocked_ips SET active = 0 WHERE ip = ?", (ip,))
            conn.commit()
            return cursor.rowcount > 0

    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM blocked_ips ORDER BY blocked_at DESC").fetchall()
            return [dict(r) for r in rows]

    def get_dashboard_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            # Total counts
            total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            critical_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL'").fetchone()[0]
            high_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'").fetchone()[0]
            active_blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active = 1").fetchone()[0]

            # Top 5 Attacking IPs
            top_ips_rows = conn.execute("""
                SELECT source_ip, geo_country, geo_city, COUNT(*) as alert_count,
                       MAX(severity) as max_severity,
                       MAX(geo_lat) as geo_lat, MAX(geo_lon) as geo_lon
                FROM alerts
                GROUP BY source_ip
                ORDER BY alert_count DESC
                LIMIT 5
            """).fetchall()
            top_ips = [dict(r) for r in top_ips_rows]

            # MITRE ATT&CK Tactic distribution
            tactics_rows = conn.execute("""
                SELECT mitre_attack_tactic, COUNT(*) as count
                FROM alerts
                GROUP BY mitre_attack_tactic
                ORDER BY count DESC
            """).fetchall()
            tactics = {r["mitre_attack_tactic"]: r["count"] for r in tactics_rows}

            # Severity distribution
            sev_rows = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
            """).fetchall()
            severities = {r["severity"]: r["count"] for r in sev_rows}

            # Map coordinates of alerts (unique attacker locations)
            geo_rows = conn.execute("""
                SELECT source_ip, geo_country, geo_city, geo_lat, geo_lon,
                       COUNT(*) as alert_count, MAX(severity) as severity, MAX(mitre_attack_id) as mitre_id
                FROM alerts
                WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
                GROUP BY source_ip
                ORDER BY alert_count DESC
            """).fetchall()
            map_markers = [dict(r) for r in geo_rows]

            # Timeline of alerts (last 15 records grouped or chronological)
            timeline_rows = conn.execute("""
                SELECT substr(timestamp, 1, 16) as time_bucket, COUNT(*) as count
                FROM alerts
                GROUP BY time_bucket
                ORDER BY time_bucket DESC
                LIMIT 15
            """).fetchall()
            timeline = [dict(r) for r in reversed(timeline_rows)]

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "blocked_ips_count": active_blocked,
                "top_attacking_ips": top_ips,
                "mitre_tactics": tactics,
                "severity_breakdown": severities,
                "map_markers": map_markers,
                "timeline": timeline
            }

    def clear_all(self):
        """Clears events and alerts for clean testing."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM blocked_ips")
            conn.commit()
