import os
import sys
import unittest
from datetime import datetime, timedelta

# Add workspace to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.models import NormalizedEvent
from core.enricher import GeoIPEnricher
from core.database import Database
from core.alerter import AlertDispatcher
from core.engine import DetectionEngine
from parsers.ssh_parser import SSHLogParser
from parsers.web_parser import WebLogParser
from parsers import AutoLogParser


class TestSOCSentinelDetections(unittest.TestCase):

    def setUp(self):
        # Use an in-memory SQLite database for testing
        self.db = Database(db_path=":memory:")
        self.enricher = GeoIPEnricher()
        self.alerter = AlertDispatcher({"alerts": {"console": {"enabled": False}}})
        self.engine = DetectionEngine(
            config_path="config/rules.yaml",
            db=self.db,
            alerter=self.alerter,
            enricher=self.enricher
        )
        self.parser = AutoLogParser(enricher=self.enricher)

    def test_ssh_brute_force_detection(self):
        """Rule T1110.001: 5 failed logins within 3 minutes from single IP should trigger alert."""
        now = datetime.utcnow()
        ip = "194.26.29.112"
        events = []

        for i in range(5):
            ts = now - timedelta(seconds=(5 - i) * 10)
            log = f"{ts.strftime('%b %d %H:%M:%S')} server sshd[10{i}]: Failed password for invalid user admin from {ip} port {40000+i} ssh2"
            ev = self.parser.parse_line(log)
            self.assertIsNotNone(ev)
            events.append(ev)

        alerts = self.engine.process_events(events)
        brute_alerts = [a for a in alerts if a.mitre_attack_id == "T1110.001"]
        self.assertTrue(len(brute_alerts) >= 1)
        self.assertEqual(brute_alerts[0].source_ip, ip)
        self.assertEqual(brute_alerts[0].severity, "HIGH")

    def test_password_spraying_detection(self):
        """Rule T1110.003: 1 IP trying >= 4 distinct usernames triggers password spray alert."""
        now = datetime.utcnow()
        ip = "103.203.57.18"
        users = ["alice", "bob", "carol", "dave", "eve"]
        events = []

        for idx, user in enumerate(users):
            ts = now - timedelta(seconds=(len(users) - idx) * 10)
            log = f"{ts.strftime('%b %d %H:%M:%S')} server sshd[20{idx}]: Failed password for {user} from {ip} port {41000+idx} ssh2"
            ev = self.parser.parse_line(log)
            self.assertIsNotNone(ev)
            events.append(ev)

        alerts = self.engine.process_events(events)
        spray_alerts = [a for a in alerts if a.mitre_attack_id == "T1110.003"]
        self.assertTrue(len(spray_alerts) >= 1)
        self.assertEqual(spray_alerts[0].source_ip, ip)

    def test_compromise_after_brute_force(self):
        """Rule T1078: Successful login right after 4+ failed attempts triggers CRITICAL compromise alert."""
        now = datetime.utcnow()
        ip = "185.220.101.5"
        user = "deploy"
        events = []

        # 4 failed attempts
        for i in range(4):
            ts = now - timedelta(seconds=(5 - i) * 10)
            log = f"{ts.strftime('%b %d %H:%M:%S')} server sshd[30{i}]: Failed password for {user} from {ip} port {42000+i} ssh2"
            events.append(self.parser.parse_line(log))

        # 1 successful login immediately following
        ts_ok = now
        log_ok = f"{ts_ok.strftime('%b %d %H:%M:%S')} server sshd[3099]: Accepted password for {user} from {ip} port 42099 ssh2"
        events.append(self.parser.parse_line(log_ok))

        alerts = self.engine.process_events(events)
        comp_alerts = [a for a in alerts if a.rule_id == "RULE-COMPROMISE-01"]
        self.assertTrue(len(comp_alerts) >= 1)
        self.assertEqual(comp_alerts[0].severity, "CRITICAL")
        self.assertTrue(comp_alerts[0].auto_blocked)

    def test_impossible_travel_anomaly(self):
        """Rule T1078: User logging in from USA and 12 mins later from Russia triggers Impossible Travel."""
        user = "sarah.connor"
        base_time = datetime.utcnow() - timedelta(minutes=15)

        # Login in NY, USA (lat: 39.0438, lon: -77.4874)
        ts1 = base_time.strftime("%b %d %H:%M:%S")
        log1 = f"{ts1} vpn-node sshd[501]: Accepted publickey for {user} from 198.51.100.42 port 50000 ssh2"
        ev1 = self.parser.parse_line(log1)

        # Login in Moscow, Russia (lat: 55.7558, lon: 37.6173) 12 mins later
        ts2 = (base_time + timedelta(minutes=12)).strftime("%b %d %H:%M:%S")
        log2 = f"{ts2} vpn-node sshd[502]: Accepted password for {user} from 194.26.29.112 port 50001 ssh2"
        ev2 = self.parser.parse_line(log2)

        self.engine.process_event(ev1)
        alerts2 = self.engine.process_event(ev2)

        travel_alerts = [a for a in alerts2 if a.rule_id == "RULE-IMPOSSIBLE-TRAVEL-01"]
        self.assertTrue(len(travel_alerts) >= 1)
        self.assertEqual(travel_alerts[0].severity, "CRITICAL")

    def test_web_sql_injection(self):
        """Rule T1190: SQL injection signature in URI triggers CRITICAL alert."""
        log = '118.25.6.39 - - [29/Sep/2026:03:01:15 +0000] "GET /item.php?id=10%20UNION%20SELECT%201,username,password%20FROM%20users-- HTTP/1.1" 200 3912 "-" "sqlmap"'
        ev = self.parser.parse_line(log)
        self.assertIsNotNone(ev)

        alerts = self.engine.process_event(ev)
        sqli_alerts = [a for a in alerts if a.mitre_attack_id == "T1190" and "SQL" in a.rule_name]
        self.assertTrue(len(sqli_alerts) >= 1)
        self.assertEqual(sqli_alerts[0].severity, "CRITICAL")

    def test_web_sensitive_file_probe(self):
        """Rule T1595.002: Probing /.env or /.git triggers HIGH severity reconnaissance alert."""
        log = '118.25.6.39 - - [29/Sep/2026:03:01:30 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl"'
        ev = self.parser.parse_line(log)
        self.assertIsNotNone(ev)

        alerts = self.engine.process_event(ev)
        probe_alerts = [a for a in alerts if a.rule_id == "RULE-WEB-SENSITIVE-01"]
        self.assertTrue(len(probe_alerts) >= 1)
        self.assertEqual(probe_alerts[0].severity, "HIGH")

    def test_privilege_escalation_detection(self):
        """Rule T1548.003: Sudo execution of /bin/bash triggers privilege escalation alert."""
        log = "Sep 29 02:22:10 prod-web sudo: devuser : TTY=pts/0 ; PWD=/home/devuser ; USER=root ; COMMAND=/bin/bash"
        ev = self.parser.parse_line(log)
        self.assertIsNotNone(ev)

        alerts = self.engine.process_event(ev)
        priv_alerts = [a for a in alerts if a.mitre_attack_id == "T1548.003"]
        self.assertTrue(len(priv_alerts) >= 1)
        self.assertEqual(priv_alerts[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
