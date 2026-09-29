import time
from datetime import datetime, timedelta
from typing import List, Dict, Any
from parsers import AutoLogParser
from core.engine import DetectionEngine
from core.models import Alert


class AttackSimulator:
    """
    Simulates realistic cyber attack scenarios (SSH Hydra brute force, SQLi,
    Impossible Travel, Dirbuster scans) to test the detection engine and UI in real-time.
    """

    def __init__(self, parser: AutoLogParser, engine: DetectionEngine):
        self.parser = parser
        self.engine = engine

    def simulate_ssh_bruteforce(self, attacker_ip: str = "194.26.29.112", count: int = 6) -> List[Alert]:
        """Simulates Hydra or Medusa SSH password brute force against 'root' / 'admin'."""
        logs = []
        now = datetime.utcnow()
        port = 44210

        for i in range(count):
            event_time = now - timedelta(seconds=(count - i) * 5)
            ts_str = event_time.strftime("%b %d %H:%M:%S")
            line = f"{ts_str} ubuntu-server sshd[2841{i}]: Failed password for root from {attacker_ip} port {port + i} ssh2"
            logs.append(line)

        events = self.parser.parse_text("\n".join(logs), forced_source="ssh")
        return self.engine.process_events(events)

    def simulate_password_spray(self, attacker_ip: str = "103.203.57.18") -> List[Alert]:
        """Simulates a password spraying attack attempting 1 password across multiple distinct usernames."""
        users = ["jsmith", "bwayne", "cstark", "pparker", "dprince", "nromanoff"]
        logs = []
        now = datetime.utcnow()

        for idx, user in enumerate(users):
            event_time = now - timedelta(seconds=(len(users) - idx) * 8)
            ts_str = event_time.strftime("%b %d %H:%M:%S")
            line = f"{ts_str} ubuntu-server sshd[3100{idx}]: Failed password for invalid user {user} from {attacker_ip} port {51200 + idx} ssh2"
            logs.append(line)

        events = self.parser.parse_text("\n".join(logs), forced_source="ssh")
        return self.engine.process_events(events)

    def simulate_compromise_after_brute(self, attacker_ip: str = "185.220.101.5", user: str = "deploy") -> List[Alert]:
        """Simulates failed brute force attempts followed immediately by a successful unauthorized login."""
        logs = []
        now = datetime.utcnow()

        # 5 failures
        for i in range(5):
            event_time = now - timedelta(seconds=(6 - i) * 10)
            ts_str = event_time.strftime("%b %d %H:%M:%S")
            line = f"{ts_str} bastion sshd[1420{i}]: Failed password for {user} from {attacker_ip} port {39100 + i} ssh2"
            logs.append(line)

        # 1 success right after
        ts_success = now.strftime("%b %d %H:%M:%S")
        logs.append(f"{ts_success} bastion sshd[14299]: Accepted password for {user} from {attacker_ip} port 39150 ssh2")

        events = self.parser.parse_text("\n".join(logs), forced_source="ssh")
        return self.engine.process_events(events)

    def simulate_impossible_travel(self, user: str = "sarah.connor") -> List[Alert]:
        """
        Simulates legitimate login from New York, USA, followed 12 minutes later
        by a login from Moscow, Russia (speed > 35,000 km/h).
        """
        logs = []
        base_time = datetime.utcnow() - timedelta(minutes=15)

        # 1. Login in USA (New York: 198.51.100.42)
        ts1 = base_time.strftime("%b %d %H:%M:%S")
        line1 = f"{ts1} corporate-vpn sshd[9101]: Accepted publickey for {user} from 198.51.100.42 port 54122 ssh2"
        logs.append(line1)

        # 2. Login in Russia (Moscow: 194.26.29.112) only 12 minutes later!
        ts2 = (base_time + timedelta(minutes=12)).strftime("%b %d %H:%M:%S")
        line2 = f"{ts2} corporate-vpn sshd[9834]: Accepted password for {user} from 194.26.29.112 port 59102 ssh2"
        logs.append(line2)

        events = self.parser.parse_text("\n".join(logs), forced_source="ssh")
        return self.engine.process_events(events)

    def simulate_web_sqli_and_xss(self, attacker_ip: str = "118.25.6.39") -> List[Alert]:
        """Simulates automated SQL injection and XSS payloads in HTTP requests."""
        now = datetime.utcnow()
        ts_web = now.strftime("%d/%b/%Y:%H:%M:%S +0000")

        logs = [
            f'{attacker_ip} - - [{ts_web}] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1" 200 4512 "-" "sqlmap/1.6.0"',
            f'{attacker_ip} - - [{ts_web}] "GET /search.php?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 1205 "-" "Mozilla/5.0"',
            f'{attacker_ip} - - [{ts_web}] "GET /view.php?file=../../../../etc/passwd HTTP/1.1" 200 892 "-" "curl/7.81.0"',
            f'{attacker_ip} - - [{ts_web}] "GET /.env HTTP/1.1" 404 153 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine)"',
            f'{attacker_ip} - - [{ts_web}] "GET /.git/config HTTP/1.1" 404 153 "-" "Mozilla/5.0"',
            f'{attacker_ip} - - [{ts_web}] "GET /wp-config.php.bak HTTP/1.1" 404 153 "-" "Mozilla/5.0"'
        ]

        events = self.parser.parse_text("\n".join(logs), forced_source="web")
        return self.engine.process_events(events)

    def simulate_web_directory_bust(self, attacker_ip: str = "45.148.10.88", count: int = 10) -> List[Alert]:
        """Simulates Gobuster / Dirb aggressive 404 directory enumeration."""
        now = datetime.utcnow()
        logs = []
        paths = ["/admin", "/backup", "/db", "/dev", "/test", "/v2", "/staging", "/api/v1/debug", "/server-status", "/portal"]

        for i in range(min(count, len(paths))):
            ts_web = (now - timedelta(seconds=(count - i) * 3)).strftime("%d/%b/%Y:%H:%M:%S +0000")
            path = paths[i]
            line = f'{attacker_ip} - - [{ts_web}] "GET {path} HTTP/1.1" 404 162 "-" "gobuster/3.1.0"'
            logs.append(line)

        events = self.parser.parse_text("\n".join(logs), forced_source="web")
        return self.engine.process_events(events)

    def simulate_privilege_escalation(self, user: str = "www-data") -> List[Alert]:
        """Simulates unauthorized sudo abuse or root shell spawning."""
        now = datetime.utcnow()
        ts = now.strftime("%b %d %H:%M:%S")
        log_line = f"{ts} web-node sudo: {user} : TTY=pts/2 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash"

        events = self.parser.parse_text(log_line, forced_source="ssh")
        return self.engine.process_events(events)
