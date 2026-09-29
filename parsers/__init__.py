from typing import List, Optional
from core.models import NormalizedEvent
from core.enricher import GeoIPEnricher
from parsers.ssh_parser import SSHLogParser
from parsers.web_parser import WebLogParser
from parsers.windows_parser import WindowsLogParser


class AutoLogParser:
    """
    Intelligent router that automatically detects log format (SSH, Nginx/Apache, Windows)
    and normalizes the stream into uniform NormalizedEvent objects.
    """

    def __init__(self, enricher: Optional[GeoIPEnricher] = None):
        self.enricher = enricher or GeoIPEnricher()
        self.ssh_parser = SSHLogParser(self.enricher)
        self.web_parser = WebLogParser(self.enricher)
        self.windows_parser = WindowsLogParser(self.enricher)

    def parse_line(self, line: str, forced_source: Optional[str] = None) -> Optional[NormalizedEvent]:
        if not line or not line.strip():
            return None

        if forced_source == "ssh":
            return self.ssh_parser.parse_line(line)
        elif forced_source == "web":
            return self.web_parser.parse_line(line)
        elif forced_source == "windows":
            return self.windows_parser.parse_line(line)

        # Heuristic detection order
        if self.web_parser.can_parse(line):
            return self.web_parser.parse_line(line)
        if self.ssh_parser.can_parse(line):
            return self.ssh_parser.parse_line(line)
        if self.windows_parser.can_parse(line):
            return self.windows_parser.parse_line(line)

        # Fallback attempts
        for p in (self.ssh_parser, self.web_parser, self.windows_parser):
            ev = p.parse_line(line)
            if ev:
                return ev

        return None

    def parse_text(self, text: str, forced_source: Optional[str] = None) -> List[NormalizedEvent]:
        events = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            ev = self.parse_line(line, forced_source)
            if ev:
                events.append(ev)
        return events
