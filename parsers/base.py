from abc import ABC, abstractmethod
from typing import List, Optional
from core.models import NormalizedEvent


class BaseLogParser(ABC):
    """Abstract Base Class for all specialized log parsers."""

    @abstractmethod
    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        """Parses a single raw log line into a NormalizedEvent."""
        pass

    def parse_text(self, text: str) -> List[NormalizedEvent]:
        """Parses multiple log lines from a text block."""
        events = []
        for line in text.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            event = self.parse_line(line)
            if event:
                events.append(event)
        return events

    @abstractmethod
    def can_parse(self, sample_line: str) -> bool:
        """Heuristic check to determine if this parser handles the given log format."""
        pass
