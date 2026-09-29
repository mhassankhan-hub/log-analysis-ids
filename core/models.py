from datetime import datetime
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
import uuid


class NormalizedEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    log_source: str  # "ssh", "web", "windows", "system"
    source_ip: str
    user: Optional[str] = None
    action: str  # "login", "http_request", "privilege_escalation", etc.
    status: str  # "success", "failure", "info"
    details: Dict[str, Any] = Field(default_factory=dict)
    raw_log: str
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    threat_score: Optional[int] = 0

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        return d


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: f"ALT-{uuid.uuid4().hex[:8].upper()}")
    rule_id: str
    rule_name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    mitre_attack_id: str
    mitre_attack_tactic: str
    mitre_attack_technique: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str
    targeted_user: Optional[str] = None
    description: str
    event_count: int = 1
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    status: str = "NEW"  # "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"
    auto_blocked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["timestamp"] = self.timestamp.isoformat()
        return d


class BlockedIP(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ip: str
    reason: str
    severity: str
    blocked_at: datetime = Field(default_factory=datetime.utcnow)
    firewall_command: str
    active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = self.model_dump()
        d["blocked_at"] = self.blocked_at.isoformat()
        return d


class ThreatIntel(BaseModel):
    ip: str
    country: str = "Unknown"
    country_code: str = "UN"
    city: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0
    isp: str = "Unknown ISP"
    threat_score: int = 0
    is_malicious: bool = False
    reputation_category: str = "Benign"
