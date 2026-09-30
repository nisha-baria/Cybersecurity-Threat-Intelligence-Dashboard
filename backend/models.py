from dataclasses import dataclass, asdict
from typing import Optional, List

@dataclass
class ThreatIndicator:
    threat_id: str
    timestamp: str
    threat_name: str
    threat_category: str
    indicator_type: str
    indicator_value: str
    source_name: str
    source_reliability: str
    confidence_score: int
    severity: str
    risk_score: int
    status: str
    first_seen: str
    last_seen: str
    description: str
    mitre_tactic: Optional[str] = "N/A"
    mitre_technique: Optional[str] = "N/A"
    mitre_technique_id: Optional[str] = "N/A"
    cve_id: Optional[str] = ""

    def to_dict(self):
        return asdict(self)

@dataclass
class VulnerabilityRecord:
    cve_id: str
    product_category: str
    severity: str
    cvss_score: float
    published_date: str
    patch_available: str
    exploitation_status_demo: str
    description: str

    def to_dict(self):
        return asdict(self)