from dataclasses import dataclass
from typing import Any, Dict

LANDED = "landed"
MISSED = "missed"


# One attack replayed against the ring: who attacked, which server they aimed at and what happened.
@dataclass(frozen=True)
class ThreatEvent:
    id: int
    time_ms: int
    ip: str
    reports: int
    target: str
    outcome: str

    # Builds the dictionary sent to the frontend.
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "time_ms": self.time_ms,
            "ip": self.ip,
            "reports": self.reports,
            "target": self.target,
            "outcome": self.outcome,
        }
