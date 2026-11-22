from dataclasses import dataclass, field
from datetime import datetime, timezone


def current_timestamp():
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class SecurityEvent:
    timestamp_utc: str
    category: str
    source: str
    subject: str
    action: str
    details: dict = field(default_factory=dict)

    def to_dict(self):
        """Convert the event into a standard dictionary."""
        return {
            "timestamp_utc": self.timestamp_utc,
            "category": self.category,
            "source": self.source,
            "subject": self.subject,
            "action": self.action,
            "details": self.details,
        }


@dataclass
class SecurityAlert:
    event: SecurityEvent
    rule_id: str
    severity: str
    reason: str
    dedup_key: str

    def to_dict(self):
        """Convert the event and detection information into one dictionary."""
        return {
            **self.event.to_dict(),
            "rule_id": self.rule_id,
            "severity": self.severity,
            "reason": self.reason,
            "dedup_key": self.dedup_key,
        }
