from dataclasses import dataclass
from datetime import datetime
from typing import Any

ALLOWED_SOURCES = {"windows", "sysmon", "identity", "network", "cloud", "endpoint"}


def parse_timestamp(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return ts


@dataclass(frozen=True)
class LogEvent:
    event_id: str
    timestamp: datetime
    source: str
    host: str
    user: str
    event_type: str
    action: str
    outcome: str
    src_ip: str = ""
    dst_ip: str = ""
    process: str = ""
    detail: str = ""

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "LogEvent":
        required = ["event_id", "timestamp", "source", "host", "user", "event_type", "action", "outcome"]
        missing = [k for k in required if not str(row.get(k, "")).strip()]
        if missing:
            raise ValueError(f"missing required fields: {', '.join(missing)}")
        source = str(row["source"]).lower()
        if source not in ALLOWED_SOURCES:
            raise ValueError(f"unsupported source: {source}")
        return cls(
            event_id=str(row["event_id"]), timestamp=parse_timestamp(str(row["timestamp"])),
            source=source, host=str(row["host"]), user=str(row["user"]),
            event_type=str(row["event_type"]).lower(), action=str(row["action"]).lower(),
            outcome=str(row["outcome"]).lower(), src_ip=str(row.get("src_ip", "")),
            dst_ip=str(row.get("dst_ip", "")), process=str(row.get("process", "")),
            detail=str(row.get("detail", "")),
        )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: int
    risk_score: int
    entity: str
    attack: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale: str
    remediation: str
    revalidation: str
