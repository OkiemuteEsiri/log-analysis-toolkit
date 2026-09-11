import json
from pathlib import Path
from .models import LogEvent


def load_events(path: str) -> list[LogEvent]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON array")
    events = [LogEvent.from_dict(row) for row in raw]
    ids = [e.event_id for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event_id detected")
    return events
