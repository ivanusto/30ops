"""RFC 3339 timestamps.

parse() accepts "Z" or a numeric offset and returns an aware datetime in
UTC. A timestamp without an offset is ambiguous on a mixed-timezone site
and is rejected (None), as the change records and the gate always did.
"""
from datetime import datetime, timezone


def parse(s):
    """'2026-10-13T12:30:00Z' -> aware UTC datetime; None for junk or no offset."""
    try:
        d = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError):
        return None
    if d.tzinfo is None:
        return None
    return d.astimezone(timezone.utc)


def to_epoch(s):
    """RFC 3339 -> int Unix time, or None."""
    d = parse(s)
    return int(d.timestamp()) if d is not None else None


def format(d):
    """aware datetime -> '2026-10-13T12:30:00Z' (seconds, UTC)."""
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def from_epoch(t):
    return format(datetime.fromtimestamp(t, timezone.utc))


def now():
    return datetime.now(timezone.utc)
