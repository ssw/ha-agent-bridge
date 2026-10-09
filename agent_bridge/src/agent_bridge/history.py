"""Time parsing and history summarizing.

Agents handle large raw HA histories badly, so numeric histories can be
condensed into time buckets (min / time-weighted mean / max), and long ranges
are served from the recorder's long-term statistics.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, tzinfo
from typing import Any

# HA keeps detailed history for 10 days by default; beyond that, statistics.
RAW_HISTORY_DAYS = 10
MAX_RAW_POINTS = 300
MAX_CHANGES = 200
TARGET_BUCKETS = 48
BUCKET_LADDER = [
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(minutes=30),
    timedelta(hours=1),
    timedelta(hours=3),
    timedelta(hours=6),
    timedelta(days=1),
    timedelta(weeks=1),
]

_RELATIVE_RE = re.compile(r"^-(\d+)([mhdw])$")
_BUCKET_RE = re.compile(r"^(\d+)([mhdw])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class TimeError(ValueError):
    pass


def parse_time(value: str, now: datetime, tz: tzinfo) -> datetime:
    """'now', a relative offset like '-12h' / '-7d', or ISO 8601.

    ISO times without an offset are taken as local time.
    """
    value = value.strip()
    if value == "now":
        return now
    if m := _RELATIVE_RE.match(value):
        return now - timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as err:
        raise TimeError(
            f"can't read time {value!r}: use 'now', '-12h', '-7d', or ISO 8601"
        ) from err
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=tz)


def parse_bucket(value: str) -> timedelta:
    if m := _BUCKET_RE.match(value.strip()):
        delta = timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
        if delta >= timedelta(minutes=5):
            return delta
    raise TimeError(f"bucket {value!r}: use e.g. '5m', '1h', '1d' (at least 5m)")


def auto_bucket(start: datetime, end: datetime) -> timedelta:
    span = end - start
    for step in BUCKET_LADDER:
        if span / step <= TARGET_BUCKETS:
            return step
    return BUCKET_LADDER[-1]


def needs_statistics(start: datetime, now: datetime) -> bool:
    return start < now - timedelta(days=RAW_HISTORY_DAYS)


def statistics_period(bucket: timedelta) -> str:
    if bucket >= timedelta(weeks=1):
        return "week"
    if bucket >= timedelta(days=1):
        return "day"
    if bucket >= timedelta(hours=1):
        return "hour"
    return "5minute"


def _value(state: str) -> float | None:
    try:
        return float(state)
    except (TypeError, ValueError):
        return None


def _when(row: dict[str, Any]) -> datetime:
    stamp = row.get("last_changed") or row.get("last_updated")
    return datetime.fromisoformat(stamp).astimezone(UTC)


def summarize(
    rows: list[dict[str, Any]],
    start: datetime,
    end: datetime,
    bucket: timedelta | None,
    tz: tzinfo,
) -> dict[str, Any]:
    """Raw HA history rows -> a compact response.

    Numeric entities with a bucket (given, or chosen automatically when there
    are too many points) become min/mean/max per bucket. Everything else is
    returned as a capped list of changes.
    """
    points = [(_when(r), r["state"]) for r in rows]
    numeric = [(t, v) for t, s in points if (v := _value(s)) is not None]
    is_numeric = bool(points) and len(numeric) == len(
        [s for _, s in points if s not in ("unavailable", "unknown")]
    )
    if is_numeric and bucket is None and len(points) > MAX_RAW_POINTS:
        bucket = auto_bucket(start, end)
    if is_numeric and bucket is not None:
        return {
            "kind": "buckets",
            "bucket_minutes": int(bucket.total_seconds() // 60),
            "buckets": _buckets(numeric, start, end, bucket, tz),
        }
    changes = [{"at": t.astimezone(tz).isoformat(), "state": s} for t, s in points]
    truncated = len(changes) > MAX_CHANGES
    return {
        "kind": "changes",
        "changes": changes[-MAX_CHANGES:],
        "truncated": truncated,
    }


def _buckets(
    points: list[tuple[datetime, float]],
    start: datetime,
    end: datetime,
    bucket: timedelta,
    tz: tzinfo,
) -> list[dict[str, Any]]:
    """Time-weighted mean of the step function the state changes describe."""
    out = []
    edge = start
    while edge < end:
        stop = min(edge + bucket, end)
        # The value in force at `edge` is the last change at or before it.
        current = None
        for t, v in points:
            if t <= edge:
                current = v
            else:
                break
        weighted = 0.0
        covered = 0.0
        values = []
        cursor = edge
        for t, v in [*((t, v) for t, v in points if edge < t < stop), (stop, None)]:
            if current is not None:
                seconds = (t - cursor).total_seconds()
                weighted += current * seconds
                covered += seconds
                values.append(current)
            current, cursor = (v if v is not None else current), t
        row: dict[str, Any] = {"start": edge.astimezone(tz).isoformat()}
        if covered:
            row |= {
                "min": round(min(values), 2),
                "mean": round(weighted / covered, 2),
                "max": round(max(values), 2),
            }
        else:
            row |= {"min": None, "mean": None, "max": None}
        out.append(row)
        edge = stop
    return out


def summarize_statistics(rows: list[dict[str, Any]], tz: tzinfo) -> dict[str, Any]:
    def at(value: Any) -> str:
        if isinstance(value, int | float):
            value = datetime.fromtimestamp(value / 1000, UTC)
        else:
            value = datetime.fromisoformat(value)
        return value.astimezone(tz).isoformat()

    return {
        "kind": "statistics",
        "buckets": [
            {
                "start": at(r["start"]),
                "min": _round(r.get("min")),
                "mean": _round(r.get("mean")),
                "max": _round(r.get("max")),
            }
            for r in rows
        ],
    }


def _round(x: float | None) -> float | None:
    return None if x is None else round(x, 2)
