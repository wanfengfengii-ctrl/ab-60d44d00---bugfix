"""Timeline helpers.

Two independent timelines drive an adjudication:

* ``signed_at``        — when the artifact was allegedly signed;
* ``knowledge_cutoff`` — when the forensic team last possessed evidence.

Revocation *conclusions* are evaluated at ``signed_at``. Evidence is only
*eligible* when its recorded ``received_at`` (set once, at ingestion) is no
later than ``knowledge_cutoff``. The server clock never enters results
except to stamp ``received_at`` when an upload is first persisted.
"""
from __future__ import annotations

import datetime as _dt
import re

from .errors import MalformedEvidenceError


def parse_time(value: str | int, field: str = "time") -> int:
    """Parse an RFC 3339 / RFC 5280 timestamp into epoch seconds (UTC).

    Accepts ``2024-05-01T10:00:00Z`` style strings (with optional offset or
    no timezone = UTC) and integer epoch seconds. Returns an int so results
    are byte-stable across platforms.
    """
    if isinstance(value, bool):
        raise MalformedEvidenceError(f"{field}: invalid time")
    if isinstance(value, int):
        return value
    if isinstance(value, _dt.datetime):
        dt = value
    elif isinstance(value, str):
        s = value.strip()
        # RFC 5280 UTCTime: YYMMDDHHMMSSZ
        m = re.fullmatch(r"(\d{12})Z", s)
        if m:
            dt = _dt.datetime.strptime(s, "%y%m%d%H%M%SZ")
            dt = dt.replace(tzinfo=_dt.timezone.utc)
        else:
            txt = s
            if txt.endswith("Z"):
                txt = txt[:-1] + "+00:00"
            # datetime.fromisoformat handles offsets and fractional seconds
            try:
                dt = _dt.datetime.fromisoformat(txt)
            except ValueError as exc:
                raise MalformedEvidenceError(f"{field}: unparseable time {value!r}") from exc
    else:
        raise MalformedEvidenceError(f"{field}: invalid time type")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    return int(dt.astimezone(_dt.timezone.utc).timestamp())


def format_time(epoch: int) -> str:
    """Inverse of parse_time: canonical Zulu RFC 3339 seconds string."""
    dt = _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_epoch() -> int:
    """Only used to freeze ``received_at`` at upload persistence time."""
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())
