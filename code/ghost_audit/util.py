from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

NULLS = {"", "null", "none", "nil", "n/a", "-"}


def is_null(v) -> bool:
    return v is None or (isinstance(v, str) and v.strip().lower() in NULLS)


def parse_ts(s: str) -> datetime:
    """ISO-8601 -> aware UTC datetime. A timestamp without an offset is taken as UTC, never as the
    machine's local time, so results do not depend on where the audit runs."""
    dt = datetime.fromisoformat(s.strip().replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def norm_phone(p: str) -> str:
    digits = re.sub(r"\D", "", p)
    return "tel:" + digits


def norm_key(v: str) -> str:
    """Normalise an identifier so different renderings compare equal."""
    v = str(v).strip()
    if "@" in v:
        return v.lower()
    if re.fullmatch(r"\+?[\d\s().-]{7,}", v):
        return norm_phone(v)
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return v.lower()
    return v.lower()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()
