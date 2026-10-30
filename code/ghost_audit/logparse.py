"""Format-agnostic parsing of the heterogeneous log exports under evidence/logs.

Every line is reduced to (timestamp, service, trace, attrs) regardless of whether
it is logfmt, JSON-in-line, pipe-delimited, bracketed, syslog or a cloud-runtime
envelope with an escaped ``message="..."`` payload.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\s*(.*)$")
KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_.]*)=("(?:[^"\\]|\\.)*"|\S+)')


@dataclass
class LogLine:
    ts: str
    service: str = ""
    trace: str = ""
    level: str = ""
    attrs: dict = field(default_factory=dict)
    raw: str = ""


def _kv(text: str) -> dict:
    out = {}
    for k, v in KV_RE.findall(text):
        if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
            v = v[1:-1].replace('\\"', '"')
        out[k] = v
    return out


def parse_line(line: str) -> LogLine | None:
    line = line.rstrip("\r\n")
    m = TS_RE.match(line)
    if not m:
        return None
    ts, rest = m.groups()
    ll = LogLine(ts=ts, raw=line)
    rest = rest.strip()
    if rest.startswith("{"):  # structured JSON payload
        try:
            d = json.loads(rest)
        except json.JSONDecodeError:
            d = {}
        ll.attrs = {k: str(v) for k, v in d.items()}
        ll.service = d.get("service") or d.get("logger", "")
        ll.trace = d.get("trace_id", "")
        ll.level = d.get("severity", "")
        return ll
    if rest.startswith("["):  # [LEVEL] [service] [trace] event: k="v"
        parts = re.match(r"\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*([\w.]+):?\s*(.*)$", rest)
        if parts:
            ll.level, ll.service, ll.trace, ev, tail = parts.groups()
            ll.attrs = _kv(tail)
            ll.attrs.setdefault("event", ev)
            return ll
    if rest.startswith("|"):  # | LEVEL | service | trace | event | k="v"
        cols = [c.strip() for c in rest.strip("|").split("|")]
        if len(cols) >= 5:
            ll.level, ll.service, ll.trace, ev = cols[0], cols[1], cols[2], cols[3]
            ll.attrs = _kv("|".join(cols[4:]))
            ll.attrs.setdefault("event", ev)
            return ll
    if rest.startswith("<"):  # syslog: <pri>1 host app procid - - k=v
        parts = re.match(r"<\d+>\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+\S+\s+\S+\s*(.*)$", rest)
        if parts:
            _host, ll.service, ll.trace, tail = parts.groups()
            ll.attrs = _kv(tail)
            ll.level = ll.attrs.get("level", "")
            return ll
    kv = _kv(rest)
    if "message" in kv and "function" in kv:  # cloud runtime envelope
        ll.service = kv.get("function", "")
        ll.trace = kv.get("requestId", "")
        ll.level = kv.get("level", "")
        ll.attrs = _kv(kv["message"])
        return ll
    ll.attrs = kv
    ll.service = kv.get("service", "")
    ll.trace = kv.get("trace_id", "")
    ll.level = kv.get("level", "")
    return ll
