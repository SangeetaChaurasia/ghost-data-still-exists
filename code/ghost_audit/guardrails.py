"""Runtime guardrails: everything that enters or leaves the agent is checked here.

* Input   - request rows (schema, duplicates, timestamps, statuses) and request text hygiene.
* Model   - intent and vision responses are schema-validated; anything malformed is dropped
            and the deterministic fallback is used instead (cached responses are re-checked too).
* Output  - the predictions must satisfy the submission contract before output.csv is written.
* Secrets - run artefacts are redacted and the packaged zip is scanned before it is built.
"""
from __future__ import annotations

import json
import os
import re

from .policy import STATE
from .util import parse_ts

REQUEST_FIELDS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]
REPORTED_STATUSES = {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}
OUTPUT_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASE_OF = {op: ("FINDING" if op.startswith("REPORT_") else "VERIFICATION" if op.startswith("VERIFY_")
                 else "REMEDIATION") for op in STATE}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
MAX_REQUEST_TEXT = 4000

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class GuardrailError(Exception):
    """Raised when a run must stop rather than produce an untrustworthy result."""


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def timestamp_ok(v: str) -> bool:
    try:
        parse_ts(v)
        return True
    except (TypeError, ValueError):
        return False


def validate_requests(rows: list[dict], header: list[str] | None = None) -> tuple[list[str], list[str]]:
    """Return (errors, warnings). Errors make the run unsafe; warnings are recorded in the trace."""
    errors, warnings = [], []
    cols = header if header is not None else (list(rows[0]) if rows else REQUEST_FIELDS)
    missing = [f for f in REQUEST_FIELDS if f not in cols]
    if missing:
        return [f"request file is missing columns: {missing}"], warnings
    if not rows:
        return ["request file has no rows"], warnings
    seen = set()
    for i, r in enumerate(rows, 2):   # line numbers as a spreadsheet shows them
        cid = (r.get("case_id") or "").strip()
        where = cid or f"line {i}"
        if not cid:
            errors.append(f"line {i}: empty case_id")
        elif cid in seen:
            errors.append(f"{cid}: duplicate case_id")
        seen.add(cid)
        bad_ts = [f for f in ("requested_at", "reported_at", "audit_at") if not timestamp_ok(r.get(f) or "")]
        if bad_ts:
            errors.append(f"{where}: unreadable timestamp(s) {bad_ts}")
        elif parse_ts(r["audit_at"]) < parse_ts(r["requested_at"]):
            warnings.append(f"{where}: audit_at is before requested_at")
        elif parse_ts(r["reported_at"]) < parse_ts(r["requested_at"]):
            warnings.append(f"{where}: reported_at is before requested_at")
        if (r.get("reported_status") or "") not in REPORTED_STATUSES:
            warnings.append(f"{where}: unexpected reported_status {r.get('reported_status')!r}")
        if not EMAIL_RE.match((r.get("email") or "").strip()):
            warnings.append(f"{where}: request email is not a valid address")
        if not (r.get("request_text") or "").strip():
            warnings.append(f"{where}: empty request_text")
    return errors, warnings


def sanitize_request_text(text: str) -> str:
    """Strip control characters and cap the length before the text reaches a model."""
    text = CONTROL_RE.sub(" ", text or "")
    return text[:MAX_REQUEST_TEXT]


# ---------------------------------------------------------------------------
# Model responses
# ---------------------------------------------------------------------------

def _short_str(v, limit=300):
    return v[:limit] if isinstance(v, str) else None


def validate_intent_response(resp) -> dict | None:
    """A usable intent answer has a real boolean verdict. Anything else is rejected."""
    if not isinstance(resp, dict) or not isinstance(resp.get("authorizes_deletion"), bool):
        return None
    return {"authorizes_deletion": resp["authorizes_deletion"], "request_type": _short_str(resp.get("request_type"), 80),
            "reason": _short_str(resp.get("reason"))}


VISION_KINDS = {"USER_PROFILE", "SEARCH_INDEX_ENTRY", "ANALYTICS_PROFILE", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT",
                "USER_EXPORT", "DATA_FLOW", "BACKUP_ARCHIVE", "SECURITY_AUDIT_LOG", "ACCOUNT_TOMBSTONE",
                "MARKETING_PROFILE", "LEGAL_HOLD_RECORD"}
ID_RE = re.compile(r"^[A-Za-z0-9_.:/@#-]{1,120}$")


def _opt_bool(v):
    return v if isinstance(v, bool) else None


def validate_vision_record(r) -> tuple[dict | None, list[str]]:
    """Coerce one extracted record to the schema the evidence store expects; report what was dropped."""
    issues = []
    if not isinstance(r, dict):
        return None, ["record is not an object"]
    out = {}
    rid = r.get("resource_id")
    if isinstance(rid, str) and ID_RE.match(rid.strip()):
        out["resource_id"] = rid.strip()
    else:
        if rid not in (None, ""):
            issues.append(f"dropped malformed resource_id {str(rid)[:40]!r}")
        out["resource_id"] = None
    aliases = r.get("aliases") if isinstance(r.get("aliases"), list) else []
    out["aliases"] = [a.strip() for a in aliases if isinstance(a, str) and a.strip() and len(a) <= 200]
    if not out["resource_id"] and not out["aliases"]:
        return None, issues + ["record has neither resource_id nor aliases"]
    for f in ("system_id", "customer_reference", "status_text"):
        out[f] = _short_str(r.get(f), 120)
    kind = r.get("kind")
    out["kind"] = kind if kind in VISION_KINDS else None
    if kind not in VISION_KINDS and kind is not None:
        issues.append(f"unknown kind {str(kind)[:40]!r}")
    email = r.get("email")
    out["email"] = email.strip() if isinstance(email, str) and EMAIL_RE.match(email.strip()) else None
    if email and not out["email"]:
        issues.append("dropped malformed email")
    phone = r.get("phone")
    out["phone"] = phone if isinstance(phone, str) and len(re.sub(r"\D", "", phone)) >= 7 else None
    if phone and not out["phone"]:
        issues.append("dropped malformed phone")
    out["full_name"] = _short_str(r.get("full_name"), 120)
    out["is_focus"] = r.get("is_focus") is True
    out["present"] = r.get("present") is not False
    out["enabled"] = _opt_bool(r.get("enabled"))
    out["restore_allowed"] = _opt_bool(r.get("restore_allowed"))
    sdi = r.get("shows_direct_identifiers")
    # When the model leaves this out, fall back to what it actually transcribed.
    out["shows_direct_identifiers"] = sdi if isinstance(sdi, bool) else bool(out["email"] or out["phone"]
                                                                             or out["full_name"])
    return out, issues


def validate_vision_response(resp) -> tuple[dict, list[str]]:
    if not isinstance(resp, dict):
        return {"records": []}, ["response is not an object"]
    issues, recs = [], []
    raw = resp.get("records") if isinstance(resp.get("records"), list) else []
    if not isinstance(resp.get("records"), list):
        issues.append("records is not a list")
    for i, r in enumerate(raw):
        rec, rec_issues = validate_vision_record(r)
        issues += [f"record {i}: {x}" for x in rec_issues]
        if rec is not None:
            if not rec["system_id"]:
                rec["system_id"] = _short_str(resp.get("system_id"), 120)
            recs.append(rec)
    out = {f: _short_str(resp.get(f), 500) for f in ("screen_title", "tool", "system_id", "captured_text")}
    out["records"] = recs
    return out, issues


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

def contract_errors(rows: list[dict], requests: list[dict], manifest: dict) -> list[str]:
    """Every way a predictions table can break the submission contract.

    ``manifest`` maps file_id -> captured_at. Returns an empty list when the output is valid."""
    errs = []
    req = {r["case_id"]: r for r in requests}
    ids = [r["case_id"] for r in rows]
    if len(ids) != len(set(ids)):
        errs.append("duplicate case_id in output")
    if set(ids) != set(req):
        errs.append(f"output/request case_id mismatch: missing={sorted(set(req) - set(ids))[:5]} "
                    f"extra={sorted(set(ids) - set(req))[:5]}")
    for r in rows:
        cid = r["case_id"]
        status = r.get("deletion_status")
        if status not in OUTPUT_STATUSES:
            errs.append(f"{cid}: bad status {status!r}")
            continue
        try:
            steps = json.loads(r["steps_json"])
        except (TypeError, json.JSONDecodeError):
            errs.append(f"{cid}: steps_json is not JSON")
            continue
        if not isinstance(steps, list):
            errs.append(f"{cid}: steps_json is not an array")
            continue
        if status == "NOT_APPLICABLE" and steps:
            errs.append(f"{cid}: NOT_APPLICABLE must have no steps")
        if status == "INCOMPLETE" and not any(isinstance(s, dict) and s.get("phase") == "FINDING" for s in steps):
            errs.append(f"{cid}: INCOMPLETE without a finding")
        audit_at = parse_ts(req[cid]["audit_at"]) if cid in req and timestamp_ok(req[cid].get("audit_at", "")) else None
        last_rank = 0
        for i, s in enumerate(steps, 1):
            if not isinstance(s, dict) or set(s) != STEP_FIELDS:
                errs.append(f"{cid}#{i}: step must have exactly the fields {sorted(STEP_FIELDS)}")
                continue
            if s["step_no"] != i or isinstance(s["step_no"], bool):
                errs.append(f"{cid}#{i}: step_no is {s['step_no']!r}")
            if s["operation"] not in STATE or STATE[s["operation"]] != s["state"]:
                errs.append(f"{cid}#{i}: invalid operation/state {s['operation']}/{s['state']}")
                continue
            if PHASE_OF[s["operation"]] != s["phase"]:
                errs.append(f"{cid}#{i}: {s['operation']} is not a {s['phase']} operation")
            rank = PHASE_RANK[PHASE_OF[s["operation"]]]
            if rank < last_rank:
                errs.append(f"{cid}#{i}: phases out of order")
            last_rank = max(last_rank, rank)
            if not all(isinstance(s[f], str) for f in ("system_id", "resource_id", "evidence_id")):
                errs.append(f"{cid}#{i}: ids must be strings")
                continue
            if not s["system_id"] or not s["resource_id"]:
                errs.append(f"{cid}#{i}: empty system_id/resource_id")
            ev = s["evidence_id"]
            needs_ev = status == "COMPLETE" or s["phase"] == "FINDING"
            if needs_ev and not ev:
                errs.append(f"{cid}#{i}: missing evidence_id")
            if not needs_ev and ev:
                errs.append(f"{cid}#{i}: proposed work must not cite evidence")
            if status == "COMPLETE" and s["phase"] != "VERIFICATION":
                errs.append(f"{cid}#{i}: COMPLETE case contains a {s['phase']} step")
            if ev in manifest and audit_at is not None and parse_ts(manifest[ev]) > audit_at:
                errs.append(f"{cid}#{i}: cites {ev}, captured after audit_at")
    return errs


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("openai-key", re.compile(r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("anthropic-key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{30,}")),
]
SECRET_ENV_VARS = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "AZURE_OPENAI_API_KEY")


def _secret_values(extra=()) -> list[str]:
    vals = [os.environ.get(k, "") for k in SECRET_ENV_VARS] + list(extra)
    return [v for v in vals if v and len(v) >= 8]


def find_secrets(text: str, extra_values=()) -> list[str]:
    """Names of the secret patterns found (never the secret itself)."""
    hits = [name for name, rx in SECRET_PATTERNS if rx.search(text)]
    if any(v in text for v in _secret_values(extra_values)):
        hits.append("configured-key-value")
    return hits


def redact(text: str, extra_values=()) -> str:
    for v in _secret_values(extra_values):
        text = text.replace(v, "[REDACTED]")
    for _, rx in SECRET_PATTERNS:
        text = rx.sub("[REDACTED]", text)
    return text

