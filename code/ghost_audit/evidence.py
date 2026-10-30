"""Normalise every participant-facing evidence file into ``Observation`` rows.

An observation is one statement of the form "at time T, evidence E showed
resource R in system S with these identifiers / this state".  All downstream
reasoning (identity linking, point-in-time state, policy) works on these rows
and never on raw file formats.
"""
from __future__ import annotations

import csv
import json
import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .guardrails import timestamp_ok
from .logparse import parse_line
from .util import norm_key, is_null

# ---------------------------------------------------------------------------
# Observation model
# ---------------------------------------------------------------------------

# Canonical record kinds (mapped onto deletion_rules.csv categories later).
KIND_BY_RECORD_TYPE = {
    "USER_PROFILE": "USER_PROFILE",
    "SEARCH_INDEX_ENTRY": "SEARCH_INDEX_ENTRY",
    "ANALYTICS_PROFILE": "ANALYTICS_PROFILE",
    "SUPPORT_MESSAGE": "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT": "SUPPORT_ATTACHMENT",
    "USER_EXPORT": "USER_EXPORT",
    "DATA_FLOW": "DATA_FLOW",
    "BACKUP_ARCHIVE": "BACKUP_ARCHIVE",
    "SECURITY_AUDIT_LOG": "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD": "LEGAL_HOLD_RECORD",
    "ACCOUNT_TOMBSTONE": "ACCOUNT_TOMBSTONE",
    "MARKETING_PROFILE": "MARKETING_PROFILE",
}

KIND_BY_PREFIX = [
    ("account_", "USER_PROFILE"),
    ("search_", "SEARCH_INDEX_ENTRY"),
    ("analytics_", "ANALYTICS_PROFILE"),
    ("export_", "USER_EXPORT"),
    ("data_flow_", "DATA_FLOW"),
    ("backup_", "BACKUP_ARCHIVE"),
    ("audit_record_", "SECURITY_AUDIT_LOG"),
    ("legal_hold_", "LEGAL_HOLD_RECORD"),
    ("tombstone_", "ACCOUNT_TOMBSTONE"),
    ("marketing_", "MARKETING_PROFILE"),
    ("object_", "SUPPORT_ATTACHMENT"),
    ("email_delivery_", "EMAIL_DELIVERY_LOG"),
    ("cache_", "CACHE_ENTRY"),
    ("support_", "SUPPORT_MESSAGE"),
]

SYSTEM_BY_KIND = {
    "USER_PROFILE": "account_service",
    "SEARCH_INDEX_ENTRY": "search_service",
    "ANALYTICS_PROFILE": "analytics_platform",
    "SUPPORT_MESSAGE": "support_platform",
    "SUPPORT_ATTACHMENT": "support_platform",
    "USER_EXPORT": "export_service",
    "DATA_FLOW": "integration_service",
    "BACKUP_ARCHIVE": "backup_service",
    "SECURITY_AUDIT_LOG": "security_service",
    "LEGAL_HOLD_RECORD": "legal_service",
    "ACCOUNT_TOMBSTONE": "identity_service",
    "MARKETING_PROFILE": "marketing_platform",
    "EMAIL_DELIVERY_LOG": "email_delivery_service",
    "CACHE_ENTRY": "cache_service",
}


def _edit1(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    if len(a) > len(b):
        a, b = b, a
    i = j = diff = 0
    while i < len(a) and j < len(b):
        if a[i] != b[j]:
            diff += 1
            j += 1
            if diff > 1:
                return False
        else:
            i += 1
            j += 1
    return True


def snap_identifier(value: str, known: set) -> str:
    """Correct single-character OCR slips (e.g. '-' read as '.') against identifiers that
    exist in the identity data; leave the value untouched when the match is not unique."""
    v = value.strip().lower()
    if v in known:
        return v
    hits = [k for k in known if _edit1(v, k)]
    return hits[0] if len(hits) == 1 else value


def kind_from_resource(resource_id: str) -> str:
    for prefix, kind in KIND_BY_PREFIX:
        if resource_id.startswith(prefix):
            return kind
    return "UNKNOWN"


@dataclass
class Observation:
    evidence_id: str
    captured_at: str          # manifest capture time (citation cut-off)
    observed_at: str          # record-level time when known
    system_id: str
    resource_id: str
    kind: str
    present: bool | None = True     # record exists?
    pii: dict = field(default_factory=dict)       # direct identifiers still on the record
    keys: set = field(default_factory=set)        # identifiers linking the record to a person
    lookup_keys: set = field(default_factory=set)  # keys the collector used to find the record
    attrs: dict = field(default_factory=dict)     # enabled / restore_allowed / retention ...
    source: str = ""

    def short(self) -> str:
        return (f"{self.evidence_id}@{self.observed_at} {self.system_id}/{self.resource_id} "
                f"{self.kind} present={self.present} pii={sorted(self.pii)} attrs={self.attrs}")


PII_FIELDS = {
    "email": "email", "owner_email": "email", "requester_email": "email", "customer_email": "email",
    "phone": "phone", "owner_phone": "phone", "requester_phone": "phone",
    "full_name": "name", "display_name": "name", "requester_name": "name", "name": "name",
    "email_hash": "email_hash",
}
REF_FIELDS = ("customer_reference", "user_id", "subject_reference", "subject_selector", "subject_ref")


def _clean(v):
    if v is None:
        return None
    if isinstance(v, str) and is_null(v):
        return None
    return v


EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
NON_IDENTITY_FIELDS = {"resource_id", "archive_key", "archive_path", "object_key", "index_name", "integrity_seal",
                       "event", "source"}


def extract_identity(rec: dict) -> tuple[dict, set]:
    """Return (direct identifiers present on the record, link keys) for a flat record.

    Named PII columns are read directly; every other free-text value (uploaded_by,
    message bodies, lookup values...) is scanned for e-mail addresses so identifiers
    embedded in content are not missed."""
    pii, keys = {}, set()
    for f, cat in PII_FIELDS.items():
        v = _clean(rec.get(f))
        if v is None or not isinstance(v, str):
            continue
        if v.strip().upper() == "[REDACTED]":
            continue
        pii[cat] = v
        keys.add(norm_key(v))
    for f in REF_FIELDS:
        v = _clean(rec.get(f))
        if isinstance(v, str):
            keys.add(norm_key(v))
    for f, v in rec.items():
        if f in PII_FIELDS or f in REF_FIELDS or f in NON_IDENTITY_FIELDS or not isinstance(v, str):
            continue
        for e in EMAIL_IN_TEXT.findall(v):
            pii.setdefault("email", e)
            pii[f"email_in_{f}"] = e
            keys.add(norm_key(e))
    return pii, keys


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

RESOURCE_ID_RE = re.compile(r"(account|search|analytics|support|export|data_flow|backup|audit_record|legal_hold|"
                            r"tombstone|marketing|object|cache|email_delivery)_\d+")


class EvidenceStore:
    def __init__(self, dataset_dir: Path, vision_cache: dict | None = None, aliases: dict | None = None,
                 known_emails=None):
        """``aliases`` maps a lower-cased display alias (file name, statement number...) to
        (resource_id, system_id); it comes from data-catalog activity rows."""
        self.dataset_dir = Path(dataset_dir)
        self.manifest: dict[str, dict] = {}
        self.by_path: dict[str, str] = {}
        self.obs: list[Observation] = []
        self.coverage: list[dict] = []
        self.vision_cache = vision_cache or {}
        self.aliases = aliases or {}
        self.alias_systems = {rid: sys for rid, sys in self.aliases.values()}
        self.known_emails = set(known_emails or ())
        self.unparsed: list[str] = []
        self.partial: set[str] = set()   # files only partly readable: never used as absence proof
        self._load_manifest()
        for fid, meta in sorted(self.manifest.items()):
            self._load_file(fid, meta)
        self.by_resource: dict[str, list[Observation]] = defaultdict(list)
        self.by_key: dict[str, list[Observation]] = defaultdict(list)
        for o in self.obs:
            self.by_resource[o.resource_id].append(o)
            for k in o.keys | o.lookup_keys:
                self.by_key[k].append(o)

    # -- manifest -----------------------------------------------------------
    def _load_manifest(self):
        """Only well-formed manifest rows are loaded. A file without a readable capture time can
        never be shown to be admissible, and a path must stay inside dataset/evidence."""
        evidence_root = (self.dataset_dir / "evidence").resolve()
        with open(self.dataset_dir / "evidence_files.csv", encoding="utf-8-sig") as fh:
            for row in csv.DictReader(fh):
                fid = (row.get("file_id") or "").strip()
                problem = None
                if not fid:
                    problem = "empty file_id"
                elif fid in self.manifest:
                    problem = "duplicate file_id (first entry kept)"
                elif not timestamp_ok(row.get("captured_at") or ""):
                    problem = "unreadable captured_at"
                elif not (self.dataset_dir / (row.get("file_path") or "")).resolve().is_relative_to(evidence_root):
                    problem = "file_path points outside dataset/evidence"
                if problem:
                    self.unparsed.append(f"{fid or '?'}: manifest row skipped: {problem}")
                    continue
                self.manifest[fid] = row
                self.by_path[row["file_path"]] = fid

    def _read_text(self, fid, path) -> str:
        data = path.read_bytes()
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            self.unparsed.append(f"{fid}: invalid UTF-8 bytes replaced; readable parts kept")
            return data.decode("utf-8", errors="replace")

    def _add(self, fid, observed_at, system, rid, kind=None, present=True, rec=None,
             extra_keys=(), lookup=(), attrs=None, source=""):
        meta = self.manifest[fid]
        rec = rec or {}
        pii, keys = extract_identity(rec)
        keys |= {norm_key(k) for k in extra_keys if k and not is_null(k)}
        kind = kind or kind_from_resource(rid)
        system = system or SYSTEM_BY_KIND.get(kind, "")
        o = Observation(
            evidence_id=fid, captured_at=meta["captured_at"], observed_at=observed_at or meta["captured_at"],
            system_id=system, resource_id=rid, kind=kind, present=present, pii=pii, keys=keys,
            lookup_keys={norm_key(k) for k in lookup if k and not is_null(k)}, attrs=attrs or {}, source=source,
        )
        self.obs.append(o)
        return o

    def _load_file(self, fid, meta):
        path = self.dataset_dir / meta["file_path"]
        suffix = path.suffix.lower()
        try:
            if suffix == ".json":
                self._load_json(fid, path)
            elif suffix == ".txt":
                self._load_ledger_text(fid, path)
            elif suffix == ".sql":
                self._load_sql(fid, path)
            elif suffix == ".log":
                self._load_log(fid, path)
            elif suffix == ".pdf":
                self._load_pdf(fid, path)
            elif suffix in (".png", ".jpg", ".jpeg"):
                self._load_image(fid, path)
            else:
                self.unparsed.append(fid)
        except Exception as exc:  # keep going; report later
            self.unparsed.append(f"{fid}: {exc!r}")

    # -- JSON ---------------------------------------------------------------
    def _load_json(self, fid, path):
        d = json.loads(self._read_text(fid, path))
        if "snapshots" in d:
            for snap in d["snapshots"]:
                self._load_collection(fid, snap.get("captured_at"), snap.get("data_store"),
                                      snap.get("collection"), snap.get("records", []))
        elif "service_exports" in d:
            for system, groups in d["service_exports"].items():
                for gname, entries in groups.items():
                    for e in entries:
                        self._load_service_export(fid, system, gname, e)
        elif "records" in d and d["records"] and "record_type" in d["records"][0]:
            for r in d["records"]:
                self._ledger_row(fid, r.get("recorded_at"), r["system"], r["resource_id"],
                                 r["record_type"], r["result"], r.get("subject_reference"))
        elif "collection" in d:
            self._load_collection(fid, d.get("captured_at"), None, d["collection"], d.get("records", []))
        else:
            self.unparsed.append(fid)

    def _load_collection(self, fid, ts, store, collection, records):
        if store == "account_service" and collection == "customer_profiles":
            self.coverage.append(dict(evidence_id=fid, captured_at=self.manifest[fid]["captured_at"],
                                      observed_at=ts or self.manifest[fid]["captured_at"], system="account_service",
                                      rids={r.get("resource_id") for r in records}, directory=False))
        for r in records:
            rid = r.get("resource_id")
            if not rid:
                continue
            self._collection_record(fid, ts, store, collection, r)

    def _collection_record(self, fid, ts, store, collection, r, source=""):
        rid = r["resource_id"]
        kind = kind_from_resource(rid)
        attrs = {}
        flat = dict(r)
        if collection == "customer_search_documents" and isinstance(r.get("document"), dict):
            flat.update(r["document"])
        if collection == "operational_record_history":
            return self._ledger_row(fid, r.get("recorded_at") or ts, r.get("system") or store, rid,
                                    r.get("record_type"), r.get("result"), r.get("lookup_value"))
        if collection == "ticket_attachments":
            kind = "SUPPORT_ATTACHMENT"
            attrs["file_name"] = r.get("file_name")
            attrs["uploaded_by"] = r.get("uploaded_by")
        if collection == "support_conversations":
            kind = "SUPPORT_MESSAGE"
            attrs["message_text"] = r.get("message_text")
        if collection == "deleted_customer_references":
            kind = "ACCOUNT_TOMBSTONE"
            attrs["account_status"] = r.get("account_status")
        if collection == "retained_order_records":
            kind = "LEGAL_HOLD_RECORD"
            attrs["retained_until"] = r.get("retained_until")
            attrs["retention_reason"] = r.get("retention_reason")
        if "enabled" in r:
            attrs["enabled"] = bool(r["enabled"])
        if "restore_allowed" in r:
            attrs["restore_allowed"] = bool(r["restore_allowed"])
        if "download_available" in r:
            attrs["available"] = bool(r["download_available"])
        if "account_status" in r:
            attrs["account_status"] = r["account_status"]
        if "retention_until" in r:
            attrs["retention_until"] = r["retention_until"]
        if "expires_at" in r:
            attrs["expires_at"] = r["expires_at"]
        if "subject_selector" in r:
            attrs["selector"] = r["subject_selector"]
        system = store or SYSTEM_BY_KIND.get(kind)
        if store == "support_platform":
            system = "support_platform"
        present = True
        if kind == "USER_PROFILE" and attrs.get("account_status") in ("DELETED",):
            present = False
        if kind == "USER_EXPORT" and attrs.get("available") is False:
            present = False   # expired / withdrawn download: the export object is gone
        self._add(fid, ts, system, rid, kind, present, flat, attrs=attrs, source=source or collection or "")

    def _load_service_export(self, fid, system, group, e):
        rid = e.get("resource_id")
        ts = e.get("observed_at")
        if group == "profile_lookups":
            prof = e.get("profile") or {}
            present = e.get("status_code") == 200
            self._add(fid, ts, system, rid, "USER_PROFILE", present, prof, source="profile_lookups")
        elif group == "index_queries":
            docs = (e.get("hits") or {}).get("documents") or []
            if docs:
                for d in docs:
                    self._add(fid, ts, system, d.get("resource_id") or rid, "SEARCH_INDEX_ENTRY", True, d,
                              lookup=[e.get("query")], source="index_queries")
            else:
                self._add(fid, ts, system, rid, "SEARCH_INDEX_ENTRY", False, {}, lookup=[e.get("query")],
                          source="index_queries")
        else:
            kind = {"profiles": "ANALYTICS_PROFILE", "restore_entries": "BACKUP_ARCHIVE", "exports": "USER_EXPORT",
                    "connectors": "DATA_FLOW", "audit_records": "SECURITY_AUDIT_LOG",
                    "tickets": "SUPPORT_MESSAGE"}.get(group, kind_from_resource(rid))
            attrs = {}
            for f in ("enabled", "restore_allowed", "retention_until", "last_delivery_status", "connector_name",
                      "event_code", "message_excerpt"):
                if f in e:
                    attrs[f] = e[f]
            self._add(fid, ts, system, rid, kind, True, e, attrs=attrs, source=group)

    # -- ledger style rows (handover txt, manifests, diagnostic logs) --------
    LEDGER_STATE = {
        "NOT_FOUND": dict(present=False),
        "FOUND": dict(present=True),
        "IDENTIFIABLE": dict(present=True, identifiable=True),
        "ANONYMIZED": dict(present=True, identifiable=False),
        "REDACTED": dict(present=True, identifiable=False),
        "ACTIVE": dict(present=True, active=True),
        "DISABLED": dict(present=True, active=False),
        "BLOCKED": dict(present=True, active=False),
    }

    def _ledger_row(self, fid, ts, system, rid, record_type, result, subject):
        st = dict(self.LEDGER_STATE.get((result or "").upper(), {"present": True}))
        present = st.pop("present")
        kind = KIND_BY_RECORD_TYPE.get(record_type or "", kind_from_resource(rid))
        attrs = {"ledger_result": result}
        if "identifiable" in st:
            attrs["identifiable"] = st["identifiable"]
        if "active" in st:
            if kind == "DATA_FLOW":
                attrs["enabled"] = st["active"]
            elif kind == "BACKUP_ARCHIVE":
                attrs["restore_allowed"] = st["active"]
        subj = subject if subject and "no direct identifier" not in subject.lower() else None
        rec = {}
        keys = []
        if subj:
            keys.append(subj)
            if attrs.get("identifiable") or (present and kind not in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD")
                                             and not subj.lower().startswith("user_")):
                # the subject value is visible on the record itself
                if "@" in subj:
                    rec["email"] = subj
        o = self._add(fid, ts, system, rid, kind, present, rec, extra_keys=keys, attrs=attrs, source="ledger")
        if subj and not present:
            o.lookup_keys.add(norm_key(subj))
            o.keys.discard(norm_key(subj))
        return o

    LEDGER_LINE = re.compile(r"^-\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(.+?)\s*$")

    def _load_ledger_text(self, fid, path):
        for line in self._read_text(fid, path).splitlines():
            m = self.LEDGER_LINE.match(line.strip())
            if m:
                ts, system, rid, rtype, result, subj = m.groups()
                self._ledger_row(fid, ts, system, rid, rtype, result, subj)

    # -- SQL ----------------------------------------------------------------
    def _load_sql(self, fid, path):
        text = self._read_text(fid, path)
        con = sqlite3.connect(":memory:")
        try:
            con.executescript(text)
        except sqlite3.Error as exc:
            # Salvage statement by statement. Rows that did load still show data is present, but a
            # damaged table cannot prove that anything is absent.
            con.close()
            con = sqlite3.connect(":memory:")
            buf, failed = "", 0
            for line in text.splitlines(keepends=True):
                buf += line
                if sqlite3.complete_statement(buf):
                    try:
                        con.execute(buf)
                    except sqlite3.Error:
                        failed += 1
                    buf = ""
            tail = ", last statement cut off" if buf.strip() else ""
            self.partial.add(fid)
            self.unparsed.append(f"{fid}: SQL only partly loaded ({exc}; {failed} statements failed{tail}); "
                                 "kept as presence evidence only")
        m = re.search(r"Captured at:\s*(\S+)", text)
        cap = m.group(1) if m else self.manifest[fid]["captured_at"]
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        con.row_factory = sqlite3.Row
        scope = []
        if "snapshot_scope" in tables:
            scope = [r[0] for r in con.execute("select origin_system from snapshot_scope")]
        for t in tables:
            rows = [dict(r) for r in con.execute(f'select * from "{t}"')]
            cols = set(rows[0]) if rows else set()
            if t == "snapshot_scope":
                continue
            if fid in self.partial:
                pass
            elif t.startswith("customer_profiles") and (t != "customer_profiles" or "account_service" in scope):
                # A complete account-table capture proves absence of anything it does not hold.
                self.coverage.append(dict(evidence_id=fid, captured_at=self.manifest[fid]["captured_at"],
                                          observed_at=cap, system="account_service",
                                          rids={r["resource_id"] for r in rows}, directory=t != "customer_profiles",
                                          table=t))
            if "record_json" in cols:
                acct = {r["resource_id"] for r in rows if r["origin_system"] == "account_service"}
                if acct and fid not in self.partial:
                    # replica capture that includes the account table for its subjects
                    self.coverage.append(dict(evidence_id=fid, captured_at=self.manifest[fid]["captured_at"],
                                              observed_at=cap, system="account_service", rids=acct,
                                              directory=False, table=t))
                for r in rows:
                    rec = json.loads(r["record_json"])
                    self._collection_record(fid, r.get("updated_at") or cap, r["origin_system"], r["collection_name"],
                                            rec, source=t)
                continue
            for r in rows:
                rid = r["resource_id"]
                kind = kind_from_resource(rid)
                attrs = {}
                for f in ("enabled", "restore_allowed", "retention_until", "account_status", "last_delivery_status",
                          "connector_name", "event_code", "message_excerpt", "source_resource_id", "index_name",
                          "audience_cohort", "object_key"):
                    if f in r and r[f] is not None:
                        attrs[f] = r[f]
                if "enabled" in attrs:
                    attrs["enabled"] = bool(attrs["enabled"])
                if "restore_allowed" in attrs:
                    attrs["restore_allowed"] = bool(attrs["restore_allowed"])
                present = True
                if attrs.get("account_status") == "DELETED":
                    present = False
                self._add(fid, r.get("updated_at") or r.get("indexed_at") or cap, None, rid, kind, present, r,
                          attrs=attrs, source=t)
            self.manifest[fid]["_sql_tables"] = tables
        self.manifest[fid]["_scope"] = scope
        con.close()

    # -- logs -----------------------------------------------------------------
    LOOKUP_ATTRS = ("lookup_key", "match_key", "subject_key", "scan_key", "owner_key", "subject_ref",
                    "correlation_key")

    def _load_log(self, fid, path):
        lines = [ll for ll in (parse_line(x) for x in self._read_text(fid, path).splitlines()) if ll]
        traces: dict[str, list] = defaultdict(list)
        for i, ll in enumerate(lines):
            key = ll.trace or f"__line{i}"
            traces[key].append(ll)
        for tid, group in traces.items():
            lookups = set()
            for ll in group:
                for a in self.LOOKUP_ATTRS:
                    v = ll.attrs.get(a)
                    if v and not is_null(v):
                        lookups.add(v)
            for ll in group:
                self._log_event(fid, ll, lookups)

    def _log_event(self, fid, ll, lookups):
        a = ll.attrs
        ev = a.get("event", "")
        rid = a.get("resource_id")
        svc = ll.service
        if ev == "record_lookup":
            self._ledger_row(fid, ll.ts, a.get("system"), rid, a.get("record_type"), a.get("result"),
                             a.get("subject_reference"))
            return
        if not rid or is_null(rid):
            return
        if lookups and rid in lookups:
            lookups = lookups - {rid}
        rec = {k: v for k, v in a.items() if k in PII_FIELDS or k in REF_FIELDS}
        attrs = {"event": ev}
        present = True
        kind = kind_from_resource(rid)
        system = svc
        if svc == "profile_service":
            system = "account_service"
        if ev == "profile_lookup_completed":
            present = a.get("http_status") == "200" or a.get("rows") == "1"
            kind = "USER_PROFILE"
            system = "account_service"
        elif ev == "index_query_completed":
            present = a.get("result") == "hit"
        elif ev == "message_pii_scan":
            rec = {"email": a.get("matched_value")} if "@" in a.get("matched_value", "") else {"phone": a.get("matched_value")}
            attrs["identifiable"] = True
            kind = "SUPPORT_MESSAGE"
        elif ev == "attachment_pii_scan":
            mv = a.get("matched_value", "")
            rec = {"email": mv} if "@" in mv else {"phone": mv}
            attrs["file_name"] = a.get("file")
            kind = "SUPPORT_ATTACHMENT"
        elif ev == "message_read":
            attrs["identifiable"] = a.get("message_text", "").strip() != "[REDACTED]"
            attrs["message_text"] = a.get("message_text")
            kind = "SUPPORT_MESSAGE"
        elif ev in ("analytics_identity_scan",):
            mv = a.get("matched_value", "")
            rec = {"email": mv} if "@" in mv else ({"phone": mv} if mv else {})
            attrs["identifiable"] = True
        elif ev == "analytics_profile_read":
            attrs["identifiable"] = a.get("direct_identifiers", "0") != "0"
        elif ev == "contact_lookup_completed":
            kind = "SECONDARY_IDENTIFIER"
            present = a.get("rows", "1") != "0"
            if a.get("correlation_key"):
                rec = {"email_hash": a["correlation_key"]}
        elif ev in ("connector_heartbeat", "connector_config_loaded", "connector_config_read_completed"):
            attrs["enabled"] = a.get("enabled") == "true"
            kind = "DATA_FLOW"
        elif ev == "restore_candidate_evaluated":
            attrs["restore_allowed"] = a.get("eligible") == "true" and a.get("deletion_block") != "true"
            kind = "BACKUP_ARCHIVE"
        elif ev == "restore_authorization_completed":
            attrs["restore_allowed"] = a.get("decision") != "deny"
            kind = "BACKUP_ARCHIVE"
        elif ev == "restore_policy_read_completed":
            attrs["restore_allowed"] = a.get("restore_allowed") == "true"
            present = a.get("archive_present", "true") == "true"
            kind = "BACKUP_ARCHIVE"
        elif ev in ("export_download_check_completed", "export_metadata_read_completed"):
            attrs["available"] = a.get("available") == "true"
            present = attrs["available"]
            kind = "USER_EXPORT"
        elif ev == "audit_record_read_completed":
            present = a.get("rows", "1") != "0"
            attrs["retention_until"] = a.get("retention_until")
            kind = "SECURITY_AUDIT_LOG"
        elif ev == "retained_order_loaded":
            kind = "LEGAL_HOLD_RECORD"
            attrs["reason"] = a.get("reason")
        elif ev == "support_ticket_read_completed":
            kind = "SUPPORT_MESSAGE"
        elif ev in ("contact_query_completed",):
            present = a.get("rows", "1") != "0"
        elif ev == "deletion_marker_check":
            attrs["deletion_marker"] = a.get("marker_found") == "true"
        elif ev.endswith("_started") or ev in ("thumbnail_failed",):
            return
        else:
            attrs["unhandled"] = True
        if svc == "support_replica":
            system = "support_platform"
        if system in ("attachment_preview",):
            return
        # A lookup key only links the subject when the read actually returned the record,
        # or as a "we looked for X and it was absent" statement.
        self._add(fid, ll.ts, system, rid, kind, present, rec, attrs=attrs, source=ev, lookup=lookups)

    # -- PDFs ----------------------------------------------------------------
    def _load_pdf(self, fid, path):
        from .documents import pdf_observations
        for item in pdf_observations(path, self.manifest[fid], self.aliases):
            self._add(fid, item.get("observed_at"), item.get("system_id"), item["resource_id"], item.get("kind"),
                      item.get("present", True), item.get("record", {}), extra_keys=item.get("keys", []),
                      attrs=item.get("attrs", {}), source="pdf")

    # -- images --------------------------------------------------------------
    def _load_image(self, fid, path):
        extracted = self.vision_cache.get(path.name)
        if not extracted:
            self.unparsed.append(f"{fid}: no vision extraction cached for {path.name}")
            return
        for item in extracted.get("records", []):
            rid = item.get("resource_id")
            system = item.get("system_id")
            alias_candidates = list(item.get("aliases") or [])
            if rid and not RESOURCE_ID_RE.fullmatch(rid):
                alias_candidates.insert(0, rid)   # e.g. a tombstone shown under its user reference
                rid = None
            if not rid:
                for alias in alias_candidates:
                    hit = self.aliases.get(str(alias).strip().lower())
                    if hit:
                        rid, system = hit
                        break
            if not rid:
                continue
            if rid in self.alias_systems:
                system = self.alias_systems[rid]
            rec = {k: item.get(k) for k in ("email", "phone", "full_name")}
            if rec.get("email") and self.known_emails:
                rec["email"] = snap_identifier(rec["email"], self.known_emails)
            if item.get("is_focus"):
                # Only the record the screen is about carries a trustworthy subject reference;
                # neighbouring rows are context.
                rec["customer_reference"] = item.get("customer_reference")
            # The resource-id namespace is authoritative; the model's label only refines
            # namespaces that hold several record types (support_*: message vs attachment).
            kind = kind_from_resource(rid)
            vlm_kind = item.get("kind")
            if rid.startswith(("support_", "object_")) and vlm_kind in ("SUPPORT_ATTACHMENT", "SUPPORT_MESSAGE"):
                kind = vlm_kind
            attrs = {"identifiable": bool(item.get("shows_direct_identifiers")), "is_focus": bool(item.get("is_focus")),
                     "status_text": item.get("status_text")}
            if item.get("enabled") is not None:
                attrs["enabled"] = bool(item["enabled"])
            if item.get("restore_allowed") is not None:
                attrs["restore_allowed"] = bool(item["restore_allowed"])
            self._add(fid, None, system, rid, kind or kind_from_resource(rid), item.get("present", True) is not False,
                      rec, attrs=attrs, source="image")
