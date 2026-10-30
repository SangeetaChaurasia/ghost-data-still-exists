"""Shared helpers for the unit tests: import path, repo paths and a synthetic mini dataset.

The mini dataset is written to a temp directory and contains only fictional people. Each
scenario's expected plan was worked out by hand from these files, so the engine tests pin
behaviour without depending on the real corpus.
"""
from __future__ import annotations

import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

CODE = Path(__file__).resolve().parents[1]
REPO = CODE.parent
DATASET = REPO / "dataset"
if str(CODE) not in sys.path:
    sys.path.insert(0, str(CODE))

ACTIVITY_FIELDS = ["activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id",
                   "reported_result", "details"]


def write_csv(path: Path, fields: list[str], rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def snapshot(captured_at: str, data_store: str, collection: str, records: list[dict]) -> dict:
    return {"captured_at": captured_at, "data_store": data_store, "collection": collection, "records": records}


# ---------------------------------------------------------------------------
# Mini dataset
# ---------------------------------------------------------------------------
# user_01 Alice  - asks with her OLD email; account gone, tombstone redacted      -> COMPLETE
# user_02 Bob    - search entry still live, sync flow enabled, legal hold, export
#                  link withdrawn                                                  -> INCOMPLETE
# user_03 Carol  - audited on 09-05: only the 09-01 capture is admissible         -> INCOMPLETE (account)
# user_04 Dan    - asks for a copy of his data                                     -> NOT_APPLICABLE
USERS = [
    dict(user_id="user_01", name="Alice Varga", email="alice.varga@example.test", phone="+36 30 111 2222"),
    dict(user_id="user_02", name="Bob Okafor", email="bob.okafor@example.test", phone="+234 803 555 0101"),
    dict(user_id="user_03", name="Carol Lindqvist", email="carol.l@example.test", phone="+46 70 123 4567"),
    dict(user_id="user_04", name="Dan Mori", email="dan.mori@example.test", phone="+81 90 0000 1111"),
]
ALICE_OLD_EMAIL = "alice.v.old@example.test"

FILE_A = "evidence_01"   # 2026-09-01: accounts still live
FILE_B = "evidence_02"   # 2026-09-10: after the deletion workflow ran
CAPTURE_A = "2026-09-01T12:00:00Z"
CAPTURE_B = "2026-09-10T12:00:00Z"

CASES = [
    dict(case_id="case_01", email=ALICE_OLD_EMAIL, requested_at="2026-09-02T09:00:00Z", reported_status="COMPLETE",
         reported_at="2026-09-03T09:00:00Z", audit_at="2026-09-12T00:00:00Z",
         request_text="Please delete my account and all personal data."),
    dict(case_id="case_02", email="bob.okafor@example.test", requested_at="2026-09-02T09:00:00Z",
         reported_status="COMPLETE", reported_at="2026-09-03T10:00:00Z", audit_at="2026-09-12T00:00:00Z",
         request_text="Erase everything you hold about me."),
    dict(case_id="case_03", email="carol.l@example.test", requested_at="2026-08-30T09:00:00Z",
         reported_status="COMPLETE", reported_at="2026-08-31T09:00:00Z", audit_at="2026-09-05T00:00:00Z",
         request_text="Close my account and delete my data."),
    dict(case_id="case_04", email="dan.mori@example.test", requested_at="2026-09-02T09:00:00Z",
         reported_status="COMPLETE", reported_at="2026-09-03T09:00:00Z", audit_at="2026-09-12T00:00:00Z",
         request_text="Please send me a copy of my personal data in a portable format."),
]


def _identity_rows():
    from ghost_audit.util import sha256
    return [dict(u, email_hash=sha256(u["email"].lower()), updated_at="2026-06-01T00:00:00Z") for u in USERS]


def _evidence_a():
    return {"snapshots": [snapshot(CAPTURE_A, "account_service", "customer_profiles", [
        {"resource_id": "account_001", "email": "alice.varga@example.test", "full_name": "Alice Varga"},
        {"resource_id": "account_003", "email": "carol.l@example.test", "full_name": "Carol Lindqvist"},
    ])]}


def _evidence_b():
    return {"snapshots": [
        # account directory after the workflow: Alice's and Carol's profiles are gone
        snapshot(CAPTURE_B, "account_service", "customer_profiles", [
            {"resource_id": "account_900", "email": "someone.else@example.test", "full_name": "Somebody Else"}]),
        snapshot(CAPTURE_B, "identity_service", "deleted_customer_references", [
            {"resource_id": "tombstone_001", "customer_reference": "user_01", "account_status": "DELETED",
             "email": None, "full_name": None}]),
        snapshot(CAPTURE_B, "search_service", "customer_search_documents", [
            {"resource_id": "search_002", "document": {"email": "bob.okafor@example.test", "full_name": "Bob Okafor"}},
            # Carol's entry is only visible in a capture taken after her audit_at
            {"resource_id": "search_003", "document": {"email": "carol.l@example.test"}}]),
        snapshot(CAPTURE_B, "integration_service", "sync_connectors", [
            {"resource_id": "data_flow_002", "subject_reference": "user_02", "enabled": True}]),
        snapshot(CAPTURE_B, "legal_service", "retained_order_records", [
            {"resource_id": "legal_hold_002", "subject_reference": "user_02", "retained_until": "2030-01-01"}]),
        snapshot(CAPTURE_B, "export_service", "customer_exports", [
            {"resource_id": "export_002", "subject_reference": "user_02", "download_available": False}]),
    ]}


def build_mini_dataset(activity_rows: list[dict] | None = None) -> Path:
    """Write the mini dataset to a fresh temp dir and return its path (caller removes it)."""
    root = Path(tempfile.mkdtemp(prefix="ghost_audit_test_"))
    write_csv(root / "user_identities.csv", ["user_id", "name", "email", "phone", "email_hash", "updated_at"],
              _identity_rows())
    write_csv(root / "user_audit_log.csv", ["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"],
              [dict(audit_id="audit_01", user_id="user_01", event_time="2026-05-01T00:00:00Z", field_name="email",
                    old_value=ALICE_OLD_EMAIL, new_value="alice.varga@example.test")])
    write_csv(root / "system_activity.csv", ACTIVITY_FIELDS, activity_rows or [])
    shutil.copy(DATASET / "deletion_rules.csv", root / "deletion_rules.csv")
    files = {FILE_A: ("evidence/records/accounts_20260901.json", CAPTURE_A, _evidence_a()),
             FILE_B: ("evidence/records/bundle_20260910.json", CAPTURE_B, _evidence_b())}
    manifest = []
    for fid, (rel, captured, payload) in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload), encoding="utf-8")
        manifest.append(dict(file_id=fid, file_path=rel, origin="unit_test", captured_at=captured))
    write_csv(root / "evidence_files.csv", ["file_id", "file_path", "origin", "captured_at"], manifest)
    return root


def build_auditor(root: Path, cases: list[dict] | None = None, deletion_flags: dict | None = None):
    """Construct the real Auditor over a mini dataset. ``deletion_flags`` overrides intent per case."""
    from ghost_audit.activity import ActivityLog
    from ghost_audit.engine import Auditor, Case
    from ghost_audit.evidence import EvidenceStore
    from ghost_audit.identity import IdentityResolver
    from ghost_audit.intent import rule_intent
    from ghost_audit.policy import Policy

    acts = ActivityLog(root)
    idr = IdentityResolver(root)
    store = EvidenceStore(root, aliases=acts.alias_map(), known_emails=set(idr.email_index))
    out = []
    for r in cases or CASES:
        c = Case(**r)
        c.is_deletion = (deletion_flags or {}).get(c.case_id, rule_intent(c.request_text))
        out.append(c)
    return Auditor(store, acts, idr, Policy(root), out), store


def step(no, phase, system_id, resource_id, operation, state, evidence_id=""):
    return dict(step_no=no, phase=phase, system_id=system_id, resource_id=resource_id, operation=operation,
                state=state, evidence_id=evidence_id)
