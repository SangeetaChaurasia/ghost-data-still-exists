"""Attempts to break the agent: hostile manifests, corrupted evidence, a failing model API,
unknown record states, and metamorphic changes that must not change any answer.

Every test here started as a probe; the ones that found bugs are kept as regressions:
naive timestamps read as local time, BOM headers, crashes on bad capture times and orphan audit
users, stale screenshot facts after an image changed, a damaged SQL file proving absence, an
unreadable PDF turning a case COMPLETE, and long silent stalls when the API is down.

The real-data tests run the full offline pipeline several times (about 30 s); set
GHOST_SKIP_SLOW=1 to skip them.
"""
import csv
import json
import os
import random
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support
from ghost_audit import llm as llm_mod
from ghost_audit.activity import ActivityLog
from ghost_audit.evidence import EvidenceStore
from ghost_audit.guardrails import contract_errors
from ghost_audit.identity import IdentityResolver
from ghost_audit.intent import IntentClassifier
from ghost_audit.llm import LLMClient
from ghost_audit.pipeline import Pipeline, read_requests
from ghost_audit.util import parse_ts

SLOW = not os.environ.get("GHOST_SKIP_SLOW")


def rewrite_csv(path: Path, mutate):
    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    rows = mutate(rows) or rows
    _support.write_csv(path, list(rows[0]), rows)


# ---------------------------------------------------------------------------
# Portability
# ---------------------------------------------------------------------------

class PortabilityTests(unittest.TestCase):
    def test_timestamp_without_offset_is_utc_not_local_time(self):
        self.assertEqual(parse_ts("2026-09-01T12:00:00"), parse_ts("2026-09-01T12:00:00Z"))

    def test_csv_with_byte_order_mark_is_read(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            p = tmp / "requests.csv"
            rows = read_requests(_support.DATASET / "deletion_requests.csv")[:2]
            with open(p, "w", encoding="utf-8-sig", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
            self.assertEqual(read_requests(p)[0]["case_id"], rows[0]["case_id"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Hostile corpus (mini dataset)
# ---------------------------------------------------------------------------

class HostileManifestTests(unittest.TestCase):
    def setUp(self):
        self.root = _support.build_mini_dataset()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def add_manifest_row(self, **row):
        rewrite_csv(self.root / "evidence_files.csv", lambda rows: rows + [
            dict(dict(file_id="evidence_99", file_path="", origin="x", captured_at="2026-09-01T00:00:00Z"), **row)])

    def test_path_outside_the_evidence_folder_is_never_read(self):
        (self.root / "outside.json").write_text(json.dumps({"collection": "x", "records": [
            {"resource_id": "account_777", "email": "leak@x.test"}]}), encoding="utf-8")
        self.add_manifest_row(file_path="../outside.json")
        self.add_manifest_row(file_id="evidence_98", file_path="evidence/../outside.json")
        store = EvidenceStore(self.root)
        self.assertNotIn("account_777", store.by_resource)
        self.assertEqual(sum("outside dataset/evidence" in u for u in store.unparsed), 2)

    def test_unreadable_capture_time_and_duplicates_are_skipped_with_warnings(self):
        self.add_manifest_row(file_path="evidence/records/bundle_20260910.json", captured_at="sometime")
        self.add_manifest_row(file_id=_support.FILE_A, file_path="evidence/records/bundle_20260910.json")
        store = EvidenceStore(self.root)
        self.assertNotIn("evidence_99", store.manifest)
        self.assertEqual(store.manifest[_support.FILE_A]["file_path"], "evidence/records/accounts_20260901.json")
        joined = " | ".join(store.unparsed)
        self.assertIn("unreadable captured_at", joined)
        self.assertIn("duplicate file_id", joined)

    def test_audit_history_for_a_user_missing_from_identities(self):
        rewrite_csv(self.root / "user_audit_log.csv", lambda rows: rows + [dict(
            audit_id="audit_02", user_id="user_99", event_time="2026-01-01T00:00:00Z", field_name="email",
            old_value="orphan.old@example.test", new_value="orphan@example.test")])
        idr = IdentityResolver(self.root)
        self.assertEqual(idr.resolve_email("orphan.old@example.test"), ["user_99"])
        self.assertIn("orphan@example.test", idr.identity("user_99").emails)

    def test_activity_rows_with_unreadable_times_are_dropped(self):
        rewrite_csv(self.root / "system_activity.csv", lambda rows: [dict(
            activity_id="activity_1", event_time="not-a-time", event_type="DELETE_RECORD",
            source_system="deletion_worker", target_system="account_service", resource_id="account_1",
            reported_result="SUCCESS", details="x")] if not rows else rows)
        acts = ActivityLog(self.root)
        self.assertEqual(acts.rows, [])
        self.assertEqual(len(acts.skipped), 1)

    def test_damaged_sql_rows_count_as_present_but_never_prove_absence(self):
        # a regional replica table counts as a full account directory when the file is intact
        sql = ("CREATE TABLE customer_profiles_eu_west (resource_id TEXT, email TEXT);\n"
               "INSERT INTO customer_profiles_eu_west VALUES ('account_001', 'alice.varga@example.test');\n"
               "INSERT INTO customer_profiles_eu_west VALUES ('account_900', 'someone");   # cut off mid-row
        (self.root / "evidence/databases").mkdir(parents=True)
        (self.root / "evidence/databases/accounts.sql").write_text(sql, encoding="utf-8")
        self.add_manifest_row(file_path="evidence/databases/accounts.sql", captured_at="2026-09-11T00:00:00Z")
        store = EvidenceStore(self.root)
        self.assertIn("evidence_99", store.partial)
        self.assertTrue(any(o.evidence_id == "evidence_99" for o in store.by_resource["account_001"]))
        self.assertFalse(any(c["evidence_id"] == "evidence_99" for c in store.coverage))
        # control: the same table, intact, IS used as absence proof
        p = self.root / "evidence/databases/accounts.sql"
        p.write_text(sql + "');\n", encoding="utf-8")
        intact = EvidenceStore(self.root)
        self.assertNotIn("evidence_99", intact.partial)
        self.assertTrue(any(c["evidence_id"] == "evidence_99" for c in intact.coverage))

    def test_invalid_utf8_keeps_the_readable_parts(self):
        p = self.root / "evidence/records/accounts_20260901.json"
        p.write_bytes(p.read_bytes().replace(b"Alice Varga", b"Alice \xff\xfe Varga"))
        store = EvidenceStore(self.root)
        self.assertIn("account_001", store.by_resource)
        self.assertTrue(any("invalid UTF-8" in u for u in store.unparsed))


class FailClosedTests(unittest.TestCase):
    """A record that needs action but whose state cannot be established must not be 'verified'."""

    def test_record_known_only_from_a_catalog_link_keeps_the_case_open(self):
        link = dict(activity_id="activity_7", event_time="2026-09-02T10:00:00Z", event_type="LINK_RESOURCE_IDENTITY",
                    source_system="data_catalog", target_system="export_service", resource_id="export_501",
                    reported_result="SUCCESS",
                    details="Catalog linked export_501 (alice-export.zip) to alice.varga@example.test and user_01.")
        root = _support.build_mini_dataset([link])
        try:
            auditor, _ = _support.build_auditor(root)
            c = auditor.cases["case_01"]
            status, steps, _ = auditor.audit(c)
            self.assertEqual(status, "INCOMPLETE")
            self.assertEqual(steps[0], _support.step(1, "FINDING", "export_service", "export_501",
                                                     "REPORT_REMAINING_RECORD", "PRESENT", "activity_7"))
            self.assertTrue(any("no evidence of its state" in f for f in c.flags))
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# Model API failures
# ---------------------------------------------------------------------------

class FakeAPIError(Exception):
    pass


class AuthenticationError(Exception):   # same class name as the OpenAI SDK's, which is what the client checks
    pass


class FailingClient:
    def __init__(self, exc):
        self.calls = 0
        outer = self

        class Completions:
            def create(self, **kw):
                outer.calls += 1
                raise exc

        self.chat = type("Chat", (), {"completions": Completions()})()


class APIFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.sleep = mock.patch.object(llm_mod.time, "sleep")
        self.sleep.start()

    def tearDown(self):
        self.sleep.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def client(self, exc):
        c = LLMClient(self.tmp / "cache.json", offline=True)
        c._client = FailingClient(exc)
        return c

    def test_breaker_opens_after_repeated_failures(self):
        c = self.client(FakeAPIError("connection refused"))
        with mock.patch("builtins.print"):
            for i in range(10):
                self.assertIsNone(c.json_completion("s", f"u{i}"))
        self.assertTrue(c.breaker_open)
        self.assertEqual(c._client.calls, llm_mod.BREAKER_LIMIT * len(llm_mod.RETRY_DELAYS))
        self.assertEqual(len(c.failures), llm_mod.BREAKER_LIMIT)

    def test_bad_key_stops_at_the_first_call(self):
        c = self.client(AuthenticationError("invalid api key"))
        with mock.patch("builtins.print"):
            c.json_completion("s", "u1")
            c.json_completion("s", "u2")
        self.assertTrue(c.breaker_open)
        self.assertEqual(c._client.calls, 1)

    def test_failure_messages_never_contain_the_key(self):
        key = "sk-" + "live" * 10
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": key}), mock.patch("builtins.print") as p:
            c = self.client(AuthenticationError(f"Incorrect API key provided: {key}"))
            c.json_completion("s", "u")
        self.assertNotIn(key, " ".join(c.failures))
        self.assertNotIn(key, " ".join(str(a) for call in p.call_args_list for a in call.args))

    def test_cases_decided_without_a_model_are_flagged_and_still_correct(self):
        c = self.client(FakeAPIError("down"))
        clf = IntentClassifier(c)
        with mock.patch("builtins.print"):
            for text, want in [("Necesito que borren todos mis datos personales.", True),
                               ("Please purge every trace of me.", True),
                               ("Can I get a printout of my order history?", False)]:
                out = clf.classify(text)
                self.assertEqual(out["is_deletion"], want, text)
                self.assertIn("keyword rules", out["guardrail"])


# ---------------------------------------------------------------------------
# Real data: metamorphic invariance and corrupted evidence
# ---------------------------------------------------------------------------

def run_pipeline(requests, dataset=_support.DATASET, workers=8):
    llm = LLMClient(_support.CODE / "cache" / "llm_cache.json", offline=True)
    pipe = Pipeline(_support.REPO, dataset, llm, workers=workers, log=lambda *a: None).build(extra_requests=requests)
    rows, traces = pipe.run([r["case_id"] for r in requests])
    return {r["case_id"]: (r["deletion_status"], r["steps_json"]) for r in rows}, rows, pipe


@unittest.skipUnless(SLOW, "GHOST_SKIP_SLOW set")
class RealDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (_support.CODE / "cache" / "llm_cache.json").exists():
            raise unittest.SkipTest("no committed model cache")
        cls.requests = read_requests(_support.DATASET / "deletion_requests.csv")
        cls.base, _, _ = run_pipeline(cls.requests)

    def assertSameAnswers(self, out):
        diff = [c for c in self.base if self.base[c] != out.get(c)]
        self.assertEqual(diff, [])

    # -- metamorphic: none of these may change any answer ----------------------
    def test_request_order(self):
        shuffled = self.requests[:]
        random.Random(7).shuffle(shuffled)
        self.assertSameAnswers(run_pipeline(shuffled)[0])

    def test_email_case_and_whitespace(self):
        self.assertSameAnswers(run_pipeline([dict(r, email=f"  {r['email'].upper()} ") for r in self.requests])[0])

    def test_another_email_of_the_same_person(self):
        idr = IdentityResolver(_support.DATASET)
        swapped, n = [], 0
        for r in self.requests:
            users = idr.resolve_email(r["email"])
            alts = sorted(e for e in idr.identity(users[0]).emails
                          if e.lower() != r["email"].lower() and idr.resolve_email(e) == users) if users else []
            n += bool(alts)
            swapped.append(dict(r, email=alts[0]) if alts else r)
        self.assertGreater(n, 50)
        self.assertSameAnswers(run_pipeline(swapped)[0])

    def test_single_worker(self):
        self.assertSameAnswers(run_pipeline(self.requests, workers=1)[0])

    def test_row_order_of_corpus_files(self):
        tmp = Path(tempfile.mkdtemp())
        try:
            d = tmp / "dataset"
            shutil.copytree(_support.DATASET, d)
            rnd = random.Random(11)
            for f in ("evidence_files.csv", "system_activity.csv", "user_audit_log.csv", "user_identities.csv"):
                rewrite_csv(d / f, lambda rows: rnd.sample(rows, len(rows)))
            self.assertSameAnswers(run_pipeline(self.requests, dataset=d)[0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # -- corrupted evidence: degrade, warn, never invent a COMPLETE -------------
    def corrupt(self, ext, damage):
        tmp = Path(tempfile.mkdtemp())
        try:
            d = tmp / "dataset"
            shutil.copytree(_support.DATASET, d)
            with open(d / "evidence_files.csv", encoding="utf-8") as fh:
                meta = next(r for r in csv.DictReader(fh) if r["file_path"].endswith(ext))
            damage(d / meta["file_path"])
            out, rows, pipe = run_pipeline(self.requests, dataset=d)
            manifest = {fid: m["captured_at"] for fid, m in pipe.store.manifest.items()}
            self.assertEqual(contract_errors(rows, self.requests, manifest), [])
            self.assertTrue(pipe.warnings, "damage must be reported")
            flips = [c for c in self.base if self.base[c][0] != "COMPLETE" and out[c][0] == "COMPLETE"]
            self.assertEqual(flips, [], "damaged evidence produced a COMPLETE verdict")
            return sum(self.base[c] != out[c] for c in self.base)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_truncated_sql(self):
        def cut(p):
            t = p.read_text(encoding="utf-8")
            p.write_text(t[: len(t) // 2], encoding="utf-8")
        self.corrupt(".sql", cut)

    def test_garbage_pdf(self):
        self.corrupt(".pdf", lambda p: p.write_bytes(random.Random(1).randbytes(4000)))

    def test_binary_log(self):
        self.corrupt(".log", lambda p: p.write_bytes(random.Random(2).randbytes(20000)))

    def test_replaced_screenshot_drops_its_cached_facts(self):
        self.corrupt(".png", lambda p: p.write_bytes(b""))


if __name__ == "__main__":
    unittest.main()
