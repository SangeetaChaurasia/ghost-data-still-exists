"""Submission contract on output.csv, scoring helpers, and an offline regression on the public samples.

The contract checker itself lives in ghost_audit.guardrails (main.py runs it before writing).

The regression runs the full pipeline from the committed model cache only (no API calls,
about 5 s). Set GHOST_SKIP_SLOW=1 to skip it.
"""
import csv
import io
import json
import os
import sys
import unittest

import _support
from ghost_audit.guardrails import contract_errors

sys.path.insert(0, str(_support.CODE / "evaluation"))
from scoring import lcs, score  # noqa: E402


def read_csv(path):
    with open(path, encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def manifest_times():
    return {r["file_id"]: r["captured_at"] for r in read_csv(_support.DATASET / "evidence_files.csv")}


class ContractValidatorSelfTests(unittest.TestCase):
    """The validator must actually catch broken outputs, or the contract test proves nothing."""
    REQ = [{"case_id": "case_1", "audit_at": "2026-09-12T00:00:00Z"}]
    GOOD = [{"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_1",
             "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}]
    MANIFEST = {"evidence_01": "2026-09-01T00:00:00Z", "evidence_99": "2026-10-01T00:00:00Z"}

    def errs(self, status, steps):
        return contract_errors([{"case_id": "case_1", "deletion_status": status, "steps_json": json.dumps(steps)}],
                               self.REQ, self.MANIFEST)

    def test_good_row_passes(self):
        self.assertEqual(self.errs("COMPLETE", self.GOOD), [])
        self.assertEqual(self.errs("NOT_APPLICABLE", []), [])

    def test_broken_rows_fail(self):
        bad = lambda **kw: [{**self.GOOD[0], **kw}]  # noqa: E731
        cases = {
            "wrong state": ("COMPLETE", bad(state="PRESENT")),
            "invented op": ("COMPLETE", bad(operation="VERIFY_RECORD_GONE")),
            "late evidence": ("COMPLETE", bad(evidence_id="evidence_99")),
            "no evidence": ("COMPLETE", bad(evidence_id="")),
            "numbering": ("COMPLETE", bad(step_no=2)),
            "extra field": ("COMPLETE", [{**self.GOOD[0], "note": "x"}]),
            "NA with steps": ("NOT_APPLICABLE", self.GOOD),
            "incomplete no finding": ("INCOMPLETE", bad(evidence_id="")),
            "bad status": ("DONE", self.GOOD),
        }
        for name, (status, steps) in cases.items():
            self.assertTrue(self.errs(status, steps), name)


@unittest.skipUnless((_support.REPO / "output.csv").exists(), "output.csv not generated yet")
class SubmissionOutputTests(unittest.TestCase):
    def test_output_csv_meets_the_contract(self):
        path = _support.REPO / "output.csv"
        with open(path, encoding="utf-8", newline="") as fh:
            header = fh.readline().strip()
        self.assertEqual(header, "case_id,deletion_status,steps_json")
        rows = read_csv(path)
        requests = read_csv(_support.DATASET / "deletion_requests.csv")
        self.assertEqual(len(rows), 518)
        errs = contract_errors(rows, requests, manifest_times())
        self.assertEqual(errs[:20], [])

    def test_rows_are_sorted_by_case_number(self):
        from ghost_audit.pipeline import case_sort_key
        ids = [r["case_id"] for r in read_csv(_support.REPO / "output.csv")]
        self.assertEqual(ids, sorted(ids, key=case_sort_key))


class ScoringTests(unittest.TestCase):
    S1 = {"step_no": 1, "phase": "FINDING", "system_id": "s", "resource_id": "r1", "operation": "REPORT_REMAINING_RECORD",
          "state": "PRESENT", "evidence_id": "e1"}
    S2 = {**S1, "step_no": 2, "phase": "REMEDIATION", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""}

    def test_perfect_prediction(self):
        gold = {"c1": ("INCOMPLETE", [self.S1, self.S2])}
        m = score(gold, gold)
        self.assertEqual((m["status_accuracy"], m["step_f1"], m["exact_case_accuracy"], m["sequence_accuracy"]),
                         (1.0, 1.0, 1.0, 1.0))

    def test_missing_step_and_wrong_evidence(self):
        gold = {"c1": ("INCOMPLETE", [self.S1, self.S2])}
        pred = {"c1": ("INCOMPLETE", [{**self.S1, "evidence_id": "e9"}])}
        m = score(pred, gold)
        self.assertEqual((m["step_precision"], m["step_recall"]), (1.0, 0.5))
        self.assertEqual(m["exact_case_accuracy"], 0.0)
        self.assertEqual(m["per_case"]["c1"]["evidence_diff"], [("r1", "REPORT_REMAINING_RECORD", "e1", "e9")])

    def test_missing_case_counts_as_wrong(self):
        m = score({}, {"c1": ("COMPLETE", [])})
        self.assertEqual(m["status_accuracy"], 0.0)

    def test_lcs(self):
        self.assertEqual(lcs("abcde", "ace"), 3)
        self.assertEqual(lcs([], [1]), 0)


@unittest.skipIf(os.environ.get("GHOST_SKIP_SLOW"), "GHOST_SKIP_SLOW set")
class SampleRegressionTests(unittest.TestCase):
    """Full offline pipeline on the 32 public samples; guards against silent quality regressions."""

    @classmethod
    def setUpClass(cls):
        from ghost_audit.llm import LLMClient
        from ghost_audit.pipeline import Pipeline, read_requests
        llm = LLMClient(_support.CODE / "cache" / "llm_cache.json", offline=True)
        if not llm.cache:
            raise unittest.SkipTest("no committed model cache")
        cls.pipe = Pipeline(_support.REPO, _support.DATASET, llm, log=lambda *_: None).build()
        samples = read_requests(_support.DATASET / "sample_deletion_requests.csv")
        cls.rows, _ = cls.pipe.run([r["case_id"] for r in samples])
        cls.samples = samples
        gold = read_csv(_support.DATASET / "sample_output.csv")
        cls.metrics = score({r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in cls.rows},
                            {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in gold})

    def test_quality_floor(self):
        m = self.metrics
        self.assertEqual(m["status_accuracy"], 1.0)
        self.assertGreaterEqual(m["step_f1"], 0.98)
        self.assertGreaterEqual(m["exact_case_accuracy"], 0.875)
        self.assertEqual(m["sequence_accuracy"], 1.0)

    def test_sample_output_meets_the_contract(self):
        self.assertEqual(contract_errors(self.rows, self.samples, manifest_times()), [])

    def test_serialisation_is_compact_and_stable(self):
        buf = io.StringIO()
        for r in self.rows:
            steps = json.loads(r["steps_json"])
            self.assertEqual(r["steps_json"], json.dumps(steps, ensure_ascii=False, separators=(",", ":")))
            buf.write(r["steps_json"])
        self.assertNotIn("NaN", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
