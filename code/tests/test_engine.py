"""Engine behaviour on the synthetic mini dataset (see _support.py for the scenario)."""
import shutil
import unittest
from dataclasses import replace

import _support
from _support import FILE_A, FILE_B, step
from ghost_audit.engine import Auditor
from ghost_audit.evidence import Observation
from ghost_audit.policy import STATE, TREATMENT_STEPS, Policy

PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


class EngineScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = _support.build_mini_dataset()
        cls.auditor, cls.store = _support.build_auditor(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def audit(self, cid):
        status, steps, _ = self.auditor.audit(self.auditor.cases[cid])
        return status, steps

    # -- hand-derived plans --------------------------------------------------
    def test_historical_email_complete_case_cites_proof(self):
        """Alice asks with a former email. Her profile is gone from the later account directory
        and her tombstone keeps only the internal reference."""
        self.assertEqual(self.audit("case_01"), ("COMPLETE", [
            step(1, "VERIFICATION", "account_service", "account_001", "VERIFY_RECORD_ABSENT", "ABSENT", FILE_B),
            step(2, "VERIFICATION", "identity_service", "tombstone_001", "VERIFY_RECORD_REDACTED", "REDACTED", FILE_B),
        ]))

    def test_incomplete_case_full_plan(self):
        """Live search entry + enabled sync flow -> report both, disable the flow before deleting,
        verify every relevant record including the retained legal hold and withdrawn export."""
        self.assertEqual(self.audit("case_02"), ("INCOMPLETE", [
            step(1, "FINDING", "search_service", "search_002", "REPORT_REMAINING_RECORD", "PRESENT", FILE_B),
            step(2, "FINDING", "integration_service", "data_flow_002", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", FILE_B),
            step(3, "REMEDIATION", "integration_service", "data_flow_002", "DISABLE_DATA_FLOW", "DISABLED"),
            step(4, "REMEDIATION", "search_service", "search_002", "DELETE_RECORD", "ABSENT"),
            step(5, "VERIFICATION", "export_service", "export_002", "VERIFY_RECORD_ABSENT", "ABSENT"),
            step(6, "VERIFICATION", "search_service", "search_002", "VERIFY_RECORD_ABSENT", "ABSENT"),
            step(7, "VERIFICATION", "legal_service", "legal_hold_002", "VERIFY_RECORD_PRESENT", "PRESENT"),
            step(8, "VERIFICATION", "integration_service", "data_flow_002", "VERIFY_DATA_FLOW_DISABLED", "DISABLED"),
        ]))

    def test_point_in_time_ignores_later_captures(self):
        """Carol was audited before the 09-10 capture: only the 09-01 file counts, so her account
        is still present and the later search entry is out of scope."""
        self.assertEqual(self.audit("case_03"), ("INCOMPLETE", [
            step(1, "FINDING", "account_service", "account_003", "REPORT_REMAINING_RECORD", "PRESENT", FILE_A),
            step(2, "REMEDIATION", "account_service", "account_003", "DELETE_RECORD", "ABSENT"),
            step(3, "VERIFICATION", "account_service", "account_003", "VERIFY_RECORD_ABSENT", "ABSENT"),
        ]))

    def test_non_deletion_request_is_not_applicable(self):
        self.assertEqual(self.audit("case_04"), ("NOT_APPLICABLE", []))

    def test_moving_audit_at_earlier_flips_the_verdict(self):
        c = replace(self.auditor.cases["case_01"], audit_at="2026-09-05T00:00:00Z", case_id="case_01_early")
        status, steps, _ = self.auditor.audit(c)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps[0], step(1, "FINDING", "account_service", "account_001", "REPORT_REMAINING_RECORD",
                                        "PRESENT", FILE_A))

    # -- invariants over every scenario ---------------------------------------
    def test_contract_invariants(self):
        captured = {fid: m["captured_at"] for fid, m in self.store.manifest.items()}
        for cid, c in self.auditor.cases.items():
            status, steps = self.audit(cid)
            self.assertEqual([s["step_no"] for s in steps], list(range(1, len(steps) + 1)), cid)
            ranks = [PHASE_RANK[s["phase"]] for s in steps]
            self.assertEqual(ranks, sorted(ranks), cid)
            for s in steps:
                self.assertEqual(s["state"], STATE[s["operation"]], cid)
                if status == "COMPLETE":
                    self.assertEqual(s["phase"], "VERIFICATION", cid)
                    self.assertTrue(s["evidence_id"], cid)
                elif s["phase"] != "FINDING":
                    self.assertEqual(s["evidence_id"], "", cid)
                else:
                    self.assertTrue(s["evidence_id"], cid)
                if s["evidence_id"] in captured:
                    self.assertLessEqual(captured[s["evidence_id"]], c.audit_at, f"{cid} cites a later file")

    def test_audit_is_deterministic(self):
        for cid in self.auditor.cases:
            self.assertEqual(self.audit(cid), self.audit(cid))


class ClaimsAreNotProofTests(unittest.TestCase):
    def test_successful_delete_activity_does_not_override_evidence(self):
        """The worker reports SUCCESS deleting Carol's account, but a later capture still shows it."""
        act = dict(activity_id="activity_1", event_time="2026-08-31T08:00:00Z", event_type="DELETE_RECORD",
                   source_system="deletion_worker", target_system="account_service", resource_id="account_003",
                   reported_result="SUCCESS", details="Deletion worker removed account_003.")
        root = _support.build_mini_dataset([act])
        try:
            auditor, _ = _support.build_auditor(root)
            status, steps, trace = auditor.audit(auditor.cases["case_03"])
            self.assertEqual(status, "INCOMPLETE")
            self.assertEqual(steps[0]["resource_id"], "account_003")
            self.assertEqual(steps[0]["evidence_id"], FILE_A)
            self.assertTrue(any(r.startswith("account:") for r in trace["account_003"]["reasons"]))
        finally:
            shutil.rmtree(root, ignore_errors=True)


class LatestStateTests(unittest.TestCase):
    def obs(self, **kw):
        base = dict(evidence_id="evidence_09", captured_at="2026-09-10T00:00:00Z", observed_at="2026-09-10T00:00:00Z",
                    system_id="account_service", resource_id="account_5", kind="USER_PROFILE")
        return Observation(**{**base, **kw})

    def test_lagging_replica_copy_wins(self):
        primary = self.obs(present=False, source="primary")
        replica = self.obs(present=True, pii={"email": "x@y.test"}, source="replica")
        self.assertIs(Auditor._latest_state([primary, replica]), replica)
        self.assertIs(Auditor._latest_state([replica, primary]), replica)

    def test_newer_capture_supersedes_older(self):
        old = self.obs(present=True, pii={"email": "x@y.test"}, observed_at="2026-09-01T00:00:00Z",
                       evidence_id="evidence_01")
        new = self.obs(present=False)
        self.assertIs(Auditor._latest_state([old, new]), new)

    def test_no_observations(self):
        self.assertIsNone(Auditor._latest_state([]))


class PolicyTests(unittest.TestCase):
    def test_rules_file_maps_to_treatments(self):
        p = Policy(_support.DATASET)
        expected = {"USER_PROFILE": "DELETE", "SEARCH_INDEX_ENTRY": "DELETE", "SUPPORT_MESSAGE": "REDACT",
                    "SUPPORT_ATTACHMENT": "DELETE", "ANALYTICS_PROFILE": "ANONYMIZE", "SECURITY_AUDIT_LOG": "RETAIN",
                    "LEGAL_HOLD_RECORD": "RETAIN", "ACCOUNT_TOMBSTONE": "REDACT", "DATA_FLOW": "DISABLE_FLOW",
                    "BACKUP_ARCHIVE": "BLOCK_RESTORE"}
        for kind, treatment in expected.items():
            self.assertEqual(p.treatment(kind), treatment, kind)
        self.assertIsNone(p.treatment("NOT_A_CATEGORY"))

    def test_every_treatment_uses_contract_operations(self):
        prefixes = ("REPORT_", None), ("", None), ("VERIFY_", None)
        for treatment, ops in TREATMENT_STEPS.items():
            for op, (prefix, _) in zip(ops, prefixes):
                if op is None:
                    continue
                self.assertIn(op, STATE, treatment)
                self.assertTrue(op.startswith(prefix), (treatment, op))


if __name__ == "__main__":
    unittest.main()
