import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support
from ghost_audit import documents
from ghost_audit.activity import ActivityLog
from ghost_audit.evidence import EvidenceStore, extract_identity, kind_from_resource, snap_identifier
from ghost_audit.identity import IdentityResolver
from ghost_audit.util import sha256


class ExtractIdentityTests(unittest.TestCase):
    def test_named_pii_columns(self):
        pii, keys = extract_identity({"email": "A@X.test", "phone": "+1 555 010 0000", "full_name": "A B"})
        self.assertEqual(pii, {"email": "A@X.test", "phone": "+1 555 010 0000", "name": "A B"})
        self.assertIn("a@x.test", keys)
        self.assertIn("tel:15550100000", keys)

    def test_redacted_and_null_values_are_not_pii(self):
        pii, keys = extract_identity({"email": "[REDACTED]", "phone": None, "full_name": "null"})
        self.assertEqual((pii, keys), ({}, set()))

    def test_references_link_but_are_not_pii(self):
        pii, keys = extract_identity({"customer_reference": "user_01"})
        self.assertEqual(pii, {})
        self.assertEqual(keys, {"user_01"})

    def test_emails_embedded_in_free_text_are_found(self):
        pii, keys = extract_identity({"uploaded_by": "Agent on behalf of bob@x.test", "message_text": "hi"})
        self.assertEqual(pii["email_in_uploaded_by"], "bob@x.test")
        self.assertIn("bob@x.test", keys)

    def test_technical_fields_are_not_scanned(self):
        pii, keys = extract_identity({"object_key": "s3://bucket/carol@x.test/file.pdf"})
        self.assertEqual((pii, keys), ({}, set()))


class SnapAndKindTests(unittest.TestCase):
    KNOWN = {"lucia-torres@example.test", "mark@example.test"}

    def test_unique_single_edit_is_snapped(self):
        self.assertEqual(snap_identifier("lucia.torres@example.test", self.KNOWN), "lucia-torres@example.test")

    def test_exact_match_and_far_values_are_kept(self):
        self.assertEqual(snap_identifier("Mark@Example.test", self.KNOWN), "mark@example.test")
        self.assertEqual(snap_identifier("nobody@example.test", self.KNOWN), "nobody@example.test")

    def test_ambiguous_snap_is_refused(self):
        known = {"ann1@x.test", "ann2@x.test"}
        self.assertEqual(snap_identifier("ann3@x.test", known), "ann3@x.test")

    def test_kind_from_resource_namespace(self):
        self.assertEqual(kind_from_resource("account_1"), "USER_PROFILE")
        self.assertEqual(kind_from_resource("data_flow_2"), "DATA_FLOW")
        self.assertEqual(kind_from_resource("audit_record_3"), "SECURITY_AUDIT_LOG")
        self.assertEqual(kind_from_resource("object_4"), "SUPPORT_ATTACHMENT")
        self.assertEqual(kind_from_resource("weird_5"), "UNKNOWN")


class MiniStoreTests(unittest.TestCase):
    """EvidenceStore over the synthetic mini dataset."""

    @classmethod
    def setUpClass(cls):
        cls.root = _support.build_mini_dataset()
        cls.store = EvidenceStore(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def obs(self, rid):
        return self.store.by_resource[rid]

    def test_everything_parses(self):
        self.assertEqual(self.store.unparsed, [])

    def test_capture_time_comes_from_the_manifest(self):
        o = self.obs("account_001")[0]
        self.assertEqual((o.evidence_id, o.captured_at), (_support.FILE_A, _support.CAPTURE_A))

    def test_kinds_systems_and_attrs(self):
        flow = self.obs("data_flow_002")[0]
        self.assertEqual((flow.kind, flow.system_id, flow.attrs["enabled"]), ("DATA_FLOW", "integration_service", True))
        tomb = self.obs("tombstone_001")[0]
        self.assertEqual((tomb.kind, tomb.attrs["account_status"], tomb.pii), ("ACCOUNT_TOMBSTONE", "DELETED", {}))
        self.assertEqual(self.obs("legal_hold_002")[0].kind, "LEGAL_HOLD_RECORD")

    def test_withdrawn_export_is_absent(self):
        self.assertIs(self.obs("export_002")[0].present, False)

    def test_search_document_body_is_flattened(self):
        self.assertIn("bob.okafor@example.test", self.obs("search_002")[0].keys)

    def test_profile_snapshot_registers_coverage(self):
        cov = [c for c in self.store.coverage if c["evidence_id"] == _support.FILE_B]
        self.assertEqual(len(cov), 1)
        self.assertEqual(cov[0]["rids"], {"account_900"})

    def test_unreadable_file_is_reported_not_fatal(self):
        root = _support.build_mini_dataset()
        try:
            (root / "evidence/records/bundle_20260910.json").write_text("{not json", encoding="utf-8")
            store = EvidenceStore(root)
            self.assertTrue(any(u.startswith(_support.FILE_B) for u in store.unparsed))
            self.assertIn("account_001", store.by_resource)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class IdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = _support.build_mini_dataset()
        cls.idr = IdentityResolver(cls.root)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_historical_and_current_email_resolve_to_the_same_user(self):
        self.assertEqual(self.idr.resolve_email(_support.ALICE_OLD_EMAIL.upper()), ["user_01"])
        self.assertEqual(self.idr.resolve_email("alice.varga@example.test"), ["user_01"])
        self.assertEqual(self.idr.resolve_email("stranger@example.test"), [])

    def test_identity_includes_hashes_of_old_emails(self):
        ident = self.idr.identity("user_01")
        self.assertIn(sha256(_support.ALICE_OLD_EMAIL), ident.hashes)
        self.assertIn(sha256(_support.ALICE_OLD_EMAIL), ident.keys())
        self.assertIn("user_01", ident.keys())

    def test_changes_after_the_cutoff_are_unknown(self):
        ident = self.idr.identity("user_01", as_of="2026-04-01T00:00:00Z")
        self.assertNotIn(_support.ALICE_OLD_EMAIL, ident.emails)


class DocumentTests(unittest.TestCase):
    META = {"captured_at": "2026-09-01T00:00:00Z"}

    def run_pdf(self, text, aliases=None):
        with mock.patch.object(documents, "pdf_text", return_value=text):
            return documents.pdf_observations(Path("x.pdf"), self.META, aliases)

    def test_single_subject_document_links_identifiers(self):
        out = self.run_pdf("Invoice for user_02 bob@x.test  ref support_77 attachment uploaded")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["resource_id"], "support_77")
        self.assertEqual(out[0]["kind"], "SUPPORT_ATTACHMENT")
        self.assertEqual(set(out[0]["keys"]), {"user_02", "bob@x.test"})

    def test_multi_subject_register_links_nobody(self):
        out = self.run_pdf("Legal register: user_02 bob@x.test, user_17 eve@x.test  legal_hold_5 legal hold")
        self.assertEqual(out[0]["keys"], [])
        self.assertEqual(out[0]["record"], {})
        self.assertTrue(out[0]["attrs"]["legal_hold"])

    def test_aliases_match_on_word_boundaries_and_skip_user_aliases(self):
        aliases = {"inv-2024-77": ("support_88", "support_platform"), "user_17": ("tombstone_17", "identity_service")}
        out = self.run_pdf("Statement INV-2024-77 for user_17", aliases)
        self.assertEqual([o["resource_id"] for o in out], ["support_88"])
        self.assertEqual(out[0]["system_id"], "support_platform")
        self.assertEqual(self.run_pdf("Statement INV-2024-770", aliases), [])

    def test_retention_date_is_parsed(self):
        out = self.run_pdf("audit_record_9 retained until 05 Mar 2031 14 30")
        self.assertEqual(out[0]["attrs"]["retention_until"], "2031-03-05T14:30:00Z")


class ActivityLogTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        row = dict(source_system="catalog", reported_result="SUCCESS")
        _support.write_csv(self.root / "system_activity.csv", _support.ACTIVITY_FIELDS, [
            dict(row, activity_id="activity_2", event_time="2026-09-02T00:00:00Z", event_type="LINK_RESOURCE_IDENTITY",
                 target_system="support_platform", resource_id="support_5",
                 details="Catalog linked support_5 (Receipt-55.pdf) to bob@x.test and user_02."),
            dict(row, activity_id="activity_1", event_time="2026-09-01T00:00:00Z", event_type="SYNC_RECORD",
                 target_system="search_service", resource_id="data_flow_9",
                 details="Connector run repopulated downstream resource search_44 from CRM."),
        ])

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_rows_are_time_ordered(self):
        self.assertEqual([a.activity_id for a in ActivityLog(self.root).rows], ["activity_1", "activity_2"])

    def test_catalog_link_parsing_and_lookup(self):
        acts = ActivityLog(self.root)
        link = acts.links[0]
        self.assertEqual((link["resource_id"], link["alias"], link["email"], link["user_id"]),
                         ("support_5", "Receipt-55.pdf", "bob@x.test", "user_02"))
        self.assertEqual(acts.alias_map()["receipt-55.pdf"], ("support_5", "support_platform"))
        self.assertEqual(len(acts.links_for({"bob@x.test"})), 1)
        self.assertEqual(acts.links_for({"someone@x.test"}), [])

    def test_recreation_edges(self):
        rel = ActivityLog(self.root).relations_by_downstream["search_44"][0]
        self.assertEqual(rel["upstream"], "data_flow_9")


if __name__ == "__main__":
    unittest.main()
