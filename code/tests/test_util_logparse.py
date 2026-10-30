import unittest

import _support  # noqa: F401  (sets the import path)
from ghost_audit.logparse import parse_line
from ghost_audit.util import is_null, norm_key, parse_ts, sha256


class NormKeyTests(unittest.TestCase):
    def test_email_is_lowercased_and_trimmed(self):
        self.assertEqual(norm_key("  Alice.Varga@Example.TEST "), "alice.varga@example.test")

    def test_phone_renderings_compare_equal(self):
        variants = ["+36 30 111 2222", "+36-30-111-2222", "+36 (30) 111 2222", "+3630.111.2222"]
        self.assertEqual({norm_key(v) for v in variants}, {"tel:36301112222"})

    def test_hash_is_lowercased(self):
        h = "AB" * 32
        self.assertEqual(norm_key(h), h.lower())

    def test_resource_and_user_ids_unchanged_apart_from_case(self):
        self.assertEqual(norm_key("user_01"), "user_01")
        self.assertEqual(norm_key("Account_001"), "account_001")

    def test_short_digit_strings_are_not_phones(self):
        self.assertEqual(norm_key("12345"), "12345")


class MiscUtilTests(unittest.TestCase):
    def test_is_null(self):
        for v in (None, "", "  ", "null", "NULL", "None", "n/a", "-"):
            self.assertTrue(is_null(v), v)
        for v in ("0", "x", 0, False):
            self.assertFalse(is_null(v), v)

    def test_parse_ts_normalises_to_utc(self):
        self.assertEqual(parse_ts("2026-09-01T12:00:00Z"), parse_ts("2026-09-01T14:00:00+02:00"))
        self.assertEqual(parse_ts("2026-09-01T12:00:00Z").utcoffset().total_seconds(), 0)

    def test_sha256_matches_known_vector(self):
        self.assertEqual(sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


class LogParseTests(unittest.TestCase):
    TS = "2026-09-15T11:59:39Z"

    def test_logfmt(self):
        ll = parse_line(f'{self.TS} level=INFO service=account-api trace_id=t1 event=profile.lookup '
                        f'email="a@b.test" status=404')
        self.assertEqual((ll.ts, ll.service, ll.trace, ll.level), (self.TS, "account-api", "t1", "INFO"))
        self.assertEqual(ll.attrs["email"], "a@b.test")
        self.assertEqual(ll.attrs["status"], "404")

    def test_json_payload(self):
        ll = parse_line(f'{self.TS} {{"service": "search", "trace_id": "t2", "severity": "WARN", "hits": 3}}')
        self.assertEqual((ll.service, ll.trace, ll.level), ("search", "t2", "WARN"))
        self.assertEqual(ll.attrs["hits"], "3")

    def test_bracketed(self):
        ll = parse_line(f'{self.TS} [INFO] [support-svc] [t3] ticket.read: resource_id="support_1" note="x y"')
        self.assertEqual((ll.level, ll.service, ll.trace), ("INFO", "support-svc", "t3"))
        self.assertEqual(ll.attrs, {"resource_id": "support_1", "note": "x y", "event": "ticket.read"})

    def test_pipe_delimited(self):
        ll = parse_line(f'{self.TS} | ERROR | export-svc | t4 | export.fetch | resource_id="export_9"')
        self.assertEqual((ll.level, ll.service, ll.trace), ("ERROR", "export-svc", "t4"))
        self.assertEqual(ll.attrs["event"], "export.fetch")
        self.assertEqual(ll.attrs["resource_id"], "export_9")

    def test_syslog(self):
        ll = parse_line(f'{self.TS} <134>1 host-a backup-agent t5 - - level=INFO resource_id=backup_7')
        self.assertEqual((ll.service, ll.trace, ll.level), ("backup-agent", "t5", "INFO"))
        self.assertEqual(ll.attrs["resource_id"], "backup_7")

    def test_cloud_runtime_envelope_unwraps_escaped_message(self):
        ll = parse_line(f'{self.TS} function=sync-fn requestId=r6 level=INFO '
                        f'message="event=sync.run resource_id=\\"data_flow_3\\" enabled=true"')
        self.assertEqual((ll.service, ll.trace), ("sync-fn", "r6"))
        self.assertEqual(ll.attrs, {"event": "sync.run", "resource_id": "data_flow_3", "enabled": "true"})

    def test_lines_without_timestamp_are_skipped(self):
        self.assertIsNone(parse_line("not a log line"))
        self.assertIsNone(parse_line(""))

    def test_malformed_json_does_not_raise(self):
        ll = parse_line(f"{self.TS} {{broken json")
        self.assertEqual(ll.attrs, {})


if __name__ == "__main__":
    unittest.main()
