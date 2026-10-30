import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401
from ghost_audit.intent import IntentClassifier, rule_intent
from ghost_audit.llm import LLMClient, load_env, price_for


class RuleIntentTests(unittest.TestCase):
    DELETION = [
        "Please delete my account and all personal data.",
        "I want my profile erased under GDPR.",
        "Close my account please, I no longer use it.",
        "Bitte um Löschung meines Kontos.",
        "Solicito la eliminación de mis datos personales.",
        "Peço a exclusão da minha conta.",
        "내 계정을 삭제해 주세요.",
        "アカウントを削除してください。",
        "My account was closed but a search result still shows my name, please remove it too.",
        "Can you check my deletion actually finished?",
    ]
    NOT_DELETION = [
        "Please send me a copy of my personal data in a portable format.",
        "What personal information do you hold about me?",
        "My surname is misspelled, please correct it.",
        "Please unsubscribe me from newsletters.",
        "I need to reset my password.",
        "Where can I download my invoices?",
        "Delete me from marketing lists only. Keep my account open.",
        "This is not a request to erase anything; just update my phone.",
        "Please do not delete my account, I only want to change the email.",
    ]

    def test_deletion_requests(self):
        for t in self.DELETION:
            self.assertTrue(rule_intent(t), t)

    def test_non_deletion_requests(self):
        for t in self.NOT_DELETION:
            self.assertFalse(rule_intent(t), t)


class FakeLLM:
    """Stands in for LLMClient: answers by model, records the calls made."""

    def __init__(self, answers: dict, available=True):
        self.answers, self.available, self.calls = answers, available, []
        self.vision_model = "big-model"

    def json_completion(self, system, user, purpose="text", model=None, **_):
        self.calls.append((purpose, model))
        return self.answers.get(model or "small-model")


class IntentClassifierTests(unittest.TestCase):
    TEXT = "Please delete my account."

    def test_agreement_makes_one_call(self):
        llm = FakeLLM({"small-model": {"authorizes_deletion": True, "request_type": "erasure"}})
        out = IntentClassifier(llm).classify(self.TEXT)
        self.assertTrue(out["is_deletion"])
        self.assertTrue(out["agree"])
        self.assertEqual(len(llm.calls), 1)

    def test_disagreement_is_adjudicated_by_the_stronger_model(self):
        llm = FakeLLM({"small-model": {"authorizes_deletion": False},
                       "big-model": {"authorizes_deletion": True, "request_type": "erasure"}})
        out = IntentClassifier(llm).classify(self.TEXT)
        self.assertEqual(llm.calls[1], ("intent-adjudication", "big-model"))
        self.assertTrue(out["adjudicated"])
        self.assertTrue(out["is_deletion"])

    def test_malformed_llm_answer_falls_back_to_rules(self):
        for bad in (None, {}, {"authorizes_deletion": "yes"}):
            llm = FakeLLM({"small-model": bad})
            out = IntentClassifier(llm).classify(self.TEXT)
            self.assertIsNone(out["llm"])
            self.assertTrue(out["is_deletion"])

    def test_no_llm_uses_rules(self):
        self.assertTrue(IntentClassifier(None).classify(self.TEXT)["is_deletion"])
        out = IntentClassifier(FakeLLM({}, available=False)).classify("Send me a copy of my data")
        self.assertFalse(out["is_deletion"])


class LLMClientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {}, clear=False)
        self.env.start()
        for k in ("OPENAI_API_KEY", "OPENAI_MODEL", "OPENAI_VISION_MODEL", "LLM_PRICE_GPT_4_1_MINI"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()

    def test_cache_key_is_deterministic_and_input_sensitive(self):
        c = LLMClient(self.tmp / "cache.json", offline=True)
        k = c._key("m", "sys", "user")
        self.assertEqual(k, c._key("m", "sys", "user"))
        self.assertNotEqual(k, c._key("m2", "sys", "user"))
        self.assertNotEqual(k, c._key("m", "sys", "user2"))
        # field boundaries matter: ("ab","c") must not collide with ("a","bc")
        self.assertNotEqual(c._key("m", "ab", "c"), c._key("m", "a", "bc"))

    def test_offline_cache_hit_returns_response_and_counts_usage(self):
        path = self.tmp / "cache.json"
        probe = LLMClient(path, offline=True)
        key = probe._key("gpt-4.1-mini", "sys", "user")
        path.write_text(json.dumps({key: {"response": {"ok": True},
                                          "usage": {"input_tokens": 100, "output_tokens": 10}}}), encoding="utf-8")
        c = LLMClient(path, offline=True)
        self.assertTrue(c.available)
        self.assertEqual(c.json_completion("sys", "user", purpose="intent"), {"ok": True})
        u = c.usage_summary()["gpt-4.1-mini"]
        self.assertEqual((u["calls"], u["cached_calls"], u["input_tokens"], u["output_tokens"]), (1, 1, 100, 10))
        self.assertAlmostEqual(u["estimated_cost_usd"], 100 / 1e6 * 0.40 + 10 / 1e6 * 1.60)

    def test_offline_cache_miss_returns_none_without_network(self):
        c = LLMClient(self.tmp / "missing.json", offline=True)
        self.assertFalse(c.available)
        self.assertIsNone(c.json_completion("sys", "never cached"))

    def test_offline_never_builds_a_client_even_with_a_key(self):
        os.environ["OPENAI_API_KEY"] = "sk-test-not-real"
        self.assertIsNone(LLMClient(self.tmp / "c.json", offline=True)._client)

    def test_save_round_trips(self):
        path = self.tmp / "sub" / "cache.json"
        c = LLMClient(path, offline=True)
        c.cache["k"] = {"response": {"a": 1}}
        c.save()
        self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"k": {"response": {"a": 1}}})

    def test_price_lookup_prefers_longest_prefix_and_env_override(self):
        self.assertEqual(price_for("gpt-4.1-mini-2025-04-14"), (0.40, 1.60))
        self.assertEqual(price_for("gpt-4.1"), (2.00, 8.00))
        self.assertEqual(price_for("unknown-model"), (0.0, 0.0))
        os.environ["LLM_PRICE_GPT_4_1_MINI"] = "1,2"
        self.assertEqual(price_for("gpt-4.1-mini"), (1.0, 2.0))

    def test_load_env_reads_file_but_never_overrides_the_environment(self):
        (self.tmp / ".env.local").write_text('# comment\nOPENAI_MODEL="from-file"\nOPENAI_VISION_MODEL=\n'
                                             "malformed line\n", encoding="utf-8")
        os.environ["OPENAI_VISION_MODEL"] = "from-env"
        load_env(self.tmp)
        self.assertEqual(os.environ["OPENAI_MODEL"], "from-file")
        self.assertEqual(os.environ["OPENAI_VISION_MODEL"], "from-env")


if __name__ == "__main__":
    unittest.main()
