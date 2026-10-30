"""Does the request text authorise account/personal-data deletion?

Primary path: an LLM classifier (prompts in prompts/intent_*.md) (multilingual, handles negation such as
"remove me from marketing lists only").  A deterministic multilingual rule
classifier is used as a fallback when no API key is configured and as a
cross-check; disagreements are logged in the run trace.
"""
from __future__ import annotations

import re

from . import prompts
from .guardrails import sanitize_request_text, validate_intent_response
from .llm import LLMClient

DELETE_PATTERNS = [
    r"\bdelet", r"\berase", r"\berasure", r"\bremove (my|the) (account|profile)", r"\bclose (my|this|the) account",
    r"account[- ]deletion", r"permanently deleted", r"\bremove my account",
    r"exclus[aã]o", r"eliminaci[oó]n", r"suppression", r"삭제", r"削除", r"löschung", r"cancellazione",
    # used when no model is reachable, so cover common verbs in more languages
    r"\bborr(ar|en|e|ad|o)\b", r"\bpurge", r"\bwipe", r"forget me", r"right to be forgotten", r"\bsupprim",
    r"\beffac", r"\belimin(ar|en|e)\b", r"\bexclu(ir|am|a)\b", r"\bapag(ar|uem|ue)\b", r"\bcancella",
    r"\bl[öo]sch", r"verwijder", r"\busu[nń]", r"удал", r"删除|刪除", r"حذف", r"मिटा|हटा",
]
NON_DELETE_PATTERNS = [
    r"marketing lists only", r"stop the promotional", r"\bunsubscribe", r"copy of", r"download my", r"portable format",
    r"what personal information", r"misspelled", r"out of date", r"change the email", r"reset", r"invoices",
    r"\bcorrect(ion)?\b",
]

NEGATED_DELETE = [r"do not (delete|erase|close|remove)", r"don't (delete|erase|close|remove)",
                  r"not a (request|deletion request) to (delete|erase|remove)", r"not (a )?(deletion|erasure) request",
                  r"not (asking|requesting) (for )?(deletion|to delete)", r"without deleting", r"keep (my|the) account"]


def rule_intent(text: str) -> bool:
    """Fallback classifier. Requests in this channel default to deletion unless they are
    clearly another privacy right (access, correction, opt-out...) or negate deletion."""
    t = text.lower()
    if any(re.search(p, t) for p in NEGATED_DELETE):
        return False
    strong = any(re.search(p, t) for p in DELETE_PATTERNS)
    if any(re.search(p, t) for p in NON_DELETE_PATTERNS) and not strong:
        return False
    if strong:
        return True
    return bool(re.search(r"\bremov|\bgone\b|\bclean|\bdelet|\berase|\bclose", t))


def request_message(text: str) -> str:
    """User message for the intent prompts. The text is untrusted, so it cannot close its own tag."""
    safe = sanitize_request_text(text).replace("</request", "< /request")
    return prompts.render(prompts.INTENT_USER, request_text=safe)


class IntentClassifier:
    def __init__(self, llm: LLMClient | None):
        self.llm = llm

    def classify(self, text: str) -> dict:
        rule = rule_intent(text)
        out = {"rule": rule, "llm": None, "label": None}
        if self.llm and self.llm.available:
            user = request_message(text)
            resp = validate_intent_response(
                self.llm.json_completion(prompts.system(prompts.INTENT), user, purpose="intent"))
            if resp is None:
                out["guardrail"] = "intent answer missing or malformed; keyword rules used"
            else:
                out["llm"] = resp["authorizes_deletion"]
                out["label"] = resp["request_type"]
                out["reason"] = resp["reason"]
            if out["llm"] is not None and out["llm"] != rule:
                # Disagreement: a second, stronger look decides (self-consistency check).
                adj = validate_intent_response(self.llm.json_completion(
                    prompts.system(prompts.INTENT, prompts.INTENT_ADJUDICATION), user,
                    purpose="intent-adjudication", model=self.llm.vision_model))
                if adj is not None:
                    out["adjudicated"] = adj["authorizes_deletion"]
                    out["llm"] = adj["authorizes_deletion"]
                    out["label"] = adj["request_type"] or out["label"]
                    out["reason"] = adj["reason"]
        else:
            out["guardrail"] = "no model available; keyword rules used"
        out["is_deletion"] = out["llm"] if out["llm"] is not None else rule
        out["agree"] = out["llm"] is None or out["llm"] == rule
        return out
