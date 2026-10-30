"""End-to-end orchestration used by main.py and the evaluation workflow."""
from __future__ import annotations

import csv
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .activity import ActivityLog
from .engine import Auditor, Case
from .evidence import EvidenceStore
from .identity import IdentityResolver
from .intent import IntentClassifier
from .llm import LLMClient
from .policy import Policy
from .vision import VisionExtractor

REQUEST_FIELDS = ["case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"]


def read_requests(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig") as fh:
        return list(csv.DictReader(fh))


def case_sort_key(cid: str):
    tail = cid.split("_")[-1]
    return (0, int(tail), cid) if tail.isdigit() else (1, 0, cid)


class Pipeline:
    def __init__(self, repo_root: Path, dataset_dir: Path, llm: LLMClient, workers: int = 8, log=print,
                 ablate: set | None = None):
        self.repo_root, self.dataset_dir, self.llm, self.workers, self.log = repo_root, dataset_dir, llm, workers, log
        self.ablate = set(ablate or ())
        self.vision = VisionExtractor(llm, dataset_dir, repo_root / "code" / "cache" / "vision_extractions.json")
        self.intent = IntentClassifier(llm)

    def build(self, extra_requests: list[dict] | None = None, exclude_ids: set | None = None):
        self.log("[1/5] extracting screenshot facts (vision model, cached)")
        vision_cache = self.vision.extract_all()
        self.log("[2/5] normalising evidence corpus")
        self.acts = ActivityLog(self.dataset_dir)
        self.idr = IdentityResolver(self.dataset_dir)
        self.store = EvidenceStore(self.dataset_dir, vision_cache=vision_cache, aliases=self.acts.alias_map(),
                                   known_emails=set(self.idr.email_index))
        self.warnings = list(self.store.unparsed) + list(self.acts.skipped) + [
            f"{n}: {'; '.join(i)}" for n, i in self.vision.issues.items()]
        for w in self.warnings:
            self.log(f"      evidence warning: {w}")
        self.policy = Policy(self.dataset_dir)
        # Every request in the participant data competes for activity attribution.
        self.all_requests = {}
        for name in ("sample_deletion_requests.csv", "deletion_requests.csv"):
            if (self.dataset_dir / name).exists():
                self.all_requests.update({r["case_id"]: r for r in read_requests(self.dataset_dir / name)})
        for r in extra_requests or []:
            self.all_requests[r["case_id"]] = r
        for cid in exclude_ids or ():
            self.all_requests.pop(cid, None)
        self.log(f"[3/5] classifying intent for {len(self.all_requests)} requests")
        texts = sorted({r["request_text"] for r in self.all_requests.values()})
        with ThreadPoolExecutor(self.workers) as ex:
            results = dict(zip(texts, ex.map(self.intent.classify, texts)))
        self.intent_results = results
        cases = []
        for r in self.all_requests.values():
            c = Case(**{k: r[k] for k in REQUEST_FIELDS})
            c.is_deletion = results[r["request_text"]]["is_deletion"]
            if results[r["request_text"]].get("guardrail"):
                c.flags.append("intent: " + results[r["request_text"]]["guardrail"])
            cases.append(c)
        self.log("[4/5] linking identities, evidence and workflow activity")
        self.auditor = Auditor(self.store, self.acts, self.idr, self.policy, cases, ablate=self.ablate)
        return self

    def run(self, case_ids: list[str]) -> tuple[list[dict], dict]:
        self.log(f"[5/5] auditing {len(case_ids)} cases")
        rows, traces = [], {}
        for cid in sorted(case_ids, key=case_sort_key):
            c = self.auditor.cases[cid]
            status, steps, trace = self.auditor.audit(c)
            rows.append({"case_id": cid, "deletion_status": status,
                         "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})
            traces[cid] = {"status": status, "user_ids": c.user_ids, "intent": self.intent_results[c.request_text],
                           "flags": list(c.flags), "resources": trace}
        return rows, traces


def write_output(rows: list[dict], path: Path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["case_id", "deletion_status", "steps_json"], lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
