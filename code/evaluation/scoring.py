"""Scoring helpers shared by the evaluation workflow.

Metrics (computed against any labelled CSV with case_id,deletion_status,steps_json):
* status accuracy            - exact deletion_status match per case
* step precision/recall/F1   - steps matched on (phase, system_id, resource_id, operation, state)
* field accuracy             - per-field agreement on aligned steps (incl. evidence_id)
* exact-steps accuracy       - full steps_json equality (order-sensitive)
* sequence accuracy          - predicted step order equals gold order on the matched steps
"""
from __future__ import annotations

import csv
import json
from collections import Counter

FIELDS = ("phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def load(path):
    with open(path, encoding="utf-8-sig") as fh:
        return {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}


def step_key(s):
    return (s["phase"], s["system_id"], s["resource_id"], s["operation"], s["state"])


def lcs(a, b):
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) - 1, -1, -1):
        for j in range(len(b) - 1, -1, -1):
            dp[i][j] = dp[i + 1][j + 1] + 1 if a[i] == b[j] else max(dp[i + 1][j], dp[i][j + 1])
    return dp[0][0]


def score(pred: dict, gold: dict) -> dict:
    n = len(gold)
    status_ok = 0
    tp = fp = fn = 0
    field_hits = Counter()
    field_total = 0
    exact = 0
    seq_ok = 0
    seq_lcs = 0.0
    per_case = {}
    for cid, (gs, gsteps) in gold.items():
        ps, psteps = pred.get(cid, (None, []))
        status_ok += ps == gs
        gk = [step_key(s) for s in gsteps]
        pk = [step_key(s) for s in psteps]
        gc, pc = Counter(gk), Counter(pk)
        inter = sum((gc & pc).values())
        tp += inter
        fp += sum(pc.values()) - inter
        fn += sum(gc.values()) - inter
        # field accuracy over position-aligned steps (union length)
        L = max(len(gsteps), len(psteps))
        for i in range(L):
            field_total += 1
            g = gsteps[i] if i < len(gsteps) else {}
            p = psteps[i] if i < len(psteps) else {}
            for f in FIELDS:
                field_hits[f] += (g.get(f) == p.get(f)) and bool(g)
        strip = lambda ss: [{k: s[k] for k in FIELDS} for s in ss]
        exact_case = ps == gs and strip(psteps) == strip(gsteps)
        exact += exact_case
        common = [k for k in pk if k in gc]
        gold_common = [k for k in gk if k in pc]
        seq_ok += common == gold_common
        seq_lcs += (lcs(pk, gk) / max(len(gk), len(pk))) if max(len(gk), len(pk)) else 1.0
        gev = {step_key(s): s.get("evidence_id") for s in gsteps}
        ev_diff = sorted((k[2], k[3], gev[k], s.get("evidence_id")) for s in psteps
                         for k in [step_key(s)] if k in gev and gev[k] != s.get("evidence_id"))
        per_case[cid] = dict(status_ok=ps == gs, exact=exact_case, gold_status=gs, pred_status=ps,
                             missing=sorted(set(gk) - set(pk)), extra=sorted(set(pk) - set(gk)),
                             evidence_diff=ev_diff)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return {
        "cases": n,
        "status_accuracy": status_ok / n,
        "step_precision": prec, "step_recall": rec,
        "step_f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "field_accuracy": {f: field_hits[f] / field_total for f in FIELDS} if field_total else {},
        "exact_case_accuracy": exact / n,
        "sequence_accuracy": seq_ok / n,
        "sequence_lcs_ratio": seq_lcs / n,
        "per_case": per_case,
    }
