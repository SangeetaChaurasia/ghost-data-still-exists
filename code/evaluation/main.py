"""Evaluation workflow.

    python code/evaluation/main.py                 # score public samples (+ custom cases)
    python code/evaluation/main.py --offline       # same, without API calls

Runs the full agent on dataset/sample_deletion_requests.csv, scores it
against dataset/sample_output.csv, then runs the participant-authored custom
cases in code/evaluation/custom_cases/ and checks their expectations.
Writes a machine-readable summary to code/runs/eval_summary.json.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "code"))
sys.path.insert(0, str(HERE))

from ghost_audit.llm import LLMClient, load_env  # noqa: E402
from ghost_audit.pipeline import Pipeline, read_requests  # noqa: E402
from scoring import score  # noqa: E402


def fmt(m):
    fa = ", ".join(f"{k}={v:.3f}" for k, v in m["field_accuracy"].items())
    return (f"status_acc={m['status_accuracy']:.3f}  step_P={m['step_precision']:.3f} step_R={m['step_recall']:.3f} "
            f"step_F1={m['step_f1']:.3f}  exact={m['exact_case_accuracy']:.3f}  seq={m['sequence_accuracy']:.3f} "
            f"seqLCS={m['sequence_lcs_ratio']:.3f}\n  fields: {fa}")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=str(REPO / "dataset"))
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--ablation", action="store_true", help="also score component ablations")
    ap.add_argument("--prune-cache", action="store_true",
                    help="drop cached model answers not used by this run (samples + evaluation + custom texts)")
    args = ap.parse_args(argv)
    load_env(REPO)
    dataset = Path(args.dataset)
    llm = LLMClient(REPO / "code" / "cache" / "llm_cache.json", offline=args.offline)

    custom_dir = HERE / "custom_cases"
    custom_reqs = read_requests(custom_dir / "custom_requests.csv") if (custom_dir / "custom_requests.csv").exists() else []
    pipe = Pipeline(REPO, dataset, llm, log=lambda *_: None).build()

    samples = read_requests(dataset / "sample_deletion_requests.csv")
    rows, traces = pipe.run([r["case_id"] for r in samples])
    pred = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in rows}
    with open(dataset / "sample_output.csv", encoding="utf-8-sig") as fh:
        gold = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in csv.DictReader(fh)}
    m = score(pred, gold)
    print("PUBLIC SAMPLES (32):\n  " + fmt(m))
    failures = {cid: pc for cid, pc in m["per_case"].items() if not pc["exact"]}
    for cid, pc in failures.items():
        print(f"  x {cid}: gold={pc['gold_status']} pred={pc['pred_status']}")
        for s in pc["missing"]:
            print(f"      missing {s}")
        for s in pc["extra"]:
            print(f"      extra   {s}")
        for s in pc["evidence_diff"]:
            print(f"      evidence {s[0]} {s[1]}: gold={s[2]!r} pred={s[3]!r}")
        if args.verbose:
            print(json.dumps(traces[cid]["resources"], indent=1)[:3000])

    custom_result = None
    if custom_reqs:
        # Custom cases may stand in for an existing request (column "replaces") so the
        # original does not compete with its variant for the same workflow activity.
        replaced = {r["replaces"] for r in custom_reqs if r.get("replaces")}
        reqs = [{k: v for k, v in r.items() if k != "replaces"} for r in custom_reqs]
        cpipe = Pipeline(REPO, dataset, llm, log=lambda *_: None).build(extra_requests=reqs, exclude_ids=replaced)
        crow, ctr = cpipe.run([r["case_id"] for r in reqs])
        cpred = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in crow}
        cgold = {}
        with open(custom_dir / "custom_expected.csv", encoding="utf-8-sig") as fh:
            for r in csv.DictReader(fh):
                cgold[r["case_id"]] = (r["deletion_status"], json.loads(r["steps_json"]))
        custom_result = score(cpred, cgold)
        print(f"CUSTOM CASES ({len(cgold)}):\n  " + fmt(custom_result))
        for cid, pc in custom_result["per_case"].items():
            mark = "ok" if pc["exact"] else "x"
            print(f"  {mark} {cid}: gold={pc['gold_status']} pred={pc['pred_status']} missing={pc['missing']} "
                  f"extra={pc['extra']}")

    ablations = {}
    if args.ablation:
        print("ABLATION (public samples):")
        variants = [("full system", set(), False), ("- activity attribution", {"chain"}, False),
                    ("- absence coverage proofs", {"coverage"}, False), ("- tie-break by request order", {"tiebreak"}, False),
                    ("- per-request time scoping", {"scope"}, False), ("- recreation edges", {"recreation"}, False),
                    ("rules-only intent (no LLM)", set(), True)]
        for name, abl, rules_only in variants:
            vllm = LLMClient(REPO / "code" / "cache" / "__none__.json", offline=True) if rules_only else llm
            vp = Pipeline(REPO, dataset, vllm, log=lambda *_: None, ablate=abl).build()
            vrows, _ = vp.run([r["case_id"] for r in samples])
            vpred = {r["case_id"]: (r["deletion_status"], json.loads(r["steps_json"])) for r in vrows}
            vm = score(vpred, gold)
            ablations[name] = {k: v for k, v in vm.items() if k != "per_case"}
            print(f"  {name:32s} status={vm['status_accuracy']:.3f} F1={vm['step_f1']:.3f} "
                  f"exact={vm['exact_case_accuracy']:.3f} evidence_acc={vm['field_accuracy']['evidence_id']:.3f}")

    out = {"samples": {k: v for k, v in m.items() if k != "per_case"}, "sample_failures": failures,
           "ablations": ablations,
           "custom": {k: v for k, v in (custom_result or {}).items() if k != "per_case"} if custom_result else None,
           "custom_per_case": custom_result["per_case"] if custom_result else None,
           "usage": llm.usage_summary()}
    (REPO / "code" / "runs").mkdir(parents=True, exist_ok=True)
    (REPO / "code" / "runs" / "eval_summary.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    llm.save(prune=args.prune_cache)


if __name__ == "__main__":
    main()
