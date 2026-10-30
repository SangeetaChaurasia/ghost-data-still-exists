"""Ghost Data Still Exists - deletion-audit agent.

Usage (from the repository root):
    python code/main.py                       # audit dataset/deletion_requests.csv -> output.csv
    python code/main.py --input dataset/sample_deletion_requests.csv --output sample_pred.csv
    python code/main.py --offline             # no API calls; use cached model outputs / rule fallbacks

API keys are read from the environment or an uncommitted .env.local / .env at the repo root.

Guardrails: the request file is validated before anything runs, and the predictions must pass the
output contract before output.csv is written. On a contract failure nothing is written to --output;
the rejected rows go to code/runs/rejected_output.csv. Exit codes: 0 ok, 2 bad input, 3 bad output.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

from ghost_audit import prompts  # noqa: E402
from ghost_audit.guardrails import GuardrailError, contract_errors, redact, validate_requests  # noqa: E402
from ghost_audit.llm import LLMClient, load_env  # noqa: E402
from ghost_audit.pipeline import Pipeline, read_requests, write_output  # noqa: E402


DATASET_FILES = ["evidence_files.csv", "user_identities.csv", "user_audit_log.csv", "system_activity.csv",
                 "deletion_rules.csv"]


def fail(code: int, title: str, problems: list[str]):
    print(f"GUARDRAIL STOP: {title}", file=sys.stderr)
    for p in problems[:25]:
        print(f"  - {p}", file=sys.stderr)
    if len(problems) > 25:
        print(f"  ... and {len(problems) - 25} more", file=sys.stderr)
    sys.exit(code)


def write_redacted(path: Path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(redact(json.dumps(payload, indent=1, ensure_ascii=False)), encoding="utf-8")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=str(REPO / "dataset"))
    ap.add_argument("--input", default=None, help="requests CSV (default: <dataset>/deletion_requests.csv)")
    ap.add_argument("--output", default=str(REPO / "output.csv"))
    ap.add_argument("--trace", default=str(REPO / "code" / "runs" / "last_run_trace.json"),
                    help="where to write the per-case reasoning trace")
    ap.add_argument("--usage", default=str(REPO / "code" / "runs" / "last_run_usage.json"))
    ap.add_argument("--offline", action="store_true", help="never call the API (cache + rule fallbacks only)")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args(argv)

    load_env(REPO)
    dataset = Path(args.dataset)
    missing = [f for f in DATASET_FILES if not (dataset / f).exists()]
    if missing:
        fail(2, f"dataset folder {dataset} is incomplete", [f"missing {f}" for f in missing])
    input_path = Path(args.input) if args.input else dataset / "deletion_requests.csv"
    if not input_path.exists():
        fail(2, "request file not found", [str(input_path)])
    with open(input_path, encoding="utf-8-sig") as fh:
        header = next(csv.reader(fh), [])
    requests = read_requests(input_path)
    errors, warnings = validate_requests(requests, header)
    if errors:
        fail(2, f"{input_path.name} failed input validation", errors)
    for w in warnings[:10]:
        print(f"input warning: {w}")

    t0 = time.time()
    llm = LLMClient(REPO / "code" / "cache" / "llm_cache.json", offline=args.offline)
    try:
        pipe = Pipeline(REPO, dataset, llm, workers=args.workers).build(extra_requests=requests)
        rows, traces = pipe.run([r["case_id"] for r in requests])
    except GuardrailError as exc:
        fail(2, "configuration problem", [str(exc)])
    llm.save()

    manifest = {fid: m["captured_at"] for fid, m in pipe.store.manifest.items()}
    problems = contract_errors(rows, requests, manifest)
    if problems:
        rejected = REPO / "code" / "runs" / "rejected_output.csv"
        rejected.parent.mkdir(parents=True, exist_ok=True)
        write_output(rows, rejected)
        fail(3, f"predictions break the output contract; {args.output} was NOT written "
                f"(rows kept in {rejected})", problems)
    write_output(rows, Path(args.output))

    flagged = {cid: t["flags"] for cid, t in traces.items() if t["flags"]}
    write_redacted(Path(args.trace), traces)
    usage = {"requests": len(requests), "elapsed_seconds": round(time.time() - t0, 2),
             "prompt_fingerprints": prompts.fingerprints(), "input_warnings": warnings,
             "evidence_warnings": pipe.warnings,
             "api_failures": len(llm.failures), "api_disabled_mid_run": llm.breaker_open,
             "flagged_cases": len(flagged), "models": llm.usage_summary()}
    write_redacted(Path(args.usage), usage)
    if llm.failures:
        print(f"WARNING: {len(llm.failures)} model calls failed; affected cases used deterministic fallbacks "
              f"and are flagged in the trace. First error: {llm.failures[0]}")
    counts = {}
    for r in rows:
        counts[r["deletion_status"]] = counts.get(r["deletion_status"], 0) + 1
    print(f"wrote {len(rows)} rows to {args.output}  {counts}  ({usage['elapsed_seconds']}s)")
    print(f"guardrails: input ok ({len(warnings)} warnings), {len(pipe.warnings)} evidence warnings, "
          f"output contract ok, {len(flagged)} cases flagged in trace")


if __name__ == "__main__":
    main()
