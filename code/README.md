# Ghost Data Still Exists — deletion-audit agent

For every request in `dataset/deletion_requests.csv` the agent decides whether deletion was actually
requested. For authorised deletions it then rebuilds the subject's current and historical identifiers,
traces every copy of their data through the evidence corpus and the global activity stream, works out
each record's state at `audit_at`, applies `deletion_rules.csv`, and writes the ordered
FINDING → REMEDIATION → VERIFICATION plan to `output.csv`.

## Quick start

`code.zip` holds the contents of this `code/` folder. Unzip it into `code/` at the repository root,
next to `dataset/`. All paths are resolved relative to that layout.

```bash
# from the repository root
python -m pip install -r code/requirements.txt
cp .env.example .env.local          # then set OPENAI_API_KEY=... (never commit it)
python code/main.py                 # -> output.csv (518 rows) at the repo root
python code/evaluation/main.py      # score public samples + custom cases
python code/evaluation/main.py --ablation   # + component ablation table
python code/package.py              # -> code.zip (secret-scanned)
```

* Python 3.10+ (developed on 3.14). Standard library apart from `openai` and `pypdf`.
* **No key? Still runs.** `python code/main.py --offline` uses the committed model-response cache
  in `code/cache/`. Without a cache it falls back to the rule-based intent classifier, and
  screenshots that haven't been extracted are reported as unparsed. With the committed cache,
  online and offline runs produce byte-identical output.
* Outputs: `output.csv`, plus `code/runs/last_run_trace.json` (per-case reasoning: every linked
  resource, why it was linked, its state, and the evidence cited) and `code/runs/last_run_usage.json`
  (token accounting).
* Optional env vars: `OPENAI_MODEL` (intent, default `gpt-4.1-mini`), `OPENAI_VISION_MODEL`
  (screenshots and intent adjudication, default `gpt-4.1`), `OPENAI_BASE_URL`, `GHOST_PROMPTS_DIR`.
* **Prompts** live as Markdown files in `prompts/` (packaged as `code/prompts/`). Each one is the shared
  mission statement plus a task prompt; see `prompts/README.md`.

## Guardrails

| Where | Check | On failure |
|---|---|---|
| Input | required columns, duplicate or empty `case_id`, unreadable timestamps | stop, exit 2, nothing written |
| Input | `audit_at` before `requested_at`, unknown `reported_status`, bad email, empty text | warning, recorded in the usage file |
| Request text | control characters stripped, length capped, wrapped in `<request>` tags the text cannot close; prompt says it is data, not instructions | — |
| Model answers | intent must be a real boolean; screenshot records are schema-checked (id format, email/phone shape, known kinds, booleans), cached answers included | intent falls back to the keyword rules; bad screenshot fields or records are dropped and logged |
| Identity | request email matches no user: evidence is searched by address and hash; several users: identifiers merged | flagged in the trace |
| Output | full contract check (fields, ids, `step_no`, operation/state pairs, phase order, evidence rules, no file captured after `audit_at`) | stop, exit 3, `output.csv` NOT written; rows kept in `code/runs/rejected_output.csv` |
| Secrets | trace and usage files are redacted; `code/package.py` refuses to build if any file matches a key pattern or contains the configured key | packaging stops |
| Prompts | missing or empty prompt file, unknown placeholder | stop with an error |
| Dataset | required corpus files present; `deletion_rules.csv` actions limited to DELETE/REDACT/ANONYMIZE/RETAIN | stop, exit 2 |
| Evidence manifest | path must stay inside `dataset/evidence/`; readable `captured_at`; no duplicate ids | row skipped, warning |
| Damaged evidence | invalid UTF-8 replaced; truncated SQL salvaged statement by statement, but a damaged file is **never** used to prove absence; changed screenshots invalidate their cached facts (content hash) | warning, case degrades toward INCOMPLETE |
| Unknown state | a record that needs action but has no admissible state evidence cannot be verified, so it is reported at its last known state (fail closed) | case stays INCOMPLETE, flagged |
| Model API | bounded timeout; bad key or unknown model stops calls at once; 3 consecutive failures open a circuit breaker | keyword fallback, every affected case flagged, loud warning |
| Portability | CSVs with a byte-order mark are accepted; timestamps without an offset are UTC, never machine-local time | — |

## Tests

```bash
python -m unittest discover -s code/tests -t code/tests     # 125 tests, ~30 s, no API key needed
GHOST_SKIP_SLOW=1 python -m unittest discover -s code/tests -t code/tests   # fast subset, ~3 s
```

* **Unit:** identifier normalisation, the 7 log dialects, PDF grounding, OCR snapping, identity history,
  activity parsing, rule intent (8 languages, negations), LLM cache/pricing/env handling, scoring.
* **Engine scenarios:** a synthetic mini dataset (`tests/_support.py`, fictional people) with hand-written
  expected plans: historical email + tombstone (COMPLETE), live search entry + enabled sync flow
  (flow disabled first), point-in-time cutoff, claims-vs-evidence, replica drift, NOT_APPLICABLE.
* **Guardrails:** every check in the table above, including `main.py` exiting 2 or 3 without writing
  output, and the packager refusing a file with a key in it.
* **Adversarial** (`test_adversarial.py`): hostile manifests, corrupted evidence (no damage may ever
  produce a COMPLETE), API outages, the fail-closed rule, and metamorphic checks on all 518 requests
  (request order, email case, another email of the same person, worker count, corpus row order must
  not change any answer).
* **Contract + regression:** `output.csv` is checked against the output contract, and the full pipeline
  runs offline on the 32 public samples with a quality floor (status 1.0, step F1 ≥ 0.98). Set
  `GHOST_SKIP_SLOW=1` to skip that part.
* The suite was mutation-checked: eleven injected bugs (six in the core logic, five that each remove a
  guardrail) each made it fail.

## Architecture

```
dataset/ ──► EvidenceStore ───────────┐   (JSON bundles/exports/ledgers, SQL replicas via sqlite3,
             (evidence.py, logparse.py,│    7 log dialects, PDFs via pypdf, PNGs via vision LLM)
              documents.py, vision.py) │
user_identities + audit_log ─► IdentityResolver (all emails/phones/hashes ever held; sha256 of old emails)
system_activity ─► ActivityLog (worker actions, catalog links, "repopulated downstream" recreation edges)
request_text ─► IntentClassifier (LLM + multilingual rules; disagreements adjudicated by a 2nd model)
                         │
                         ▼
                 Auditor (engine.py)
   1. link resources: identifiers on records ∪ catalog links ∪ attributed workflow activity ∪ recreation edges
   2. reconstruct state at audit_at from admissible evidence (captured ≤ audit_at); any lagging replica copy = present
   3. policy (policy.py ← deletion_rules.csv): DELETE / REDACT / ANONYMIZE / RETAIN / tombstone / disable flow / block restore
   4. plan: findings → remediation (flows & restores first) → verification, sorted per the contract
```

Main design points:

* **Evidence is normalised once.** Every file becomes `Observation` rows (system, resource, state,
  direct identifiers, link keys, capture time). The reasoning layer never deals with file formats.
* **Claims vs. state.** Activity `reported_result` and workflow statuses are never treated as proof.
  Activity is used only to *attribute* resources to a request, or as a last-resort cited claim that a
  recreation path is live.
* **Global activity attribution.** Worker rows don't name the subject, so they are assigned across *all*
  requests jointly. Scoring uses evidence ownership, timing relative to `reported_at`, the reported
  outcome vs. `reported_status`, a provisional evidence-only verdict and co-occurrence in the same
  capture. Exact ties are broken by request order (documented in the evaluation report).
* **Absence is proven, not assumed.** A COMPLETE verdict cites evidence for every check. Account
  absence comes from 404 lookups, complete account-table captures, or deleted-customer tombstones that
  post-date the deletion submission.
* **Point-in-time discipline.** Only evidence captured at or before `audit_at` is cited. When a person
  filed an earlier, already-audited request, evidence from that earlier scope is excluded.

## Layout

```
code/
  main.py                    CLI entry point
  ghost_audit/               agent package (evidence, identity, activity, intent, vision, policy, engine, llm,
                             guardrails, prompts loader)
  prompts/                   model prompts (in the repo: ../prompts/)
  package.py                 builds code.zip with a secret scan
  cache/                     content-addressed model-response cache + structured screenshot extractions
  tests/                     unit, engine-scenario, contract and regression tests
  evaluation/main.py         evaluation workflow (samples, custom cases, ablations)
  evaluation/scoring.py      metrics
  evaluation/custom_cases/   5 participant-authored cases with hand-derived expected outputs
  evaluation/evaluation_report.md
  evaluation/usage_report.md
```
