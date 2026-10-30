# Evaluation report — Ghost Data Still Exists

Reproduce: `python code/evaluation/main.py --ablation` (add `--offline` to use only the committed cache).
Machine-readable results are written to `code/runs/eval_summary.json`.

## 1. Method

* **Labelled set:** the 32 public samples (`dataset/sample_deletion_requests.csv` scored against
  `sample_output.csv`). The agent runs over the full participant corpus, exactly as in the real
  run. No sample label is read by the agent.
* **Custom set:** 5 cases we wrote ourselves (`custom_cases/`). Expected outputs were derived by
  hand from the raw evidence *before* running the agent.
* **Metrics** (`scoring.py`):
  * *Case-level status accuracy:* exact `deletion_status` match.
  * *Step-level P/R/F1:* multiset match on (phase, system_id, resource_id, operation, state).
  * *Field-level accuracy:* per field, over position-aligned steps; misaligned or missing steps count as wrong.
  * *Exact-case accuracy:* the full `steps_json` is identical, including evidence and order.
  * *Sequence accuracy:* matched steps appear in gold order. *Sequence LCS ratio:* longest common
    subsequence / max length.

## 2. Results — public samples (32)

| Metric | Value |
|---|---|
| Case-level status accuracy | **1.000** (32/32) |
| Step precision / recall / F1 | **0.995 / 0.979 / 0.987** |
| Exact-case accuracy (full steps_json incl. evidence) | 0.875 (28/32) |
| Sequence accuracy | **1.000** |
| Sequence LCS ratio | 0.974 |

| Field | Accuracy |
|---|---|
| phase | 0.984 |
| system_id | 0.959 |
| resource_id | 0.953 |
| operation | 0.959 |
| state | 0.959 |
| evidence_id | 0.979 |

The 4 remaining sample mismatches are records the participant data cannot support:

| Case | Gap | Why it can't be recovered |
|---|---|---|
| case_04 | missing `account_004` VERIFY_ABSENT | The id appears in no evidence file and no activity row. |
| case_18 | missing `audit_record_6645` | Appears nowhere in participant data. |
| case_20 | missing `audit_record_5569` | Appears nowhere in participant data. |
| case_23 | `account_7015` instead of `account_410` | Three NOT_STARTED requests share one `reported_at`, and three FAILED profile submissions fall in the window. None of the three accounts appears in any evidence, so the pick is a 1-in-3 guess. |

## 3. Custom evaluation cases (5) — all pass

| Case | What it tests | Expected (hand-derived) | Result |
|---|---|---|---|
| custom_01 | Deletion-shaped fields, but the text asks for a surname correction and says "not asking you to delete or erase anything" | NOT_APPLICABLE, `[]` | ✅ |
| custom_02 | Historical email (`noah.f438085@…`, changed 2026-05-18), German text not seen in the data, replaces sample case_29 | 14-step INCOMPLETE plan equal to case_29 gold | ✅ |
| custom_03 | Point-in-time cutoff: haruka.s1838 audited on 2026-09-20, *before* the 26-Sep admin-console screenshot | Only the 15-Sep log is admissible. The account was a 404 then, so it's verified absent. A support attachment still carries her **old** phone, so it's a REMAINING finding. The audit record is retained. 5 steps. | ✅ |
| custom_04 | Replication drift, Portuguese text: account deleted from primary and eu_west but alive in `replica_ap_south` | REMAINING account_585 + search_7660 (evidence_29), 7 steps | ✅ |
| custom_05 | "Delete me from newsletter and promotional mailing lists only. Keep my account open." | NOT_APPLICABLE (marketing opt-out, despite the word "delete") | ✅ |

Custom set: status 1.000, step F1 1.000, exact 1.000, every field 1.000.

## 4. Ablation study (public samples)

| Variant | Status | Step F1 | Exact | evidence_id acc |
|---|---|---|---|---|
| **Full system** | **1.000** | **0.987** | **0.875** | **0.979** |
| − workflow-activity attribution | 0.969 | 0.910 | 0.344 | 0.845 |
| − absence-coverage proofs | 1.000 | 0.987 | 0.781 | 0.964 |
| − request-order tie-break | 1.000 | 0.974 | 0.719 | 0.955 |
| − per-request time scoping | 1.000 | 0.974 | 0.812 | 0.944 |
| − recreation edges | 1.000 | 0.987 | 0.875 | 0.979 |
| rules-only intent (no LLM) | 1.000 | 0.987 | 0.875 | 0.979 |

Recreation edges and the LLM intent model don't move the sample score. The samples contain no
sync-recreation case and only one ambiguous text. On the evaluation set, the recreation edges attach
29 connectors, and the LLM is the safety net for negated or unusual wording (e.g. custom_01, custom_05,
case_539 "not a request to erase it").

## 5. Failures found and improvements made

| Iteration | Change | Status | Step F1 | Exact |
|---|---|---|---|---|
| v1 | Identifier linking + first-match activity chain + keyword intent | 0.844 | 0.850 | 0.312 |
| v2 | Fixed keyword-intent fallback (5 deletion requests misread). Stopped a multi-person legal register PDF linking every resource to every listed user. Replaced first-match with a **scored global assignment** that uses a provisional evidence-only verdict. | 1.000 | 0.963 | 0.562 |
| v3 | **Per-request time scoping**: users with an earlier, already-audited request (user_07, user_17) were inheriting that request's records | 1.000 | 0.974 | 0.625 |
| v4 | **Absence proofs**: empty or complete account captures prove an account is gone, so COMPLETE verdicts cite real evidence. Guarded against replica drift: any copy in a lagging replica table means present. | 1.000 | 0.974 | 0.719 |
| v5 | Request-order tie-break for balanced ties. Emails embedded in free text (`uploaded_by`, message bodies) are now extracted; before, 20+ un-redacted support messages were wrongly treated as compliant. | 1.000 | 0.987 | 0.875 |
| v6 | **LLM regression caught by the eval:** `gpt-4.1-mini` labelled case_06 ("remove that search result too") as non-deletion (status fell to 0.969). Fixed with an explicit policy definition in the prompt plus a disagreement-adjudication pass on `gpt-4.1`. | 1.000 | 0.987 | 0.875 |

Fixes found by auditing evaluation-set families the samples don't cover (no effect on the sample score):

* The vision model labelled a tombstone screenshot `USER_PROFILE`. The resource-id namespace is now
  authoritative, and the model's label only refines `support_*` (message vs. attachment).
* Tombstones with `account_status=DELETED` are used as account-absence proof. A capture taken *before*
  the deletion was submitted is never accepted as proof (it had wrongly cited a 2-Sep snapshot for
  accounts deleted on 5-Sep).
* OCR slips such as `lucia.torres` vs `lucia-torres` are snapped to a known identity, but only when the
  edit-distance-1 match is unique.
* Downstream recreation (`… repopulated downstream resource search_X`) links the connector or restore
  job to the subject and raises an ACTIVE finding.

Changes after the first submission-ready build (scores unchanged; `output.csv` byte-identical):

* **Prompts moved to `prompts/`** with a shared mission statement. Validation: we diffed the
  screenshot extractions before and after. The first draft's "use null when not shown" rule made the
  model return `restore_allowed: null` for backups, and it put ticket ids and file names in
  `resource_id`. Neither changed a verdict, but both made the evidence weaker, so we tightened the
  prompt and re-extracted. The remaining differences are two record kinds that the resource-id
  namespace overrides anyway.
* **Runtime guardrails** (`ghost_audit/guardrails.py`): input validation, schema checks on every
  model answer (cached ones too), an output-contract gate in `main.py` (nothing is written if it
  fails), redaction of run files, and a secret scan in `code/package.py`. A request email that
  matches no known user is now searched by address and hash and flagged in the trace. Before, it
  returned an unflagged empty COMPLETE.
* **Test suite** (`code/tests/`, 125 tests): units, engine scenarios on a synthetic mini dataset,
  guardrail stop conditions, the output contract and a sample regression with a quality floor.
  We checked the suite itself by injecting six realistic bugs, and each one made it fail.

### Adversarial testing ("breaking the app")

We attacked the agent from five directions. Each attack that found a bug is now a regression test in
`code/tests/test_adversarial.py`. None of the fixes changed `output.csv` or any score.

| Attack | Before | After |
|---|---|---|
| Unreadable PDF holding the only state evidence for a record | case_33 flipped INCOMPLETE → **COMPLETE**, citing a catalog row as "proof" of deletion | Fail closed: a record whose state is unknown cannot be verified, so it is reported at its last known state |
| Truncated SQL replica | whole file dropped (10 rows changed); a partly loaded account table could have "proven" absence | salvaged statement by statement (4 rows changed); damaged files never prove absence |
| Screenshot replaced by another file | stale cached facts still used (cache keyed by file name) | facts tied to a content hash; a changed image drops them |
| Malformed `captured_at`, audit-log user missing from identities | crash | row skipped with a warning; identity built from history |
| Missing `deletion_rules.csv` | traceback | clean stop, exit 2 |
| `../` path in the manifest | file outside the dataset would be read | refused, warning |
| Timestamp without offset | read as machine-local time (shifted 5.5 h on the dev machine) | read as UTC |
| CSV saved with a byte-order mark (Excel) | rejected as "missing case_id" | accepted |
| Model API down (dead endpoint) | 47 s for 3 texts, about 15 min projected for a full run; Spanish "borren todos mis datos" and "purge every trace of me" fell back to NOT_APPLICABLE, silently | circuit breaker (stall capped at about 25 s), bad key stops at once, keyword rules cover 15+ languages, every fallback case flagged, loud warning |
| 8 live prompt-injection texts (fake `</request>`, fake system/assistant turns, embedded JSON verdicts) | — | 8/8 classified correctly; one fooled the keyword rules and was correctly settled by adjudication |

Metamorphic checks on all 518 evaluation requests changed no answers: shuffled request order, email
upper-case and whitespace, 101 requests switched to another email of the same person, 1 vs 8
workers, and shuffled rows in every corpus CSV.

## 6. Evaluation-set diagnostics (518 requests, no labels)

* Status mix: 357 INCOMPLETE, 151 COMPLETE, 10 NOT_APPLICABLE. The LLM and rule intent agree on all
  398 distinct texts (550 requests incl. samples), so no adjudication call was needed.
* Every COMPLETE step cites a file captured at or before `audit_at`. Only the 2 screenshot-driven cases
  cite more than one file, which is consistent with the one-capture-per-case pattern in the samples.
* Linking provenance of the evaluation-set resources: 1,799 identifier links, 864 attributed workflow
  actions, 496 profile submissions, 29 recreation edges and 12 catalog links.
* Account attribution (all 550 requests): 252 confirmed by evidence, 221 unique by activity, and 54
  contended (best-scored pick; see case_23 for the failure mode).
* 48 balanced ties were broken by request order. 8 unbalanced ties keep the record on both requests.
* Output passes the contract validator: 518 unique rows, consecutive `step_no`, phase and operation
  order, state/operation pairs, and evidence rules per phase.

## 7. Known limitations

* Contended profile submissions (≈10% of requests) can be mis-assigned when no evidence names the
  account. Each miss costs one verification step and never flips the status.
* The request-order tie-break matches all 3 tied pairs in the samples, but it is an inference about how
  the workflow processes requests, not a fact stated in the data.
* Security or legal records that appear only in logs exported *after* `audit_at` are verified in
  INCOMPLETE plans (no citation needed) but are never cited.
