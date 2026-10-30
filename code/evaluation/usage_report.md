# Token usage and cost — final full-dataset run

This is the run that produced the submitted `output.csv`: `python code/main.py` on 2026-10-24.
Every call below was made live against the API with the current prompt files (`prompts/`), and the
cached answers keep their original token counts. Raw numbers, including a fingerprint of each prompt
file: `code/runs/last_run_usage.json`. Wall time for a fully live run: 132 s with 8 parallel workers.
A rerun from the cache takes about 2 s and reproduces `output.csv` byte-for-byte.

## Where models are used

| Purpose | Provider / model | Prompts | Unit of work | Calls |
|---|---|---|---|---|
| Screenshot evidence extraction (structured JSON) | OpenAI `gpt-4.1` (vision) | `system_prompt.md` + `vision_extraction.md`, `vision_user.md` | once per image in the corpus (11 PNGs) | 11 |
| Request-intent classification | OpenAI `gpt-4.1-mini` | `system_prompt.md` + `intent_classification.md`, `intent_user.md` | once per *distinct* request text: 398 texts across 550 requests (518 evaluation + 32 samples, which take part in global activity attribution) | 398 |
| Intent adjudication (only when the model and the keyword rules disagree) | OpenAI `gpt-4.1` | adds `intent_adjudication.md` | 0 disagreements in the final run | 0 |

Everything else is deterministic Python: evidence parsing, identity resolution, activity
attribution, point-in-time state reconstruction, policy and planning.

## Per-model totals

| Model | Calls | Input tokens | Output tokens | Total tokens | Price (USD / 1M in, out) | Est. cost (USD) |
|---|---|---|---|---|---|---|
| gpt-4.1 (vision) | 11 | 24,001 | 4,663 | 28,664 | 2.00 / 8.00 | 0.0853 |
| gpt-4.1-mini (intent) | 398 | 267,849 | 15,396 | 283,245 | 0.40 / 1.60 | 0.1318 |
| **Overall** | **409** | **291,850** | **20,059** | **311,909** | — | **0.2171** |

## Per-request figures (518 evaluation requests)

| Metric | Value |
|---|---|
| Model calls per request | 0.79 |
| Average total tokens per request | 602.1 (563.4 input + 38.7 output) |
| Estimated cost per request | USD 0.00042 |
| Estimated cost for the full run | USD 0.22 |

The totals cover the whole run, including the 32 sample texts that are classified so they can compete
for activity attribution. Dividing by 518 is therefore slightly conservative.

## Change from the previous run

Moving the prompts into `prompts/` added the shared mission statement (`system_prompt.md`) to every
call and made the intent prompt more explicit about scope words, negation and untrusted text. Intent
input tokens rose from 107k to 268k and the run cost from USD 0.14 to USD 0.22. `output.csv` was
byte-identical before and after, and the sample and custom-case scores did not move. We kept the
longer prompts because they state the injection rule and the decision boundary explicitly, for
about USD 0.0002 more per request.

## Efficiency choices

* Deduplicating texts: 550 requests need only 398 classifications.
* Screenshots are extracted once per corpus, not once per case. A case reads the structured records.
* The small model handles the high-volume text task. The larger model is reserved for vision and the
  rare disagreement adjudication.
* `temperature=0`, JSON response format and a content-addressed cache keep reruns deterministic and
  free. `python code/evaluation/main.py --prune-cache` drops answers to prompt versions no longer in use.
* Prices are list prices configured in `code/ghost_audit/llm.py`. Override them with
  `LLM_PRICE_<MODEL>="in,out"`.
