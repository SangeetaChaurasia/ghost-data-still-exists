# Prompts

Every prompt the agent sends to a model lives in this folder. The code loads them at run time
through `code/ghost_audit/prompts.py`, so editing a file here changes the agent's behaviour with no
code change.

## How prompts are put together

Each model call gets a **system message** and a **user message**:

```
system = system_prompt.md  +  <task prompt>  [+ addendum]
user   = <user template> with the placeholders filled in
```

`system_prompt.md` is the shared mission statement. Every task prompt starts from it, so each model
knows what the audit is for and what a mistake costs.

| Stage | System message | User message | Model | When it runs |
|---|---|---|---|---|
| Intent classification | `system_prompt.md` + `intent_classification.md` | `intent_user.md` | `gpt-4.1-mini` (`OPENAI_MODEL`) | once per distinct request text |
| Intent adjudication | `system_prompt.md` + `intent_classification.md` + `intent_adjudication.md` | `intent_user.md` | `gpt-4.1` (`OPENAI_VISION_MODEL`) | only when the model and the keyword rules disagree |
| Screenshot extraction | `system_prompt.md` + `vision_extraction.md` | `vision_user.md` + the image | `gpt-4.1` (`OPENAI_VISION_MODEL`) | once per screenshot in the corpus |

Placeholders: `{request_text}` (sanitised request text) and `{file_name}` (screenshot file name).

## Why the other stages have no prompt

Identity resolution, evidence linking, point-in-time state, policy and remediation planning are
deterministic code. They must be reproducible, cite exact evidence ids and follow the fixed
operation order, which rules do more reliably than a model. The models only handle the two inputs
that need language or vision understanding: free-text requests and screenshots.

## Guardrails around these prompts

- Request text is wrapped in `<request>` tags and the task prompt says to treat it as data, never as
  instructions. Control characters are stripped and the length is capped before it is sent.
- Every model answer is schema-checked (`code/ghost_audit/guardrails.py`). A malformed intent answer
  falls back to the keyword rules, and malformed screenshot records are dropped.
- Answers are cached by a hash of model + full prompt + image, so changing a prompt file
  automatically invalidates the old answers. The usage file records a fingerprint of each prompt.
- A missing or empty prompt file stops the run with an error instead of silently sending an empty
  prompt.

## Location

The loader looks in `GHOST_PROMPTS_DIR` if set, then `code/prompts/` (the layout inside `code.zip`),
then this `prompts/` folder at the repository root.
