"""Loads the model prompts from the prompts/ folder (see prompts/README.md).

system message = system_prompt.md + task prompt (+ addendum); user message = filled-in template.
"""
from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from pathlib import Path

from .guardrails import GuardrailError

CODE = Path(__file__).resolve().parents[1]
REPO = CODE.parent

SYSTEM = "system_prompt"
INTENT = "intent_classification"
INTENT_ADJUDICATION = "intent_adjudication"
INTENT_USER = "intent_user"
VISION = "vision_extraction"
VISION_USER = "vision_user"
ALL = (SYSTEM, INTENT, INTENT_ADJUDICATION, INTENT_USER, VISION, VISION_USER)


def prompts_dir() -> Path:
    env = os.environ.get("GHOST_PROMPTS_DIR")
    candidates = [Path(env)] if env else [CODE / "prompts", REPO / "prompts"]
    for d in candidates:
        if (d / f"{SYSTEM}.md").exists():
            return d
    raise GuardrailError(f"prompt folder not found (looked in {[str(c) for c in candidates]})")


@lru_cache(maxsize=None)
def load(name: str) -> str:
    path = prompts_dir() / f"{name}.md"
    if not path.exists():
        raise GuardrailError(f"missing prompt file: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise GuardrailError(f"empty prompt file: {path}")
    return text


def system(*parts: str) -> str:
    """The shared mission statement followed by the task prompt(s)."""
    return "\n\n".join(load(p) for p in (SYSTEM,) + parts)


def render(name: str, **values: str) -> str:
    """Fill ``{placeholder}`` slots. Plain replacement, so braces in values or JSON stay intact."""
    text = load(name)
    for k, v in values.items():
        slot = "{" + k + "}"
        if slot not in text:
            raise GuardrailError(f"prompt {name} has no placeholder {slot}")
        text = text.replace(slot, v)
    return text


def fingerprints() -> dict:
    """Short content hashes, recorded with each run so results can be tied to prompt versions."""
    return {n: hashlib.sha256(load(n).encode("utf-8")).hexdigest()[:12] for n in ALL}
