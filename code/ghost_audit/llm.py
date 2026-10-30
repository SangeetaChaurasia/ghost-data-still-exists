"""Thin OpenAI wrapper with a content-addressed disk cache and token accounting.

* Keys are read from the environment (``OPENAI_API_KEY``), optionally loaded
  from an uncommitted ``.env.local`` / ``.env`` at the repository root.
* Every response is cached by sha256(model, prompt, image bytes) so reruns are
  deterministic and free; cached entries keep their original token usage so the
  usage report can still describe the full-dataset run.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from collections import defaultdict
from pathlib import Path

# USD per 1M tokens (input, output).  Override with LLM_PRICE_<MODEL>="in,out".
DEFAULT_PRICES = {
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-5": (1.25, 10.00),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5-nano": (0.05, 0.40),
}


# Errors that retrying cannot fix (bad key, no access, unknown model, invalid request).
FATAL_ERRORS = {"AuthenticationError", "PermissionDeniedError", "NotFoundError", "BadRequestError"}
BREAKER_LIMIT = 3      # consecutive failed calls before the API is no longer tried in this run
RETRY_DELAYS = (1, 2, 4)


def load_env(repo_root: Path):
    for name in (".env.local", ".env"):
        p = repo_root / name
        if not p.exists():
            continue
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if v and k not in os.environ:
                os.environ[k] = v


def price_for(model: str) -> tuple[float, float]:
    env = os.environ.get("LLM_PRICE_" + model.upper().replace("-", "_").replace(".", "_"))
    if env:
        a, b = env.split(",")
        return float(a), float(b)
    for name in sorted(DEFAULT_PRICES, key=len, reverse=True):
        if model.startswith(name):
            return DEFAULT_PRICES[name]
    return (0.0, 0.0)


class LLMClient:
    def __init__(self, cache_path: Path, text_model: str | None = None, vision_model: str | None = None,
                 offline: bool = False):
        self.cache_path = Path(cache_path)
        self.cache = json.loads(self.cache_path.read_text(encoding="utf-8")) if self.cache_path.exists() else {}
        self.text_model = text_model or os.environ.get("OPENAI_MODEL", "gpt-4.1-mini")
        self.vision_model = vision_model or os.environ.get("OPENAI_VISION_MODEL", "gpt-4.1")
        self.offline = offline
        self._client = None
        self._lock = threading.Lock()
        self.used: set[str] = set()   # cache keys touched in this run (for pruning stale prompts)
        self.failures: list[str] = []   # redacted error summaries
        self._consecutive_failures = 0
        self.breaker_open = False
        self.usage = defaultdict(lambda: {"calls": 0, "cached_calls": 0, "input_tokens": 0, "output_tokens": 0,
                                          "purposes": defaultdict(int)})
        key = os.environ.get("OPENAI_API_KEY", "").strip()
        if key and not offline:
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=key, base_url=os.environ.get("OPENAI_BASE_URL") or None,
                                      max_retries=1, timeout=float(os.environ.get("OPENAI_TIMEOUT", "60")))
            except Exception:
                self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None or bool(self.cache)

    def _key(self, model, system, user, image_b64=None):
        h = hashlib.sha256()
        for part in (model, system, user, image_b64 or ""):
            h.update(part.encode("utf-8"))
            h.update(b"\x00")
        return h.hexdigest()

    def _record(self, model, usage, purpose, cached):
        u = self.usage[model]
        u["calls"] += 1
        u["cached_calls"] += int(cached)
        u["input_tokens"] += int(usage.get("input_tokens", 0))
        u["output_tokens"] += int(usage.get("output_tokens", 0))
        u["purposes"][purpose] += 1

    def json_completion(self, system: str, user: str, image_path: Path | None = None, purpose: str = "text",
                        model: str | None = None) -> dict | None:
        image_b64 = None
        if image_path is not None:
            image_b64 = base64.b64encode(Path(image_path).read_bytes()).decode("ascii")
            model = model or self.vision_model
        model = model or self.text_model
        key = self._key(model, system, user, image_b64)
        with self._lock:
            hit = self.cache.get(key)
            self.used.add(key)
        if hit is not None:
            self._record(model, hit.get("usage", {}), purpose, cached=True)
            return hit["response"]
        if self._client is None or self.breaker_open:
            return None
        content = [{"type": "text", "text": user}]
        if image_b64:
            mime = "image/png" if str(image_path).lower().endswith(".png") else "image/jpeg"
            content.append({"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image_b64}",
                                                                "detail": "high"}})
        messages = [{"role": "system", "content": system}, {"role": "user", "content": content}]
        last_err = None
        for attempt, delay in enumerate(RETRY_DELAYS):
            if self.breaker_open:
                break
            try:
                kwargs = dict(model=model, messages=messages, response_format={"type": "json_object"})
                if not model.startswith("gpt-5") and not model.startswith("o"):
                    kwargs["temperature"] = 0
                resp = self._client.chat.completions.create(**kwargs)
                text = resp.choices[0].message.content or "{}"
                parsed = json.loads(text)
                usage = {"input_tokens": getattr(resp.usage, "prompt_tokens", 0),
                         "output_tokens": getattr(resp.usage, "completion_tokens", 0)}
                with self._lock:
                    self.cache[key] = {"model": model, "purpose": purpose, "usage": usage, "response": parsed,
                                       "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
                self._record(model, usage, purpose, cached=False)
                with self._lock:
                    self._consecutive_failures = 0
                return parsed
            except Exception as exc:
                last_err = exc
                if type(exc).__name__ in FATAL_ERRORS:
                    break
                time.sleep(delay)
        self._fail(last_err)
        return None

    def _fail(self, err):
        from .guardrails import redact
        msg = redact(f"{type(err).__name__}: {err}")[:300]
        with self._lock:
            self.failures.append(msg)
            self._consecutive_failures += 1
            trip = not self.breaker_open and (type(err).__name__ in FATAL_ERRORS
                                              or self._consecutive_failures >= BREAKER_LIMIT)
            if trip:
                self.breaker_open = True
        if trip:
            print(f"[llm] API disabled for the rest of this run after: {msg}")

    def save(self, prune: bool = False):
        """Write the cache. ``prune`` keeps only entries used in this run, dropping answers to
        prompts that no longer exist (any prompt edit changes every key)."""
        if prune:
            self.cache = {k: v for k, v in self.cache.items() if k in self.used}
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache, indent=1, sort_keys=True, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.cache_path)

    def usage_summary(self) -> dict:
        out = {}
        for model, u in self.usage.items():
            pin, pout = price_for(model)
            cost = u["input_tokens"] / 1e6 * pin + u["output_tokens"] / 1e6 * pout
            out[model] = {**{k: v for k, v in u.items() if k != "purposes"}, "purposes": dict(u["purposes"]),
                          "price_in_per_mtok": pin, "price_out_per_mtok": pout, "estimated_cost_usd": cost}
        return out
