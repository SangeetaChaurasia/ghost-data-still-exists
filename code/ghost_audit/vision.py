"""Screenshot understanding with a vision LLM.

Each internal-tool screenshot is converted once into structured JSON records
(resource ids, aliases, identifiers, state) and cached in
``code/cache/vision_extractions.json``.  The evidence store then treats those
records exactly like rows from any other evidence file.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import prompts
from .guardrails import validate_vision_response
from .llm import LLMClient


class VisionExtractor:
    def __init__(self, llm: LLMClient, dataset_dir: Path, cache_path: Path):
        self.llm, self.dataset_dir, self.cache_path = llm, Path(dataset_dir), Path(cache_path)

    def extract_all(self) -> dict:
        cache = json.loads(self.cache_path.read_text(encoding="utf-8")) if self.cache_path.exists() else {}
        images = sorted((self.dataset_dir / "evidence" / "images").glob("*.png"))
        system = prompts.system(prompts.VISION)
        changed = False
        for img in images:
            resp = self.llm.json_completion(system, prompts.render(prompts.VISION_USER, file_name=img.name),
                                            image_path=img, purpose="vision")
            if resp is None:
                continue
            norm = self._normalise(resp)
            norm["image_sha256"] = hashlib.sha256(img.read_bytes()).hexdigest()
            if cache.get(img.name) != norm:
                cache[img.name] = norm
                changed = True
        if changed:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(cache, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        # The structured cache is re-validated on every load: a hand-edited or stale entry must
        # meet the same schema as a fresh model answer.
        self.issues = {}
        checked = {}
        current = {img.name: hashlib.sha256(img.read_bytes()).hexdigest() for img in images}
        for name, entry in cache.items():
            if name in current and entry.get("image_sha256") != current[name]:
                # The screenshot changed since it was read: its old facts must not be used.
                self.issues[name] = ["image differs from the one extracted; cached facts ignored"]
                continue
            norm, issues = validate_vision_response(entry)
            checked[name] = norm
            if issues:
                self.issues[name] = issues
        return checked

    @staticmethod
    def _normalise(resp: dict) -> dict:
        norm, _ = validate_vision_response(resp)
        return norm
