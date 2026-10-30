"""Build code.zip for submission, refusing to package anything that looks like a secret.

    python code/package.py            # -> code.zip at the repository root

The archive holds the contents of code/ plus the prompts/ folder (as prompts/). Run outputs,
caches of compiled Python, env files and temporary files are left out. The build stops if any file
matches a secret pattern or contains the configured API key, or if a required report is missing.
"""
from __future__ import annotations

import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))

from ghost_audit.guardrails import find_secrets  # noqa: E402
from ghost_audit.llm import load_env  # noqa: E402

REQUIRED = ["main.py", "README.md", "requirements.txt", "evaluation/evaluation_report.md",
            "evaluation/usage_report.md", "prompts/system_prompt.md"]
SKIP_DIRS = {"runs", "__pycache__", ".pytest_cache"}
SKIP_SUFFIXES = {".tmp", ".pyc", ".zip"}


def collect() -> dict[str, Path]:
    files = {}
    for base, prefix in ((HERE, ""), (REPO / "prompts", "prompts/")):
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(base)
            if not p.is_file() or SKIP_DIRS & set(rel.parts) or p.suffix in SKIP_SUFFIXES:
                continue
            if p.name.startswith(".env"):
                continue
            files[prefix + rel.as_posix()] = p
    return files


def check(files: dict[str, Path]) -> list[str]:
    problems = [f"required file missing: {r}" for r in REQUIRED if r not in files]
    for name, p in files.items():
        if "dataset/" in name or p.name in (".env", ".env.local"):
            problems.append(f"{name}: must not be packaged")
            continue
        text = p.read_bytes().decode("utf-8", errors="ignore")
        hits = find_secrets(text)
        if hits:
            problems.append(f"{name}: looks like it contains a secret ({', '.join(hits)})")
    return problems


def main():
    load_env(REPO)   # so the configured key itself is part of the scan
    files = collect()
    problems = check(files)
    if problems:
        print("PACKAGING STOPPED:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(1)
    out = REPO / "code.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, p in files.items():
            z.write(p, name)
    print(f"wrote {out} ({len(files)} files); secret scan clean; required reports present")


if __name__ == "__main__":
    main()
