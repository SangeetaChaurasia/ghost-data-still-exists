"""Text extraction for PDF business documents (invoices, journals, registers...).

PDFs in the corpus carry a text layer, so pypdf is enough; the extracted text is
turned into observations with light regex grounding on resource IDs and
identifiers.  Nothing here assumes which case a document belongs to.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

RID_RE = re.compile(r"\b(account|search|analytics|support|export|data_flow|backup|audit_record|legal_hold|tombstone|"
                    r"marketing|object)_\d+\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+\d[\d ()-]{6,}\d")
USER_RE = re.compile(r"\buser_\d+\b")
DATE_RE = re.compile(r"(\d{1,2}) (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (\d{4})(?: (\d{2}) (\d{2}))?")


def pdf_text(path: Path) -> str:
    import logging
    from pypdf import PdfReader
    logging.getLogger("pypdf").setLevel(logging.ERROR)   # damage is reported as an evidence warning instead
    return "\n".join((p.extract_text() or "") for p in PdfReader(str(path)).pages)


def _date(m) -> str | None:
    if not m:
        return None
    d, mon, y, hh, mm = m.groups()
    dt = datetime.strptime(f"{d} {mon} {y} {hh or '00'}:{mm or '00'}", "%d %b %Y %H:%M")
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def pdf_observations(path: Path, meta: dict, aliases: dict | None = None) -> list[dict]:
    text = pdf_text(path)
    rids = set(m.group(0) for m in RID_RE.finditer(text))
    systems = {}
    low_text = text.lower()
    for alias, (rid, system) in (aliases or {}).items():
        if alias == rid or USER_RE.fullmatch(alias) or len(alias) < 6:
            continue
        if re.search(r"(?<![\w-])" + re.escape(alias) + r"(?![\w-])", low_text):
            rids.add(rid)
            systems[rid] = system
    rids = sorted(rids)
    emails = sorted(set(EMAIL_RE.findall(text)))
    phones = sorted(set(p.strip() for p in PHONE_RE.findall(text)))
    users = sorted(set(USER_RE.findall(text)))
    lower = text.lower()
    out = []
    retain = re.search(r"retain(?:ed)? until\s+(\d{1,2} \w{3} \d{4}(?: \d{2} \d{2})?)", text, re.I)
    retain_until = _date(DATE_RE.search(retain.group(1))) if retain else None
    # A register listing many subjects does not tie any one resource to all of them.
    single_subject = len(users) <= 1 and len(emails) <= 1
    if not single_subject:
        users, emails, phones = [], [], []
    for rid in rids:
        rec = {}
        if emails:
            rec["email"] = emails[0]
        if phones:
            rec["phone"] = phones[0]
        attrs = {"document_text": text[:4000]}
        kind = None
        if rid.startswith("support_"):
            # A customer-uploaded document stored with a support case is an attachment.
            kind = "SUPPORT_ATTACHMENT" if ("attachment" in lower or "uploader" in lower) else "SUPPORT_MESSAGE"
        if retain_until:
            attrs["retention_until"] = retain_until
        if "legal hold" in lower or "legal_hold" in lower:
            attrs["legal_hold"] = True
        out.append({"resource_id": rid, "kind": kind, "record": rec, "keys": users + emails, "attrs": attrs,
                    "observed_at": meta["captured_at"], "present": True, "system_id": systems.get(rid)})
    return out
