"""Identity resolution: current snapshot + audit history -> every identifier a
subject has ever had (as of a point in time)."""
from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from .guardrails import timestamp_ok
from .util import norm_key, sha256, parse_ts


@dataclass
class Identity:
    user_id: str
    name: str
    emails: set = field(default_factory=set)
    phones: set = field(default_factory=set)
    hashes: set = field(default_factory=set)
    names: set = field(default_factory=set)
    history: list = field(default_factory=list)   # audit rows used

    def keys(self) -> set:
        ks = {norm_key(self.user_id)} if self.user_id else set()
        for group in (self.emails, self.phones, self.hashes):
            ks |= {norm_key(v) for v in group if v}
        return ks

    def strong_keys(self) -> set:
        """Keys that identify the subject on their own (names are too ambiguous)."""
        return self.keys()


class IdentityResolver:
    def __init__(self, dataset_dir: Path):
        d = Path(dataset_dir)
        with open(d / "user_identities.csv", encoding="utf-8-sig") as fh:
            self.current = {r["user_id"]: r for r in csv.DictReader(fh)}
        with open(d / "user_audit_log.csv", encoding="utf-8-sig") as fh:
            self.audit = list(csv.DictReader(fh))
        self.audit_by_user = defaultdict(list)
        for a in self.audit:
            self.audit_by_user[a["user_id"]].append(a)
        self.email_index: dict[str, set] = defaultdict(set)
        for uid, r in self.current.items():
            self.email_index[r["email"].lower()].add(uid)
        for a in self.audit:
            if a["field_name"] == "email":
                self.email_index[a["old_value"].lower()].add(a["user_id"])
                self.email_index[a["new_value"].lower()].add(a["user_id"])

    @staticmethod
    def from_email(email: str) -> Identity:
        """Provisional identity for a request email that matches no known user: the address and
        its hash are still searched for in the evidence."""
        e = email.strip()
        return Identity(user_id="", name="", emails={e}, hashes={sha256(e.lower())})

    def resolve_email(self, email: str) -> list[str]:
        return sorted(self.email_index.get(email.strip().lower(), set()))

    def identity(self, user_id: str, as_of: str | None = None) -> Identity:
        r = self.current.get(user_id)
        if r is None:
            # Known only from the audit history (no current snapshot row): use what history holds.
            ident = Identity(user_id=user_id, name="")
        else:
            ident = Identity(user_id=user_id, name=r["name"])
            ident.emails.add(r["email"])
            ident.phones.add(r["phone"])
            ident.hashes.add(r["email_hash"])
            ident.names.add(r["name"])
        for a in self.audit_by_user.get(user_id, []):
            # Historical values remain valid identifiers regardless of when they changed;
            # only changes recorded after the cut-off are unknown at audit time.
            if not timestamp_ok(a["event_time"]) or (as_of and parse_ts(a["event_time"]) > parse_ts(as_of)):
                continue
            ident.history.append(a)
            f = a["field_name"]
            for v in (a["old_value"], a["new_value"]):
                if f == "email":
                    ident.emails.add(v)
                elif f == "phone":
                    ident.phones.add(v)
                elif f == "email_hash":
                    ident.hashes.add(v)
                elif f in ("name", "full_name"):
                    ident.names.add(v)
        for group in (ident.emails, ident.phones, ident.hashes):
            group.discard("")
        ident.hashes |= {sha256(e.strip().lower()) for e in ident.emails}
        return ident
