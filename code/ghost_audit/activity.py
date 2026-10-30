"""system_activity.csv loader + helpers.  Activity rows are *claims*: they tell
us which resources a workflow touched (useful for linking) but a reported
SUCCESS never proves the resulting state."""
from __future__ import annotations

import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .guardrails import timestamp_ok
from .util import norm_key, parse_ts

LINK_RE = re.compile(r"linked (\S+) \(([^)]*)\) to (\S+?) and (user_\d+)")
LINK_ONLY_RE = re.compile(r"confirmed (\S+) \(([^)]*)\) belongs only to (\S+?) and (user_\d+)")
REPOPULATED_RE = re.compile(r"repopulated downstream resource (\w+_\d+)")


@dataclass
class Activity:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


class ActivityLog:
    def __init__(self, dataset_dir: Path):
        with open(Path(dataset_dir) / "system_activity.csv", encoding="utf-8-sig") as fh:
            raw = [Activity(**{k: (r.get(k) or "") for k in Activity.__dataclass_fields__})
                   for r in csv.DictReader(fh)]
        self.rows = [a for a in raw if timestamp_ok(a.event_time)]
        self.skipped = [f"{a.activity_id}: unreadable event_time; row ignored" for a in raw
                        if not timestamp_ok(a.event_time)]
        self.rows.sort(key=lambda a: (parse_ts(a.event_time), a.activity_id))
        self.by_resource = defaultdict(list)
        for a in self.rows:
            self.by_resource[a.resource_id].append(a)
        # recreation edges: an active connector / restore job repopulated a downstream record
        self.relations = []
        for a in self.rows:
            m = REPOPULATED_RE.search(a.details)
            if m and m.group(1) != a.resource_id:
                self.relations.append(dict(upstream=a.resource_id, downstream=m.group(1), activity=a,
                                           system_id=a.source_system))
        self.relations_by_downstream = defaultdict(list)
        self.relations_by_upstream = defaultdict(list)
        for r in self.relations:
            self.relations_by_downstream[r["downstream"]].append(r)
            self.relations_by_upstream[r["upstream"]].append(r)
        # explicit catalog links: resource -> (alias, email, user)
        self.links = []
        for a in self.rows:
            if a.event_type == "LINK_RESOURCE_IDENTITY":
                m = LINK_RE.search(a.details) or LINK_ONLY_RE.search(a.details)
                if m:
                    rid, alias, email, uid = m.groups()
                    self.links.append(dict(activity=a, resource_id=rid, alias=alias, email=email.rstrip(".;"),
                                           user_id=uid, system_id=a.target_system,
                                           exclusive="belongs only" in a.details))

    def alias_map(self) -> dict:
        out = {}
        for l in self.links:
            out[l["alias"].strip().lower()] = (l["resource_id"], l["system_id"])
            out[l["resource_id"].lower()] = (l["resource_id"], l["system_id"])
        return out

    def links_for(self, keys: set) -> list[dict]:
        return [l for l in self.links if norm_key(l["email"]) in keys or norm_key(l["user_id"]) in keys]
