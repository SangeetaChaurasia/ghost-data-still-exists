"""Case reasoning: identity -> relevant resources -> state at audit_at -> policy -> steps.

The engine is deterministic.  The only model-dependent inputs are the intent
label for ``request_text`` and the structured facts a vision model extracted
from screenshots (both cached on disk).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .activity import ActivityLog
from .evidence import EvidenceStore, Observation, SYSTEM_BY_KIND, kind_from_resource
from .identity import IdentityResolver, Identity
from .policy import (Policy, TREATMENT_STEPS, ACTIVITY_VERB_TREATMENT, FINDING_ORDER, REMEDIATION_ORDER,
                     VERIFICATION_ORDER, STATE)
from .util import parse_ts, norm_key

STATUS_TO_RESULT = {"COMPLETE": "SUCCESS", "NOT_STARTED": "FAILED", "PARTIALLY_COMPLETE": "PARTIAL"}
WORKER_VERBS = {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
                "CHECK_DATA_FLOW", "CHECK_RESTORE_ACCESS", "RETAIN_RECORD"}

# Activity windows (minutes relative to reported_at) learned from the public samples: the
# workflow submits the primary profile ~45-75 min before it reports, applies successful
# policy actions in the half hour before reporting and records failed / follow-up checks
# in the two hours after.
ACCOUNT_WINDOW = (-80.0, -40.0)
POLICY_WINDOWS = ((-35.0, -3.0), (30.0, 125.0))
NEAR_WINDOW = (-15.0, 15.0)   # hand-off style workflows that act right at reporting time


def case_number(cid: str) -> int:
    tail = cid.rsplit("_", 1)[-1]
    return int(tail) if tail.isdigit() else 10 ** 9


def minutes(a: str, b: str) -> float:
    return (parse_ts(a) - parse_ts(b)).total_seconds() / 60.0


@dataclass
class Case:
    case_id: str
    email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str
    is_deletion: bool = True
    user_ids: list = field(default_factory=list)
    identity: Identity | None = None
    flags: list = field(default_factory=list)   # guardrail notes surfaced in the run trace


@dataclass
class ResourceView:
    system_id: str
    resource_id: str
    kind: str
    reasons: set = field(default_factory=set)
    observations: list = field(default_factory=list)   # admissible, linked or not
    late_observations: list = field(default_factory=list)
    activities: list = field(default_factory=list)
    treatment: str | None = None
    compliant: bool | None = None
    evidence_id: str = ""
    state_note: str = ""


class Auditor:
    def __init__(self, store: EvidenceStore, acts: ActivityLog, idr: IdentityResolver, policy: Policy,
                 cases: list[Case], ablate: set | None = None):
        self.store, self.acts, self.idr, self.policy = store, acts, idr, policy
        # Optional component switches for the evaluation ablation study:
        # chain, coverage, tiebreak, scope, recreation
        self.ablate = set(ablate or ())
        self.cases = {c.case_id: c for c in cases}
        for c in cases:
            c.user_ids = idr.resolve_email(c.email)
            if c.user_ids:
                c.identity = idr.identity(c.user_ids[0])
                for extra in c.user_ids[1:]:
                    other = idr.identity(extra)
                    c.identity.emails |= other.emails
                if len(c.user_ids) > 1:
                    c.flags.append(f"request email maps to several users: {c.user_ids}")
            elif c.email.strip():
                c.identity = IdentityResolver.from_email(c.email)
                c.flags.append("request email matches no known user; searched evidence by email and hash only")
        self._build_key_owner_index()
        self._build_resource_owners()
        self._assign_activity_chains()

    # ------------------------------------------------------------------ ownership
    def _build_key_owner_index(self):
        self.key_owner: dict[str, set] = defaultdict(set)
        for uid in self.idr.current:
            ident = self.idr.identity(uid)
            for k in ident.keys():
                self.key_owner[k].add(uid)

    @staticmethod
    def link_keys(o: Observation) -> set:
        return o.keys if o.keys else o.lookup_keys

    def _build_resource_owners(self):
        """resource -> users whose identifiers appear on (or were used to find) it."""
        self.resource_owners: dict[str, set] = defaultdict(set)
        for o in self.store.obs:
            for k in self.link_keys(o):
                self.resource_owners[o.resource_id] |= self.key_owner.get(k, set())
        for l in self.acts.links:
            self.resource_owners[l["resource_id"]].add(l["user_id"])

    # ------------------------------------------------------------- activity chains
    def _case_files(self, c: Case) -> set:
        """Evidence files (admissible for the case) that carry the subject's identifiers."""
        files = set()
        for k in c.identity.keys():
            for o in self.store.by_key.get(k, []):
                if k in self.link_keys(o) and parse_ts(o.captured_at) <= parse_ts(c.audit_at):
                    files.add(o.evidence_id)
        return files

    def _admissible_obs(self, rid: str, c: Case) -> list:
        return [o for o in self.store.by_resource.get(rid, []) if parse_ts(o.captured_at) <= parse_ts(c.audit_at)]

    def _assign_activity_chains(self):
        """Attribute deletion-worker activity to requests.

        Workflow rows never name the subject, so attribution is a global assignment over
        every request in the participant data, scored by:
          * evidence ownership (identifiers on the record) - decisive either way;
          * timing relative to the request's reported_at (profile submission ~1h before,
            successful policy actions in the 30 min before, failures/checks after);
          * the reported outcome matching the request's reported_status;
          * consistency with the request's provisional evidence-only verdict (successful
            pre-report actions belong to deletions that really completed, post-report
            failures to ones that did not);
          * co-occurrence in the same evidence capture as the subject's other records.
        Each activity resource is given to the single best request; exact ties are left
        unassigned rather than guessed.
        """
        # Unresolved subjects have no user_id to own activity, so they never compete for it.
        deletion_cases = [c for c in self.cases.values() if c.is_deletion and c.user_ids]
        self.case_account: dict[str, tuple] = {}
        self.case_chain: dict[str, dict] = defaultdict(dict)
        self.chain_ties: dict[str, list] = {}
        # provisional verdict from identifier-linked evidence only
        self.provisional: dict[str, str] = {}
        self.case_files: dict[str, set] = {}
        for c in deletion_cases:
            views = self.relevant_resources(c, use_chain=False)
            bad = False
            for v in views.values():
                self.evaluate(c, v)
                bad |= v.compliant is False
            self.provisional[c.case_id] = "INCOMPLETE" if bad else "COMPLETE"
            self.case_files[c.case_id] = self._case_files(c)

        worker = [a for a in self.acts.rows if a.source_system == "deletion_worker" and a.event_type in WORKER_VERBS]

        def owner_score(rid, c):
            owners = self.resource_owners.get(rid, set())
            if not owners:
                return 0
            return 100 if owners & set(c.user_ids) else None

        acc_pairs, res_pairs = [], []
        for c in deletion_cases:
            prov = self.provisional[c.case_id]
            for a in worker:
                m = minutes(a.event_time, c.reported_at)
                if m < -95 or m > 130 or parse_ts(a.event_time) > parse_ts(c.audit_at):
                    continue
                own = owner_score(a.resource_id, c)
                if own is None:
                    continue
                files = {o.evidence_id for o in self._admissible_obs(a.resource_id, c)}
                co = 3 if files & self.case_files[c.case_id] else 0
                if a.target_system == "account_service" and a.event_type == "DELETE_RECORD":
                    if ACCOUNT_WINDOW[0] <= m <= ACCOUNT_WINDOW[1]:
                        base = 20
                    elif NEAR_WINDOW[0] <= m <= NEAR_WINDOW[1]:
                        base = 10
                    else:
                        continue
                    s = own + base + co
                    s += 10 if a.reported_result == STATUS_TO_RESULT.get(c.reported_status) else 0
                    if prov == "COMPLETE":
                        s += 5 if files else 0   # a verified-complete case must be able to prove absence
                    s -= abs(m + 58) / 100.0
                    acc_pairs.append((s, c.case_id, a))
                    continue
                pre = POLICY_WINDOWS[0][0] <= m <= POLICY_WINDOWS[0][1]
                post = POLICY_WINDOWS[1][0] <= m <= POLICY_WINDOWS[1][1]
                near = NEAR_WINDOW[0] <= m <= NEAR_WINDOW[1]
                if not (pre or post or near):
                    continue
                s = own + 10 + co
                if pre and a.reported_result == "SUCCESS":
                    s += 6 if prov == "COMPLETE" else -6
                if post:
                    s += 6 if prov == "INCOMPLETE" else -6
                res_pairs.append((s, c.case_id, a))

        # accounts: one per request, one request per account, best score first
        acc_pairs.sort(key=lambda t: (-t[0], t[1], t[2].activity_id))
        best_for_case: dict[str, float] = {}
        used = set()
        by_case = defaultdict(list)
        for s, cid, a in acc_pairs:
            by_case[cid].append((s, a))
        for s, cid, a in acc_pairs:
            if cid in self.case_account or a.resource_id in used:
                continue
            rivals = [x for x, aa in by_case[cid] if aa.resource_id not in used and aa.resource_id != a.resource_id]
            how = "evidence+activity" if s >= 100 else ("activity" if not rivals or s - max(rivals) >= 1 else
                                                         "activity-contended")
            self.case_account[cid] = (a, how)
            used.add(a.resource_id)
            best_for_case[cid] = s

        # other resources: each to its single best request
        per_res = defaultdict(list)
        for s, cid, a in res_pairs:
            per_res[a.resource_id].append((s, cid, a))
        tie_blocks = defaultdict(list)
        for rid, lst in per_res.items():
            agg = defaultdict(lambda: [float("-inf"), []])
            for s, cid, a in lst:
                agg[cid][0] = max(agg[cid][0], s)
                agg[cid][1].append(a)
            ranked = sorted(agg.items(), key=lambda kv: -kv[1][0])
            top = ranked[0][1][0]
            if top < 10:
                continue
            winners = sorted(cid for cid, (s, _) in ranked if s == top)
            if len(winners) == 1:
                self.case_chain[winners[0]][rid] = agg[winners[0]][1]
            else:
                tie_blocks[tuple(winners)].append((rid, agg))
        # Exact ties: requests reported at the same instant competing for indistinguishable
        # actions.  When a block is balanced (k requests, k actions of one verb) the
        # workflow processed them in request order, so pair them in order of action time
        # and case number (consistent with every tied pair in the public samples).
        # Unbalanced blocks keep the record on every tied request (<=2) rather than drop it.
        for winners, items in tie_blocks.items():
            verbs = {agg[winners[0]][1][0].event_type for _, agg in items}
            if len(items) == len(winners) and len(verbs) == 1 and "tiebreak" not in self.ablate:
                items = sorted(items, key=lambda it: min(a.event_time for a in it[1][winners[0]][1]))
                ordered = sorted(winners, key=lambda cid: case_number(cid))
                for (rid, agg), cid in zip(items, ordered):
                    self.case_chain[cid][rid] = agg[cid][1]
                    self.chain_ties[rid] = {"candidates": list(winners), "assigned": cid, "rule": "request-order"}
            elif len(winners) <= 2:
                for rid, agg in items:
                    for cid in winners:
                        self.case_chain[cid][rid] = agg[cid][1]
                    self.chain_ties[rid] = {"candidates": list(winners), "assigned": list(winners), "rule": "shared"}

    # ------------------------------------------------------------------ per case
    def relevant_resources(self, c: Case, use_chain: bool = True) -> dict[str, ResourceView]:
        A = c.audit_at
        keys = c.identity.keys()
        views: dict[str, ResourceView] = {}
        # If the same person filed an earlier request that was already audited, evidence
        # gathered up to that audit belongs to the earlier request's scope.
        floor = None if "scope" in self.ablate else self.scope_floor(c)

        def view(rid, system=None, kind=None):
            if rid not in views:
                k = kind or kind_from_resource(rid)
                views[rid] = ResourceView(system_id=system or SYSTEM_BY_KIND.get(k, ""), resource_id=rid, kind=k)
            return views[rid]

        # 1. evidence that carries one of the subject's identifiers
        for k in keys:
            for o in self.store.by_key.get(k, []):
                if k not in self.link_keys(o):
                    continue
                if parse_ts(o.observed_at) > parse_ts(A) and parse_ts(o.captured_at) > parse_ts(A):
                    continue
                if floor and parse_ts(o.observed_at) <= floor:
                    continue
                v = view(o.resource_id, o.system_id, o.kind)
                v.reasons.add(f"identifier:{o.evidence_id}")
        # 2. explicit catalog links
        for l in self.acts.links_for(keys):
            t = parse_ts(l["activity"].event_time)
            if t <= parse_ts(A) and not (floor and t <= floor):
                v = view(l["resource_id"], l["system_id"])
                v.reasons.add(f"catalog:{l['activity'].activity_id}")
                v.activities.append(l["activity"])
        # 3. the account the deletion workflow submitted for this request
        use_chain = use_chain and "chain" not in self.ablate
        if use_chain and c.case_id in self.case_account:
            a, how = self.case_account[c.case_id]
            if parse_ts(a.event_time) <= parse_ts(A):
                v = view(a.resource_id, "account_service", "USER_PROFILE")
                v.reasons.add(f"account:{how}:{a.activity_id}")
                v.activities.append(a)
        # 4. other resources the workflow touched for this request
        for rid, alist in (self.case_chain.get(c.case_id, {}) if use_chain else {}).items():
            alist = [a for a in alist if parse_ts(a.event_time) <= parse_ts(A)]
            if not alist:
                continue
            v = view(rid, alist[0].target_system)
            v.reasons.add("chain:" + ",".join(a.activity_id for a in alist))
            v.activities.extend(alist)
        # 5. processes that recreated one of the subject's records (sync connectors, restores)
        for rid in list(views):
            for rel in ([] if "recreation" in self.ablate else self.acts.relations_by_downstream.get(rid, [])):
                a = rel["activity"]
                if parse_ts(a.event_time) > parse_ts(A) or (floor and parse_ts(a.event_time) <= floor):
                    continue
                up = view(rel["upstream"], rel["system_id"])
                up.reasons.add(f"recreates:{rid}:{a.activity_id}")
                up.activities.append(a)
        # attach every observation of the resource (linked or not) for state reconstruction
        for rid, v in views.items():
            for o in self.store.by_resource.get(rid, []):
                if parse_ts(o.captured_at) <= parse_ts(A):
                    v.observations.append(o)
                elif parse_ts(o.observed_at) <= parse_ts(A):
                    v.late_observations.append(o)
            if v.kind == "UNKNOWN" and v.observations:
                v.kind = v.observations[0].kind
            # prefer the most specific kind observed (e.g. SUPPORT_ATTACHMENT over SUPPORT_MESSAGE)
            kinds = {o.kind for o in v.observations + v.late_observations}
            for specific in ("SUPPORT_ATTACHMENT", "SECONDARY_IDENTIFIER"):
                if specific in kinds:
                    v.kind = specific
            if not v.system_id and v.observations:
                v.system_id = v.observations[0].system_id
            if v.kind == "USER_PROFILE":
                if "coverage" not in self.ablate:
                    self._add_coverage_absence(c, v)
            if not v.observations:
                v.observations.extend(self._activity_state_claims(v, A))
        return views

    @staticmethod
    def _activity_state_claims(v: ResourceView, audit_at: str) -> list:
        """Last-resort state for processes with no captured evidence: activity rows that
        explicitly state a recreation path is live (a connector repopulated data, a restore
        ran, a status check found the flow still enabled / the archive still restorable)."""
        out = []
        for a in v.activities:
            if parse_ts(a.event_time) > parse_ts(audit_at):
                continue
            d = a.details.lower()
            attrs = None
            if v.kind == "DATA_FLOW" and ("repopulated" in d or "remains enabled" in d):
                attrs = {"enabled": True}
            elif v.kind == "BACKUP_ARCHIVE" and ("repopulated" in d or "can still be restored" in d):
                attrs = {"restore_allowed": True}
            if attrs:
                out.append(Observation(evidence_id=a.activity_id, captured_at=a.event_time, observed_at=a.event_time,
                                       system_id=v.system_id, resource_id=v.resource_id, kind=v.kind, present=True,
                                       attrs=attrs, source="activity-claim"))
        return out

    def _add_coverage_absence(self, c: Case, v: ResourceView):
        """An account-table capture that does not contain the account proves it absent at
        that time - but only captures that are complete directories, or that belong to the
        same capture as the subject's other records, are trusted for this."""
        A = parse_ts(c.audit_at)
        latest = max((parse_ts(o.observed_at) for o in v.observations), default=None)
        # a capture taken before the workflow even submitted the deletion proves nothing
        acts = [parse_ts(a.event_time) for a in v.activities if a.event_type == "DELETE_RECORD"]
        if acts:
            latest = max([latest] + acts) if latest else max(acts)
        related = self._case_files_cached(c)
        # any copy of the record in a capture (e.g. a lagging replica table) means present
        seen_in = {o.evidence_id for o in self.store.by_resource.get(v.resource_id, [])}
        best = None
        for cov in self.store.coverage:
            if cov["system"] != "account_service" or v.resource_id in cov["rids"] or cov["evidence_id"] in seen_in:
                continue
            t = parse_ts(cov["observed_at"])
            if parse_ts(cov["captured_at"]) > A or t > A:
                continue
            if latest is not None and t <= latest:
                continue
            if not (cov["directory"] or cov["evidence_id"] in related):
                continue
            rank = (cov["evidence_id"] in related, t)
            if best is None or rank > best[0]:
                best = (rank, cov)
        # A deleted-customer reference (tombstone) for the same subject, captured after the
        # submission, is itself proof that the primary profile no longer exists.
        uids = {norm_key(u) for u in c.user_ids}
        for o in self.store.obs:
            if o.kind != "ACCOUNT_TOMBSTONE" or o.attrs.get("account_status") != "DELETED":
                continue
            if not (o.keys & uids) or parse_ts(o.captured_at) > A or parse_ts(o.observed_at) > A:
                continue
            t = parse_ts(o.observed_at)
            if latest is not None and t <= latest:
                continue
            cov = dict(evidence_id=o.evidence_id, observed_at=o.observed_at)
            rank = (o.evidence_id in related, t)
            if best is None or rank > best[0]:
                best = (rank, cov)
        if best:
            cov = best[1]
            m = self.store.manifest[cov["evidence_id"]]
            v.observations.append(Observation(evidence_id=cov["evidence_id"], captured_at=m["captured_at"],
                                              observed_at=cov["observed_at"], system_id="account_service",
                                              resource_id=v.resource_id, kind="USER_PROFILE", present=False,
                                              source="coverage"))

    def _case_files_cached(self, c: Case) -> set:
        if not hasattr(self, "_cf_cache"):
            self._cf_cache = {}
        if c.case_id not in self._cf_cache:
            self._cf_cache[c.case_id] = self._case_files(c)
        return self._cf_cache[c.case_id]

    def scope_floor(self, c: Case):
        if not hasattr(self, "_by_user"):
            self._by_user = defaultdict(list)
            for x in self.cases.values():
                if x.is_deletion:
                    for u in x.user_ids:
                        self._by_user[u].append(x)
        floor = None
        for u in c.user_ids:
            for other in self._by_user.get(u, []):
                if other.case_id == c.case_id:
                    continue
                if parse_ts(other.audit_at) < parse_ts(c.requested_at):
                    t = parse_ts(other.audit_at)
                    floor = t if floor is None or t > floor else floor
        return floor

    # ------------------------------------------------------------------ state
    def evaluate(self, c: Case, v: ResourceView):
        """Decide the treatment the policy requires and whether the state at audit_at meets it."""
        verbs = [a.event_type for a in v.activities if a.event_type in ACTIVITY_VERB_TREATMENT]
        treatment = self.policy.treatment(v.kind)
        if v.kind in ("SUPPORT_MESSAGE",) and "DELETE_RECORD" in verbs:
            treatment = "DELETE"
        if v.kind == "ANALYTICS_PROFILE" and "DELETE_RECORD" in verbs:
            treatment = "DELETE"
        if treatment is None and verbs:
            treatment = ACTIVITY_VERB_TREATMENT[verbs[0]]
        if treatment is None:
            treatment = "DELETE"
        v.treatment = treatment

        obs = sorted(v.observations, key=lambda o: (o.observed_at, o.captured_at))
        latest = self._latest_state(obs)
        if latest is None:
            v.compliant = None
            v.state_note = "no admissible evidence"
            return v
        o = latest
        v.evidence_id = o.evidence_id
        if treatment == "DELETE":
            v.compliant = not o.present
        elif treatment in ("REDACT", "ANONYMIZE"):
            if not o.present:
                v.compliant = True   # gone entirely is at least as strong
            else:
                ident = o.attrs.get("identifiable")
                if ident is None:
                    ident = bool(o.pii)
                v.compliant = not ident
        elif treatment == "RETAIN":
            v.compliant = bool(o.present)
        elif treatment == "DISABLE_FLOW":
            en = o.attrs.get("enabled")
            v.compliant = (en is False) or (not o.present)
        elif treatment == "BLOCK_RESTORE":
            ra = o.attrs.get("restore_allowed")
            v.compliant = (ra is False) or (not o.present)
        v.state_note = o.short()
        return v

    @staticmethod
    def _latest_state(obs: list[Observation]) -> Observation | None:
        if not obs:
            return None
        last_t = max(o.observed_at for o in obs)
        # If several tables/replicas in the same capture disagree, any copy that still
        # holds data wins (replication drift keeps data alive).
        group = [o for o in obs if o.evidence_id == max(obs, key=lambda x: (x.observed_at, x.captured_at)).evidence_id
                 and o.observed_at == last_t] or [obs[-1]]
        worst = [o for o in group if o.present and (o.pii or o.attrs.get("identifiable") or o.attrs.get("enabled")
                                                       or o.attrs.get("restore_allowed"))]
        return worst[0] if worst else group[-1]

    # ------------------------------------------------------------------ steps
    def audit(self, c: Case) -> tuple[str, list[dict], dict]:
        if not c.is_deletion:
            return "NOT_APPLICABLE", [], {"reason": "request does not authorize deletion"}
        if not c.identity:
            self._flag(c, "request has no email; nothing could be searched")
            return "COMPLETE", [], {"reason": "no identity resolved"}
        views = self.relevant_resources(c)
        for v in views.values():
            self.evaluate(c, v)
        findings, remediation, verification = [], [], []
        for v in views.values():
            if v.treatment is None:
                continue
            f_op, r_op, v_op = TREATMENT_STEPS[v.treatment]
            if v.compliant is False:
                findings.append((f_op, v))
                remediation.append((r_op, v))
            if v.compliant is None and v.treatment == "RETAIN":
                pass
            verification.append((v_op, v))
        if not findings:
            # Fail closed: a case is only COMPLETE when every record's state is proven. A record that
            # needs action but has no admissible state evidence is reported at its last known state
            # (it existed), citing the activity that showed it.
            for v in views.values():
                if v.compliant is not None or v.treatment in (None, "RETAIN"):
                    continue
                known = [a for a in v.activities if parse_ts(a.event_time) <= parse_ts(c.audit_at)]
                if not known:
                    self._flag(c, f"{v.resource_id}: state unknown and no evidence to cite")
                    continue
                v.compliant = False
                v.evidence_id = max(known, key=lambda a: (parse_ts(a.event_time), a.activity_id)).activity_id
                f_op, r_op, _ = TREATMENT_STEPS[v.treatment]
                findings.append((f_op, v))
                remediation.append((r_op, v))
                self._flag(c, f"{v.resource_id}: no evidence of its state at audit_at; reported at last known "
                              f"state ({v.evidence_id})")
        status = "INCOMPLETE" if findings else "COMPLETE"
        if status == "COMPLETE" and not verification:
            self._flag(c, "no relevant record found: COMPLETE has nothing to verify")

        def key(order):
            return lambda t: (order.index(t[0]), t[1].system_id, t[1].resource_id)

        steps = []
        if status == "COMPLETE":
            for op, v in sorted(verification, key=key(VERIFICATION_ORDER)):
                ev = v.evidence_id or (v.activities[0].activity_id if v.activities else "")
                steps.append(self._step(op, v, ev))
        else:
            for op, v in sorted(findings, key=key(FINDING_ORDER)):
                steps.append(self._step(op, v, v.evidence_id))
            for op, v in sorted(remediation, key=key(REMEDIATION_ORDER)):
                steps.append(self._step(op, v, ""))
            for op, v in sorted(verification, key=key(VERIFICATION_ORDER)):
                steps.append(self._step(op, v, ""))
        for i, s in enumerate(steps, 1):
            s["step_no"] = i
        trace = {rid: dict(kind=v.kind, treatment=v.treatment, compliant=v.compliant, reasons=sorted(v.reasons),
                           evidence=v.evidence_id, note=v.state_note) for rid, v in views.items()}
        return status, steps, trace

    @staticmethod
    def _flag(c: Case, note: str):
        if note not in c.flags:
            c.flags.append(note)

    @staticmethod
    def _step(op, v, evidence_id):
        phase = "FINDING" if op.startswith("REPORT") else ("VERIFICATION" if op.startswith("VERIFY") else "REMEDIATION")
        return {"step_no": 0, "phase": phase, "system_id": v.system_id, "resource_id": v.resource_id,
                "operation": op, "state": STATE[op], "evidence_id": evidence_id}
