"""deletion_rules.csv -> per-record treatment, and the canonical step tables."""
from __future__ import annotations

import csv
from pathlib import Path

# Operation order inside each phase (problem statement table order).
FINDING_ORDER = ["REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK"]
REMEDIATION_ORDER = ["DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"]
VERIFICATION_ORDER = ["VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
                      "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED"]
STATE = {
    "REPORT_REMAINING_RECORD": "PRESENT", "REPORT_EXPOSED_PII": "PRESENT", "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE", "DISABLE_DATA_FLOW": "DISABLED", "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT", "REDACT_RECORD": "REDACTED", "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT", "VERIFY_RECORD_PRESENT": "PRESENT", "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

# Treatment -> (finding when violated, remediation, verification)
TREATMENT_STEPS = {
    "DELETE": ("REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
    "REDACT": ("REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
    "ANONYMIZE": ("REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
    "RETAIN": (None, None, "VERIFY_RECORD_PRESENT"),
    "DISABLE_FLOW": ("REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
    "BLOCK_RESTORE": ("REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
}

# Evidence kinds that are not data categories in the rules but processes.
PROCESS_KINDS = {"DATA_FLOW": "DISABLE_FLOW", "BACKUP_ARCHIVE": "BLOCK_RESTORE"}

# Map the verb a deletion workflow attempted onto the treatment it implies.
ACTIVITY_VERB_TREATMENT = {"DELETE_RECORD": "DELETE", "REDACT_RECORD": "REDACT", "ANONYMIZE_RECORD": "ANONYMIZE",
                           "DISABLE_DATA_FLOW": "DISABLE_FLOW", "CHECK_DATA_FLOW": "DISABLE_FLOW",
                           "BLOCK_RESTORE": "BLOCK_RESTORE", "CHECK_RESTORE_ACCESS": "BLOCK_RESTORE",
                           "RETAIN_RECORD": "RETAIN"}


RULE_ACTIONS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}


class Policy:
    def __init__(self, dataset_dir: Path):
        from .guardrails import GuardrailError
        with open(Path(dataset_dir) / "deletion_rules.csv", encoding="utf-8-sig") as fh:
            self.rules = {r["data_category"]: r for r in csv.DictReader(fh)}
        bad = {k: r.get("required_action") for k, r in self.rules.items() if r.get("required_action") not in RULE_ACTIONS}
        if bad or not self.rules:
            raise GuardrailError(f"deletion_rules.csv has unknown or missing actions: {bad or 'no rules'}")

    def treatment(self, kind: str) -> str | None:
        if kind in PROCESS_KINDS:
            return PROCESS_KINDS[kind]
        rule = self.rules.get(kind)
        if not rule:
            return None
        return rule["required_action"]

    def rule_id(self, kind: str) -> str | None:
        r = self.rules.get(kind)
        return r["rule_id"] if r else None
