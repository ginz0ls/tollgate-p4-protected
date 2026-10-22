"""I due gruppi di `attenzione` (spec 9.2, decisione 7): ogni voce è «da leggere» (cambia cosa
garantisce la PR) o «informativa». `tollgate/attention` è rosso solo con una voce «da leggere»."""
from __future__ import annotations

READ = "read"
INFO = "info"

GROUPS: dict[str, str] = {
    **dict.fromkeys((
        "waiver_test", "waiver_ci", "waiver_threshold", "waiver_command", "waiver_pattern",
        "waiver_scope_over_two", "level_cap", "review_unverified", "audit_suspended",
        "audit_off", "components_off", "findings_overridden", "unverified_tests",
        "manual_must_have", "sentinel_open", "off_periods", "plan_changed", "approval_stale",
        "no_tests_counted", "not_tg_branch", "tollgate_config", "ci_waived_workflow",
        "base_ids_from_run"), READ),
    **dict.fromkeys((
        "waiver_scope", "allow_no_tests", "task_over_warn", "task_over_max", "skills_absent",
        "lockfile_without_manifest", "no_issue", "base_failing_on_head",
        "existing_workflow_rules"), INFO),
}


def group(key: str) -> str:
    """`READ` o `INFO`; `KeyError` per una chiave sconosciuta (ogni voce ha un gruppo)."""
    return GROUPS[key]
