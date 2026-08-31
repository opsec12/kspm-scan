"""Ties a scan source (list of WorkloadUnits) to the rule engine."""
from __future__ import annotations

from collections.abc import Iterable

from kspm.models import Finding, Severity, WorkloadUnit
from kspm.rules import get_enabled_rules


def run_rules(
    units: Iterable[WorkloadUnit], ignored_rule_ids: Iterable[str] = ()
) -> list[Finding]:
    rules = get_enabled_rules(ignored_rule_ids)
    findings: list[Finding] = []
    for unit in units:
        for rule in rules:
            findings.extend(rule.check(unit))
    findings.sort(key=lambda f: (f.severity.rank, f.workload.locator, f.rule_id))
    return findings


def compute_posture_score(findings: Iterable[Finding]) -> int:
    """A simple 0-100 score: start at 100, deduct per-finding penalties."""
    score = 100
    for finding in findings:
        score -= finding.severity.score_penalty
    return max(0, score)


def summarize_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts
