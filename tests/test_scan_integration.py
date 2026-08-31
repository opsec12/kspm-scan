"""End-to-end tests: load the fixture manifests and run the full rule set
against them, the same way the CLI does."""
from __future__ import annotations

from pathlib import Path

from kspm.manifest_loader import load_workloads_from_path
from kspm.rules import ALL_RULES
from kspm.scanner import compute_posture_score, run_rules

FIXTURES = Path(__file__).parent / "fixtures"


def test_loader_extracts_pod_and_deployment():
    units = load_workloads_from_path(FIXTURES)
    kinds = {u.kind for u in units}
    assert kinds == {"Pod", "Deployment"}
    assert len(units) == 2


def test_insecure_pod_trips_every_rule_exactly_once():
    units = load_workloads_from_path(FIXTURES / "insecure_pod.yaml")
    findings = run_rules(units)
    rule_ids_hit = {f.rule_id for f in findings}
    assert rule_ids_hit == {rule.id for rule in ALL_RULES}
    assert len(findings) == len(ALL_RULES)


def test_insecure_pod_score_is_low():
    units = load_workloads_from_path(FIXTURES / "insecure_pod.yaml")
    findings = run_rules(units)
    score = compute_posture_score(findings)
    assert score < 50


def test_hardened_deployment_is_clean():
    units = load_workloads_from_path(FIXTURES / "hardened_deployment.yaml")
    findings = run_rules(units)
    assert findings == []
    assert compute_posture_score(findings) == 100


def test_ignore_rule_suppresses_finding():
    units = load_workloads_from_path(FIXTURES / "insecure_pod.yaml")
    findings = run_rules(units, ignored_rule_ids=["KSPM001"])
    assert all(f.rule_id != "KSPM001" for f in findings)
    assert len(findings) == len(ALL_RULES) - 1
