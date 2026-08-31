"""Unit tests: each workload rule against a minimal spec that should trip
it, and a minimal spec that should not."""
from __future__ import annotations

from kspm.models import WorkloadUnit
from kspm.rules.workload import (
    DangerousCapabilitiesRule,
    HostNamespaceRule,
    HostPathVolumeRule,
    HostPortRule,
    MissingResourceLimitsRule,
    MutableImageTagRule,
    PrivilegedContainerRule,
    PrivilegeEscalationRule,
    RunAsRootRule,
    ServiceAccountTokenAutomountRule,
    WritableRootFilesystemRule,
)


def _unit(pod_spec: dict) -> WorkloadUnit:
    return WorkloadUnit(
        kind="Pod", name="test", namespace="default", pod_spec=pod_spec, source="test"
    )


def test_privileged_container_flagged():
    unit = _unit({"containers": [{"name": "c", "securityContext": {"privileged": True}}]})
    findings = list(PrivilegedContainerRule().check(unit))
    assert len(findings) == 1
    assert findings[0].rule_id == "KSPM001"


def test_non_privileged_container_clean():
    unit = _unit({"containers": [{"name": "c", "securityContext": {"privileged": False}}]})
    assert list(PrivilegedContainerRule().check(unit)) == []


def test_run_as_root_flagged_when_unset():
    unit = _unit({"containers": [{"name": "c"}]})
    assert len(list(RunAsRootRule().check(unit))) == 1


def test_run_as_root_clean_with_non_root_user():
    unit = _unit(
        {"containers": [{"name": "c", "securityContext": {"runAsNonRoot": True, "runAsUser": 1000}}]}
    )
    assert list(RunAsRootRule().check(unit)) == []


def test_run_as_root_clean_via_pod_level_setting():
    unit = _unit(
        {
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000},
            "containers": [{"name": "c"}],
        }
    )
    assert list(RunAsRootRule().check(unit)) == []


def test_privilege_escalation_flagged_when_unset():
    unit = _unit({"containers": [{"name": "c"}]})
    assert len(list(PrivilegeEscalationRule().check(unit))) == 1


def test_privilege_escalation_clean_when_false():
    unit = _unit(
        {"containers": [{"name": "c", "securityContext": {"allowPrivilegeEscalation": False}}]}
    )
    assert list(PrivilegeEscalationRule().check(unit)) == []


def test_host_namespace_flagged():
    unit = _unit({"hostNetwork": True, "containers": []})
    findings = list(HostNamespaceRule().check(unit))
    assert len(findings) == 1
    assert "hostNetwork" in findings[0].message


def test_host_namespace_clean():
    unit = _unit({"containers": []})
    assert list(HostNamespaceRule().check(unit)) == []


def test_hostpath_volume_flagged():
    unit = _unit({"containers": [], "volumes": [{"name": "v", "hostPath": {"path": "/etc"}}]})
    assert len(list(HostPathVolumeRule().check(unit))) == 1


def test_hostpath_volume_clean_with_emptydir():
    unit = _unit({"containers": [], "volumes": [{"name": "v", "emptyDir": {}}]})
    assert list(HostPathVolumeRule().check(unit)) == []


def test_missing_resource_limits_flagged():
    unit = _unit({"containers": [{"name": "c", "resources": {}}]})
    findings = list(MissingResourceLimitsRule().check(unit))
    assert len(findings) == 1
    assert "cpu" in findings[0].message and "memory" in findings[0].message


def test_resource_limits_clean():
    unit = _unit(
        {"containers": [{"name": "c", "resources": {"limits": {"cpu": "1", "memory": "1Gi"}}}]}
    )
    assert list(MissingResourceLimitsRule().check(unit)) == []


def test_writable_root_fs_flagged_when_unset():
    unit = _unit({"containers": [{"name": "c"}]})
    assert len(list(WritableRootFilesystemRule().check(unit))) == 1


def test_readonly_root_fs_clean():
    unit = _unit(
        {"containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}]}
    )
    assert list(WritableRootFilesystemRule().check(unit)) == []


def test_dangerous_capability_added_flagged():
    unit = _unit(
        {
            "containers": [
                {"name": "c", "securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}}
            ]
        }
    )
    findings = list(DangerousCapabilitiesRule().check(unit))
    assert len(findings) == 1


def test_capabilities_clean_when_all_dropped():
    unit = _unit(
        {"containers": [{"name": "c", "securityContext": {"capabilities": {"drop": ["ALL"]}}}]}
    )
    assert list(DangerousCapabilitiesRule().check(unit)) == []


def test_hostport_flagged():
    unit = _unit({"containers": [{"name": "c", "ports": [{"containerPort": 80, "hostPort": 80}]}]})
    assert len(list(HostPortRule().check(unit))) == 1


def test_hostport_clean_without_hostport():
    unit = _unit({"containers": [{"name": "c", "ports": [{"containerPort": 80}]}]})
    assert list(HostPortRule().check(unit)) == []


def test_mutable_tag_flagged_for_latest():
    unit = _unit({"containers": [{"name": "c", "image": "nginx:latest"}]})
    assert len(list(MutableImageTagRule().check(unit))) == 1


def test_mutable_tag_flagged_for_no_tag():
    unit = _unit({"containers": [{"name": "c", "image": "nginx"}]})
    assert len(list(MutableImageTagRule().check(unit))) == 1


def test_pinned_digest_clean():
    unit = _unit({"containers": [{"name": "c", "image": "nginx@sha256:" + "a" * 64}]})
    assert list(MutableImageTagRule().check(unit)) == []


def test_pinned_version_tag_clean():
    unit = _unit({"containers": [{"name": "c", "image": "nginx:1.27.0"}]})
    assert list(MutableImageTagRule().check(unit)) == []


def test_registry_with_port_not_confused_for_tag():
    unit = _unit(
        {"containers": [{"name": "c", "image": "localhost:5000/myapp:1.2.3"}]}
    )
    assert list(MutableImageTagRule().check(unit)) == []


def test_automount_sa_token_flagged_by_default():
    unit = _unit({"containers": []})
    assert len(list(ServiceAccountTokenAutomountRule().check(unit))) == 1


def test_automount_sa_token_clean_when_disabled():
    unit = _unit({"automountServiceAccountToken": False, "containers": []})
    assert list(ServiceAccountTokenAutomountRule().check(unit)) == []
