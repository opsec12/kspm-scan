"""Workload security posture rules.

These check pod/container specs against the security-relevant fields
covered by the Kubernetes Pod Security Standards ("baseline"/"restricted"
profiles) and the CIS Kubernetes Benchmark section 5.2 (Pod Security
Policies / equivalent admission controls). Each rule works off the
normalized ``WorkloadUnit.pod_spec`` dict so it runs identically whether
the spec came from a YAML file or a live cluster.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from kspm.models import Finding, Severity, WorkloadUnit
from kspm.rules.base import Rule

_DANGEROUS_CAPABILITIES = {
    "ALL",
    "SYS_ADMIN",
    "NET_ADMIN",
    "NET_RAW",
    "SYS_PTRACE",
    "SYS_MODULE",
    "DAC_READ_SEARCH",
    "SYS_RAWIO",
}


def _container_security_context(container: dict[str, Any]) -> dict[str, Any]:
    return container.get("securityContext") or {}


def _effective(
    container_sc: dict[str, Any], pod_sc: dict[str, Any], field_name: str
) -> Any:
    """Container-level securityContext overrides pod-level; fall back to pod."""
    if field_name in container_sc:
        return container_sc[field_name]
    return pod_sc.get(field_name)


class PrivilegedContainerRule(Rule):
    id = "KSPM001"
    title = "Container runs in privileged mode"
    severity = Severity.CRITICAL
    category = "workload"
    cis_reference = "CIS 5.2.1"
    description = (
        "A privileged container has full access to the host's devices and "
        "kernel capabilities, effectively disabling container isolation."
    )
    remediation = (
        "Remove `securityContext.privileged: true` from the container. If "
        "specific host access is required, grant only the exact Linux "
        "capability needed instead."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            sc = _container_security_context(c)
            if sc.get("privileged") is True:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' sets privileged: true.",
                    container=c.get("name"),
                )


class RunAsRootRule(Rule):
    id = "KSPM002"
    title = "Container may run as root"
    severity = Severity.HIGH
    category = "workload"
    cis_reference = "CIS 5.2.6"
    description = (
        "Neither the container nor pod sets runAsNonRoot: true, and no "
        "non-root runAsUser is set, so the container can run as root (UID 0) "
        "if its image defaults to root."
    )
    remediation = (
        "Set `securityContext.runAsNonRoot: true` and a non-zero "
        "`runAsUser` at the pod or container level."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        pod_sc = unit.pod_spec.get("securityContext") or {}
        for c in unit.containers:
            sc = _container_security_context(c)
            run_as_non_root = _effective(sc, pod_sc, "runAsNonRoot")
            run_as_user = _effective(sc, pod_sc, "runAsUser")
            if run_as_non_root is True:
                continue
            if isinstance(run_as_user, int) and run_as_user != 0:
                continue
            yield self._finding(
                unit,
                f"Container '{c.get('name', '?')}' does not enforce a "
                "non-root user (runAsNonRoot/runAsUser unset or root).",
                container=c.get("name"),
            )


class PrivilegeEscalationRule(Rule):
    id = "KSPM003"
    title = "Privilege escalation is not explicitly blocked"
    severity = Severity.MEDIUM
    category = "workload"
    cis_reference = "CIS 5.2.5"
    description = (
        "allowPrivilegeEscalation defaults to true when unset, letting a "
        "process gain more privileges than its parent (e.g. via setuid "
        "binaries)."
    )
    remediation = (
        "Set `securityContext.allowPrivilegeEscalation: false` on the "
        "container."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            sc = _container_security_context(c)
            if sc.get("allowPrivilegeEscalation") is not False:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' does not set "
                    "allowPrivilegeEscalation: false.",
                    container=c.get("name"),
                )


class HostNamespaceRule(Rule):
    id = "KSPM004"
    title = "Pod shares a host namespace"
    severity = Severity.CRITICAL
    category = "workload"
    cis_reference = "CIS 5.2.3 / 5.2.4"
    description = (
        "hostNetwork, hostPID, or hostIPC lets the pod see (and potentially "
        "interfere with) host-level networking, processes, or IPC, breaking "
        "isolation from the node."
    )
    remediation = (
        "Remove hostNetwork/hostPID/hostIPC from the pod spec unless the "
        "workload has a specific, reviewed need for host access."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        flags = [f for f in ("hostNetwork", "hostPID", "hostIPC") if unit.pod_spec.get(f)]
        if flags:
            yield self._finding(
                unit, f"Pod sets {', '.join(flags)} = true."
            )


class HostPathVolumeRule(Rule):
    id = "KSPM005"
    title = "Pod mounts a hostPath volume"
    severity = Severity.HIGH
    category = "workload"
    cis_reference = "CIS 5.2.12"
    description = (
        "hostPath volumes expose the node's filesystem to the container, "
        "which can allow container-to-host breakout or tampering with node "
        "files."
    )
    remediation = (
        "Use a PersistentVolumeClaim, ConfigMap, Secret, or emptyDir "
        "instead of hostPath. If unavoidable, mount read-only and scope it "
        "to the narrowest possible path."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for vol in unit.pod_spec.get("volumes") or []:
            if "hostPath" in vol:
                path = (vol["hostPath"] or {}).get("path", "?")
                yield self._finding(
                    unit,
                    f"Volume '{vol.get('name', '?')}' mounts hostPath "
                    f"'{path}'.",
                )


class MissingResourceLimitsRule(Rule):
    id = "KSPM006"
    title = "Container has no CPU/memory limits"
    severity = Severity.MEDIUM
    category = "workload"
    cis_reference = "Pod Security Standards (baseline)"
    description = (
        "Without resource limits, a compromised or misbehaving container "
        "can exhaust node CPU/memory, degrading or crashing co-located "
        "workloads (a denial-of-service risk)."
    )
    remediation = (
        "Set `resources.limits.cpu` and `resources.limits.memory` on every "
        "container."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            limits = ((c.get("resources") or {}).get("limits")) or {}
            missing = [r for r in ("cpu", "memory") if r not in limits]
            if missing:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' is missing resource "
                    f"limits: {', '.join(missing)}.",
                    container=c.get("name"),
                )


class WritableRootFilesystemRule(Rule):
    id = "KSPM007"
    title = "Root filesystem is writable"
    severity = Severity.LOW
    category = "workload"
    cis_reference = "CIS 5.2.10"
    description = (
        "Without readOnlyRootFilesystem: true, a compromised process can "
        "modify the container's own filesystem, aiding persistence or "
        "further exploitation."
    )
    remediation = (
        "Set `securityContext.readOnlyRootFilesystem: true` and mount "
        "emptyDir volumes for any paths that genuinely need write access."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.containers:
            sc = _container_security_context(c)
            if sc.get("readOnlyRootFilesystem") is not True:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' does not set "
                    "readOnlyRootFilesystem: true.",
                    container=c.get("name"),
                )


class DangerousCapabilitiesRule(Rule):
    id = "KSPM008"
    title = "Container adds dangerous Linux capabilities"
    severity = Severity.HIGH
    category = "workload"
    cis_reference = "CIS 5.2.7 / 5.2.8 / 5.2.9"
    description = (
        "Capabilities such as SYS_ADMIN, NET_ADMIN, or ALL grant "
        "near-root power over networking, mounts, or auditing even without "
        "full privileged mode."
    )
    remediation = (
        "Drop ALL capabilities by default (`capabilities.drop: [ALL]`) and "
        "add back only the specific capability the workload requires."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            sc = _container_security_context(c)
            caps = sc.get("capabilities") or {}
            added = {str(cap).upper() for cap in (caps.get("add") or [])}
            dropped = {str(cap).upper() for cap in (caps.get("drop") or [])}
            dangerous_added = added & _DANGEROUS_CAPABILITIES
            if dangerous_added:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' adds capabilities "
                    f"{sorted(dangerous_added)}.",
                    container=c.get("name"),
                )
            elif "ALL" not in dropped:
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' does not drop ALL "
                    "capabilities by default.",
                    container=c.get("name"),
                )


class HostPortRule(Rule):
    id = "KSPM009"
    title = "Container binds a hostPort"
    severity = Severity.MEDIUM
    category = "workload"
    cis_reference = "Pod Security Standards (baseline)"
    description = (
        "hostPort binds the container directly to a port on the node, "
        "bypassing the Service/NetworkPolicy layer and risking port "
        "conflicts or unintended external exposure."
    )
    remediation = (
        "Expose the workload through a Service (ClusterIP/NodePort/"
        "LoadBalancer) instead of a container hostPort."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            for port in c.get("ports") or []:
                if port.get("hostPort"):
                    yield self._finding(
                        unit,
                        f"Container '{c.get('name', '?')}' binds "
                        f"hostPort {port.get('hostPort')}.",
                        container=c.get("name"),
                    )


class MutableImageTagRule(Rule):
    id = "KSPM010"
    title = "Container image uses a mutable or missing tag"
    severity = Severity.LOW
    category = "workload"
    cis_reference = "Pod Security Standards (supply chain hygiene)"
    description = (
        "Images referenced by `:latest` or with no tag can change contents "
        "without a corresponding manifest change, undermining "
        "reproducibility and auditability of what is actually running."
    )
    remediation = (
        "Pin images to an immutable digest (`image@sha256:...`) or a "
        "specific, immutable version tag."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        for c in unit.all_containers:
            image = c.get("image") or ""
            if "@sha256:" in image:
                continue
            tag = image.rsplit(":", 1)[-1] if ":" in image.split("/")[-1] else None
            if tag is None or tag == "latest":
                yield self._finding(
                    unit,
                    f"Container '{c.get('name', '?')}' uses image "
                    f"'{image or '?'}' with tag "
                    f"'{tag or '(none, defaults to latest)'}'.",
                    container=c.get("name"),
                )


class ServiceAccountTokenAutomountRule(Rule):
    id = "KSPM011"
    title = "Service account token is auto-mounted"
    severity = Severity.LOW
    category = "workload"
    cis_reference = "CIS 5.1.6"
    description = (
        "By default every pod automounts its ServiceAccount API token, "
        "giving any process in the pod the means to call the Kubernetes "
        "API as that identity even if the workload never needs to."
    )
    remediation = (
        "Set `automountServiceAccountToken: false` on the pod (or the "
        "ServiceAccount) unless the workload genuinely needs API access."
    )

    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        if unit.pod_spec.get("automountServiceAccountToken") is not False:
            yield self._finding(
                unit,
                "Pod does not set automountServiceAccountToken: false.",
            )
