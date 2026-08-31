"""Core data model shared by every scan source (static manifests or a live cluster).

Both scan sources normalize their input into a ``WorkloadUnit`` whose
``pod_spec`` is a plain dict following the Kubernetes API's JSON/camelCase
schema (the same shape you'd see in a YAML manifest). This lets every rule
be written once against a single, predictable shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        # Lower number = more severe. Used for sorting and --fail-on comparisons.
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    @property
    def score_penalty(self) -> int:
        """Points deducted from the 100-point posture score per finding."""
        return {
            Severity.CRITICAL: 12,
            Severity.HIGH: 7,
            Severity.MEDIUM: 3,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


@dataclass
class WorkloadUnit:
    """A single pod-template-bearing workload, normalized for rule checks.

    ``kind`` is the owning resource kind (Pod, Deployment, StatefulSet,
    DaemonSet, Job, CronJob, ...). ``pod_spec`` is the PodSpec dict
    (camelCase keys: containers, initContainers, hostNetwork, volumes, ...).
    """

    kind: str
    name: str
    namespace: str
    pod_spec: dict[str, Any]
    source: str  # file path, or "cluster:<context>" for live scans
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def containers(self) -> list[dict[str, Any]]:
        return list(self.pod_spec.get("containers") or [])

    @property
    def init_containers(self) -> list[dict[str, Any]]:
        return list(self.pod_spec.get("initContainers") or [])

    @property
    def all_containers(self) -> list[dict[str, Any]]:
        return self.containers + self.init_containers

    @property
    def locator(self) -> str:
        ns = self.namespace or "default"
        return f"{self.kind}/{self.name} (namespace: {ns})"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: str
    workload: WorkloadUnit
    message: str
    remediation: str
    container: Optional[str] = None
    cis_reference: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category,
            "kind": self.workload.kind,
            "name": self.workload.name,
            "namespace": self.workload.namespace,
            "container": self.container,
            "source": self.workload.source,
            "message": self.message,
            "remediation": self.remediation,
            "cis_reference": self.cis_reference,
        }
