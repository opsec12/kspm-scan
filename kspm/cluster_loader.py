"""Live scan source: pull running Pods out of a real cluster via kubeconfig
(or in-cluster credentials) and normalize them into WorkloadUnits.

Live scanning inspects Pods as actually scheduled -- which reflects any
mutating webhooks/defaults applied at admission -- rather than the raw
Deployment/StatefulSet manifest, so ``kind`` is reported as "Pod" with the
owning controller (if any) recorded in ``metadata['ownerReferences']``.
"""
from __future__ import annotations

from typing import Optional

from kspm.models import WorkloadUnit


class ClusterConnectionError(RuntimeError):
    """Raised when a kubeconfig/in-cluster config or API call fails."""


def load_workloads_from_cluster(
    namespace: Optional[str] = None,
    context: Optional[str] = None,
    exclude_namespaces: tuple[str, ...] = (),
) -> list[WorkloadUnit]:
    try:
        from kubernetes import client, config
        from kubernetes.client.exceptions import ApiException
        from kubernetes.config.config_exception import ConfigException
    except ImportError as exc:  # pragma: no cover
        raise ClusterConnectionError(
            "The 'kubernetes' package is required for live scans. "
            "Install it with: pip install kubernetes"
        ) from exc

    try:
        config.load_incluster_config()
        source_label = "cluster:in-cluster"
    except ConfigException:
        try:
            config.load_kube_config(context=context)
            active_context = context or "default"
            source_label = f"cluster:{active_context}"
        except ConfigException as exc:
            raise ClusterConnectionError(
                f"Could not load Kubernetes credentials: {exc}"
            ) from exc

    api = client.CoreV1Api()
    api_client = client.ApiClient()

    try:
        if namespace:
            pods = api.list_namespaced_pod(namespace).items
        else:
            pods = api.list_pod_for_all_namespaces().items
    except ApiException as exc:
        raise ClusterConnectionError(
            f"Kubernetes API error while listing pods: {exc.reason} "
            f"(status {exc.status})"
        ) from exc

    units: list[WorkloadUnit] = []
    for pod in pods:
        raw = api_client.sanitize_for_serialization(pod)
        metadata = raw.get("metadata") or {}
        pod_namespace = metadata.get("namespace", "default")
        if pod_namespace in exclude_namespaces:
            continue
        pod_spec = raw.get("spec") or {}
        units.append(
            WorkloadUnit(
                kind="Pod",
                name=metadata.get("name", "unnamed"),
                namespace=pod_namespace,
                pod_spec=pod_spec,
                source=source_label,
                metadata=metadata,
            )
        )
    return units
