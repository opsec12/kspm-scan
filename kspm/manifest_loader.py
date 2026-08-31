"""Static scan source: load WorkloadUnits out of YAML manifests on disk.

Supports plain manifests or Helm/kustomize-rendered output — anything that
is a stream of standard Kubernetes YAML documents. A single file may
contain multiple `---`-separated documents.
"""
from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from kspm.models import WorkloadUnit

# Maps a resource Kind to the path (as a tuple of dict keys) leading to its
# PodSpec within the manifest document.
_POD_SPEC_PATH: dict[str, tuple[str, ...]] = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}


def _dig(doc: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    node: Any = doc
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node if isinstance(node, dict) else None


def find_manifest_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml")
    )


def _iter_documents(path: Path) -> Iterator[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return
    try:
        docs = yaml.safe_load_all(text)
        for doc in docs:
            if isinstance(doc, dict):
                yield doc
    except yaml.YAMLError as exc:
        print(f"warning: skipping invalid YAML in {path}: {exc}", file=sys.stderr)


def load_workloads_from_path(root: Path) -> list[WorkloadUnit]:
    """Scan a file or directory tree for Kubernetes manifests.

    Returns one WorkloadUnit per pod-template-bearing resource found.
    Non-Kubernetes YAML and unsupported kinds are silently skipped.
    """
    units: list[WorkloadUnit] = []
    for file_path in find_manifest_files(root):
        for doc in _iter_documents(file_path):
            kind = doc.get("kind")
            if kind not in _POD_SPEC_PATH:
                continue
            pod_spec = _dig(doc, _POD_SPEC_PATH[kind])
            if pod_spec is None:
                continue
            metadata = doc.get("metadata") or {}
            units.append(
                WorkloadUnit(
                    kind=kind,
                    name=metadata.get("name", "unnamed"),
                    namespace=metadata.get("namespace", "default"),
                    pod_spec=pod_spec,
                    source=str(file_path),
                    metadata=metadata,
                )
            )
    return units
