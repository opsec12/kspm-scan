"""Optional .kspm.yaml config file: lets a repo/CI pipeline set defaults
(ignored rules, excluded namespaces, fail-on threshold) without having to
repeat CLI flags every run. CLI flags always take precedence.

Example .kspm.yaml:

    ignore_rules:
      - KSPM010          # allow :latest tags in this repo
    exclude_namespaces:
      - kube-system
      - kube-public
    fail_on: HIGH
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_FILENAMES = (".kspm.yaml", ".kspm.yml")


@dataclass
class KspmConfig:
    ignore_rules: list[str] = field(default_factory=list)
    exclude_namespaces: list[str] = field(default_factory=list)
    fail_on: str = "HIGH"


def find_default_config(start_dir: Path) -> Path | None:
    for name in DEFAULT_CONFIG_FILENAMES:
        candidate = start_dir / name
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> KspmConfig:
    if path is None or not path.is_file():
        return KspmConfig()
    with path.open("r", encoding="utf-8") as fh:
        raw: dict[str, Any] = yaml.safe_load(fh) or {}
    return KspmConfig(
        ignore_rules=list(raw.get("ignore_rules") or []),
        exclude_namespaces=list(raw.get("exclude_namespaces") or []),
        fail_on=str(raw.get("fail_on") or "HIGH").upper(),
    )
