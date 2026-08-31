"""Base class and registry for KSPM rules.

A rule inspects a single ``WorkloadUnit`` and yields zero or more
``Finding`` objects. Rules are self-registering: subclassing ``Rule`` and
defining the class attributes is enough for ``ALL_RULES`` to pick it up.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, Optional

from kspm.models import Finding, Severity, WorkloadUnit

ALL_RULES: list[type[Rule]] = []


class Rule(ABC):
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    cis_reference: Optional[str] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "abstract", False):
            return
        ALL_RULES.append(cls)

    @abstractmethod
    def check(self, unit: WorkloadUnit) -> Iterable[Finding]:
        """Yield Finding objects for any violations found in ``unit``."""
        raise NotImplementedError

    def _finding(
        self,
        unit: WorkloadUnit,
        message: str,
        container: Optional[str] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity,
            category=self.category,
            workload=unit,
            message=message,
            remediation=self.remediation,
            container=container,
            cis_reference=self.cis_reference,
        )


def get_enabled_rules(ignored_ids: Iterable[str] = ()) -> list[Rule]:
    ignored = set(ignored_ids)
    return [rule_cls() for rule_cls in ALL_RULES if rule_cls.id not in ignored]
