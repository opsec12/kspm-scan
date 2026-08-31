"""Rule registry. Importing this package registers every built-in rule set.

To add a new rule category (e.g. RBAC, network policy), create a new
module under kspm/rules/ with Rule subclasses and import it below — no
other code needs to change.
"""
from kspm.rules import workload  # noqa: F401  (registers workload rules)
from kspm.rules.base import ALL_RULES, Rule, get_enabled_rules

__all__ = ["ALL_RULES", "Rule", "get_enabled_rules"]
