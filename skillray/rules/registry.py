"""Central rule registry."""

from __future__ import annotations

from ..models import Rule, TargetType

_RULES: list[Rule] = []
_PATTERNS: dict[str, list[str]] = {}


def register(rule: Rule, patterns: list[str] | None = None) -> None:
    _RULES.append(rule)
    if patterns:
        _PATTERNS[rule.rule_id] = patterns


def get_all_rules() -> list[Rule]:
    return list(_RULES)


def get_rules_for_engine(engine_name: str, target: TargetType) -> list[Rule]:
    return [
        r for r in _RULES
        if r.engine == engine_name
        and (TargetType.ANY in r.targets or target in r.targets)
    ]


def get_patterns(rule_id: str) -> list[str]:
    return _PATTERNS.get(rule_id, [])


def get_rule(rule_id: str) -> Rule | None:
    for r in _RULES:
        if r.rule_id == rule_id:
            return r
    return None
