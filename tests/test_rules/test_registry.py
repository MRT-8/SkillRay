"""Tests for the rule registry."""

from skillray.rules.registry import get_all_rules, get_rule, get_rules_for_engine
from skillray.models import TargetType


def test_rules_registered():
    rules = get_all_rules()
    assert len(rules) >= 35  # ~37 rules registered


def test_rule_ids_unique():
    rules = get_all_rules()
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_all_categories_represented():
    rules = get_all_rules()
    categories = {r.category.value for r in rules}
    expected = {
        "SR-PROMPT", "SR-TOOL", "SR-CRED", "SR-EXFIL",
        "SR-SUPPLY", "SR-PRIV", "SR-OBFUSC", "SR-DESTRUCT", "SR-EXEC",
    }
    assert categories == expected


def test_get_rule_by_id():
    rule = get_rule("SR-PROMPT-001")
    assert rule is not None
    assert rule.rule_id == "SR-PROMPT-001"


def test_get_rules_for_engine():
    regex_rules = get_rules_for_engine("regex", TargetType.SCRIPT)
    assert len(regex_rules) > 0
    for r in regex_rules:
        assert r.engine == "regex"
