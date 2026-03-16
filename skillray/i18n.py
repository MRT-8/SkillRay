"""Internationalization support (English + Chinese)."""

from __future__ import annotations

from typing import Literal

Lang = Literal["en", "zh"]

_STRINGS: dict[str, dict[Lang, str]] = {
    "scanning": {"en": "Scanning", "zh": "扫描中"},
    "files_scanned": {"en": "Files scanned", "zh": "已扫描文件"},
    "total_findings": {"en": "Total findings", "zh": "发现总数"},
    "no_findings": {"en": "No security issues found.", "zh": "未发现安全问题。"},
    "severity": {"en": "Severity", "zh": "严重性"},
    "count": {"en": "Count", "zh": "数量"},
    "critical": {"en": "Critical", "zh": "严重"},
    "high": {"en": "High", "zh": "高"},
    "medium": {"en": "Medium", "zh": "中"},
    "low": {"en": "Low", "zh": "低"},
    "info": {"en": "Info", "zh": "信息"},
    "evidence": {"en": "Evidence", "zh": "证据"},
    "fix": {"en": "Fix", "zh": "修复建议"},
    "scan_complete": {"en": "Scan complete", "zh": "扫描完成"},
    "critical_attention": {
        "en": "{n} critical issue(s) require immediate attention.",
        "zh": "{n} 个严重问题需要立即处理。",
    },
    "category": {"en": "Category", "zh": "类别"},
    "engine": {"en": "Engine", "zh": "引擎"},
    "file": {"en": "File", "zh": "文件"},
    "line": {"en": "Line", "zh": "行"},
    "rule": {"en": "Rule", "zh": "规则"},
    "duration": {"en": "Duration", "zh": "耗时"},
    "ignored": {"en": "Ignored", "zh": "已忽略"},
    "summary": {"en": "Summary", "zh": "摘要"},
    "details": {"en": "Details", "zh": "详情"},
}


def t(key: str, lang: Lang = "en", **kwargs: object) -> str:
    entry = _STRINGS.get(key, {})
    text = entry.get(lang, entry.get("en", key))
    if kwargs:
        text = text.format(**kwargs)
    return text
