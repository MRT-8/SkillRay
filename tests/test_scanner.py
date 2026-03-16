"""Tests for the scanner orchestrator."""

from pathlib import Path

from skillray.scanner import scan_path, discover_files
from skillray.models import Severity


def test_scan_malicious_dir(malicious_dir: Path):
    result = scan_path(malicious_dir)
    assert len(result.findings) > 0
    # Should detect multiple categories
    categories = {f.category for f in result.findings}
    assert len(categories) >= 3


def test_scan_benign_dir(benign_dir: Path):
    result = scan_path(benign_dir)
    assert len(result.findings) == 0, (
        f"Benign samples should have zero findings, got: "
        + ", ".join(f"{f.rule_id}@{f.file}:{f.line}" for f in result.findings)
    )


def test_scan_nonexistent():
    result = scan_path(Path("/nonexistent/path"))
    assert len(result.warnings) > 0
    assert len(result.findings) == 0


def test_discover_files_skips_hidden(tmp_path: Path):
    (tmp_path / ".git" / "config").parent.mkdir()
    (tmp_path / ".git" / "config").write_text("x")
    (tmp_path / "script.py").write_text("print('hello')")
    files = discover_files(tmp_path)
    paths = [f[2] for f in files]
    assert "script.py" in paths
    assert not any(".git" in p for p in paths)


def test_engine_filter(malicious_dir: Path):
    result_all = scan_path(malicious_dir)
    result_regex = scan_path(malicious_dir, engine_names=["regex"])
    # Regex-only should have fewer findings
    assert len(result_regex.findings) <= len(result_all.findings)


def test_rule_filter(malicious_dir: Path):
    result = scan_path(malicious_dir, rule_filters=["SR-PROMPT-*"])
    for f in result.findings:
        assert f.rule_id.startswith("SR-PROMPT-")


def test_severity_counts(malicious_dir: Path):
    result = scan_path(malicious_dir)
    counts = result.severity_counts
    total = sum(counts.values())
    assert total == len(result.findings)
