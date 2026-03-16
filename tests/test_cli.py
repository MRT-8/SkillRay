"""Tests for the CLI."""

import json
from pathlib import Path

from skillray.cli import main


def test_cli_text_output(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--format", "text", "--no-color"])
    assert code == 0
    output = capsys.readouterr().out
    assert "SkillRay" in output or "CRITICAL" in output or "HIGH" in output


def test_cli_json_output(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--format", "json"])
    assert code == 0
    output = capsys.readouterr().out
    data = json.loads(output)
    assert "findings" in data
    assert len(data["findings"]) > 0


def test_cli_quiet_mode(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--quiet"])
    assert code == 0
    output = capsys.readouterr().out
    # Quiet mode should have concise output
    assert len(output.strip().splitlines()) >= 1


def test_cli_fail_on_critical(malicious_dir: Path):
    code = main([str(malicious_dir), "--fail-on", "critical", "--quiet"])
    assert code == 1  # malicious samples have critical findings


def test_cli_fail_on_benign(benign_dir: Path):
    code = main([str(benign_dir), "--fail-on", "low", "--quiet"])
    assert code == 0  # benign samples have no findings


def test_cli_json_output_file(malicious_dir: Path, tmp_path: Path):
    out_file = tmp_path / "report.json"
    main([str(malicious_dir), "--format", "json", "--output", str(out_file), "--quiet"])
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert "findings" in data


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit:
        pass
    output = capsys.readouterr().out
    assert "2.0.0" in output


def test_cli_md_output(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--format", "md"])
    assert code == 0
    output = capsys.readouterr().out
    assert "SkillRay" in output


def test_cli_sarif_output(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--format", "sarif"])
    assert code == 0
    output = capsys.readouterr().out
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) > 0


def test_cli_engine_filter(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--engines", "regex", "--format", "json"])
    assert code == 0
    output = capsys.readouterr().out
    data = json.loads(output)
    for f in data["findings"]:
        assert f["engine"] == "regex"


def test_cli_chinese_output(malicious_dir: Path, capsys):
    code = main([str(malicious_dir), "--lang", "zh", "--no-color"])
    assert code == 0
