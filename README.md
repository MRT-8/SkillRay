# SkillRay Scan

`skillray_scan` is a lightweight static security checker for newly added skills.

It scans:
- `SKILL.md` files
- script files in `scripts/` or with known script extensions (`.py`, `.sh`, `.ps1`, etc.)

It reports findings in terminal text and/or JSON.

## Requirements

- Python 3.10+

## Quick Start

Run from repository root:

```bash
python -m skillray_scan
```

Default behavior:
- scan path: `skills`
- output format: `both` (text + JSON)
- JSON output: `./skillray-report.json`
- ignore file: `./.skillrayignore`

## CLI

```bash
python -m skillray_scan \
  --path skills \
  --format both \
  --json-out ./skillray-report.json \
  --ignore-file ./.skillrayignore
```

Arguments:
- `--path`: scan root directory
- `--format`: `text | json | both`
- `--json-out`: JSON report output path (used by `json`/`both`)
- `--ignore-file`: ignore rules file path

## Ignore Rules (`.skillrayignore`)

Each non-empty, non-comment line can be:
- `RULE_ID` (ignore a rule globally)
- `RULE_ID:path/glob` (ignore a rule for matching file path pattern)

Example:

```text
# Ignore all SR-SCRIPT-003 findings
SR-SCRIPT-003

# Ignore SR-SKILL-004 only under demo skills
SR-SKILL-004:demo/*/SKILL.md
```

## Severity Model

Findings use three levels:
- `High`
- `Medium`
- `Low`

Current behavior is report-only (exit code remains `0` unless runtime error occurs).

## Built-in Rule IDs

`SKILL.md` rules:
- `SR-SKILL-001`: destructive filesystem commands
- `SR-SKILL-002`: download-and-execute patterns
- `SR-SKILL-003`: privilege escalation / bypass guidance
- `SR-SKILL-004`: sensitive data exfiltration command patterns

Script rules:
- `SR-SCRIPT-001`: shell command execution primitives
- `SR-SCRIPT-002`: dynamic code execution primitives
- `SR-SCRIPT-003`: dynamically built command execution
- `SR-SCRIPT-004`: sensitive-read + outbound-network combination

## Tests

Run all tests:

```bash
python -m unittest discover -s tests -v
```

## CI

GitHub Actions workflow is provided at:
- `.github/workflows/ci.yml`

It runs unit/integration tests and a scanner smoke check.
