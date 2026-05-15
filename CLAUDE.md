# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SkillRay is a lightweight, offline, multi-engine static security analyzer for AI agent skills (Claude Code skills, MCP tools, etc.). It detects prompt injection, credential theft, data exfiltration, persistence/backdoors, stealth/coercion, MCP configuration threats, and other threats across 12 categories using 5 detection engines (~69 rules). Only runtime dependency is `rich`.

## Commands

```bash
# Install dependencies
uv sync

# Run all tests
uv run pytest tests/ -v

# Run a single test file
uv run pytest tests/test_engines/test_regex.py -v

# Run a single test by name
uv run pytest tests/test_engines/test_regex.py -k "test_name" -v

# Scan malicious test samples (expect findings)
uv run python3 -m skillray tests/samples/malicious/

# Scan benign test samples (expect clean)
uv run python3 -m skillray tests/samples/benign/ --fail-on low

# Run as installed CLI
uv run skillray .
```

## Architecture

The scanner follows a pipeline: **file discovery -> engine dispatch -> rule matching -> ignore filtering -> reporting**.

### Core Pipeline (`skillray/scanner.py`)
`scan_path()` is the main entry point. It discovers files via `discover_files()`, classifies each into a `TargetType` (SKILL_MD, SCRIPT, MARKDOWN, CONFIG, ANY, MCP_CONFIG, CI_CONFIG), then dispatches to all selected engines. `.github/` and `.claude/` hidden directories are scanned; `.mcp.json` dotfiles are also discovered. Findings are filtered through `IgnoreConfig` before aggregation into `ScanResult`.

### Engines (`skillray/engines/`)
Each engine extends `BaseEngine` (ABC in `base.py`) and implements `scan(file_path, content, target) -> list[Finding]`. Engines query the rule registry for rules matching their engine name and the file's target type.

- **RegexEngine** — Pattern matching against all file types. Gets compiled patterns from the rule registry.
- **ASTEngine** — Python-only (`ast` module). Detects `eval`/`exec`, `shell=True`, dangerous imports. Eliminates false positives from comments/strings.
- **EntropyEngine** — Shannon entropy analysis + known key format regexes (~15 formats like AWS, GitHub, OpenAI keys).
- **DataflowEngine** — Lightweight taint tracking for Python and shell. Traces sensitive data reads (source) to network sends (sink). Also detects reverse shells, DNS subdomain exfiltration, and webhook exfiltration standalone.
- **PromptEngine** — Markdown/SKILL.md/MCP config analysis for prompt injection, hidden instructions, invisible Unicode (including Tags block U+E0001-E007F and Variation Selectors), role override, stealth/coercion instructions, cross-tool shadowing, and ANSI escape injection. Parses MCP JSON configs to scan tool descriptions.

### Rules (`skillray/rules/`)
Rules are organized by threat category (one file per category, 12 files). Each file registers `Rule` objects with the central `registry.py` at import time via `register(rule, patterns)`. Rule IDs follow the format `SR-{CATEGORY}-{NNN}` (e.g., `SR-CRED-001`). Categories: PROMPT, TOOL, CRED, EXFIL, SUPPLY, PRIV, OBFUSC, DESTRUCT, EXEC, PERSIST, STEALTH, MCP.

### Models (`skillray/models.py`)
All data types: `Severity` (IntEnum, lower value = higher severity), `ThreatCategory`, `TargetType`, `Rule`, `Finding`, `ScanResult`. The `Engine` protocol defines the interface engines must satisfy.

### Reporters (`skillray/reporters/`)
Four output formats: `TextReporter` (Rich terminal tables, supports `--lang`), `JSONReporter` (JSON + SARIF), `MarkdownReporter`.

### i18n (`skillray/i18n.py`)
Simple key-based translation dict supporting `en` and `zh`. Used by reporters via `t(key, lang)`.

## Key Design Decisions

- `Severity` is an `IntEnum` where CRITICAL=0, so `<=` comparison means "at this severity or above" (lower numeric = more severe).
- Rule patterns are stored in the registry, not in engines — engines pull patterns via `get_patterns(rule_id)`.
- File classification determines which engines run on a file (e.g., ASTEngine only processes `.py` files, PromptEngine processes `.md`/SKILL.md/MCP config files).
- The `.skillrayignore` file supports global rule suppression (`SR-PRIV-001`) and scoped suppression (`SR-CRED-001:tests/**/*.py`).

## Test Structure

- `tests/test_engines/` — Unit tests per engine with inline code snippets
- `tests/test_rules/` — Rule registry tests
- `tests/test_scanner.py` — Integration tests using `tests/samples/malicious/` and `tests/samples/benign/`
- `tests/test_cli.py` — CLI argument parsing and output format tests
- Test samples in `tests/samples/malicious/` should trigger findings; `tests/samples/benign/` should not
