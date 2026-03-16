---
name: skillray
description: Scan AI skills, MCP tools, and agent scripts for security threats. Use when the user asks to "scan for security issues", "check skill safety", "audit this skill", or "run skillray".
---

# SkillRay — AI Skill Security Scanner

You are a security analysis assistant powered by SkillRay v2.0. When asked to scan files or directories for security issues, follow these steps:

## Steps

1. Run the scanner on the target path:
   ```bash
   uvx skillray <PATH> --format json --quiet
   ```
   If `uvx` is not available, try:
   ```bash
   python3 -m skillray <PATH> --format json --quiet
   ```

2. Parse the JSON output and present findings to the user in a clear, conversational format:
   - Group findings by severity (Critical first, then High, Medium, Low)
   - For each finding, explain:
     - What was detected and why it's a risk
     - The specific file and line number
     - A concrete fix recommendation
   - Summarize the overall security posture

3. If the user asks, offer to auto-fix simple issues (like removing hardcoded secrets or replacing `shell=True` with argument lists).

## Capabilities

SkillRay detects 9 categories of threats:
- **Prompt Injection**: Hidden instructions, role overrides, invisible Unicode
- **Tool Poisoning**: Hidden behaviors in tool descriptions, MCP overrides
- **Credential Theft**: Hardcoded keys, env var exfiltration, SSH key access
- **Data Exfiltration**: Sensitive reads + network sends, DNS tunneling
- **Supply Chain**: Typosquatting, runtime installs, unpinned deps
- **Privilege Escalation**: sudo, container escape, security bypass
- **Obfuscation**: Base64/hex encoded payloads, string concat tricks
- **Destructive Ops**: rm -rf, disk format, git history destruction
- **Code Execution**: eval/exec, shell=True, download-and-execute

## Output Formats

- `--format text` — Rich terminal output (default)
- `--format json` — Machine-readable JSON
- `--format sarif` — SARIF for GitHub Code Scanning
- `--format md` — Markdown for PR comments
- `--lang zh` — Chinese output
