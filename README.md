# Enkrypt AI Skill Scanner

A security scanner for Agent Skill packages. It uses multi-agent analysis to detect prompt injection, data exfiltration, command injection, and other threats in skill packages.

## Installation

Requires Python >= 3.10, < 3.14.

### Using uv (recommended)

```bash
uv venv --python 3.13 .venv
source .venv/bin/activate
uv pip install .
```

### Using pip

```bash
pip install .
```

For development (editable mode):

```bash
uv pip install -e .
# or
pip install -e .
```

## Quick Start

```bash
# 1. Export your OpenAI API key
export OPENAI_API_KEY="sk-..."

# 2. Scan a skill directory
enkryptai-skill-scanner scan /path/to/skill/directory
```

## Usage

```
enkryptai-skill-scanner scan [provider] [OPTIONS]

Positional:
  provider              cursor / claude / codex to auto-discover that
                        provider's skills, or omit to discover all.
                        Can also be a direct path to a skill directory.

Path flags (mutually exclusive):
  --skill PATH          Scan a single skill directory.
  --dir PATH            Scan all skill subdirectories inside a parent directory.

Options:
  -o, --output PATH     Single scan: output file (default: report.json).
                        Multi-scan: output directory (default: ./skill_scanner_reports).
  --parallel            Scan multiple skills in parallel (5 concurrent).
  -m, --model MODEL     OpenAI model to use (default: gpt-4.1).
  --api-key KEY         OpenAI API key (prefer OPENAI_API_KEY env var).
  -V, --version         Show version and exit.
```

### Examples

```bash
# Scan a single skill directory
enkryptai-skill-scanner scan --skill ./my-skill
enkryptai-skill-scanner scan --skill ./my-skill -o report.json

# Scan all skills inside a parent directory
enkryptai-skill-scanner scan --dir ./all-my-skills/
enkryptai-skill-scanner scan --dir ./all-my-skills/ -o ./reports/

# Scan in parallel (5 concurrent)
enkryptai-skill-scanner scan --dir ./all-my-skills/ --parallel

# Auto-discover and scan ALL skills from cursor, claude, and codex paths
enkryptai-skill-scanner scan

# Auto-discover only Cursor skills, in parallel
enkryptai-skill-scanner scan cursor --parallel

# Scan only Claude skills
enkryptai-skill-scanner scan claude

# Custom output directory for auto-discovery
enkryptai-skill-scanner scan codex -o ./my-reports/

# Use a different model
enkryptai-skill-scanner scan --skill ./my-skill -m gpt-4o
```

### Auto-Discovery

When no path is given (or a provider keyword is used), the scanner searches these well-known locations for skill directories containing a `SKILL.md`:

| Location | Scope |
|---|---|
| `.cursor/skills/` | Project-level (Cursor) |
| `.claude/skills/` | Project-level (Claude) |
| `.codex/skills/` | Project-level (Codex) |
| `~/.cursor/skills/` | User-level global (Cursor) |
| `~/.claude/skills/` | User-level global (Claude) |
| `~/.codex/skills/` | User-level global (Codex) |

Reports are saved as `<provider>__<skill_name>.json` in `./skill_scanner_reports/` (or the directory specified with `-o`).

### Programmatic Usage

```python
from skill_scanner.main import scan

report = scan("/path/to/skill", output_path="report.json", model="gpt-4.1")
print(report["overall_risk_assessment"]["skill_verdict"])
```

## What It Does

The scanner performs a multi-step security analysis:

1. **File Discovery** — lists all files in the skill directory (static, no LLM).
2. **SKILL.md Analysis** — an agent reads the SKILL.md manifest and instructions, looking for prompt injection, trust abuse, discovery abuse, and other threats.
3. **File Verification** *(conditional)* — if the skill contains scripts or referenced files beyond SKILL.md, a second agent reads each file and checks alignment with SKILL.md claims, searching for command injection, data exfiltration, hardcoded secrets, obfuscation, etc.
4. **Report Synthesis** — a final agent filters false positives, prioritizes findings, and produces a structured JSON report.

## Output

The scanner writes a JSON report containing:

- `skill_path` — absolute path to the scanned skill directory
- `validated_findings` — confirmed threats with severity, evidence, remediation
- `false_positives` — dismissed findings with reasoning
- `priority_order` — ranked list of finding IDs
- `correlations` — related findings grouped together
- `recommendations` — actionable next steps
- `overall_risk_assessment` — risk level, verdict (SAFE / SUSPICIOUS / MALICIOUS), reasoning
- `token_usage` — LLM token usage metrics for the scan

## Project Structure

```
skill_scanner_package/
├── pyproject.toml              # Package build config
├── README.md
└── src/skill_scanner/
    ├── __init__.py             # Package version
    ├── cli.py                  # CLI entry point
    ├── main.py                 # Programmatic API
    ├── crew.py                 # Multi-agent crew definition
    ├── config/
    │   ├── agents.yaml         # Agent definitions
    │   └── tasks.yaml          # Task definitions
    ├── data/
    │   ├── threat_categories.md    # Threat taxonomy
    │   └── report_schema.json      # Output JSON schema
    └── tools/
        ├── custom_tool.py      # ReadFile & Grep tools
        └── file_discovery.py   # Static file listing
```

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `OPENAI_API_KEY` | Your OpenAI API key (required) | — |
| `OPENAI_MODEL_NAME` | Model to use for analysis | `gpt-4.1` |
