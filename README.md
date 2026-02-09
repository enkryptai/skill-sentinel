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
enkryptai-skill-scanner scan <skill_directory> [OPTIONS]

Options:
  -o, --output PATH     Path for the output report (default: report.json)
  -m, --model MODEL     OpenAI model to use (default: gpt-4.1)
  --api-key KEY         OpenAI API key (prefer OPENAI_API_KEY env var)
  -V, --version         Show version and exit
```

### Examples

```bash
# Basic scan (writes report.json in the current directory)
enkryptai-skill-scanner scan ./my-skill

# Custom output path
enkryptai-skill-scanner scan ./my-skill -o ~/reports/my-skill-report.json

# Use a different model
enkryptai-skill-scanner scan ./my-skill -m gpt-4o

# Pass API key inline (prefer env var instead)
enkryptai-skill-scanner scan ./my-skill --api-key sk-...
```

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
