# Contributing to Skill Sentinel

Thank you for considering contributing to Skill Sentinel. By submitting a pull request or other contribution, you agree to the terms of our [Contributor License Agreement (CLA)](CLA.md).

## Getting Started

### 1. Fork and clone

Fork the [repository](https://github.com/enkryptai/skill-sentinel) on GitHub, then clone your fork:

```bash
git clone https://github.com/enkryptai/skill-sentinel.git
cd skill-sentinel
```

### 2. Create a branch

Create a branch for your work:

```bash
git checkout -b feature/my-feature
# or: git checkout -b fix/some-bug
```

### 3. Set up the development environment

Requires Python >= 3.10, < 3.14. We recommend Python 3.13 and [uv](https://docs.astral.sh/uv/).

**With uv (recommended):**

```bash
uv venv --python 3.13 .venv
source .venv/bin/activate   # On Windows: .venv\Scripts\activate
uv pip install -e .
```

**With pip:**

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For local scans you’ll need an OpenAI API key (and optionally a VirusTotal key). Copy `.env.example` to `.env` and fill in your keys.

### 4. Make your changes

- Follow the existing code style and structure.
- Keep changes focused; prefer several small PRs over one large one.
- Update documentation (README, docstrings, config comments) if you change behavior or add options.

### 5. Verify your changes

Run the CLI to confirm nothing is broken:

```bash
skill-sentinel scan --help
skill-sentinel scan --skill .   # Optional: quick scan of repo root
```

### 6. Submit a pull request

1. Push your branch to your fork.
2. Open a pull request against the `main` branch of `enkryptai/skill-sentinel`.
3. Describe what you changed and why; link any related issues.
4. Ensure the CLA is agreed to (see [CLA.md](CLA.md)).

Maintainers will review and may request changes. Once approved, your PR can be merged.

## Project structure

```
skill-sentinel/
├── pyproject.toml           # Package config and dependencies
├── README.md
├── CLA.md
├── CONTRIBUTING.md
├── LICENSE
└── src/skill_sentinel/
    ├── __init__.py          # Package version
    ├── cli.py               # CLI entry point
    ├── main.py              # Programmatic API (scan)
    ├── crew.py              # Multi-agent crew definition
    ├── config/
    │   ├── agents.yaml      # Agent definitions
    │   └── tasks.yaml       # Task definitions
    ├── data/
    │   ├── threat_categories.md
    │   └── report_schema.json
    └── tools/
        ├── custom_tool.py   # ReadFile & Grep tools
        ├── file_discovery.py
        └── virustotal_tool.py
```

- **New agents or tasks:** Edit `config/agents.yaml` and `config/tasks.yaml`, and wire them in `crew.py`.
- **New tools:** Add under `tools/` and register in the crew.
- **Threat taxonomy or report shape:** Update `data/threat_categories.md` and `data/report_schema.json` as needed.

## Questions or issues?

- Open an [issue](https://github.com/enkryptai/skill-sentinel/issues) for bugs, feature ideas, or questions.
- For security-sensitive findings, consider reporting privately to the maintainers if appropriate.

Thanks for contributing.
