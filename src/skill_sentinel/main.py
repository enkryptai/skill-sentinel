#!/usr/bin/env python
"""
Programmatic helpers for the SkillScanner CrewAI crew.

The primary user-facing entry point is ``skill_sentinel.cli:main``
(registered as the ``skill-sentinel`` console script).

This module provides a simple ``scan()`` function for use as a library.
"""

import json
import os
import warnings

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")

from skill_sentinel.crew import SkillScanner
from skill_sentinel.tools.file_discovery import discover_skill_files

# The bundled data directory lives next to this file at install time.
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def _load_knowledge() -> dict:
    """Load threat categories and report schema bundled with the package."""
    with open(os.path.join(_DATA_DIR, "threat_categories.md"), "r") as f:
        threat_categories = f.read()
    with open(os.path.join(_DATA_DIR, "report_schema.json"), "r") as f:
        report_schema = f.read()
    return {
        "threat_categories": threat_categories,
        "report_schema": report_schema,
    }


def _append_token_usage(report_path: str, crew_instance) -> None:
    """Read the report JSON, inject crew usage_metrics, and write back."""
    try:
        with open(report_path, "r") as f:
            raw = f.read().strip()

        try:
            report_data = json.loads(raw)
        except json.JSONDecodeError:
            last_brace = raw.rfind("}")
            if last_brace != -1:
                report_data = json.loads(raw[: last_brace + 1])
            else:
                raise

        report_data["token_usage"] = json.loads(
            crew_instance.usage_metrics.model_dump_json()
        )

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)
    except Exception as e:
        print(
            f"[Skill Sentinel] Warning: Could not append token usage: {e}"
        )


def scan(
    skill_directory: str,
    output_path: str = "report.json",
    model: str | None = None,
) -> dict:
    """
    Run the skill scanner programmatically.

    Args:
        skill_directory: Path to the Agent Skill directory.
        output_path: Where to write the JSON report.
        model: OpenAI model name (default: gpt-4.1 or OPENAI_MODEL_NAME env).

    Returns:
        The parsed report dict.
    """
    if model:
        os.environ["OPENAI_MODEL_NAME"] = model

    skill_directory = os.path.abspath(skill_directory)
    output_path = os.path.abspath(output_path)

    # CrewAI's Task.output_file joins the path with cwd, so pass a
    # relative path to avoid nested directory creation.
    output_relpath = os.path.relpath(output_path)

    file_info = discover_skill_files(skill_directory)

    if file_info["skill_md_path"] is None:
        raise FileNotFoundError(
            f"No SKILL.md found in '{skill_directory}'. "
            "Are you sure this is an Agent Skill package?"
        )

    knowledge = _load_knowledge()

    has_other_files = bool(
        file_info["script_files"] or file_info["markdown_files"]
    )

    inputs = {
        "skill_directory": file_info["skill_directory"],
        "skill_md_path": file_info["skill_md_path"],
        "file_discovery_results": json.dumps(file_info, indent=2),
        "threat_categories": knowledge["threat_categories"],
        "report_schema": knowledge["report_schema"],
    }

    scanner = SkillScanner()
    the_crew = scanner.build_crew(
        include_file_verification=has_other_files,
        output_file=output_relpath,
    )
    the_crew.kickoff(inputs=inputs)

    _append_token_usage(output_path, the_crew)

    with open(output_path, "r") as f:
        return json.load(f)
