#!/usr/bin/env python
"""
CLI entry point for enkryptai-skill-scanner.

Usage:
    enkryptai-skill-scanner scan <skill_directory> [-o report.json] [--model gpt-4.1]
"""

import argparse
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore", category=SyntaxWarning, module="pysbd")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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


def _append_metadata(
    report_path: str, crew_instance, elapsed_seconds: float
) -> None:
    """Read the report JSON, inject token usage and scan duration, write back."""
    try:
        with open(report_path, "r") as f:
            raw = f.read().strip()

        try:
            report_data = json.loads(raw)
        except json.JSONDecodeError:
            # Attempt to recover a valid JSON prefix
            last_brace = raw.rfind("}")
            if last_brace != -1:
                report_data = json.loads(raw[: last_brace + 1])
            else:
                raise

        report_data["token_usage"] = json.loads(
            crew_instance.usage_metrics.model_dump_json()
        )

        mins, secs = divmod(int(elapsed_seconds), 60)
        report_data["scan_duration"] = {
            "seconds": round(elapsed_seconds, 1),
            "display": f"{mins}m {secs}s",
        }

        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2)

    except Exception as e:
        print(
            f"\n[SkillScanner] Warning: Could not append metadata to report: {e}"
        )


def _print_summary(report_path: str, elapsed_seconds: float) -> None:
    """Print the overall risk assessment from the report to the console."""
    mins, secs = divmod(int(elapsed_seconds), 60)
    duration_str = f"{mins}m {secs}s"

    try:
        with open(report_path, "r") as f:
            report = json.load(f)
    except Exception:
        print(f"\n[SkillScanner] Done ({duration_str}). Report written to {report_path}")
        return

    risk = report.get("overall_risk_assessment", {})
    verdict = risk.get("skill_verdict", "UNKNOWN")
    risk_level = risk.get("risk_level", "UNKNOWN")
    summary = risk.get("summary", "")
    top_priority = risk.get("top_priority", "")
    reasoning = risk.get("verdict_reasoning", "")

    findings = report.get("validated_findings", [])

    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE — Verdict: {verdict}")
    print("=" * 60)
    print(f"  Risk Level:    {risk_level}")
    print(f"  Findings:      {len(findings)} confirmed threat(s)")
    print(f"  Scan Time:     {duration_str}")
    if summary:
        print(f"  Summary:       {summary}")
    if top_priority:
        print(f"  Top Priority:  {top_priority}")
    if reasoning:
        print(f"  Reasoning:     {reasoning}")
    print("-" * 60)
    print(f"  Detailed report: {report_path}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# scan command
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> None:
    """Execute the skill-scanner crew against the given directory."""
    # ------------------------------------------------------------------
    # Load .env from the package repo root (won't override existing env vars)
    # ------------------------------------------------------------------
    from dotenv import load_dotenv

    _PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    )))
    load_dotenv(os.path.join(_PACKAGE_ROOT, ".env"), override=False)

    # ------------------------------------------------------------------
    # Validate API key early, before heavy imports
    # ------------------------------------------------------------------
    api_key = args.api_key or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        print(
            "Error: OpenAI API key not found.\n"
            "Set it via:  export OPENAI_API_KEY='sk-...'\n"
            "Or pass:     --api-key sk-...",
            file=sys.stderr,
        )
        sys.exit(1)

    os.environ["OPENAI_API_KEY"] = api_key

    # ------------------------------------------------------------------
    # Set model (env var is how CrewAI / litellm pick it up)
    # ------------------------------------------------------------------
    model = args.model or os.environ.get("OPENAI_MODEL_NAME", "gpt-4.1")
    os.environ["OPENAI_MODEL_NAME"] = model

    # ------------------------------------------------------------------
    # Heavy imports after env is configured
    # ------------------------------------------------------------------
    from skill_scanner.crew import SkillScanner  # noqa: E402
    from skill_scanner.tools.file_discovery import discover_skill_files  # noqa: E402

    skill_directory = os.path.abspath(args.skill_directory)
    output_path = os.path.abspath(args.output)

    # CrewAI's Task.output_file joins the path with cwd, so we must pass
    # a relative path to avoid nested directory creation.
    output_relpath = os.path.relpath(output_path)

    # 1. Static file discovery
    file_info = discover_skill_files(skill_directory)

    if file_info["skill_md_path"] is None:
        print(
            f"Error: No SKILL.md found in '{skill_directory}'. "
            "Are you sure this is an Agent Skill package?",
            file=sys.stderr,
        )
        sys.exit(1)

    # 2. Load bundled knowledge files
    knowledge = _load_knowledge()

    # 3. Determine whether file verification is needed
    has_other_files = bool(
        file_info["script_files"] or file_info["markdown_files"]
    )

    # 4. Build crew inputs
    inputs = {
        "skill_directory": file_info["skill_directory"],
        "skill_md_path": file_info["skill_md_path"],
        "file_discovery_results": json.dumps(file_info, indent=2),
        "threat_categories": knowledge["threat_categories"],
        "report_schema": knowledge["report_schema"],
    }

    # 5. Print summary
    print(f"[SkillScanner] Model:          {model}")
    print(f"[SkillScanner] Scanning:       {inputs['skill_directory']}")
    print(f"[SkillScanner] SKILL.md:       {inputs['skill_md_path']}")
    print(
        f"[SkillScanner] Files found:    {len(file_info['all_files'])}"
    )
    print(f"[SkillScanner] Script files:   {len(file_info['script_files'])}")
    if not has_other_files:
        print(
            "[SkillScanner] No script/reference files -- "
            "skipping file verification"
        )
    print(f"[SkillScanner] Output:         {output_path}")
    print()

    # 6. Build crew and run
    scanner = SkillScanner()
    the_crew = scanner.build_crew(
        include_file_verification=has_other_files,
        output_file=output_relpath,
    )

    t_start = time.monotonic()
    the_crew.kickoff(inputs=inputs)
    elapsed = time.monotonic() - t_start

    # 7. Append token usage + scan duration to report
    _append_metadata(output_path, the_crew, elapsed)

    # 8. Print summary
    _print_summary(output_path, elapsed)


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enkryptai-skill-scanner",
        description="Scan an Agent Skill package for security threats.",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- scan sub-command ---
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run the security scanner on a skill directory.",
    )
    scan_parser.add_argument(
        "skill_directory",
        help="Path to the Agent Skill directory to scan.",
    )
    scan_parser.add_argument(
        "-o",
        "--output",
        default="report.json",
        help="Path for the output report (default: report.json).",
    )
    scan_parser.add_argument(
        "-m",
        "--model",
        default=None,
        help=(
            "OpenAI model to use (default: gpt-4.1). "
            "Also settable via OPENAI_MODEL_NAME env var."
        ),
    )
    scan_parser.add_argument(
        "--api-key",
        default=None,
        help=(
            "OpenAI API key. Prefer using the OPENAI_API_KEY env var instead."
        ),
    )

    return parser


def _get_version() -> str:
    try:
        from skill_scanner import __version__

        return __version__
    except Exception:
        return "unknown"


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
