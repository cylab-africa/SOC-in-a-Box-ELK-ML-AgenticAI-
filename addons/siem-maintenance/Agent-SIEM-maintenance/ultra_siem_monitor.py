#!/usr/bin/env python3
"""Scheduled SIEM health / executive report CLI.

Invoked by ``maintenance_service.py`` (scheduled morning report) or run directly.
Composes ``enhanced_health_monitor.py`` for the daily SIEM maintenance Chat report.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


def _load_env_files() -> None:
    """Load repo root ``../.env`` first, then ``./.env`` in this directory (overrides)."""
    here = Path(__file__).resolve().parent
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:
        return
    load_dotenv(here.parent / ".env", override=False)
    load_dotenv(here / ".env", override=True)


def main() -> int:
    _load_env_files()
    parser = argparse.ArgumentParser(description="SIEM scheduled health report (wrapper)")
    parser.add_argument("--mode", default="daily-report", choices=["daily-report"])
    parser.add_argument(
        "--format",
        default="html",
        help="When 'html', writes results/daily_health_report_latest.html pointing at the latest JSON artifact",
    )
    parser.add_argument(
        "--alert",
        action="store_true",
        help="Allow Google Chat notification from enhanced_health_monitor (threshold: warning+)",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    here = Path(__file__).resolve().parent
    py = sys.executable
    enhanced = here / "enhanced_health_monitor.py"

    if args.mode != "daily-report":
        return 0

    cmd = [
        py,
        str(enhanced),
        "--analyze-alerts",
        "--llm-model",
        os.getenv("LLM_MODEL", "gpt-4o-mini"),
        "--send-alert-threshold",
        "warning",
    ]
    if not args.alert:
        cmd.append("--no-chat")
    if args.dry_run:
        cmd.append("--dry-run")

    if args.dry_run:
        print("[dry-run] would run:", " ".join(cmd))
        return 0

    proc = subprocess.run(cmd, cwd=str(here))
    if proc.returncode != 0:
        return proc.returncode

    if args.format == "html":
        _write_latest_report_index(here)
    return 0


def _write_latest_report_index(here: Path) -> None:
    results = here / "results"
    if not results.is_dir():
        return
    files = sorted(
        results.glob("health_analysis_*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not files:
        return
    latest = files[0].name
    html = results / "daily_health_report_latest.html"
    html.write_text(
        "<!DOCTYPE html><html><head><meta charset='utf-8'/>"
        "<title>Daily SIEM health</title></head><body>"
        f"<h1>Daily SIEM health report</h1><p>Latest artifact: "
        f"<a href=\"{latest}\">{latest}</a></p></body></html>\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    raise SystemExit(main())
