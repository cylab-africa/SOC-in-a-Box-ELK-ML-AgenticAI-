#!/usr/bin/env python3
"""SIEM maintenance scheduler — one process for morning Chat reports + periodic health polls.

What it does
------------
1. **Daily morning report** (default 08:30 local): runs ``ultra_siem_monitor.py --alert``,
   which calls ``enhanced_health_monitor.py --analyze-alerts``. That gathers cluster +
   ingestion facts, asks the LLM for recommendations, and posts a Google Chat card
   (``GC_ALERT_WEBHOOK``).
2. **Periodic SIEM poll**: runs ``es_health_monitor.py`` on a timer. That checks
   Elasticsearch health, freshness, shards, etc., and posts Chat alerts when needed
   (subject to ``ES_ALERT_COOLDOWN_HOURS`` inside that script).

LLM routing (same as ``enhanced_health_monitor``)
-------------------------------------------------
- ``LLM_MODEL`` starting with ``gpt-`` → OpenAI (needs ``OPENAI_API_KEY``).
- Any other model name → **Ollama** at ``OLLAMA_URL`` (e.g. ``LLM_MODEL=llama3.2``).

Environment
-----------
Loads ``../.env`` then ``./.env`` (latter overrides). Important keys:

- ``DAILY_REPORT_TIME_CAT`` — ``HH:MM`` for the morning job (default ``08:30``).
- ``MAINTENANCE_IANA_TIMEZONE`` — IANA zone for that wall clock (default ``Africa/Johannesburg``, CAT-aligned).
- ``SIEM_HEALTH_POLL_INTERVAL_SECONDS`` — optional override; else ``ES_HEALTH_MONITOR_INTERVAL_SECONDS``, else 7200.
- ``AUTO_REMEDIATION_INTERVAL_HOURS`` — auto-fix cadence (default ``12``; set ``0`` to disable).
- ``AUTO_REMEDIATION_DRY_RUN`` — ``true`` to schedule in dry-run mode (default ``false``).

Usage
-----
::

    cd Agent-SIEM-maintenance
    python maintenance_service.py

One-shot (no scheduler)::

    python maintenance_service.py --once-daily       # morning report now
    python maintenance_service.py --once-poll        # ES health check now
    python maintenance_service.py --once-remediate   # auto-remediation pass now
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path


def _here() -> Path:
    return Path(__file__).resolve().parent


def load_env() -> None:
    here = _here()
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(here.parent / ".env", override=False)
    load_dotenv(here / ".env", override=True)


def run_daily_report() -> None:
    log = logging.getLogger("maintenance_service")
    py = sys.executable
    here = _here()
    cmd = [
        py,
        str(here / "ultra_siem_monitor.py"),
        "--mode",
        "daily-report",
        "--format",
        "html",
        "--alert",
    ]
    log.info("Scheduled job: morning maintenance report")
    proc = subprocess.run(cmd, cwd=str(here))
    log.info("Morning report finished with exit code %s", proc.returncode)


def run_health_poll() -> None:
    log = logging.getLogger("maintenance_service")
    py = sys.executable
    here = _here()
    cmd = [py, str(here / "es_health_monitor.py")]
    log.info("Scheduled job: SIEM health poll")
    proc = subprocess.run(cmd, cwd=str(here))
    log.info("Health poll finished with exit code %s", proc.returncode)


def run_auto_remediation() -> None:
    log = logging.getLogger("maintenance_service")
    py = sys.executable
    here = _here()
    dry = os.getenv("AUTO_REMEDIATION_DRY_RUN", "false").lower() in ("1", "true", "yes", "on")
    cmd = [py, str(here / "auto_remediate.py"), "--auto-fix"]
    if dry:
        cmd.append("--dry-run")
    log.info("Scheduled job: auto-remediation pass (dry_run=%s)", dry)
    proc = subprocess.run(cmd, cwd=str(here))
    log.info("Auto-remediation finished with exit code %s", proc.returncode)



def _parse_remediation_time() -> tuple[int, int]:
    """Return (hour, minute) for the daily auto-remediation run.

    Uses AUTO_REMEDIATION_TIME if set, otherwise defaults to
    DAILY_REPORT_TIME_CAT + 5 minutes so remediation acts on
    issues the report just detected.
    """
    raw = os.getenv("AUTO_REMEDIATION_TIME", "").strip()
    if raw:
        try:
            parts = raw.replace(".", ":").split(":")
            return int(parts[0]) % 24, int(parts[1]) % 60
        except (ValueError, IndexError):
            pass

    report_hour, report_minute = _parse_report_time()
    rem_minute = report_minute + 5
    rem_hour = report_hour
    if rem_minute >= 60:
        rem_minute -= 60
        rem_hour = (rem_hour + 1) % 24
    return rem_hour, rem_minute


def _parse_report_time() -> tuple[int, int]:
    time_str = os.getenv("DAILY_REPORT_TIME_CAT", "08:30").strip()
    try:
        parts = time_str.replace(".", ":").split(":")
        hour, minute = int(parts[0]), int(parts[1])
        return hour % 24, minute % 60
    except (ValueError, IndexError):
        return 8, 30


def _poll_interval_seconds() -> int:
    raw = os.getenv("SIEM_HEALTH_POLL_INTERVAL_SECONDS") or os.getenv(
        "ES_HEALTH_MONITOR_INTERVAL_SECONDS",
        "7200",
    )
    try:
        sec = int(raw)
    except ValueError:
        sec = 7200
    return max(60, sec)


def _scheduler_timezone():
    tz_name = os.getenv("MAINTENANCE_IANA_TIMEZONE", "Africa/Johannesburg")
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(tz_name), tz_name
    except Exception:
        from datetime import timezone, timedelta

        return timezone(timedelta(hours=2)), f"UTC+2 fallback ({tz_name} unavailable)"


def main() -> int:
    load_env()

    parser = argparse.ArgumentParser(description="SIEM maintenance scheduler (daily Chat + health polls)")
    parser.add_argument(
        "--once-daily",
        action="store_true",
        help="Run the morning report once and exit (no scheduler)",
    )
    parser.add_argument(
        "--once-poll",
        action="store_true",
        help="Run es_health_monitor once and exit (no scheduler)",
    )
    parser.add_argument(
        "--once-remediate",
        action="store_true",
        help="Run auto_remediate.py --auto-fix once and exit (no scheduler)",
    )
    parser.add_argument(
        "--start-feedback-server",
        action="store_true",
        help="Also start feedback_server.py as a subprocess (Google Chat webhook receiver)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    log = logging.getLogger("maintenance_service")

    if args.once_daily:
        run_daily_report()
        return 0
    if args.once_poll:
        run_health_poll()
        return 0
    if args.once_remediate:
        run_auto_remediation()
        return 0

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        from apscheduler.triggers.cron import CronTrigger
        from apscheduler.triggers.interval import IntervalTrigger
    except ImportError:
        log.error("Install apscheduler: pip install apscheduler")
        return 1

    hour, minute = _parse_report_time()
    poll_sec = _poll_interval_seconds()
    tz, tz_label = _scheduler_timezone()

    sched = BackgroundScheduler(timezone=tz)
    sched.add_job(
        run_daily_report,
        CronTrigger(hour=hour, minute=minute, timezone=tz),
        id="morning_maintenance_report",
        misfire_grace_time=3600,
        coalesce=True,
        max_instances=1,
    )
    sched.add_job(
        run_health_poll,
        IntervalTrigger(seconds=poll_sec),
        id="siem_health_poll",
        misfire_grace_time=min(300, poll_sec),
        coalesce=True,
        max_instances=1,
    )

    r_hour, r_min = _parse_remediation_time()
    sched.add_job(
        run_auto_remediation,
        CronTrigger(hour=r_hour, minute=r_min, timezone=tz),
        id="auto_remediation",
        misfire_grace_time=3600,
        coalesce=True,
        max_instances=1,
    )
    log.info("Auto-remediation scheduled daily at %02d:%02d (%s)", r_hour, r_min, tz_label)

    feedback_proc = None
    if args.start_feedback_server:
        fb_port = os.getenv("FEEDBACK_SERVER_PORT", "8090")
        fb_cmd = [
            sys.executable,
            str(_here() / "feedback_server.py"),
            "--host", "0.0.0.0",
            "--port", fb_port,
        ]
        log.info("Starting feedback server on port %s", fb_port)
        feedback_proc = subprocess.Popen(fb_cmd, cwd=str(_here()))

    sched.start()
    log.info(
        "Maintenance service running — morning report at %02d:%02d (%s); health poll every %ss; "
        "auto-remediation daily at %02d:%02d",
        hour,
        minute,
        tz_label,
        poll_sec,
        r_hour,
        r_min,
    )
    log.info(
        "If the LLM is unavailable, jobs still run with Elasticsearch metrics only (warnings in health monitor logs)."
    )
    log.info(
        "LLM: LLM_MODEL=%r → %s; Ollama URL=%s",
        os.getenv("LLM_MODEL", "gpt-4o-mini"),
        "OpenAI" if str(os.getenv("LLM_MODEL", "")).startswith("gpt-") else "Ollama",
        os.getenv("OLLAMA_URL", "http://localhost:11434"),
    )

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        log.info("Stopping scheduler (SIGINT)")
        sched.shutdown(wait=False)
        if feedback_proc is not None:
            log.info("Stopping feedback server (pid %s)", feedback_proc.pid)
            feedback_proc.terminate()
            feedback_proc.wait(timeout=10)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
