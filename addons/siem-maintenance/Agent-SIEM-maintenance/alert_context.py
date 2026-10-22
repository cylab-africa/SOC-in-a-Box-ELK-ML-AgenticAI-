#!/usr/bin/env python3
"""Alert context store for the feedback refinement loop.

Persists alert metadata so that incoming feedback events (card clicks or
thread replies) can be correlated back to the original alert payload.
Uses a JSON file with TTL-based expiry, consistent with the project's
file-based state management pattern.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

LOG = logging.getLogger("alert_context")

RESULTS_DIR = Path(__file__).resolve().parent / "results"
ALERT_CONTEXT_PATH = RESULTS_DIR / "feedback_alert_context.json"
DEFAULT_TTL_HOURS = int(os.getenv("FEEDBACK_CONTEXT_TTL_HOURS", "72"))


def generate_alert_id() -> str:
    """Generate a short, unique alert ID (8-char hex from uuid4).

    Returns:
        An 8-character hex string.
    """
    return uuid.uuid4().hex[:8]


def save_alert_context(
    alert_id: str,
    scenario: str,
    issues: List[Dict[str, Any]],
    recommendations: Optional[List[str]],
    llm_analysis: Optional[Dict[str, Any]],
    card_title: str,
    thread_name: Optional[str] = None,
) -> None:
    """Persist alert context for later correlation with feedback events.

    Args:
        alert_id: Unique identifier for this alert.
        scenario: Alert scenario category (e.g. 'shutdown', 'ingest').
        issues: List of issue dicts from the health check.
        recommendations: Static recommendations list, if any.
        llm_analysis: LLM-generated analysis dict, if any.
        card_title: Title of the Google Chat card.
        thread_name: Google Chat thread name for reply correlation.
    """
    RESULTS_DIR.mkdir(exist_ok=True)
    store = _load_store()

    store[alert_id] = {
        "alert_id": alert_id,
        "scenario": scenario,
        "issues": issues,
        "recommendations": recommendations,
        "llm_analysis": llm_analysis,
        "card_title": card_title,
        "thread_name": thread_name,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    _save_store(store)
    LOG.info("Saved alert context: alert_id=%s scenario=%s", alert_id, scenario)


def load_alert_context(alert_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve alert context by alert_id.

    Args:
        alert_id: The alert identifier to look up.

    Returns:
        The alert context dict, or None if not found or expired.
    """
    store = _load_store()
    entry = store.get(alert_id)
    if entry is None:
        return None

    created = datetime.fromisoformat(entry["created_at"])
    if datetime.now(timezone.utc) - created > timedelta(hours=DEFAULT_TTL_HOURS):
        LOG.debug("Alert context expired: alert_id=%s", alert_id)
        return None

    return entry


def find_context_by_thread(thread_name: str) -> Optional[Dict[str, Any]]:
    """Find the most recent alert context associated with a Google Chat thread.

    Args:
        thread_name: The Google Chat thread name (e.g. 'spaces/.../threads/...').

    Returns:
        The matching alert context dict, or None if not found.
    """
    store = _load_store()
    matches: List[Dict[str, Any]] = []

    for entry in store.values():
        if entry.get("thread_name") == thread_name:
            created = datetime.fromisoformat(entry["created_at"])
            if datetime.now(timezone.utc) - created <= timedelta(hours=DEFAULT_TTL_HOURS):
                matches.append(entry)

    if not matches:
        return None

    matches.sort(key=lambda e: e["created_at"], reverse=True)
    return matches[0]


def cleanup_expired_contexts(ttl_hours: Optional[int] = None) -> int:
    """Remove alert contexts older than the TTL.

    Args:
        ttl_hours: Override TTL in hours. Defaults to FEEDBACK_CONTEXT_TTL_HOURS.

    Returns:
        Number of expired entries removed.
    """
    ttl = ttl_hours if ttl_hours is not None else DEFAULT_TTL_HOURS
    store = _load_store()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl)
    original_count = len(store)

    store = {
        aid: entry for aid, entry in store.items()
        if datetime.fromisoformat(entry["created_at"]) > cutoff
    }

    removed = original_count - len(store)
    if removed > 0:
        _save_store(store)
        LOG.info("Cleaned up %d expired alert context(s)", removed)
    return removed


def _load_store() -> Dict[str, Any]:
    """Load the alert context JSON file."""
    if not ALERT_CONTEXT_PATH.exists():
        return {}
    try:
        with open(ALERT_CONTEXT_PATH, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            data = json.load(f)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as e:
        LOG.warning("Failed to load alert context store: %s", e)
        return {}


def _save_store(store: Dict[str, Any]) -> None:
    """Atomically save the alert context JSON file."""
    RESULTS_DIR.mkdir(exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(RESULTS_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            json.dump(store, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(ALERT_CONTEXT_PATH))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
