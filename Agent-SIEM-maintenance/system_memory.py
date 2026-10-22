#!/usr/bin/env python3
"""Persistent system memory manager for the feedback refinement loop.

Manages SYSTEM_MEMORY.md with structured sections for active rules, pending
hypotheses, and rejected patterns. Provides atomic reads/writes with file
locking for concurrent access safety.
"""
from __future__ import annotations

import fcntl
import logging
import os
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

LOG = logging.getLogger("system_memory")

SYSTEM_MEMORY_PATH = Path(__file__).resolve().parent / "SYSTEM_MEMORY.md"

PROMOTION_THRESHOLD = int(os.getenv("FEEDBACK_PROMOTION_THRESHOLD", "2"))

_SECTION_ACTIVE = "## Active Rules & Guidelines"
_SECTION_PENDING = "## Pending Hypotheses/Refinements"
_SECTION_REJECTED = "## Rejected Patterns"

_RULE_PATTERN = re.compile(
    r"^- \[(?P<date>[^\]]+)\] "
    r"(?:rule_id=(?P<rule_id>\S+) \| )?"
    r"(?:hypothesis_id=(?P<hyp_id>\S+) \| )?"
    r"(?:REJECTED: )?"
    r"(?P<text>.+?)(?:\s*\((?:confirmed|feedback_count): (?P<count>\d+)"
    r"(?:, source: (?P<sources>[^)]+))?\))?\s*$"
)


@dataclass
class MemoryRule:
    """A single rule/hypothesis/rejection entry in system memory."""

    rule_id: str
    text: str
    created_at: str
    feedback_count: int = 1
    source_alert_ids: List[str] = field(default_factory=list)


@dataclass
class SystemMemory:
    """Parsed representation of SYSTEM_MEMORY.md."""

    active_rules: List[MemoryRule] = field(default_factory=list)
    pending_hypotheses: List[MemoryRule] = field(default_factory=list)
    rejected_patterns: List[MemoryRule] = field(default_factory=list)


def _parse_rules(lines: List[str]) -> List[MemoryRule]:
    """Parse rule entries from markdown list lines."""
    rules: List[MemoryRule] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("<!--") or line.startswith("#"):
            continue
        m = _RULE_PATTERN.match(line)
        if m:
            rule_id = m.group("rule_id") or m.group("hyp_id") or ""
            sources_str = m.group("sources") or ""
            sources = [s.strip() for s in sources_str.split(",") if s.strip()] if sources_str else []
            rules.append(MemoryRule(
                rule_id=rule_id,
                text=m.group("text").strip(),
                created_at=m.group("date"),
                feedback_count=int(m.group("count")) if m.group("count") else 1,
                source_alert_ids=sources,
            ))
        elif line.startswith("- "):
            rules.append(MemoryRule(
                rule_id="",
                text=line[2:].strip(),
                created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                feedback_count=1,
                source_alert_ids=[],
            ))
    return rules


def _format_active_rule(rule: MemoryRule) -> str:
    """Format an active rule as a markdown line."""
    sources = ", ".join(rule.source_alert_ids) if rule.source_alert_ids else ""
    source_part = f", source: {sources}" if sources else ""
    return f"- [{rule.created_at}] rule_id={rule.rule_id} | {rule.text} (confirmed: {rule.feedback_count}{source_part})"


def _format_pending_hypothesis(rule: MemoryRule) -> str:
    """Format a pending hypothesis as a markdown line."""
    sources = ", ".join(rule.source_alert_ids) if rule.source_alert_ids else ""
    source_part = f", source: {sources}" if sources else ""
    return f"- [{rule.created_at}] hypothesis_id={rule.rule_id} | {rule.text} (feedback_count: {rule.feedback_count}{source_part})"


def _format_rejected_pattern(rule: MemoryRule) -> str:
    """Format a rejected pattern as a markdown line."""
    return f"- [{rule.created_at}] REJECTED: {rule.text}"


def read_system_memory() -> SystemMemory:
    """Parse SYSTEM_MEMORY.md into a structured SystemMemory object.

    Returns:
        SystemMemory with parsed sections, or empty SystemMemory if file is missing.
    """
    if not SYSTEM_MEMORY_PATH.exists():
        return SystemMemory()

    try:
        content = _file_locked_read(SYSTEM_MEMORY_PATH)
    except Exception as e:
        LOG.warning("Failed to read SYSTEM_MEMORY.md: %s", e)
        return SystemMemory()

    sections: dict[str, List[str]] = {
        _SECTION_ACTIVE: [],
        _SECTION_PENDING: [],
        _SECTION_REJECTED: [],
    }
    current_section: Optional[str] = None

    for line in content.splitlines():
        stripped = line.strip()
        if stripped in sections:
            current_section = stripped
            continue
        if stripped.startswith("## ") or stripped.startswith("# SYSTEM MEMORY"):
            current_section = None
            continue
        if current_section is not None:
            sections[current_section].append(line)

    return SystemMemory(
        active_rules=_parse_rules(sections[_SECTION_ACTIVE]),
        pending_hypotheses=_parse_rules(sections[_SECTION_PENDING]),
        rejected_patterns=_parse_rules(sections[_SECTION_REJECTED]),
    )


def write_system_memory(memory: SystemMemory) -> None:
    """Atomically write a SystemMemory object to SYSTEM_MEMORY.md.

    Uses write-to-temp + os.replace for atomicity.
    """
    lines = ["# SYSTEM MEMORY", ""]
    lines.append(_SECTION_ACTIVE)
    lines.append("<!-- Rules confirmed by multiple feedback events. Injected into LLM system prompts. -->")
    for rule in memory.active_rules:
        lines.append(_format_active_rule(rule))
    lines.append("")

    lines.append(_SECTION_PENDING)
    lines.append("<!-- Single-feedback-derived rules awaiting confirmation. -->")
    for rule in memory.pending_hypotheses:
        lines.append(_format_pending_hypothesis(rule))
    lines.append("")

    lines.append(_SECTION_REJECTED)
    lines.append("<!-- Patterns contradicted by feedback. Injected as negative constraints. -->")
    for rule in memory.rejected_patterns:
        lines.append(_format_rejected_pattern(rule))
    lines.append("")

    _atomic_write(SYSTEM_MEMORY_PATH, "\n".join(lines))


def initialize_system_memory() -> None:
    """Create SYSTEM_MEMORY.md with empty sections if it does not exist."""
    if not SYSTEM_MEMORY_PATH.exists():
        write_system_memory(SystemMemory())
        LOG.info("Initialized SYSTEM_MEMORY.md at %s", SYSTEM_MEMORY_PATH)


def add_pending_hypothesis(rule: MemoryRule) -> None:
    """Thread-safe append of a new hypothesis to the Pending section.

    Args:
        rule: The hypothesis to add.
    """
    memory = read_system_memory()
    memory.pending_hypotheses.append(rule)
    write_system_memory(memory)
    LOG.info("Added pending hypothesis: %s (rule_id=%s)", rule.text[:80], rule.rule_id)


def promote_hypothesis(rule_id: str) -> bool:
    """Move a pending hypothesis to Active Rules & Guidelines.

    Args:
        rule_id: The hypothesis rule_id to promote.

    Returns:
        True if the hypothesis was found and promoted, False otherwise.
    """
    memory = read_system_memory()
    target: Optional[MemoryRule] = None
    remaining: List[MemoryRule] = []

    for h in memory.pending_hypotheses:
        if h.rule_id == rule_id:
            target = h
        else:
            remaining.append(h)

    if target is None:
        return False

    memory.pending_hypotheses = remaining
    memory.active_rules.append(target)
    write_system_memory(memory)
    LOG.info("Promoted hypothesis to active rule: %s (rule_id=%s)", target.text[:80], rule_id)
    return True


def reject_hypothesis(rule_id: str, reason: str) -> bool:
    """Move a hypothesis or active rule to the Rejected Patterns section.

    Args:
        rule_id: The rule_id to reject.
        reason: Human-readable reason for rejection.

    Returns:
        True if the rule was found and rejected, False otherwise.
    """
    memory = read_system_memory()
    target: Optional[MemoryRule] = None

    new_pending: List[MemoryRule] = []
    for h in memory.pending_hypotheses:
        if h.rule_id == rule_id:
            target = h
        else:
            new_pending.append(h)

    if target is None:
        new_active: List[MemoryRule] = []
        for r in memory.active_rules:
            if r.rule_id == rule_id:
                target = r
            else:
                new_active.append(r)
        memory.active_rules = new_active

    memory.pending_hypotheses = new_pending

    if target is None:
        return False

    target.text = f"{target.text} - Reason: {reason}"
    target.created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    memory.rejected_patterns.append(target)
    write_system_memory(memory)
    LOG.info("Rejected rule: %s (rule_id=%s)", target.text[:80], rule_id)
    return True


def increment_hypothesis_confirmation(rule_id: str, alert_id: str) -> int:
    """Bump feedback_count for a hypothesis and auto-promote if threshold met.

    Args:
        rule_id: The hypothesis to confirm.
        alert_id: The alert that triggered this confirmation.

    Returns:
        The new feedback_count, or 0 if rule_id was not found.
    """
    memory = read_system_memory()

    for h in memory.pending_hypotheses:
        if h.rule_id == rule_id:
            h.feedback_count += 1
            if alert_id not in h.source_alert_ids:
                h.source_alert_ids.append(alert_id)
            new_count = h.feedback_count
            write_system_memory(memory)

            if new_count >= PROMOTION_THRESHOLD:
                promote_hypothesis(rule_id)
                LOG.info("Auto-promoted hypothesis (count=%d >= threshold=%d): %s",
                         new_count, PROMOTION_THRESHOLD, rule_id)
            return new_count

    return 0


def get_active_rules_text() -> str:
    """Return the Active Rules section formatted for prompt injection.

    Returns:
        Newline-separated rules, or empty string if none exist.
    """
    memory = read_system_memory()
    if not memory.active_rules:
        return ""
    return "\n".join(f"- {rule.text}" for rule in memory.active_rules)


def get_rejected_patterns_text() -> str:
    """Return the Rejected Patterns section formatted for prompt injection.

    Returns:
        Newline-separated patterns, or empty string if none exist.
    """
    memory = read_system_memory()
    if not memory.rejected_patterns:
        return ""
    return "\n".join(f"- {rule.text}" for rule in memory.rejected_patterns)


def _atomic_write(path: Path, content: str) -> None:
    """Write content atomically using write-to-temp + os.replace."""
    dir_path = path.parent
    dir_path.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(dir_path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _file_locked_read(path: Path) -> str:
    """Read file content with a shared lock for concurrent access safety."""
    with open(path, "r", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_SH)
        content = f.read()
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    return content
