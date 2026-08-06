"""
Graduated allowlist management for FP/FN tuning.

Replaces binary allow/block with score dampening factors so that
allowlisted processes still generate alerts if their score is high enough.

ATT&CK techniques guarded against suppression:
  T1059 (Command and Scripting Interpreter),
  T1105 (Ingress Tool Transfer),
  T1046 (Network Service Scanning),
  T1548 (Abuse Elevation Control Mechanism)
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Results directory for hit logging
ALLOWLIST_HITS_LOG: Path = Path("results/allowlist_hits.jsonl")

# Days without a hit before an entry is flagged for review
STALE_ENTRY_DAYS: int = 90

# LOLBins — never dampen regardless of any allowlist entry.
# These binaries are too commonly abused (T1059, T1105, T1046, T1548) to mute.
NEVER_ALLOWLIST: list[str] = [
    "sudo", "ssh", "scp", "curl", "wget", "python", "python3",
    "perl", "ruby", "bash", "sh", "zsh", "nc", "ncat", "netcat",
    "socat", "awk", "sed", "dd", "tar", "gzip", "base64",
    "openssl", "nmap", "tcpdump", "strace", "ltrace", "gdb",
    "chmod", "chown", "crontab", "at", "systemctl",
    "php", "chattr", "xxd", "nsenter", "unshare", "xargs",
]


@dataclass
class AllowlistEntry:
    """A single graduated allowlist entry with dampening semantics."""

    pattern: str
    match_type: str  # "exact", "prefix", "regex"
    dampening_factor: float  # multiply raw score by this value (0.0–1.0)
    category: str  # "infrastructure", "monitoring", "system", "custom"
    created_at: datetime
    expires_at: Optional[datetime] = None  # None = permanent
    hit_count: int = 0
    last_hit: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Return True if this entry has passed its expiry date."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def is_stale(self) -> bool:
        """Return True if the entry has had no hits in STALE_ENTRY_DAYS days."""
        if self.last_hit is None:
            age = datetime.now(timezone.utc) - self.created_at
            return age.days >= STALE_ENTRY_DAYS
        age = datetime.now(timezone.utc) - self.last_hit
        return age.days >= STALE_ENTRY_DAYS

    def matches(self, value: str) -> bool:
        """Return True if this entry matches the given value string."""
        if self.match_type == "exact":
            return value == self.pattern
        if self.match_type == "prefix":
            return value.startswith(self.pattern)
        if self.match_type == "regex":
            return bool(re.search(self.pattern, value))
        return False


# Default built-in entries — infrastructure / monitoring noise
DEFAULT_ALLOWLIST: list[AllowlistEntry] = [
    AllowlistEntry(
        pattern="systemd",
        match_type="prefix",
        dampening_factor=0.3,
        category="system",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ),
    AllowlistEntry(
        pattern=r"^(auditd|sshd|rsyslogd|chronyd|crond)$",
        match_type="regex",
        dampening_factor=0.35,
        category="system",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ),
    AllowlistEntry(
        pattern=r"^(prometheus|node_exporter|telegraf|filebeat|metricbeat)$",
        match_type="regex",
        dampening_factor=0.4,
        category="monitoring",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ),
    AllowlistEntry(
        pattern=r"^(puppet|chef-client|ansible|saltstack)$",
        match_type="regex",
        dampening_factor=0.45,
        category="infrastructure",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    ),
]


class AllowlistManager:
    """Manages graduated allowlist entries and applies score dampening."""

    def __init__(self, extra_entries: Optional[list[AllowlistEntry]] = None) -> None:
        """Initialise with default entries plus any caller-supplied extras."""
        self._entries: list[AllowlistEntry] = list(DEFAULT_ALLOWLIST)
        if extra_entries:
            self._entries.extend(extra_entries)
        ALLOWLIST_HITS_LOG.parent.mkdir(parents=True, exist_ok=True)

    def add_entry(self, entry: AllowlistEntry) -> None:
        """Append a new allowlist entry at runtime."""
        self._entries.append(entry)

    def apply(self, process_name: str, raw_score: float) -> tuple[float, dict]:
        """
        Apply allowlist dampening to a raw anomaly score.

        Returns the (possibly dampened) score and a trace dict describing
        what happened.  If the process is in NEVER_ALLOWLIST no dampening
        is applied.
        """
        trace: dict = {
            "allowlist_checked": True,
            "allowlist_match": None,
            "dampening_applied": 1.0,
            "original_score": raw_score,
            "dampened_score": raw_score,
            "lolbin_protected": False,
        }

        if process_name in NEVER_ALLOWLIST:
            trace["lolbin_protected"] = True
            logger.debug(
                "LOLBin protection: skipping allowlist for %s", process_name
            )
            return raw_score, trace

        for entry in self._entries:
            if entry.is_expired():
                logger.info(
                    "Skipping expired allowlist entry: pattern=%s expires=%s",
                    entry.pattern,
                    entry.expires_at,
                )
                continue

            if entry.is_stale():
                logger.warning(
                    "Stale allowlist entry flagged for review: pattern=%s last_hit=%s",
                    entry.pattern,
                    entry.last_hit,
                )

            if entry.matches(process_name):
                dampened = raw_score * entry.dampening_factor
                entry.hit_count += 1
                entry.last_hit = datetime.now(timezone.utc)

                trace["allowlist_match"] = entry.pattern
                trace["dampening_applied"] = entry.dampening_factor
                trace["dampened_score"] = dampened

                self._log_hit(process_name, entry, raw_score, dampened)
                return dampened, trace

        return raw_score, trace

    def flag_stale_entries(self) -> list[AllowlistEntry]:
        """Return all entries that are stale and should be reviewed."""
        return [e for e in self._entries if not e.is_expired() and e.is_stale()]

    def _log_hit(
        self,
        process_name: str,
        entry: AllowlistEntry,
        original_score: float,
        dampened_score: float,
    ) -> None:
        """Append a JSON line to the allowlist hits log."""
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "process_name": process_name,
            "pattern": entry.pattern,
            "match_type": entry.match_type,
            "category": entry.category,
            "dampening_factor": entry.dampening_factor,
            "original_score": original_score,
            "dampened_score": dampened_score,
            "hit_count": entry.hit_count,
        }
        try:
            with ALLOWLIST_HITS_LOG.open("a") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:
            logger.warning("Failed to write allowlist hit log: %s", exc)
