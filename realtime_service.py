"""
Operational hardening utilities for the realtime detection service.

Provides CircuitBreaker for ES push resilience, structured JSON logging,
and health metrics tracking for the detection pipeline.

Used by realtime_service.py to add operational resilience.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Health metrics file
HEALTH_METRICS_PATH: Path = Path("results/health_metrics.json")

# Push buffer for circuit breaker
PUSH_BUFFER_PATH: Path = Path("results/push_buffer.jsonl")

# Default circuit breaker settings
DEFAULT_FAILURE_THRESHOLD: int = 5
DEFAULT_RESET_TIMEOUT_SEC: int = 300


class CircuitBreaker:
    """Circuit breaker for ES push failures.

    After N consecutive push failures, stops pushing for a reset timeout
    period and buffers alerts locally. After timeout, attempts a single
    probe push -- if successful, closes the circuit.
    """

    def __init__(
        self,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        reset_timeout_sec: int = DEFAULT_RESET_TIMEOUT_SEC,
        buffer_path: Path | None = None,
    ) -> None:
        """Initialize the circuit breaker.

        Args:
            failure_threshold: Number of consecutive failures before opening.
            reset_timeout_sec: Seconds to wait before attempting probe push.
            buffer_path: File path for local buffer when circuit is open.
        """
        self._failure_threshold = failure_threshold
        self._reset_timeout_sec = reset_timeout_sec
        self._buffer_path = buffer_path or PUSH_BUFFER_PATH
        self._consecutive_failures: int = 0
        self._state: str = "closed"  # closed, open, half-open
        self._opened_at: float = 0.0

    @property
    def state(self) -> str:
        """Return current circuit state.

        Returns:
            One of 'closed', 'open', 'half-open'.
        """
        if self._state == "open":
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self._reset_timeout_sec:
                self._state = "half-open"
        return self._state

    def record_success(self) -> None:
        """Record a successful push, closing the circuit if half-open."""
        self._consecutive_failures = 0
        if self._state in ("half-open", "open"):
            logger.info("Circuit breaker closed after successful push")
        self._state = "closed"

    def record_failure(self) -> None:
        """Record a failed push, potentially opening the circuit."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            if self._state != "open":
                logger.warning(
                    "Circuit breaker OPEN after %d consecutive failures",
                    self._consecutive_failures,
                )
            self._state = "open"
            self._opened_at = time.monotonic()

    def allow_request(self) -> bool:
        """Check whether a push attempt should proceed.

        Returns:
            True if the push should be attempted.
        """
        state = self.state
        if state == "closed":
            return True
        if state == "half-open":
            return True  # Allow probe request
        return False

    def buffer_alert(self, alert: dict[str, Any]) -> None:
        """Write an alert to the local buffer file when circuit is open.

        Args:
            alert: Alert dict to buffer.
        """
        self._buffer_path.parent.mkdir(parents=True, exist_ok=True)
        with self._buffer_path.open("a") as fh:
            fh.write(json.dumps(alert, default=str) + "\n")

    def drain_buffer(self) -> list[dict[str, Any]]:
        """Read and clear the local buffer.

        Returns:
            List of buffered alert dicts.
        """
        if not self._buffer_path.exists():
            return []

        alerts: list[dict[str, Any]] = []
        with self._buffer_path.open() as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        # Clear the buffer
        self._buffer_path.write_text("")
        return alerts

    def to_dict(self) -> dict[str, Any]:
        """Return circuit breaker status as a dict.

        Returns:
            Status dict with state and failure count.
        """
        return {
            "state": self.state,
            "consecutive_failures": self._consecutive_failures,
            "failure_threshold": self._failure_threshold,
            "reset_timeout_sec": self._reset_timeout_sec,
        }


class JSONFormatter(logging.Formatter):
    """Structured JSON logging formatter.

    Produces one JSON object per log line with timestamp, level, module,
    correlation_id, and message fields.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record as a JSON string.

        Args:
            record: Log record from Python's logging module.

        Returns:
            JSON-encoded string.
        """
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "module": record.module,
            "correlation_id": getattr(record, "correlation_id", None),
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = str(record.exc_info[1])
        return json.dumps(log_entry, default=str)


@dataclass
class HealthMetrics:
    """Tracks operational health metrics for the detection pipeline."""

    last_detection_run: str = ""
    last_detection_duration_sec: float = 0.0
    last_push_success_count: int = 0
    last_push_failure_count: int = 0
    last_correlation_chains: int = 0
    es_connection_healthy: bool = True
    model_versions: dict[str, str] = field(default_factory=dict)
    uptime_hours: float = 0.0
    circuit_breaker_state: str = "closed"
    _start_time: float = field(default_factory=time.monotonic)

    def update_detection(
        self, duration_sec: float, push_ok: int, push_fail: int, chains: int,
    ) -> None:
        """Update metrics after a detection cycle.

        Args:
            duration_sec: Wall-clock duration of the detection cycle.
            push_ok: Number of successfully pushed alerts.
            push_fail: Number of failed push attempts.
            chains: Number of correlation chains produced.
        """
        self.last_detection_run = datetime.now(timezone.utc).isoformat()
        self.last_detection_duration_sec = round(duration_sec, 2)
        self.last_push_success_count = push_ok
        self.last_push_failure_count = push_fail
        self.last_correlation_chains = chains

    def update_uptime(self) -> None:
        """Recompute uptime from start time."""
        self.uptime_hours = round(
            (time.monotonic() - self._start_time) / 3600.0, 2
        )

    def write(self, path: Path | None = None) -> None:
        """Write metrics to a JSON file.

        Args:
            path: Output path (default: results/health_metrics.json).
        """
        out = path or HEALTH_METRICS_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        self.update_uptime()
        data = {
            "last_detection_run": self.last_detection_run,
            "last_detection_duration_sec": self.last_detection_duration_sec,
            "last_push_success_count": self.last_push_success_count,
            "last_push_failure_count": self.last_push_failure_count,
            "last_correlation_chains": self.last_correlation_chains,
            "es_connection_healthy": self.es_connection_healthy,
            "model_versions": self.model_versions,
            "uptime_hours": self.uptime_hours,
            "circuit_breaker_state": self.circuit_breaker_state,
        }
        out.write_text(json.dumps(data, indent=2, default=str))

    @classmethod
    def load(cls, path: Path | None = None) -> "HealthMetrics":
        """Load metrics from a JSON file.

        Args:
            path: Input path (default: results/health_metrics.json).

        Returns:
            HealthMetrics instance.
        """
        inp = path or HEALTH_METRICS_PATH
        metrics = cls()
        if inp.exists():
            try:
                data = json.loads(inp.read_text())
                metrics.last_detection_run = data.get("last_detection_run", "")
                metrics.last_detection_duration_sec = data.get(
                    "last_detection_duration_sec", 0.0
                )
                metrics.last_push_success_count = data.get(
                    "last_push_success_count", 0
                )
                metrics.last_push_failure_count = data.get(
                    "last_push_failure_count", 0
                )
                metrics.last_correlation_chains = data.get(
                    "last_correlation_chains", 0
                )
                metrics.es_connection_healthy = data.get(
                    "es_connection_healthy", True
                )
                metrics.model_versions = data.get("model_versions", {})
                metrics.circuit_breaker_state = data.get(
                    "circuit_breaker_state", "closed"
                )
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("Failed to load health metrics: %s", exc)
        return metrics
