#!/usr/bin/env python3
"""Realtime detection service for the Linux anomaly detection pipeline.

Features:
- Run continuous or one-shot detection cycles.
- Retrain models every N hours (configurable, default 48h).
- After each cycle, push ML-only anomalies and optionally run
  kill-chain correlation to produce consolidated alerts.
- CircuitBreaker for ES push resilience.
- HealthMetrics tracking for operational monitoring.
- Structured JSON logging for production use.

Usage:
    python realtime_service.py --once          # single cycle then exit
    python realtime_service.py                 # continuous loop
    python realtime_service.py --retrain-now   # force retrain on first cycle
    python realtime_service.py --dry-run       # print commands only
"""

from __future__ import annotations

import argparse
import glob as _glob
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Environment bootstrap
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# The repo root holds .env, config/, results/ and logs/; the code lives in engine/.
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
os.chdir(_PROJECT_ROOT)
_ENV_PATH = os.path.join(_PROJECT_ROOT, ".env")

try:
    from dotenv import load_dotenv as _load_dotenv

    def load_dotenv(dotenv_path: str = _ENV_PATH) -> bool:
        """Load environment variables from .env file."""
        return _load_dotenv(dotenv_path, override=True)
except ImportError:
    def load_dotenv(dotenv_path: str = _ENV_PATH) -> bool:
        """Fallback .env loader when python-dotenv is not installed."""
        try:
            if not os.path.exists(dotenv_path):
                return False
            with open(dotenv_path) as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip().strip('"').strip("'")
                    os.environ[key] = val
            return True
        except Exception:
            return False

load_dotenv()

if not os.environ.get("ES_USERNAME") or not os.environ.get("ES_PASSWORD"):
    print(
        f"WARNING: ES credentials not loaded from {_ENV_PATH} "
        f"(exists={os.path.exists(_ENV_PATH)}). "
        f"Detection cycles will fail to authenticate.",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
_SERVICE_LOG_FILE = os.path.join(_PROJECT_ROOT, "logs", "realtime_service.log")
os.makedirs(os.path.dirname(_SERVICE_LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        # Bounded rotation: keeps recent operational history without ever
        # growing without limit. Do NOT also shell-redirect this process's
        # stdout/stderr to a raw file - that bypasses rotation entirely and
        # is what caused runaway disk usage previously.
        RotatingFileHandler(_SERVICE_LOG_FILE, maxBytes=20 * 1024 * 1024, backupCount=10),
    ],
)
logger = logging.getLogger("realtime_service")

# ---------------------------------------------------------------------------
# Constants and configuration from environment
# ---------------------------------------------------------------------------
ALL_DATA_GROUPS: list[str] = ["process", "network", "user", "discovery", "metadata", "auth", "host"]
DEFAULT_MODEL_GROUPS: list[str] = list(ALL_DATA_GROUPS)
PYEXE: str = sys.executable or "python"


def _str_to_bool(val: Any, default: bool = False) -> bool:
    """Convert string value to boolean."""
    if val is None:
        return default
    return str(val).lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: Any) -> Any:
    """Read an integer from environment."""
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except (ValueError, TypeError):
        logger.warning(f"Environment variable {name}='{v}' is not an integer; using default={default}")
        return default


def _env_float(name: str, default: float) -> float:
    """Read a float from environment."""
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return float(v)
    except (ValueError, TypeError):
        logger.warning(f"Environment variable {name}='{v}' is not a number; using default={default}")
        return default


# Retrain cadence
_retrain_days = _env_int("RETRAIN_INTERVAL_DAYS", None)
RETRAIN_INTERVAL_HOURS: int = (_retrain_days * 24) if _retrain_days is not None else 72
RETRAIN_INTERVAL_HOURS = _env_int("RETRAIN_INTERVAL_HOURS", RETRAIN_INTERVAL_HOURS)

# Detection cycle interval
DETECTION_INTERVAL_SECONDS: int = _env_int("DETECTION_INTERVAL_SECONDS", 300)
if DETECTION_INTERVAL_SECONDS <= 0:
    logger.warning("DETECTION_INTERVAL_SECONDS must be > 0; defaulting to 300")
    DETECTION_INTERVAL_SECONDS = 300

DETECTION_MODE: str = os.getenv("DETECTION_MODE", "comprehensive")
DATA_GROUP: str = os.getenv("DETECTION_DATA_GROUP", "process")

# Correlation
CORRELATION_ENABLED: bool = _str_to_bool(os.getenv("CORRELATION_ENABLED"), True)
CORRELATION_WINDOW_MINUTES: int = _env_int("CORRELATION_WINDOW_MINUTES", 5)

# Cleanup
CLEANUP_ENABLED: bool = _str_to_bool(os.getenv("ML_CLEANUP_ENABLED"), True)
CLEANUP_INTERVAL_HOURS: int = _env_int("ML_CLEANUP_INTERVAL_HOURS", 1)

# Model staleness
MODEL_STALENESS_ENABLED: bool = _str_to_bool(os.getenv("MODEL_STALENESS_ENABLED"), True)
MODEL_STALENESS_HOURS: int = _env_int("MODEL_STALENESS_HOURS", 72)

# Auto-retrain for missing models
AUTO_RETRAIN_MISSING_ENABLED: bool = _str_to_bool(os.getenv("AUTO_RETRAIN_MISSING_ENABLED"), True)
AUTO_RETRAIN_MISSING_THRESHOLD: int = _env_int("AUTO_RETRAIN_MISSING_THRESHOLD", 50)
AUTO_RETRAIN_COOLDOWN_HOURS: int = _env_int("AUTO_RETRAIN_COOLDOWN_HOURS", 6)

# ---------------------------------------------------------------------------
# Health metrics and push buffer paths
# ---------------------------------------------------------------------------
HEALTH_METRICS_PATH: Path = Path("results/health_metrics.json")
PUSH_BUFFER_PATH: Path = Path("results/push_buffer.jsonl")
DEFAULT_FAILURE_THRESHOLD: int = 5
DEFAULT_RESET_TIMEOUT_SEC: int = 300


# ---------------------------------------------------------------------------
# Operational utility classes (CircuitBreaker, JSONFormatter, HealthMetrics)
# ---------------------------------------------------------------------------

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
        self._state: str = "closed"
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
        return state in ("closed", "half-open")

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
                stripped = line.strip()
                if stripped:
                    try:
                        alerts.append(json.loads(stripped))
                    except json.JSONDecodeError:
                        continue
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
    def load(cls, path: Path | None = None) -> HealthMetrics:
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


# ---------------------------------------------------------------------------
# Global mutable state
# ---------------------------------------------------------------------------
missing_model_errors: dict[str, int] = {}
last_auto_retrain_time: dict[str, datetime] = {}
background_trainer_proc: subprocess.Popen | None = None
last_cleanup_time: datetime = datetime.now(timezone.utc) - timedelta(hours=CLEANUP_INTERVAL_HOURS)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _log_cmd(cmd_list: list) -> None:
    """Log a command about to be executed."""
    try:
        joined = shlex.join(cmd_list)
    except Exception:
        joined = " ".join(cmd_list)
    logger.debug(f"Command: {joined}")


def _run_and_stream(cmd_list: list, dry_run: bool = False) -> bool:
    """Run a subprocess and stream stdout/stderr to the logger.

    Args:
        cmd_list: Command and arguments.
        dry_run: If True, log but do not execute.

    Returns:
        True on success (exit code 0), False otherwise.
    """
    _log_cmd(cmd_list)
    if dry_run:
        logger.info("Dry-run enabled: not executing: %s", cmd_list)
        return True

    missing_model_pattern = re.compile(r"Missing model for entity (\S+)")
    no_models_pattern = re.compile(r"No models found for job (v3_linux_\S+)")

    job_to_group = {
        "v3_linux_anomalous_process": "process",
        "v3_linux_anomalous_network": "network",
        "v3_linux_anomalous_user": "user",
        "v3_linux_rare_sudo": "user",
        "v3_linux_rare_user": "user",
        "v3_linux_network_configuration": "discovery",
        "v3_linux_network_connection": "discovery",
        "v3_linux_system_process": "discovery",
        "v3_linux_system_information": "discovery",
        "v3_linux_system_user": "discovery",
        "v3_linux_rare_metadata": "metadata",
    }

    def _infer_group(job_name: str) -> str | None:
        for prefix, group in job_to_group.items():
            if job_name.startswith(prefix):
                return group
        return None

    try:
        env_copy = os.environ.copy()
        env_copy["PYTHONUNBUFFERED"] = "1"
        with subprocess.Popen(
            cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env_copy,
        ) as proc:
            for line in proc.stdout:
                if line is None:
                    continue
                stripped = line.rstrip()
                logger.info(stripped)

                if AUTO_RETRAIN_MISSING_ENABLED:
                    match = missing_model_pattern.search(stripped)
                    if match:
                        record_missing_model_error("process", match.group(1))
                    match = no_models_pattern.search(stripped)
                    if match:
                        group = _infer_group(match.group(1))
                        if group:
                            record_missing_model_error(group, match.group(1))

            proc.wait()
            if proc.returncode != 0:
                logger.error("Process exited with returncode=%s", proc.returncode)
                return False
            return True
    except Exception:
        logger.exception("Failed to run subprocess: %s", cmd_list)
        return False


# ---------------------------------------------------------------------------
# Model management helpers
# ---------------------------------------------------------------------------

def _candidate_model_dirs() -> list:
    """Return candidate directories where models may be stored."""
    cand = []
    configured = os.getenv("MODELS_DIR")
    if configured:
        cand.append(os.path.abspath(configured))
    cand.append(os.path.abspath("./models"))
    cand.append(os.path.abspath("./results/models"))
    cand.append("/tmp/linux_anomaly_models")
    seen: set = set()
    out: list = []
    for p in cand:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def models_exist_for(data_type: str) -> bool:
    """Return True if model files for the given data_type exist."""
    for d in _candidate_model_dirs():
        model_file = os.path.join(d, f"{data_type}_models.joblib")
        if os.path.exists(model_file):
            return True
    return False


def get_model_file_age_hours(data_type: str) -> float | None:
    """Get the age of model files in hours."""
    for d in _candidate_model_dirs():
        model_file = os.path.join(d, f"{data_type}_models.joblib")
        if os.path.exists(model_file):
            try:
                mtime = os.path.getmtime(model_file)
                mtime_dt = datetime.fromtimestamp(mtime, tz=timezone.utc)
                age = datetime.now(timezone.utc) - mtime_dt
                return age.total_seconds() / 3600
            except Exception:
                return None
    return None


def is_model_stale(data_type: str, max_age_hours: int | None = None) -> bool:
    """Check if model files are stale (older than threshold)."""
    if not MODEL_STALENESS_ENABLED:
        return False
    if max_age_hours is None:
        max_age_hours = MODEL_STALENESS_HOURS
    age_hours = get_model_file_age_hours(data_type)
    if age_hours is None:
        return True
    is_old = age_hours > max_age_hours
    if is_old:
        logger.info(f"Model for {data_type} is stale: {age_hours:.1f}h old (threshold: {max_age_hours}h)")
    return is_old


def get_stale_model_groups(groups: list[str] | None = None) -> list[str]:
    """Get list of data groups with stale models."""
    if groups is None:
        groups = DEFAULT_MODEL_GROUPS
    return [g for g in groups if is_model_stale(g)]


def record_missing_model_error(group: str, entity: str | None = None) -> None:
    """Record a missing model error for auto-retrain tracking."""
    global missing_model_errors
    missing_model_errors.setdefault(group, 0)
    missing_model_errors[group] += 1
    logger.debug(f"Missing model error for {group} (entity={entity}): count={missing_model_errors[group]}")


def should_auto_retrain(group: str) -> bool:
    """Check if auto-retrain should be triggered for a group."""
    if not AUTO_RETRAIN_MISSING_ENABLED:
        return False
    error_count = missing_model_errors.get(group, 0)
    if error_count < AUTO_RETRAIN_MISSING_THRESHOLD:
        return False
    last_retrain = last_auto_retrain_time.get(group)
    if last_retrain:
        cooldown = timedelta(hours=AUTO_RETRAIN_COOLDOWN_HOURS)
        if datetime.now(timezone.utc) - last_retrain < cooldown:
            return False
    return True


def _trainer_is_running() -> bool:
    """Return True if a background trainer subprocess is still running.

    Checks both the tracked child process and any externally-launched
    train_models_background.py processes to avoid duplicate trainers.
    """
    global background_trainer_proc
    if background_trainer_proc is not None:
        status = background_trainer_proc.poll()
        if status is None:
            return True
        background_trainer_proc = None

    # Also check for externally-launched trainers (e.g. manual nohup)
    try:
        result = subprocess.run(
            ["pgrep", "-f", "train_models_background.py"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            logger.debug("External trainer process(es) detected: %s", pids)
            return True
    except Exception as exc:
        logger.debug("pgrep check for external trainer failed: %s", exc)
    return False


TRAINER_LOG_PATH: str = os.getenv("TRAINER_LOG_PATH", "logs/trainer.log")


def _start_background_trainer(data_groups: list, dry_run: bool = False) -> bool:
    """Start a non-blocking background trainer via train_models_background.py.

    Uses nohup with log redirect to survive SSH disconnects and avoid
    pipe-buffer deadlocks.  The trainer script has its own checkpoint-resume
    logic so it picks up where it left off after infrastructure failures.
    """
    global background_trainer_proc

    if _trainer_is_running():
        pid = background_trainer_proc.pid if background_trainer_proc else "?"
        logger.info(f"Background trainer already running (pid={pid}); skipping")
        return True

    # Build command using the checkpoint-enabled trainer
    cmd = [PYEXE, "-u", os.path.join(_SCRIPT_DIR, "train_models_background.py"),
           "--restart-on-fail", "--skip-existing"]
    if data_groups:
        cmd += ["--groups"] + data_groups
    else:
        cmd.append("--all")

    if dry_run:
        _log_cmd(cmd)
        logger.info("Dry-run: would start background trainer: %s", cmd)
        return True

    try:
        # Ensure log directory exists
        Path(TRAINER_LOG_PATH).parent.mkdir(parents=True, exist_ok=True)
        log_fh = open(TRAINER_LOG_PATH, "a")
        proc = subprocess.Popen(
            cmd, stdout=log_fh, stderr=subprocess.STDOUT,
            start_new_session=True,  # survives parent exit like nohup
        )
        log_fh.close()  # parent does not need the fd; child inherited it
        background_trainer_proc = proc
        logger.info(
            f"Started background trainer (pid={proc.pid}) for groups: {data_groups}  "
            f"-- logs: {TRAINER_LOG_PATH}"
        )
        return True
    except Exception:
        logger.exception("Failed to start background trainer")
        return False


def trigger_auto_retrain_for_missing(groups: list[str], dry_run: bool = False) -> bool:
    """Trigger auto-retrain for groups with too many missing model errors."""
    global missing_model_errors, last_auto_retrain_time
    groups_to_retrain = [g for g in groups if should_auto_retrain(g)]
    if not groups_to_retrain:
        return False
    for group in groups_to_retrain:
        logger.warning(
            f"Auto-retrain triggered for {group}: {missing_model_errors.get(group, 0)} errors "
            f"(threshold: {AUTO_RETRAIN_MISSING_THRESHOLD})"
        )
    if _start_background_trainer(groups_to_retrain, dry_run=dry_run):
        for group in groups_to_retrain:
            missing_model_errors[group] = 0
            last_auto_retrain_time[group] = datetime.now(timezone.utc)
        return True
    return False


# ---------------------------------------------------------------------------
# Detection, push, and correlation
# ---------------------------------------------------------------------------

def _dedupe_preserve_order(items: list[str]) -> list[str]:
    """Return a list with duplicates removed, preserving order."""
    seen: set = set()
    result: list = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _resolve_training_groups(detection_mode: str, allowed_groups: list[str] | None) -> list[str]:
    """Resolve which data groups should be retrained."""
    if detection_mode == "group":
        return [DATA_GROUP]
    if detection_mode == "comprehensive":
        if allowed_groups:
            return _dedupe_preserve_order(allowed_groups)
        return DEFAULT_MODEL_GROUPS.copy()
    return _dedupe_preserve_order(allowed_groups or [])


def run_detection(
    one_shot: bool = False,
    retrain: bool = False,
    retrain_force: bool = False,
    dry_run: bool = False,
    allowed_groups: list[str] | None = None,
) -> bool:
    """Run detection via main.py with realtime-friendly flags.

    Args:
        one_shot: Whether this is a single cycle.
        retrain: Whether scheduled retrain is due.
        retrain_force: Force retrain regardless of schedule.
        dry_run: Print commands without executing.
        allowed_groups: Data groups with fresh data.

    Returns:
        True on success.
    """
    detection_mode = getattr(run_detection, "_override_detection_mode", None) or DETECTION_MODE

    cmd = [PYEXE, os.path.join(_SCRIPT_DIR, "main.py"), "--log-level", os.getenv("LOG_LEVEL", "INFO"),
           "--detection-mode", detection_mode, "--disable-mlflow"]

    if detection_mode == "group":
        if allowed_groups is not None and DATA_GROUP not in allowed_groups:
            logger.info("Skipping group detection for '%s' (no fresh data)", DATA_GROUP)
            return True
        cmd += ["--data-group", DATA_GROUP]
    elif detection_mode == "comprehensive":
        if allowed_groups is not None:
            if not allowed_groups:
                logger.info("No data groups with fresh data; skipping detection")
                return True
            logger.info("Running comprehensive detection for groups: %s", ", ".join(allowed_groups))
            cmd += ["--data-groups"] + allowed_groups

    # Schedule background retrain as needed
    training_groups = _resolve_training_groups(detection_mode, allowed_groups)
    missing_groups = [g for g in training_groups if not models_exist_for(g)]
    stale_groups = get_stale_model_groups(training_groups) if MODEL_STALENESS_ENABLED else []
    stale_groups = [g for g in stale_groups if g not in missing_groups]

    groups_to_train: list[str] = []
    trainer_reason: str | None = None

    if missing_groups:
        groups_to_train = missing_groups
        trainer_reason = "missing trained models"
    if stale_groups:
        groups_to_train = list(set(groups_to_train + stale_groups))
        trainer_reason = (trainer_reason or "") + f" + stale models (>{MODEL_STALENESS_HOURS}h)"

    if retrain_force and training_groups:
        groups_to_train = training_groups
        trainer_reason = "forced retrain via --retrain-now"
    elif retrain and training_groups and not missing_groups and not stale_groups:
        groups_to_train = training_groups
        trainer_reason = f"scheduled retrain ({RETRAIN_INTERVAL_HOURS}h)"

    if groups_to_train:
        groups_to_train = _dedupe_preserve_order(groups_to_train)
        if missing_groups:
            logger.warning("Missing models for: %s", ", ".join(missing_groups))
        for g in stale_groups:
            age = get_model_file_age_hours(g)
            if age is not None:
                logger.warning("Stale model %s: %.1fh old (threshold: %dh)", g, age, MODEL_STALENESS_HOURS)
        if not _trainer_is_running():
            if _start_background_trainer(groups_to_train, dry_run=dry_run):
                run_detection._trainer_started = True
                logger.info("Background trainer launched (%s) for: %s", trainer_reason, ", ".join(groups_to_train))
        else:
            pid = background_trainer_proc.pid if background_trainer_proc else "?"
            logger.info("Trainer already running (pid=%s); deferring retrain", pid)

    return _run_and_stream(cmd, dry_run=dry_run)


def push_anomalies(dry_run: bool = False) -> bool:
    """Call push_all_anomalies.py to index detected anomalies."""
    cmd = [PYEXE, os.path.join(_SCRIPT_DIR, "push_all_anomalies.py"), "--cleanup"]
    return _run_and_stream(cmd, dry_run=dry_run)


def run_correlation(dry_run: bool = False) -> bool:
    """Run post_correlation.py for kill-chain correlation.

    Args:
        dry_run: Print commands without executing.

    Returns:
        True on success.
    """
    if not CORRELATION_ENABLED:
        logger.debug("Correlation disabled by CORRELATION_ENABLED")
        return True

    cmd = [PYEXE, os.path.join(_SCRIPT_DIR, "post_correlation.py"),
           "--time-window-minutes", str(CORRELATION_WINDOW_MINUTES)]

    out_path = os.getenv("CORRELATION_OUT_FILE") or "correlated_fallback.jsonl"
    cmd += ["--out-file", out_path]

    max_retries = _env_int("CORRELATION_RETRIES", 2)
    backoff_seconds = _env_int("CORRELATION_RETRY_BACKOFF_SECONDS", 5)
    ok = False
    for attempt in range(1, max_retries + 2):
        logger.info("Running correlation (attempt %s/%s)", attempt, max_retries + 1)
        ok = _run_and_stream(cmd, dry_run=dry_run)
        if ok:
            break
        logger.warning("Correlation failed on attempt %s/%s", attempt, max_retries + 1)
        if attempt <= max_retries:
            sleep_for = backoff_seconds * (2 ** (attempt - 1))
            logger.info("Retrying correlation after %ss", sleep_for)
            time.sleep(sleep_for)

    if not ok:
        logger.error("Correlation failed after %s attempts", max_retries + 1)

    return ok


# ---------------------------------------------------------------------------
# File cleanup and log rotation
# ---------------------------------------------------------------------------

AUDIT_TRUNCATE_MAX_LINES: int = _env_int("AUDIT_TRUNCATE_MAX_LINES", 5000)
ANOMALY_SUMMARY_MAX_FILES: int = _env_int("ANOMALY_SUMMARY_MAX_FILES", 20)
ALLOWLIST_HITS_MAX_LINES: int = _env_int("ALLOWLIST_HITS_MAX_LINES", 5000)
FP_TRACE_MAX_LINES: int = _env_int("FP_TRACE_MAX_LINES", 20000)
VISUALIZATION_MAX_FILES: int = _env_int("VISUALIZATION_MAX_FILES", 50)
STALE_LOG_MAX_AGE_HOURS: int = _env_int("STALE_LOG_MAX_AGE_HOURS", 24)
RESULT_ARTIFACT_MAX_AGE_HOURS: int = _env_int("RESULT_ARTIFACT_MAX_AGE_HOURS", 72)
RESULT_ARTIFACT_MAX_FILES: int = _env_int("RESULT_ARTIFACT_MAX_FILES", 6000)


def _truncate_jsonl(path: Path, keep_lines: int) -> bool:
    """Truncate a JSONL/append-only file to the last *keep_lines* lines."""
    try:
        if not path.exists() or path.stat().st_size == 0:
            return False
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        if len(lines) <= keep_lines:
            return False
        with path.open("w", encoding="utf-8") as fh:
            fh.writelines(lines[-keep_lines:])
        return True
    except OSError:
        return False


def _prune_by_age_and_count(
    results_dir: str, patterns: list[str], max_age_hours: int, max_files: int
) -> int:
    """Delete files in *results_dir* matching *patterns* that are stale or surplus.

    For each pattern the newest files are kept: a file is removed when it is
    older than *max_age_hours*, or when at least *max_files* newer siblings
    match the same pattern. Returns the number of files removed.
    """
    removed = 0
    cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
    for pat in patterns:
        files = sorted(_glob.glob(os.path.join(results_dir, pat)), key=os.path.getmtime, reverse=True)
        for i, fpath in enumerate(files):
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc)
                if i >= max_files or mtime < cutoff:
                    os.remove(fpath)
                    removed += 1
            except OSError:
                pass
    return removed


def _cleanup_old_results(max_age_hours: int = 4, max_files: int = 5) -> None:
    """Remove old ML anomaly result files and truncate audit logs."""
    results_dir = os.path.join(os.getcwd(), "results")
    removed = _prune_by_age_and_count(
        results_dir,
        ["ml_only_anomalies_*.json", "ml_only_anomalies_*.csv"],
        max_age_hours,
        max_files,
    )
    # Per-data-type CSV/markdown artifacts written by visualizer.py on every
    # detection cycle. The globs above only match "ml_only_anomalies_*", so
    # these accumulated unbounded and were the dominant consumer of results/.
    removed += _prune_by_age_and_count(
        results_dir,
        [
            "ml_only_*_data_*.csv",
            "ml_only_*_report_*.md",
            "*_anomaly_data_*.csv",
            "*_anomaly_report_*.md",
        ],
        RESULT_ARTIFACT_MAX_AGE_HOURS,
        RESULT_ARTIFACT_MAX_FILES,
    )
    # Clean old parquet persistence files (keep latest 10)
    pq_dir = os.path.join(results_dir, "persisted_results")
    if os.path.isdir(pq_dir):
        pq_files = sorted(_glob.glob(os.path.join(pq_dir, "*.parquet")), key=os.path.getmtime, reverse=True)
        for fpath in pq_files[10:]:
            try:
                os.remove(fpath)
                removed += 1
            except OSError:
                pass

    # Truncate threshold_audit.json (append-only, grows every push cycle)
    threshold_audit = Path(results_dir) / "threshold_audit.json"
    if _truncate_jsonl(threshold_audit, AUDIT_TRUNCATE_MAX_LINES):
        logger.info("Truncated threshold_audit.json to last %d lines", AUDIT_TRUNCATE_MAX_LINES)

    # Truncate allowlist_hits.jsonl
    allowlist_hits = Path(results_dir) / "allowlist_hits.jsonl"
    if _truncate_jsonl(allowlist_hits, ALLOWLIST_HITS_MAX_LINES):
        logger.info("Truncated allowlist_hits.jsonl to last %d lines", ALLOWLIST_HITS_MAX_LINES)

    # Truncate fp_classification_trace.jsonl (append-only, grows every push cycle)
    fp_trace = Path(results_dir) / "fp_classification_trace.jsonl"
    if _truncate_jsonl(fp_trace, FP_TRACE_MAX_LINES):
        logger.info("Truncated fp_classification_trace.jsonl to last %d lines", FP_TRACE_MAX_LINES)

    # Prune old visualization PNGs (keep newest N)
    viz_dir = Path(results_dir) / "visualizations"
    if viz_dir.is_dir():
        viz_files = sorted(viz_dir.glob("*.png"), key=os.path.getmtime, reverse=True)
        for fpath in viz_files[VISUALIZATION_MAX_FILES:]:
            try:
                fpath.unlink()
                removed += 1
            except OSError:
                pass

    # Remove stale per-run log files left behind by direct main.py invocations
    # (the realtime loop itself now logs to a single rotating logs/linux_anomaly_detection.log)
    logs_dir = Path(os.getcwd()) / "logs"
    if logs_dir.is_dir():
        cutoff = datetime.now(timezone.utc) - timedelta(hours=STALE_LOG_MAX_AGE_HOURS)
        for fpath in logs_dir.glob("linux_anomaly_detection_*.log"):
            try:
                mtime = datetime.fromtimestamp(fpath.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff:
                    fpath.unlink()
                    removed += 1
            except OSError:
                pass

    # Prune anomaly summary markdown files (keep newest N)
    summary_files = sorted(
        _glob.glob(os.path.join(results_dir, "anomaly_summary_*.md")),
        key=os.path.getmtime, reverse=True,
    )
    for fpath in summary_files[ANOMALY_SUMMARY_MAX_FILES:]:
        try:
            os.remove(fpath)
            removed += 1
        except OSError:
            pass

    # Remove stale models_audit.json (regenerated on demand by scripts/audit_models.py)
    models_audit = Path(results_dir) / "models_audit.json"
    try:
        if models_audit.exists():
            age_h = (datetime.now(timezone.utc) - datetime.fromtimestamp(
                models_audit.stat().st_mtime, tz=timezone.utc
            )).total_seconds() / 3600
            if age_h > max_age_hours:
                models_audit.unlink()
                removed += 1
    except OSError:
        pass

    if removed:
        logger.info("Auto-cleanup: removed %d old result files", removed)


def _cleanup_stale_model_dirs() -> None:
    """Remove model files from non-primary candidate directories after swap.

    When models are retrained they land in the primary MODELS_DIR.  Old copies
    in other candidate locations (./models, ./results/models, /tmp/...) become
    orphans that waste disk.  This function keeps only the freshest copy of
    each data-type's files and deletes the rest.
    """
    active_types = list(ALL_DATA_GROUPS)
    suffixes = ["_models.joblib", "_scalers.joblib", "_baselines.joblib",
                "_metadata.joblib", "_feature_manifests.json"]
    dirs = _candidate_model_dirs()
    if len(dirs) < 2:
        return

    removed = 0
    for data_type in active_types:
        # Find the freshest copy across all candidate dirs
        best_mtime: float = 0.0
        best_dir: str | None = None
        for d in dirs:
            model_file = os.path.join(d, f"{data_type}_models.joblib")
            if os.path.exists(model_file):
                try:
                    mt = os.path.getmtime(model_file)
                    if mt > best_mtime:
                        best_mtime = mt
                        best_dir = d
                except OSError:
                    pass

        if best_dir is None:
            continue

        # Delete copies in every other directory
        for d in dirs:
            if d == best_dir:
                continue
            for suffix in suffixes:
                fpath = os.path.join(d, f"{data_type}{suffix}")
                if os.path.exists(fpath):
                    try:
                        os.remove(fpath)
                        removed += 1
                    except OSError:
                        pass

    if removed:
        logger.info("Model cleanup: removed %d stale model files from non-primary dirs", removed)


SERVICE_LOG_PATH: Path = Path(os.path.expanduser("~/logs/realtime_service.log"))


def _rotate_logs(max_size_mb: int = 50, keep_lines: int = 5000) -> None:
    """Overwrite the systemd service log and truncate large project logs each cycle."""
    rotated = 0

    try:
        if SERVICE_LOG_PATH.exists() and SERVICE_LOG_PATH.stat().st_size > 0:
            SERVICE_LOG_PATH.write_text("")
            rotated += 1
    except OSError:
        pass

    log_dir = os.path.join(os.getcwd(), "logs")
    if not os.path.isdir(log_dir):
        if rotated:
            logger.info("Log rotation: truncated %d log files", rotated)
        return
    for fname in os.listdir(log_dir):
        if not fname.endswith(".log") and not fname.endswith(".err"):
            continue
        fpath = os.path.join(log_dir, fname)
        try:
            size_mb = os.path.getsize(fpath) / (1024 * 1024)
            if size_mb > max_size_mb:
                with open(fpath, encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
                tail = lines[-keep_lines:] if len(lines) > keep_lines else lines
                with open(fpath, "w", encoding="utf-8") as f:
                    f.writelines(tail)
                rotated += 1
        except OSError:
            pass
    if rotated:
        logger.info("Log rotation: truncated %d log files", rotated)


def should_run_cleanup() -> bool:
    """Check if it is time to run file cleanup."""
    if not CLEANUP_ENABLED:
        return False
    return (datetime.now(timezone.utc) - last_cleanup_time) >= timedelta(hours=CLEANUP_INTERVAL_HOURS)


def run_file_cleanup(dry_run: bool = False) -> bool:
    """Run cleanup of old result files, stale models, and rotate logs."""
    if not CLEANUP_ENABLED:
        return True
    logger.info("Running file cleanup, model cleanup, and log rotation")
    if not dry_run:
        _cleanup_old_results()
        _cleanup_stale_model_dirs()
        _rotate_logs()
    return True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Parse arguments and run the detection service."""
    parser = argparse.ArgumentParser(description="Realtime anomaly detection service")
    parser.add_argument("--once", action="store_true", help="Run a single detection cycle and exit")
    parser.add_argument("--detection-mode", choices=["single", "group", "comprehensive"],
                        help="Override detection mode (default: env or comprehensive)")
    parser.add_argument("--retrain-now", action="store_true", help="Force retrain models on next cycle")
    parser.add_argument("--detection-interval", type=int, help="Seconds between detection cycles")
    parser.add_argument("--retrain-hours", type=int, help="Hours between retrain cycles")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")
    args = parser.parse_args()

    global DETECTION_INTERVAL_SECONDS, RETRAIN_INTERVAL_HOURS, last_cleanup_time
    if args.detection_interval:
        DETECTION_INTERVAL_SECONDS = args.detection_interval
    if args.retrain_hours:
        RETRAIN_INTERVAL_HOURS = args.retrain_hours

    last_retrain = datetime.now(timezone.utc) - timedelta(hours=RETRAIN_INTERVAL_HOURS + 1)
    dry_run = args.dry_run

    # Resolve detection mode: CLI > env > default
    if args.detection_mode:
        resolved_mode = args.detection_mode
    else:
        resolved_mode = DETECTION_MODE
        if resolved_mode == "group":
            logger.info("DETECTION_MODE='group' in env; defaulting to 'comprehensive' for realtime")
            resolved_mode = "comprehensive"
    run_detection._override_detection_mode = resolved_mode
    logger.info(f"Detection mode: {resolved_mode}")

    # Health metrics
    health = HealthMetrics.load()
    circuit_breaker = CircuitBreaker()

    # Startup: check model health
    if AUTO_RETRAIN_MISSING_ENABLED and not dry_run:
        logger.info("Startup model health check...")
        groups_needing_train: list = []
        for group in DEFAULT_MODEL_GROUPS:
            if not models_exist_for(group):
                groups_needing_train.append(group)
                logger.warning(f"No models found for group: {group}")
            elif is_model_stale(group):
                groups_needing_train.append(group)
                age = get_model_file_age_hours(group)
                logger.warning(f"Stale model for {group}: {age:.1f}h old") if age else None
            else:
                age = get_model_file_age_hours(group)
                if age is not None:
                    logger.info(f"Group {group}: model {age:.1f}h old (fresh)")
                else:
                    logger.info(f"Group {group}: models present")
        if groups_needing_train and not _trainer_is_running():
            logger.info(f"Launching startup trainer for: {', '.join(groups_needing_train)}")
            _start_background_trainer(groups_needing_train, dry_run=dry_run)

    # Suppress heavy artifacts in realtime
    os.environ["GENERATE_REPORTS"] = "false"
    os.environ["VISUALIZATION"] = "false"

    try:
        if args.once:
            return _run_one_shot(args, last_retrain, health, circuit_breaker, dry_run)

        logger.info("Starting realtime detection loop (interval=%ds)", DETECTION_INTERVAL_SECONDS)
        return _run_loop(args, last_retrain, health, circuit_breaker, dry_run)

    except KeyboardInterrupt:
        logger.info("Realtime detection service stopped by user")
        return 0


def _run_one_shot(
    args: argparse.Namespace,
    last_retrain: datetime,
    health: HealthMetrics,
    circuit_breaker: CircuitBreaker,
    dry_run: bool,
) -> int:
    """Execute a single detection cycle.

    Args:
        args: Parsed CLI arguments.
        last_retrain: Timestamp of last retrain.
        health: HealthMetrics instance.
        circuit_breaker: CircuitBreaker instance.
        dry_run: If True, do not execute subprocesses.

    Returns:
        Exit code.
    """
    logger.info("Running one-shot detection cycle")
    retrain_now = (datetime.now(timezone.utc) - last_retrain) >= timedelta(hours=RETRAIN_INTERVAL_HOURS)

    cycle_start = time.monotonic()

    ok = run_detection(
        one_shot=True,
        retrain=retrain_now,
        retrain_force=args.retrain_now,
        dry_run=dry_run,
        allowed_groups=list(ALL_DATA_GROUPS),
    )

    push_ok = 0
    push_fail = 0
    chains = 0

    if ok:
        pushed = push_anomalies(dry_run=dry_run)
        if pushed:
            push_ok += 1
            if circuit_breaker.allow_request():
                circuit_breaker.record_success()
            corr_ok = run_correlation(dry_run=dry_run)
            if corr_ok:
                chains += 1
        else:
            push_fail += 1
            circuit_breaker.record_failure()

        if should_run_cleanup():
            run_file_cleanup(dry_run=dry_run)
            global last_cleanup_time
            last_cleanup_time = datetime.now(timezone.utc)

        if not dry_run:
            _cleanup_old_results()
            _rotate_logs()

        # Auto-retrain check
        if AUTO_RETRAIN_MISSING_ENABLED and not _trainer_is_running():
            groups_needing = [g for g in ALL_DATA_GROUPS if should_auto_retrain(g)]
            if groups_needing:
                trigger_auto_retrain_for_missing(groups_needing, dry_run=dry_run)

    duration = time.monotonic() - cycle_start
    health.update_detection(duration, push_ok, push_fail, chains)
    health.circuit_breaker_state = circuit_breaker.state
    health.write()

    logger.info(
        f"One-shot cycle completed in {duration:.1f}s "
        f"(push_ok={push_ok}, push_fail={push_fail}, chains={chains})"
    )
    return 0 if ok else 1


def _run_loop(
    args: argparse.Namespace,
    last_retrain: datetime,
    health: HealthMetrics,
    circuit_breaker: CircuitBreaker,
    dry_run: bool,
) -> int:
    """Run the continuous detection loop.

    Args:
        args: Parsed CLI arguments.
        last_retrain: Timestamp of last retrain.
        health: HealthMetrics instance.
        circuit_breaker: CircuitBreaker instance.
        dry_run: If True, do not execute subprocesses.

    Returns:
        Exit code.
    """
    global last_cleanup_time
    cycle_count = 0

    while True:
        cycle_count += 1
        retrain_now = (datetime.now(timezone.utc) - last_retrain) >= timedelta(hours=RETRAIN_INTERVAL_HOURS)

        logger.info("=== Detection cycle %d starting ===", cycle_count)
        cycle_start = time.monotonic()

        push_ok = 0
        push_fail = 0
        chains = 0

        try:
            ok = run_detection(
                one_shot=False,
                retrain=retrain_now,
                retrain_force=(args.retrain_now and cycle_count == 1),
                dry_run=dry_run,
                allowed_groups=list(ALL_DATA_GROUPS),
            )

            if ok:
                trainer_started = getattr(run_detection, "_trainer_started", False)
                if trainer_started:
                    last_retrain = datetime.now(timezone.utc)
                    run_detection._trainer_started = False

                pushed = push_anomalies(dry_run=dry_run)
                if not dry_run:
                    _cleanup_old_results()
                    _rotate_logs()
                if pushed:
                    push_ok += 1
                    if circuit_breaker.allow_request():
                        circuit_breaker.record_success()
                    corr_ok = run_correlation(dry_run=dry_run)
                    if corr_ok:
                        chains += 1
                else:
                    push_fail += 1
                    circuit_breaker.record_failure()

                if should_run_cleanup():
                    run_file_cleanup(dry_run=dry_run)
                    last_cleanup_time = datetime.now(timezone.utc)

                # Auto-retrain check
                if AUTO_RETRAIN_MISSING_ENABLED and not _trainer_is_running():
                    groups_needing = [g for g in ALL_DATA_GROUPS if should_auto_retrain(g)]
                    if groups_needing:
                        trigger_auto_retrain_for_missing(groups_needing, dry_run=dry_run)
            else:
                logger.warning("Detection run failed; will retry after sleep")

        except KeyboardInterrupt:
            raise
        except Exception:
            logger.exception("Detection loop error")

        duration = time.monotonic() - cycle_start
        health.update_detection(duration, push_ok, push_fail, chains)
        health.circuit_breaker_state = circuit_breaker.state
        health.write()

        logger.info(
            "=== Cycle %d completed in %.1fs (push_ok=%d, push_fail=%d, chains=%d) ===",
            cycle_count, duration, push_ok, push_fail, chains,
        )
        logger.info("Sleeping %ds until next cycle...", DETECTION_INTERVAL_SECONDS)
        time.sleep(DETECTION_INTERVAL_SECONDS)

    return 0


if __name__ == "__main__":
    sys.exit(main())
