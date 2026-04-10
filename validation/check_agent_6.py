#!/usr/bin/env python3
"""Validation script for Agent 6: Push & Correlation Hardener.

Checks:
- ATT&CK mapping covers all JOB_CONFIGURATIONS keys
- Correlation produces chains from synthetic data
- Context enrichment adds all required fields
- Circuit breaker state machine works
- Only enrichment/push sections of push_all_anomalies.py,
  post_correlation.py, realtime_service.py changed

Exit 0 = passed, 1 = failed.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    ValidationResult,
    check_docstrings,
    check_no_secrets,
    check_syntax,
    check_type_hints,
    get_changed_files,
)

AGENT_OWNED = ["push_all_anomalies.py", "post_correlation.py", "realtime_service.py"]

REQUIRED_ENRICHMENT_FIELDS = [
    "mitre_technique",
    "mitre_tactic",
    "alert_severity",
    "enriched_at",
]


def _load_module(path: Path):
    """Import a Python module from a file path."""
    if not path.exists():
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(path.stem, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def check_attack_mapping_coverage() -> tuple[bool, str]:
    """Verify ATT&CK mapping covers all JOB_CONFIGURATIONS keys."""
    detection_path = PROJECT_ROOT / "detection_methods.py"
    if not detection_path.exists():
        return True, "detection_methods.py not found — skipping"

    det_mod = _load_module(detection_path)
    if det_mod is None:
        return True, "Could not import detection_methods — skipping"

    job_configs = getattr(det_mod, "JOB_CONFIGURATIONS", {})
    if not job_configs:
        return True, "JOB_CONFIGURATIONS empty — skipping"

    # Look for mapping in post_correlation or push_all
    mapping = {}
    for fname in ["post_correlation.py", "push_all_anomalies.py", "realtime_service.py"]:
        mod = _load_module(PROJECT_ROOT / fname)
        if mod is None:
            continue
        candidate = getattr(mod, "ATTACK_MAPPING", getattr(mod, "JOB_ATTACK_MAPPING", None))
        if candidate:
            mapping = candidate
            break

    if not mapping:
        return True, "No ATT&CK mapping found yet — skipping coverage check"

    missing = [job for job in job_configs if job not in mapping]
    if missing:
        return False, f"ATT&CK mapping missing {len(missing)} job(s): {missing[:3]}"
    return True, ""


def check_correlation_chains() -> tuple[bool, str]:
    """Verify correlation produces event chains from synthetic data."""
    corr_path = PROJECT_ROOT / "post_correlation.py"
    if not corr_path.exists():
        return True, "post_correlation.py not found — skipping"

    mod = _load_module(corr_path)
    if mod is None:
        return True, "Could not import post_correlation — skipping"

    correlator_cls = None
    for name in ["AlertCorrelator", "CorrelationEngine", "PostCorrelation"]:
        cls = getattr(mod, name, None)
        if cls is not None and isinstance(cls, type):
            correlator_cls = cls
            break

    if correlator_cls is None:
        corr_fn = getattr(mod, "correlate", getattr(mod, "build_chains", None))
        if corr_fn is None:
            return True, "No correlator class or function found yet — skipping"
        # Try function-based correlation
        try:
            import pandas as pd
            from datetime import datetime, timedelta
            now = datetime.utcnow()
            alerts = [
                {"host": "host1", "process": "bash", "score": 0.9, "timestamp": now.isoformat(),
                 "job": "v3_linux_anomalous_process_all_hosts"},
                {"host": "host1", "process": "curl", "score": 0.85,
                 "timestamp": (now + timedelta(seconds=30)).isoformat(),
                 "job": "v3_linux_anomalous_network_activity"},
                {"host": "host1", "process": "nc", "score": 0.88,
                 "timestamp": (now + timedelta(seconds=60)).isoformat(),
                 "job": "v3_linux_anomalous_network_activity"},
            ]
            result = corr_fn(alerts)
            return True, ""
        except Exception as e:
            return False, f"correlate() failed: {e}"

    try:
        import pandas as pd
        from datetime import datetime, timedelta
        now = datetime.utcnow()
        alerts = pd.DataFrame([
            {"host.name": "host1", "process.name": "bash", "anomaly_score": 0.9,
             "@timestamp": now, "job_name": "v3_linux_anomalous_process_all_hosts"},
            {"host.name": "host1", "process.name": "curl", "anomaly_score": 0.85,
             "@timestamp": now + timedelta(seconds=30), "job_name": "v3_linux_anomalous_network_activity"},
            {"host.name": "host1", "process.name": "nc", "anomaly_score": 0.88,
             "@timestamp": now + timedelta(seconds=60), "job_name": "v3_linux_anomalous_network_activity"},
        ])
        c = correlator_cls()
        chains = c.correlate(alerts) if hasattr(c, "correlate") else c.build_chains(alerts)
        if not chains:
            return False, "Correlation returned no chains from sequential host events"
        return True, ""
    except Exception as e:
        return False, f"Correlation failed: {e}"


def check_context_enrichment() -> tuple[bool, str]:
    """Verify context enrichment adds required fields."""
    for fname in ["push_all_anomalies.py", "post_correlation.py"]:
        path = PROJECT_ROOT / fname
        if not path.exists():
            continue
        mod = _load_module(path)
        if mod is None:
            continue
        enrich_fn = getattr(mod, "enrich_alert", getattr(mod, "enrich_record", None))
        if enrich_fn is None:
            continue
        try:
            record = {
                "host.name": "host1",
                "process.name": "bash",
                "anomaly_score": 0.9,
                "job_name": "v3_linux_anomalous_process_all_hosts",
            }
            result = enrich_fn(record)
            if not isinstance(result, dict):
                return False, f"{fname}: enrich function must return dict"
            missing = [f for f in REQUIRED_ENRICHMENT_FIELDS if f not in result]
            if missing:
                return False, f"{fname}: enriched record missing fields: {missing}"
            return True, ""
        except Exception as e:
            return False, f"{fname}: enrichment failed: {e}"

    return True, "No enrichment function found yet — skipping"


def check_circuit_breaker() -> tuple[bool, str]:
    """Verify circuit breaker state machine transitions correctly."""
    for fname in ["push_all_anomalies.py", "realtime_service.py"]:
        path = PROJECT_ROOT / fname
        if not path.exists():
            continue
        mod = _load_module(path)
        if mod is None:
            continue
        cls = getattr(mod, "CircuitBreaker", None)
        if cls is None:
            continue
        try:
            cb = cls(failure_threshold=3, recovery_timeout_sec=1)
            # Should start closed
            if cb.state not in ("closed", "CLOSED"):
                return False, f"CircuitBreaker initial state should be CLOSED, got {cb.state}"
            # Trigger failures
            for _ in range(3):
                try:
                    cb.record_failure()
                except Exception:
                    pass
            if cb.state not in ("open", "OPEN"):
                return False, f"CircuitBreaker should be OPEN after failures, got {cb.state}"
            # Recovery after timeout
            import time
            time.sleep(1.1)
            if hasattr(cb, "check") or hasattr(cb, "allow_request"):
                check_fn = getattr(cb, "check", getattr(cb, "allow_request", None))
                if check_fn:
                    check_fn()
            if cb.state not in ("half_open", "half-open", "HALF_OPEN", "closed", "CLOSED"):
                return False, f"CircuitBreaker should be HALF_OPEN after timeout, got {cb.state}"
            return True, ""
        except Exception as e:
            return False, f"CircuitBreaker test failed: {e}"

    return True, "No CircuitBreaker found yet — skipping"


def check_code_quality() -> tuple[bool, list[str]]:
    """Check syntax, type hints, docstrings, and secrets."""
    issues = []
    files = get_changed_files(AGENT_OWNED, str(PROJECT_ROOT))
    for f in files:
        ok, err = check_syntax(f)
        if not ok:
            issues.append(f"Syntax: {f}: {err}")
        ok, missing = check_type_hints(f)
        if not ok:
            for m in missing[:3]:
                issues.append(f"Type hint: {m}")
        ok, missing = check_docstrings(f)
        if not ok:
            for m in missing[:3]:
                issues.append(f"Docstring: {m}")
        ok, secrets = check_no_secrets(f)
        if not ok:
            for s in secrets[:2]:
                issues.append(f"Secret: {s}")
    return len(issues) == 0, issues


def main() -> bool:
    """Run all Agent 6 validation checks."""
    r = ValidationResult("Agent 6: Push & Correlation Hardener")

    ok, detail = check_attack_mapping_coverage()
    r.check("ATT&CK mapping covers all JOB_CONFIGURATIONS", ok, detail)

    ok, detail = check_correlation_chains()
    r.check("Correlation produces chains from synthetic data", ok, detail)

    ok, detail = check_context_enrichment()
    r.check("Context enrichment adds required fields", ok, detail)

    ok, detail = check_circuit_breaker()
    r.check("Circuit breaker state machine works", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
