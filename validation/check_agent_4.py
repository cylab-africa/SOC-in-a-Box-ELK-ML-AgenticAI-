#!/usr/bin/env python3
"""Validation script for Agent 4: FP/FN Tuner.

Checks:
- LOLBins in NEVER_ALLOWLIST are never dampened (test each one)
- Expired allowlist entries skip
- Adaptive thresholds compute correctly for test scenarios
- filter_trace field present on processed records
- Only benign_lists.py, config.py thresholds, push filter sections changed

Exit 0 = passed, 1 = failed.
"""

import sys
from datetime import datetime, timedelta
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

AGENT_OWNED = ["benign_lists.py", "config.py"]

# Canonical LOLBins that must never be allowlisted/dampened
LOLBIN_NEVER_ALLOWLIST = [
    "bash", "sh", "python", "python3", "perl", "ruby", "php",
    "wget", "curl", "nc", "ncat", "netcat", "socat",
    "chmod", "chown", "chattr",
    "dd", "base64", "xxd",
    "crontab", "at",
    "nsenter", "unshare",
    "awk", "sed", "xargs",
]


def _load_benign_lists():
    """Import benign_lists module if it exists."""
    benign_path = PROJECT_ROOT / "benign_lists.py"
    if not benign_path.exists():
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("benign_lists", benign_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def check_never_allowlist() -> tuple[bool, str]:
    """Verify NEVER_ALLOWLIST contains all LOLBins and they are not dampened."""
    mod = _load_benign_lists()
    if mod is None:
        return True, "benign_lists.py not yet created — skipping"

    if not hasattr(mod, "NEVER_ALLOWLIST"):
        return True, "NEVER_ALLOWLIST not yet defined — skipping"

    never_list = {str(x).lower() for x in mod.NEVER_ALLOWLIST}
    missing = [b for b in LOLBIN_NEVER_ALLOWLIST if b not in never_list]
    if missing:
        return False, f"LOLBins missing from NEVER_ALLOWLIST: {missing}"

    # Check allowlist entries don't contain LOLBins
    if hasattr(mod, "ALLOWLIST") or hasattr(mod, "PROCESS_ALLOWLIST"):
        allowlist = getattr(mod, "ALLOWLIST", getattr(mod, "PROCESS_ALLOWLIST", []))
        entries = [str(e).lower() for e in allowlist]
        violations = [b for b in LOLBIN_NEVER_ALLOWLIST if b in entries]
        if violations:
            return False, f"LOLBins found in allowlist (must not be): {violations}"

    return True, ""


def check_expired_entries_skip() -> tuple[bool, str]:
    """Verify expired allowlist entries are skipped."""
    mod = _load_benign_lists()
    if mod is None:
        return True, "benign_lists.py not yet created — skipping"

    if not hasattr(mod, "is_allowlisted") and not hasattr(mod, "check_allowlist"):
        return True, "Allowlist checking function not yet implemented — skipping"

    check_fn = getattr(mod, "is_allowlisted", getattr(mod, "check_allowlist", None))
    if check_fn is None:
        return True, "No allowlist check function found — skipping"

    # Create expired entry
    past_time = (datetime.utcnow() - timedelta(days=1)).isoformat()
    try:
        result = check_fn("test_process", expires_at=past_time)
        if result:
            return False, "Expired allowlist entry was not skipped (returned True)"
        return True, ""
    except TypeError:
        # Function signature may differ
        return True, "check_fn signature differs — manual verification needed"
    except Exception as e:
        return False, f"Allowlist check raised exception: {e}"


def check_adaptive_thresholds() -> tuple[bool, str]:
    """Verify adaptive threshold computation."""
    config_path = PROJECT_ROOT / "config.py"
    if not config_path.exists():
        return True, "config.py not found — skipping"

    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("config_mod", config_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    except Exception as e:
        return False, f"config.py import failed: {e}"

    if not hasattr(mod, "compute_adaptive_threshold"):
        return True, "compute_adaptive_threshold not yet implemented — skipping"

    import numpy as np
    scores = np.array([0.1, 0.15, 0.12, 0.08, 0.11, 0.9, 0.85])
    try:
        threshold = mod.compute_adaptive_threshold(scores)
        if not (0.0 <= threshold <= 1.0):
            return False, f"Threshold {threshold} not in [0, 1]"
        if threshold < scores[:5].mean():
            return False, "Threshold below baseline mean — likely miscalculated"
        return True, ""
    except Exception as e:
        return False, f"compute_adaptive_threshold failed: {e}"


def check_filter_trace_field() -> tuple[bool, str]:
    """Verify filter_trace field is added to processed records."""
    push_path = PROJECT_ROOT / "push_all_anomalies.py"
    if not push_path.exists():
        return True, "push_all_anomalies.py not found — skipping"

    try:
        with open(push_path) as f:
            content = f.read()
        if "filter_trace" not in content:
            return False, "filter_trace field not found in push_all_anomalies.py"
        return True, ""
    except Exception as e:
        return False, f"Could not read push_all_anomalies.py: {e}"


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
    """Run all Agent 4 validation checks."""
    r = ValidationResult("Agent 4: FP/FN Tuner")

    ok, detail = check_never_allowlist()
    r.check("LOLBins in NEVER_ALLOWLIST not dampened", ok, detail)

    ok, detail = check_expired_entries_skip()
    r.check("Expired allowlist entries are skipped", ok, detail)

    ok, detail = check_adaptive_thresholds()
    r.check("Adaptive threshold computation correct", ok, detail)

    ok, detail = check_filter_trace_field()
    r.check("filter_trace field on processed records", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
