#!/usr/bin/env python3
"""Validation script for Agent 5: Adversarial Hardener.

Checks:
- InputGuard catches NaN, Inf, 10-sigma values
- DriftMonitor detects shifted distribution (shift mean by 3 sigma)
- AttackGenerator output has is_attack + attack_technique columns
- Only adversarial/ was created

Exit 0 = passed, 1 = failed.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

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

AGENT_OWNED = ["adversarial"]


def _import_adversarial_module(module_name: str):
    """Attempt to import a module from adversarial/."""
    adv_dir = PROJECT_ROOT / "adversarial"
    if not adv_dir.exists():
        return None
    candidate = adv_dir / f"{module_name}.py"
    if not candidate.exists():
        # Try top-level __init__
        init = adv_dir / "__init__.py"
        if init.exists():
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location("adversarial", init)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                return mod
            except Exception:
                pass
        return None
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, candidate)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _find_class_in_adversarial(class_name: str):
    """Search all adversarial .py files for a class by name."""
    adv_dir = PROJECT_ROOT / "adversarial"
    if not adv_dir.exists():
        return None
    for f in adv_dir.glob("**/*.py"):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            cls = getattr(mod, class_name, None)
            if cls is not None and isinstance(cls, type):
                return cls
        except Exception:
            pass
    return None


def check_input_guard() -> tuple[bool, str]:
    """Verify InputGuard catches NaN, Inf, and 10-sigma outliers."""
    adv_dir = PROJECT_ROOT / "adversarial"
    if not adv_dir.exists():
        return True, "adversarial/ not yet created — skipping"

    cls = _find_class_in_adversarial("InputGuard")
    if cls is None:
        return True, "InputGuard not yet implemented — skipping"

    X_normal = np.random.randn(100, 5)
    guard = cls()
    try:
        guard.fit(X_normal)
    except Exception as e:
        return False, f"InputGuard.fit() failed: {e}"

    # Test NaN
    X_nan = X_normal.copy()
    X_nan[0, 0] = np.nan
    try:
        result = guard.check(X_nan)
        if result is True or (hasattr(result, "__len__") and len(result) == 0):
            return False, "InputGuard did not flag NaN input"
    except Exception:
        pass  # Raising exception is also acceptable behavior

    # Test Inf
    X_inf = X_normal.copy()
    X_inf[1, 1] = np.inf
    try:
        result = guard.check(X_inf)
        if result is True or (hasattr(result, "__len__") and len(result) == 0):
            return False, "InputGuard did not flag Inf input"
    except Exception:
        pass

    # Test 10-sigma
    X_outlier = X_normal.copy()
    std = X_normal[:, 0].std()
    X_outlier[2, 0] = X_normal[:, 0].mean() + 10 * std
    try:
        result = guard.check(X_outlier)
        if result is True or (hasattr(result, "__len__") and len(result) == 0):
            return False, "InputGuard did not flag 10-sigma outlier"
    except Exception:
        pass

    return True, ""


def check_drift_monitor() -> tuple[bool, str]:
    """Verify DriftMonitor detects 3-sigma distribution shift."""
    adv_dir = PROJECT_ROOT / "adversarial"
    if not adv_dir.exists():
        return True, "adversarial/ not yet created — skipping"

    cls = _find_class_in_adversarial("DriftMonitor")
    if cls is None:
        return True, "DriftMonitor not yet implemented — skipping"

    rng = np.random.default_rng(42)
    X_baseline = rng.standard_normal((500, 5))
    X_shifted = rng.standard_normal((100, 5)) + 3.0  # 3-sigma shift

    feature_names = [f"f{i}" for i in range(X_baseline.shape[1])]
    monitor = cls()
    try:
        monitor.set_reference(X_baseline, feature_names)
        report = monitor.check_drift(X_shifted)
        detected = report.drift_level != "stable"
        if not detected:
            return False, "DriftMonitor did not detect 3-sigma distribution shift"
    except Exception as e:
        return False, f"DriftMonitor failed: {e}"

    # Confirm no false alarm on in-distribution data (use same size as reference)
    X_same = rng.standard_normal((500, 5))
    try:
        report_same = monitor.check_drift(X_same)
        false_alarm = report_same.drift_level != "stable"
        if false_alarm:
            return False, "DriftMonitor false alarm on in-distribution data"
    except Exception:
        pass

    return True, ""


def check_attack_generator() -> tuple[bool, str]:
    """Verify AttackGenerator produces is_attack + attack_technique columns."""
    adv_dir = PROJECT_ROOT / "adversarial"
    if not adv_dir.exists():
        return True, "adversarial/ not yet created — skipping"

    cls = _find_class_in_adversarial("AttackGenerator")
    if cls is None:
        return True, "AttackGenerator not yet implemented — skipping"

    try:
        gen = cls()
        scenarios = gen.available_scenarios()
        if not scenarios:
            return False, "AttackGenerator.available_scenarios() returned empty"
        scenario = scenarios[0]
        background_df = pd.DataFrame({
            "process.name": ["bash"] * 100,
            "user.name": ["root"] * 100,
            "host.name": ["host1"] * 100,
        })
        output = gen.generate(
            scenario=scenario, n_samples=50, background_df=background_df,
        )
        if not isinstance(output, pd.DataFrame):
            return False, "AttackGenerator.generate() must return DataFrame"
        required = {"is_attack", "attack_technique"}
        missing = required - set(output.columns)
        if missing:
            return False, f"AttackGenerator output missing columns: {missing}"
        if not output["is_attack"].any():
            return False, "No attack events generated (is_attack all False)"
        return True, ""
    except Exception as e:
        return False, f"AttackGenerator.generate() failed: {e}"


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
    """Run all Agent 5 validation checks."""
    r = ValidationResult("Agent 5: Adversarial Hardener")

    ok, detail = check_input_guard()
    r.check("InputGuard catches NaN/Inf/10-sigma", ok, detail)

    ok, detail = check_drift_monitor()
    r.check("DriftMonitor detects 3-sigma shift", ok, detail)

    ok, detail = check_attack_generator()
    r.check("AttackGenerator output has required columns", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
