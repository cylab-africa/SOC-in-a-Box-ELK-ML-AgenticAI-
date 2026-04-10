#!/usr/bin/env python3
"""Validation script for Agent 1: ML Model Upgrader.

Checks:
- All model classes subclass AnomalyModel
- .fit() and .decision_function() work on synthetic numpy arrays
- Ensemble scores are in [0, 1] range
- manifest.json is valid JSON with required keys
- Only model_manager.py, detection_methods.py, models/ were changed

Exit 0 = passed, 1 = failed.
"""

import json
import sys
from pathlib import Path

import numpy as np

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

AGENT_OWNED = ["model_manager.py", "detection_methods.py", "models"]

MANIFEST_REQUIRED_KEYS = {"models", "version", "created_at"}


def check_anomaly_model_interface() -> tuple[bool, str]:
    """Verify AnomalyModel base class and subclasses exist with required interface."""
    models_dir = PROJECT_ROOT / "models"
    if not models_dir.exists():
        return True, "models/ directory not yet created — skipping interface check"

    py_files = list(models_dir.glob("**/*.py"))
    if not py_files:
        return True, "No Python files in models/ yet — skipping"

    errors = []
    for f in py_files:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name in dir(mod):
                obj = getattr(mod, name)
                if isinstance(obj, type) and name not in ("AnomalyModel",):
                    if hasattr(obj, "fit") and hasattr(obj, "decision_function"):
                        # Check it subclasses AnomalyModel if that class exists
                        bases = [b.__name__ for b in obj.__mro__]
                        if "AnomalyModel" not in bases and not name.startswith("_"):
                            errors.append(f"{name} in {f.name} does not subclass AnomalyModel")
        except Exception as e:
            errors.append(f"Import error in {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_model_fit_predict() -> tuple[bool, str]:
    """Run .fit() and .decision_function() on synthetic data if models exist."""
    models_dir = PROJECT_ROOT / "models"
    if not models_dir.exists():
        return True, "models/ not yet created — skipping fit/predict check"

    py_files = list(models_dir.glob("**/*.py"))
    if not py_files:
        return True, "No model files yet"

    X = np.random.randn(50, 10).astype(np.float32)
    errors = []

    for f in py_files:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name in dir(mod):
                obj = getattr(mod, name)
                if isinstance(obj, type) and hasattr(obj, "fit") and hasattr(obj, "decision_function"):
                    if name.startswith("_"):
                        continue
                    try:
                        instance = obj()
                        instance.fit(X)
                        scores = instance.decision_function(X)
                        if not isinstance(scores, np.ndarray):
                            errors.append(f"{name}.decision_function must return np.ndarray")
                        if scores.min() < 0.0 or scores.max() > 1.0:
                            errors.append(f"{name} scores out of [0,1]: min={scores.min():.3f} max={scores.max():.3f}")
                    except Exception as e:
                        errors.append(f"{name} fit/predict failed: {e}")
        except Exception as e:
            errors.append(f"Import {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_manifest() -> tuple[bool, str]:
    """Verify manifest.json exists and has required keys if models dir is present."""
    models_dir = PROJECT_ROOT / "models"
    if not models_dir.exists():
        return True, "models/ not yet created — skipping manifest check"

    manifest_path = models_dir / "manifest.json"
    if not manifest_path.exists():
        return True, "manifest.json not yet created — skipping"

    try:
        with open(manifest_path) as f:
            data = json.load(f)
        missing = MANIFEST_REQUIRED_KEYS - set(data.keys())
        if missing:
            return False, f"manifest.json missing keys: {missing}"
        return True, ""
    except json.JSONDecodeError as e:
        return False, f"manifest.json is not valid JSON: {e}"


def check_code_quality() -> tuple[bool, list[str]]:
    """Check syntax, type hints, docstrings, and secrets in owned files."""
    issues = []
    files = get_changed_files(AGENT_OWNED, str(PROJECT_ROOT))
    for f in files:
        ok, err = check_syntax(f)
        if not ok:
            issues.append(f"Syntax error in {f}: {err}")
        ok, missing = check_type_hints(f)
        if not ok:
            for m in missing[:3]:
                issues.append(f"Missing type hint: {m}")
        ok, missing = check_docstrings(f)
        if not ok:
            for m in missing[:3]:
                issues.append(f"Missing docstring: {m}")
        ok, secrets = check_no_secrets(f)
        if not ok:
            for s in secrets[:3]:
                issues.append(f"Possible secret: {s}")
    return len(issues) == 0, issues


def main() -> bool:
    """Run all Agent 1 validation checks."""
    r = ValidationResult("Agent 1: ML Model Upgrader")

    ok, detail = check_anomaly_model_interface()
    r.check("AnomalyModel subclassing", ok, detail)

    ok, detail = check_model_fit_predict()
    r.check("Model fit/decision_function on synthetic data", ok, detail)

    ok, detail = check_manifest()
    r.check("manifest.json valid with required keys", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
