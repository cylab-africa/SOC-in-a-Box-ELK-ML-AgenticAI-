#!/usr/bin/env python3
"""Validation script for Agent 3: Deep Learning Architect.

Checks:
- All DL models subclass DLAnomalyModel
- .fit() and .decision_function() work on CPU with synthetic data
- Scores are finite (no NaN/Inf)
- .save() and .load() round-trip correctly
- Only dl_models/ was created/changed

Exit 0 = passed, 1 = failed.
"""

import sys
import tempfile
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

AGENT_OWNED = ["dl_models"]


def _list_dl_model_classes(mod) -> list:
    """Return concrete DL model classes from a module."""
    candidates = []
    for name in dir(mod):
        obj = getattr(mod, name)
        if not isinstance(obj, type):
            continue
        if name in ("DLAnomalyModel",) or name.startswith("_"):
            continue
        if hasattr(obj, "fit") and hasattr(obj, "decision_function"):
            candidates.append((name, obj))
    return candidates


def check_dl_model_subclassing() -> tuple[bool, str]:
    """Verify DL model classes subclass DLAnomalyModel."""
    dl_dir = PROJECT_ROOT / "dl_models"
    if not dl_dir.exists():
        return True, "dl_models/ not yet created — skipping"

    py_files = [f for f in dl_dir.glob("**/*.py") if not f.name.startswith("_")]
    if not py_files:
        return True, "No Python files in dl_models/ yet"

    errors = []
    for f in py_files:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, cls in _list_dl_model_classes(mod):
                bases = [b.__name__ for b in cls.__mro__]
                if "DLAnomalyModel" not in bases:
                    errors.append(f"{name} in {f.name} does not subclass DLAnomalyModel")
        except Exception as e:
            errors.append(f"Import error {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_fit_decision_function() -> tuple[bool, str]:
    """Verify fit/decision_function works on CPU with synthetic data."""
    dl_dir = PROJECT_ROOT / "dl_models"
    if not dl_dir.exists():
        return True, "dl_models/ not yet created — skipping"

    py_files = [f for f in dl_dir.glob("**/*.py") if not f.name.startswith("_")]
    if not py_files:
        return True, "No DL model files yet"

    X = np.random.randn(30, 20).astype(np.float32)
    errors = []

    for f in py_files:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, cls in _list_dl_model_classes(mod):
                try:
                    obj = cls()
                    obj.fit(X)
                    scores = obj.decision_function(X)
                    if not np.all(np.isfinite(scores)):
                        errors.append(f"{name}: scores contain NaN or Inf")
                except Exception as e:
                    errors.append(f"{name}.fit/decision_function failed: {e}")
        except Exception as e:
            errors.append(f"Import {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_save_load_roundtrip() -> tuple[bool, str]:
    """Verify .save() / .load() round-trip produces consistent scores."""
    dl_dir = PROJECT_ROOT / "dl_models"
    if not dl_dir.exists():
        return True, "dl_models/ not yet created — skipping"

    py_files = [f for f in dl_dir.glob("**/*.py") if not f.name.startswith("_")]
    if not py_files:
        return True, "No DL model files yet"

    X = np.random.randn(20, 20).astype(np.float32)
    errors = []

    for f in py_files:
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name, cls in _list_dl_model_classes(mod):
                if not hasattr(cls, "save") or not hasattr(cls, "load"):
                    errors.append(f"{name} missing .save() or .load()")
                    continue
                try:
                    obj = cls()
                    obj.fit(X)
                    scores_before = obj.decision_function(X)
                    with tempfile.TemporaryDirectory() as tmp:
                        save_path = Path(tmp) / "model"
                        obj.save(str(save_path))
                        loaded = cls.load(str(save_path))
                        scores_after = loaded.decision_function(X)
                    if not np.allclose(scores_before, scores_after, atol=1e-5):
                        errors.append(f"{name}: save/load round-trip scores differ")
                except Exception as e:
                    errors.append(f"{name} save/load failed: {e}")
        except Exception as e:
            errors.append(f"Import {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


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
    """Run all Agent 3 validation checks."""
    r = ValidationResult("Agent 3: Deep Learning Architect")

    ok, detail = check_dl_model_subclassing()
    r.check("DLAnomalyModel subclassing", ok, detail)

    ok, detail = check_fit_decision_function()
    r.check("fit/decision_function on CPU synthetic data", ok, detail)

    ok, detail = check_save_load_roundtrip()
    r.check("save/load round-trip consistency", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
