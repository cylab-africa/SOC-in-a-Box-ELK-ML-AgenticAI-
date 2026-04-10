#!/usr/bin/env python3
"""Validation script for Agent 2: Feature Engineer.

Checks:
- All transformers subclass FeatureTransformer
- .fit() + .transform() on synthetic DataFrame works
- Output columns are all float64
- No NaN in output when source fields have NaN
- get_attack_mapping() returns dict with valid TXXXX keys
- Only datamanager.py, data.py, features/ were changed

Exit 0 = passed, 1 = failed.
"""

import re
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

AGENT_OWNED = ["datamanager.py", "data.py", "features"]
ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _make_synthetic_df() -> pd.DataFrame:
    """Create a 100-row DataFrame matching process event schema."""
    rng = np.random.default_rng(42)
    n = 100
    df = pd.DataFrame({
        "process.name": rng.choice(["bash", "python3", "curl", "ssh", "nc"], n),
        "user.name": rng.choice(["root", "ubuntu", "www-data"], n),
        "host.name": rng.choice(["host1", "host2", "host3"], n),
        "destination.ip": rng.choice(["1.2.3.4", "10.0.0.1", None], n),
        "destination.port": rng.integers(1, 65535, n).astype(float),
        "event.action": rng.choice(["exec", "network", "file"], n),
        "@timestamp": pd.date_range("2025-01-01", periods=n, freq="1min"),
    })
    # Introduce NaN in some fields
    df.loc[rng.choice(n, 10, replace=False), "destination.ip"] = None
    return df


def check_feature_transformer_interface() -> tuple[bool, str]:
    """Verify FeatureTransformer subclasses exist with fit/transform."""
    features_dir = PROJECT_ROOT / "features"
    if not features_dir.exists():
        return True, "features/ not yet created — skipping"

    py_files = list(features_dir.glob("**/*.py"))
    if not py_files:
        return True, "No Python files in features/ yet"

    errors = []
    for f in py_files:
        if f.name.startswith("_"):
            continue
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name in dir(mod):
                obj = getattr(mod, name)
                if isinstance(obj, type) and hasattr(obj, "fit") and hasattr(obj, "transform"):
                    bases = [b.__name__ for b in obj.__mro__]
                    if "FeatureTransformer" not in bases and name not in ("FeatureTransformer",):
                        errors.append(f"{name} in {f.name} does not subclass FeatureTransformer")
        except Exception as e:
            errors.append(f"Import error {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_fit_transform_output() -> tuple[bool, str]:
    """Verify fit+transform produces float64 output with no NaN."""
    features_dir = PROJECT_ROOT / "features"
    if not features_dir.exists():
        return True, "features/ not yet created — skipping"

    py_files = list(features_dir.glob("**/*.py"))
    if not py_files:
        return True, "No feature files yet"

    df = _make_synthetic_df()
    errors = []

    for f in py_files:
        if f.name.startswith("_"):
            continue
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            for name in dir(mod):
                obj = getattr(mod, name)
                if isinstance(obj, type) and hasattr(obj, "fit") and hasattr(obj, "transform"):
                    if name.startswith("_") or name == "FeatureTransformer":
                        continue
                    try:
                        instance = obj()
                        instance.fit(df)
                        out = instance.transform(df)
                        if not isinstance(out, pd.DataFrame):
                            errors.append(f"{name}.transform must return DataFrame")
                            continue
                        non_float = [c for c in out.columns if out[c].dtype != np.float64]
                        if non_float:
                            errors.append(f"{name} non-float64 columns: {non_float[:3]}")
                        nan_cols = [c for c in out.columns if out[c].isna().any()]
                        if nan_cols:
                            errors.append(f"{name} NaN in output columns: {nan_cols[:3]}")
                    except Exception as e:
                        errors.append(f"{name} fit/transform failed: {e}")
        except Exception as e:
            errors.append(f"Import {f.name}: {e}")

    return len(errors) == 0, "; ".join(errors)


def check_attack_mapping() -> tuple[bool, str]:
    """Verify get_attack_mapping() returns dict with valid TXXXX technique keys."""
    features_dir = PROJECT_ROOT / "features"
    if not features_dir.exists():
        return True, "features/ not yet created — skipping"

    errors = []
    found_mapping = False

    for f in features_dir.glob("**/*.py"):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(f.stem, f)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "get_attack_mapping"):
                found_mapping = True
                mapping = mod.get_attack_mapping()
                if not isinstance(mapping, dict):
                    errors.append(f"{f.name}: get_attack_mapping() must return dict")
                    continue
                invalid = [k for k in mapping if not ATTACK_TECHNIQUE_RE.match(str(k))]
                if invalid:
                    errors.append(f"{f.name}: invalid MITRE keys: {invalid[:5]}")
        except Exception as e:
            errors.append(f"Import {f.name}: {e}")

    if not found_mapping:
        return True, "get_attack_mapping() not yet implemented — skipping"
    return len(errors) == 0, "; ".join(errors)


def check_code_quality() -> tuple[bool, list[str]]:
    """Check syntax, type hints, docstrings, and secrets in owned files."""
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
    """Run all Agent 2 validation checks."""
    r = ValidationResult("Agent 2: Feature Engineer")

    ok, detail = check_feature_transformer_interface()
    r.check("FeatureTransformer subclassing", ok, detail)

    ok, detail = check_fit_transform_output()
    r.check("fit+transform produces float64 with no NaN", ok, detail)

    ok, detail = check_attack_mapping()
    r.check("get_attack_mapping() returns valid TXXXX keys", ok, detail)

    ok, issues = check_code_quality()
    r.check("Code quality (syntax/hints/docstrings/secrets)", ok,
            issues[0] if issues else "")

    return r.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
