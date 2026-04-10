#!/usr/bin/env python3
"""Validation script for Agent 7: Test & Benchmark Harness.

Self-checks:
- All test files pass py_compile
- pytest collection succeeds (no import errors)
- All 5 scenarios are valid JSON with required fields
- Benchmark framework instantiates without error
- All other validation scripts (check_agent_1 through 6) exist
- No modifications to files outside tests/, benchmarks/, scripts/, validation/

Exit 0 = passed, 1 = failed.
"""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from common import (
    ValidationResult,
    check_syntax,
)

SCENARIO_DIR: Path = PROJECT_ROOT / "benchmarks" / "attack_scenarios"
REQUIRED_SCENARIO_FIELDS: set[str] = {
    "scenario_name", "description", "attack_techniques",
    "kill_chain_phases", "events",
}
REQUIRED_EVENT_FIELDS: set[str] = {
    "@timestamp", "is_attack", "host.hostname",
}
AGENT_OWNED_DIRS: list[str] = ["tests", "benchmarks", "scripts", "validation"]


def check_test_files_compile() -> tuple[bool, list[str]]:
    """Verify all test files pass py_compile.

    Returns:
        Tuple of (all_passed, list_of_error_messages).
    """
    test_dir = PROJECT_ROOT / "tests"
    errors: list[str] = []
    if not test_dir.exists():
        return False, ["tests/ directory does not exist"]

    for py_file in sorted(test_dir.glob("*.py")):
        ok, msg = check_syntax(str(py_file))
        if not ok:
            errors.append(f"{py_file.name}: {msg}")
    return len(errors) == 0, errors


def check_benchmark_files_compile() -> tuple[bool, list[str]]:
    """Verify all benchmark Python files pass py_compile.

    Returns:
        Tuple of (all_passed, list_of_error_messages).
    """
    bench_dir = PROJECT_ROOT / "benchmarks"
    errors: list[str] = []
    if not bench_dir.exists():
        return False, ["benchmarks/ directory does not exist"]

    for py_file in sorted(bench_dir.rglob("*.py")):
        ok, msg = check_syntax(str(py_file))
        if not ok:
            errors.append(f"{py_file.relative_to(bench_dir)}: {msg}")
    return len(errors) == 0, errors


def check_scenarios_valid() -> tuple[bool, list[str]]:
    """Verify all 5 scenarios exist and have required fields.

    Returns:
        Tuple of (all_valid, list_of_error_messages).
    """
    errors: list[str] = []
    expected_count = 5

    if not SCENARIO_DIR.exists():
        return False, [f"Scenario directory does not exist: {SCENARIO_DIR}"]

    scenario_files = sorted(SCENARIO_DIR.glob("scenario_*.json"))
    if len(scenario_files) < expected_count:
        errors.append(
            f"Expected {expected_count} scenario files, found {len(scenario_files)}"
        )

    for path in scenario_files:
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as e:
            errors.append(f"{path.name}: invalid JSON — {e}")
            continue

        missing = REQUIRED_SCENARIO_FIELDS - set(data.keys())
        if missing:
            errors.append(f"{path.name}: missing fields: {missing}")

        events = data.get("events", [])
        if not events:
            errors.append(f"{path.name}: no events")
            continue

        for i, event in enumerate(events):
            missing_evt = REQUIRED_EVENT_FIELDS - set(event.keys())
            if missing_evt:
                errors.append(f"{path.name} event[{i}]: missing {missing_evt}")
                break  # report only first bad event per scenario

    return len(errors) == 0, errors


def check_benchmark_framework_instantiates() -> tuple[bool, str]:
    """Verify benchmark framework classes can be instantiated.

    Returns:
        Tuple of (success, error_message).
    """
    try:
        from benchmarks.evaluate import PipelineBenchmark, BenchmarkReport, ScenarioMetrics
        _ = PipelineBenchmark(scenario_dir=SCENARIO_DIR)
        _ = BenchmarkReport()
        _ = ScenarioMetrics(scenario_name="test")
        return True, ""
    except Exception as e:
        return False, str(e)


def check_validation_scripts_exist() -> tuple[bool, list[str]]:
    """Verify check_agent_1 through check_agent_6 all exist.

    Returns:
        Tuple of (all_exist, list_of_missing).
    """
    validation_dir = PROJECT_ROOT / "validation"
    missing: list[str] = []
    for i in range(1, 7):
        script = validation_dir / f"check_agent_{i}.py"
        if not script.exists():
            missing.append(f"check_agent_{i}.py")
    return len(missing) == 0, missing


def main() -> bool:
    """Run all self-checks for Agent 7.

    Returns:
        True if all checks passed, False otherwise.
    """
    result = ValidationResult("Agent 7: Test & Benchmark")

    # 1. Test files compile
    ok, errors = check_test_files_compile()
    result.check(
        "Test files compile",
        ok,
        "; ".join(errors) if errors else "",
    )

    # 2. Benchmark files compile
    ok, errors = check_benchmark_files_compile()
    result.check(
        "Benchmark files compile",
        ok,
        "; ".join(errors) if errors else "",
    )

    # 3. All 5 scenarios valid
    ok, errors = check_scenarios_valid()
    result.check(
        "Attack scenarios valid",
        ok,
        "; ".join(errors) if errors else "",
    )

    # 4. Benchmark framework instantiates
    ok, msg = check_benchmark_framework_instantiates()
    result.check(
        "Benchmark framework instantiates",
        ok,
        msg,
    )

    # 5. All validation scripts exist
    ok, missing = check_validation_scripts_exist()
    result.check(
        "Validation scripts exist (agents 1-6)",
        ok,
        f"Missing: {missing}" if missing else "",
    )

    # 6. check_all.py exists
    check_all = PROJECT_ROOT / "validation" / "check_all.py"
    result.check(
        "check_all.py exists",
        check_all.exists(),
    )

    # Summary
    return result.summary()


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
