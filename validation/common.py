"""Shared validation helpers for agent quality gates."""

import ast
import os
import subprocess
import sys


class ValidationResult:
    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        self.checks: list[tuple[str, bool, str]] = []

    def check(self, name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        self.checks.append((name, passed, detail))
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))

    def summary(self) -> bool:
        total = len(self.checks)
        passed = sum(1 for _, p, _ in self.checks if p)
        failed = total - passed
        print(f"\n{'='*60}")
        print(f"  {self.agent_name}: {passed}/{total} checks passed, {failed} failed")
        print(f"{'='*60}")
        if failed > 0:
            print("\n  Failed checks:")
            for name, p, detail in self.checks:
                if not p:
                    print(f"    - {name}: {detail}")
        return failed == 0


def check_syntax(filepath: str) -> tuple[bool, str]:
    """Verify a Python file has no syntax errors."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", filepath],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)


def check_type_hints(filepath: str) -> tuple[bool, list[str]]:
    """Check that public functions have type hints on parameters."""
    missing = []
    try:
        with open(filepath) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                for arg in node.args.args:
                    if arg.arg == "self" or arg.arg == "cls":
                        continue
                    if arg.annotation is None:
                        missing.append(f"{filepath}:{node.lineno} {node.name}({arg.arg})")
        return len(missing) == 0, missing
    except Exception as e:
        return False, [str(e)]


def check_docstrings(filepath: str) -> tuple[bool, list[str]]:
    """Check that public functions/classes have docstrings."""
    missing = []
    try:
        with open(filepath) as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if node.name.startswith("_"):
                    continue
                docstring = ast.get_docstring(node)
                if docstring is None:
                    missing.append(f"{filepath}:{node.lineno} {node.name}")
        return len(missing) == 0, missing
    except Exception as e:
        return False, [str(e)]


def check_no_secrets(filepath: str) -> tuple[bool, list[str]]:
    """Check for hardcoded secrets patterns."""
    issues = []
    secret_patterns = [
        "password=", "api_key=", "secret=", "token=",
        "AKIA", "sk-", "ghp_", "glpat-",
    ]
    try:
        with open(filepath) as f:
            for i, line in enumerate(f, 1):
                line_stripped = line.strip()
                if line_stripped.startswith("#"):
                    continue
                for pattern in secret_patterns:
                    if pattern in line.lower() and "getenv" not in line.lower() and \
                       "os.environ" not in line.lower() and '""' not in line and \
                       "''" not in line and "None" not in line:
                        # Rough heuristic — skip obvious config patterns
                        if "=" in line and any(c.isalnum() for c in line.split("=")[-1].strip('" \'')):
                            issues.append(f"{filepath}:{i} possible secret: {line.strip()[:80]}")
        return len(issues) == 0, issues
    except Exception as e:
        return False, [str(e)]


def get_changed_files(owned_paths: list[str], project_root: str) -> list[str]:
    """List Python files in owned paths."""
    files = []
    for path in owned_paths:
        full_path = os.path.join(project_root, path)
        if os.path.isfile(full_path) and full_path.endswith(".py"):
            files.append(full_path)
        elif os.path.isdir(full_path):
            for root, _, filenames in os.walk(full_path):
                for fn in filenames:
                    if fn.endswith(".py"):
                        files.append(os.path.join(root, fn))
    return files


def check_file_boundaries(agent_owned: list[str], all_changed: list[str],
                          project_root: str) -> tuple[bool, list[str]]:
    """Verify agent only modified files within its ownership."""
    violations = []
    owned_resolved = set()
    for p in agent_owned:
        full = os.path.join(project_root, p)
        if os.path.isdir(full):
            for root, _, files in os.walk(full):
                for f in files:
                    owned_resolved.add(os.path.join(root, f))
        else:
            owned_resolved.add(full)

    for changed in all_changed:
        if changed not in owned_resolved:
            violations.append(changed)
    return len(violations) == 0, violations
