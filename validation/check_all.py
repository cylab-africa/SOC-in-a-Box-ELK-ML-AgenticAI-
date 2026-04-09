#!/usr/bin/env python3
"""Run all agent validation checks and report summary.

Usage:
    python validation/check_all.py [--agent N]   # Run one agent's check
    python validation/check_all.py               # Run all checks

Exit code 0 = all passed, 1 = at least one failure.
"""

import argparse
import importlib
import sys
from pathlib import Path


def run_check(agent_num: int) -> bool:
    """Import and run check_agent_N, return True if passed."""
    module_name = f"check_agent_{agent_num}"
    try:
        # Add validation/ to path
        sys.path.insert(0, str(Path(__file__).parent))
        mod = importlib.import_module(module_name)
        return mod.main()
    except ModuleNotFoundError:
        print(f"  [SKIP] Agent {agent_num}: validation script not found")
        return True  # Missing script = not yet built, skip
    except Exception as e:
        print(f"  [FAIL] Agent {agent_num}: validation crashed — {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run agent validation checks")
    parser.add_argument("--agent", type=int, help="Run check for specific agent (1-7)")
    args = parser.parse_args()

    print("=" * 60)
    print("  AGENT VALIDATION SUITE")
    print("=" * 60)

    if args.agent:
        agents = [args.agent]
    else:
        agents = list(range(1, 8))

    results = {}
    for n in agents:
        print(f"\n--- Agent {n} ---")
        results[n] = run_check(n)

    print("\n" + "=" * 60)
    print("  OVERALL SUMMARY")
    print("=" * 60)

    all_passed = True
    for n, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  Agent {n}: [{status}]")
        if not passed:
            all_passed = False

    if all_passed:
        print("\n  All agents passed validation.")
        return 0
    else:
        print("\n  Some agents FAILED. Fix issues before merging.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
