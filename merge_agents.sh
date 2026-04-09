#!/usr/bin/env bash
# Merge agent worktrees in dependency order with validation gates.
#
# Each agent's work is only merged if its validation check passes.
# If a check fails, the script stops and reports which agent failed.
#
# Usage:
#   chmod +x merge_agents.sh
#   ./merge_agents.sh              # Merge all in order
#   ./merge_agents.sh --dry-run    # Show what would happen without merging

set -euo pipefail

DRY_RUN=false
if [ "${1:-}" = "--dry-run" ]; then
    DRY_RUN=true
    echo "[DRY RUN] Showing merge plan without executing."
    echo ""
fi

# Merge order based on dependency graph
MERGE_ORDER=(7 2 1 3 5 4 6)

AGENT_LABELS=(
    [7]="Test & Benchmark Harness"
    [2]="Feature Engineer"
    [1]="ML Model Upgrader"
    [3]="Deep Learning Architect"
    [5]="Adversarial Hardener"
    [4]="FP/FN Tuner"
    [6]="Push & Correlation Hardener"
)

AGENT_REASON=(
    [7]="No dependencies — provides validation infrastructure for all others"
    [2]="Features are consumed by models (Agent 1, 3) and adversarial (Agent 5)"
    [1]="Models consume features from Agent 2"
    [3]="DL models consume features from Agent 2"
    [5]="Adversarial layer wraps models from Agent 1 and 3"
    [4]="Tuning uses updated scores from Agent 1 and 3"
    [6]="Ops layer consumes everything — merges last"
)

echo "============================================="
echo "  INTEGRATION MERGE — Dependency Order"
echo "============================================="
echo ""

for agent_num in "${MERGE_ORDER[@]}"; do
    label="${AGENT_LABELS[$agent_num]}"
    reason="${AGENT_REASON[$agent_num]}"

    echo "--- Step: Agent $agent_num — $label ---"
    echo "    Why now: $reason"

    if [ "$DRY_RUN" = true ]; then
        echo "    [DRY RUN] Would run: python validation/check_agent_${agent_num}.py"
        echo "    [DRY RUN] Would merge agent-${agent_num} worktree"
        echo ""
        continue
    fi

    # Run validation check
    echo "    Running validation..."
    if python validation/check_agent_${agent_num}.py; then
        echo "    [PASS] Validation passed."
    else
        echo ""
        echo "    [FAIL] Agent $agent_num failed validation."
        echo "    Fix the issues above, then re-run this script."
        echo "    The following agents were NOT merged:"
        for remaining in "${MERGE_ORDER[@]}"; do
            if [ "$remaining" -ge "$agent_num" ]; then
                echo "      - Agent $remaining: ${AGENT_LABELS[$remaining]}"
            fi
        done
        exit 1
    fi

    # Merge the worktree
    echo "    Merging worktree..."
    # The actual merge command depends on your git worktree setup.
    # Claude Code worktrees create branches like claude/agent-N
    BRANCH="claude/agent-${agent_num}"
    if git rev-parse --verify "$BRANCH" >/dev/null 2>&1; then
        git merge "$BRANCH" --no-edit -m "Merge Agent $agent_num: $label"
        echo "    [MERGED] Agent $agent_num into main."
    else
        echo "    [SKIP] Branch $BRANCH not found — agent may not have committed yet."
    fi

    # Run full test suite after merge to catch integration issues
    echo "    Running post-merge tests..."
    if python -m pytest tests/ -x --tb=short -q 2>/dev/null; then
        echo "    [PASS] Post-merge tests passed."
    else
        echo "    [WARN] Post-merge tests had issues — review before continuing."
        read -p "    Continue merging? [y/N] " confirm
        if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
            echo "    Stopping merge. Revert with: git reset --hard HEAD~1"
            exit 1
        fi
    fi

    echo ""
done

echo "============================================="
echo "  ALL AGENTS MERGED SUCCESSFULLY"
echo ""
echo "  Next steps:"
echo "    1. Run full benchmark: python benchmarks/evaluate.py"
echo "    2. Run CI hook: python benchmarks/ci_hook.py"
echo "    3. Review results in benchmarks/results/"
echo "============================================="
