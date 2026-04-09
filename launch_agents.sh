#!/usr/bin/env bash
# Launch all 7 agents in parallel using Claude Code worktrees.
#
# Prerequisites:
#   - Claude Code v2.1.32+ installed (claude --version to check)
#   - This repo is a git repository with a clean working tree
#   - Run from the project root directory
#
# Usage:
#   chmod +x launch_agents.sh
#   ./launch_agents.sh          # Launch all agents
#   ./launch_agents.sh 2 5      # Launch only agents 2 and 5

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Agent definitions: number, name, prompt file, initial task description
declare -A AGENT_NAMES=(
    [1]="ml-upgrader"
    [2]="feature-engineer"
    [3]="dl-architect"
    [4]="fp-fn-tuner"
    [5]="evasion-hardener"
    [6]="ops-hardener"
    [7]="test-benchmark"
)

declare -A AGENT_TASKS=(
    [1]="Read .claude/agents/ml-upgrader.md then upgrade model_manager.py and detection_methods.py with PyOD ensemble models (ECOD, COPOD, AutoEncoder) behind a unified AnomalyModel interface. Add per-job model selection to JOB_CONFIGURATIONS. Implement calibrated ensemble scoring. Add model versioning with manifest.json. Run validation/check_agent_1.py when done."
    [2]="Read .claude/agents/feature-engineer.md then create the features/ package with ATT&CK-mapped security features: command-line entropy, token rarity, beaconing detection, DNS entropy, auth anomalies, temporal aggregations. Wire transformers into datamanager.py preprocessing. Run validation/check_agent_2.py when done."
    [3]="Read .claude/agents/dl-architect.md then create the dl_models/ package with a temporal LSTM autoencoder, a process-tree GNN using PyTorch Geometric, and a contrastive entity learner. All must implement the DLAnomalyModel interface. Include README with architecture docs. Run validation/check_agent_3.py when done."
    [4]="Read .claude/agents/fp-fn-tuner.md then implement graduated allowlisting in benign_lists.py with NEVER_ALLOWLIST for LOLBins, adaptive per-job thresholds in config.py, intelligent dedup with score escalation in push_all_anomalies.py filter sections, and create missed_attack_audit.py. Run validation/check_agent_4.py when done."
    [5]="Read .claude/agents/evasion-hardener.md then create the adversarial/ package with input validation guards, concept drift monitoring via PSI and KS-test, synthetic ATT&CK attack data generation, model robustness perturbation tests, and ensemble disagreement monitoring. Run validation/check_agent_5.py when done."
    [6]="Read .claude/agents/ops-hardener.md then add MITRE ATT&CK enrichment to push_all_anomalies.py enrichment sections, upgrade post_correlation.py with three-way kill-chain correlation, add alert context packages, harden realtime_service.py with circuit breakers and structured logging. Run validation/check_agent_6.py when done."
    [7]="Read .claude/agents/test-benchmark.md then create ALL validation scripts in validation/ (check_agent_1.py through check_agent_7.py), build 5 labeled attack simulation scenarios in benchmarks/attack_scenarios/, create the benchmark evaluation framework, write the regression test suite in tests/, and build the CI hook. Run validation/check_agent_7.py when done."
)

# Determine which agents to launch
if [ $# -gt 0 ]; then
    AGENTS=("$@")
else
    AGENTS=(7 2 1 3 5 4 6)  # Launch order: test infra first, then by dependency
fi

echo "============================================="
echo "  Launching ${#AGENTS[@]} agents"
echo "============================================="
echo ""

# Launch Agent 7 (test harness) first if it's in the list, because other
# agents need the validation scripts it creates.
AGENT_7_FIRST=false
for a in "${AGENTS[@]}"; do
    if [ "$a" = "7" ]; then
        AGENT_7_FIRST=true
        break
    fi
done

launch_agent() {
    local num=$1
    local name="${AGENT_NAMES[$num]}"
    local task="${AGENT_TASKS[$num]}"

    echo "--- Launching Agent $num: $name ---"
    echo "    Task: ${task:0:100}..."
    echo ""

    # Use --worktree to give each agent its own git worktree
    claude --worktree "$task" &

    # Small delay to avoid git lock contention
    sleep 2
}

if [ "$AGENT_7_FIRST" = true ]; then
    echo "[Phase 0] Launching Agent 7 (test infrastructure) first..."
    echo "          Wait for it to create validation/ scripts before other agents finish."
    echo ""
    launch_agent 7
    sleep 5  # Give it a head start
fi

echo "[Phase 1] Launching remaining agents in parallel..."
echo ""

for a in "${AGENTS[@]}"; do
    if [ "$a" != "7" ] || [ "$AGENT_7_FIRST" = false ]; then
        launch_agent "$a"
    fi
done

echo ""
echo "============================================="
echo "  All agents launched."
echo ""
echo "  Monitor progress:"
echo "    - Each agent runs in its own worktree"
echo "    - Check .claude/teams/ for coordination state"
echo "    - Run: python validation/check_all.py"
echo "      after agents complete to verify quality"
echo ""
echo "  Merge order (after all agents finish):"
echo "    1. Agent 7 (tests)"
echo "    2. Agent 2 (features)"
echo "    3. Agent 1 (models)"
echo "    4. Agent 3 (DL models)"
echo "    5. Agent 5 (adversarial)"
echo "    6. Agent 4 (FP/FN tuning)"
echo "    7. Agent 6 (ops/push/correlation)"
echo "============================================="
