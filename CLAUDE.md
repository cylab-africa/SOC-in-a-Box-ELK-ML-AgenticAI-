# Linux Threat Detection Pipeline — Multi-Agent Coordination

## Project Context

This is a Linux endpoint anomaly detection system backed by Elasticsearch.
The codebase has: `main.py`, `realtime_service.py`, `config.py`, `datamanager.py`,
`model_manager.py`, `anomaly_detector.py`, `detection_methods.py`,
`push_all_anomalies.py`, `post_correlation.py`, `benign_lists.py`,
`fixedLDS.py`, `entity_alignment.py`.

We are upgrading it from basic Isolation Forest anomaly detection to a
state-of-the-art multi-model, MITRE ATT&CK-aligned threat detection pipeline.

## Sub-Agent Routing Rules

**Parallel dispatch** (ALL conditions met — this is the default):
- Agents work on independent file sets per the ownership matrix below
- No shared mutable state between agents
- New packages (features/, dl_models/, adversarial/, benchmarks/) are each
  owned by exactly one agent

**Sequential dispatch** (ANY condition triggers):
- Integration phase: merge in dependency order (see below)
- Two agents touching push_all_anomalies.py: Agent 4 owns filtering sections,
  Agent 6 owns enrichment sections — they must not overlap

**Background dispatch**:
- Agent 7 (test/benchmark) runs continuously and validates other agents' output

## File Ownership Matrix

| File / Directory           | Owner Agent | Others |
|----------------------------|-------------|--------|
| model_manager.py           | Agent 1     | read-only |
| detection_methods.py       | Agent 1     | read-only |
| datamanager.py             | Agent 2     | read-only |
| data.py                    | Agent 2     | read-only |
| features/                  | Agent 2     | Agent 3 reads |
| dl_models/                 | Agent 3     | read-only |
| models/                    | Agent 1     | read-only |
| benign_lists.py            | Agent 4     | read-only |
| config.py (thresholds)     | Agent 4     | read-only |
| adversarial/               | Agent 5     | read-only |
| push_all_anomalies.py      | Agent 4 (filter) + Agent 6 (enrich) | read-only |
| post_correlation.py        | Agent 6     | read-only |
| realtime_service.py        | Agent 6     | read-only |
| tests/                     | Agent 7     | read-only |
| benchmarks/                | Agent 7     | read-only |
| scripts/                   | Agent 7     | read-only |
| validation/                | shared      | all agents run their own checks |

## Merge Order (Integration Phase)

1. Agent 7 — test infrastructure (no dependencies)
2. Agent 2 — features/ (foundational — models depend on this)
3. Agent 1 — model upgrades (consumes features)
4. Agent 3 — deep learning models (consumes features)
5. Agent 5 — adversarial hardening (wraps models)
6. Agent 4 — FP/FN tuning (uses updated scores from 1, 3)
7. Agent 6 — ops/push/correlation (consumes everything)

## Quality Gates (Every Agent Must Pass Before Merge)

Every agent runs its own validation script at `validation/check_agent_N.py`.
A merge is blocked unless:

1. All new Python files pass `python -m py_compile <file>` (no syntax errors)
2. All new functions have type hints on params and return
3. All new public functions have docstrings
4. No hardcoded secrets, passwords, or API keys
5. No modifications to files outside the agent's ownership
6. The agent's own validation script exits 0
7. Existing tests still pass: `python -m pytest tests/ -x --tb=short`

## Code Standards

- Python 3.10+, type hints on all function signatures
- Docstrings on all public functions (one-line or multi-line)
- No emojis in code, logs, comments, or output
- f-strings over .format()
- Pathlib over os.path
- Structured logging (JSON format for production)
- No magic numbers — named constants or config values
- Every ML model implements: .fit(X), .decision_function(X) -> np.ndarray
- All scores normalized to [0.0, 1.0]
- All new dependencies in the appropriate requirements file

## ATT&CK Alignment

Every detection capability must map to at least one MITRE ATT&CK technique.
Use technique IDs in docstrings, config entries, and alert enrichment.
Reference: https://attack.mitre.org/techniques/enterprise/
