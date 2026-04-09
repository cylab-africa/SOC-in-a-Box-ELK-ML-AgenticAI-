# Agent 7: Test & Benchmark Harness

## Identity
You are the quality gate. Nothing merges without your approval. You build the
evaluation infrastructure that proves the pipeline actually detects attacks
and doesn't regress when changes are made.

## Files You Own (WRITE access)
- `tests/` — full ownership of all test files
- `benchmarks/` — new directory you create
- `scripts/` — validation and debugging scripts
- `validation/` — agent self-check scripts (you write ALL of them)
- `requirements-test.txt` (create)

## Files You Read (DO NOT MODIFY)
- Everything else in the project — you read all code but change none

## What You Must Build

### 1. Validation Scripts for Every Agent (validation/)

These are the quality gates. Each agent MUST pass their check before merging.

```
validation/
├── check_agent_1.py    # ML Model Upgrader
├── check_agent_2.py    # Feature Engineer
├── check_agent_3.py    # Deep Learning Architect
├── check_agent_4.py    # FP/FN Tuner
├── check_agent_5.py    # Adversarial Hardener
├── check_agent_6.py    # Push & Correlation Hardener
├── check_agent_7.py    # Self-check (tests pass, benchmarks run)
├── check_all.py        # Run all checks, report summary
└── common.py           # Shared validation helpers
```

Each check script:
- Exits 0 on success, 1 on failure
- Prints clear PASS/FAIL per check with failure reason
- Verifies file ownership boundaries (agent didn't touch other files)
- Verifies code quality (py_compile, type hints, docstrings)
- Runs functional tests specific to that agent's deliverables

**check_agent_1.py** verifies:
- All model classes subclass AnomalyModel
- .fit() and .decision_function() work on synthetic numpy arrays
- Ensemble scores are in [0, 1] range
- manifest.json is valid JSON with required keys
- Only model_manager.py, detection_methods.py, models/ were changed

**check_agent_2.py** verifies:
- All transformers subclass FeatureTransformer
- .fit() + .transform() on synthetic DataFrame works
- Output columns are all float64
- No NaN in output when source fields have NaN
- get_attack_mapping() returns dict with valid TXXXX keys
- Only datamanager.py, data.py, features/ were changed

**check_agent_3.py** verifies:
- All DL models subclass DLAnomalyModel
- .fit() and .decision_function() work on CPU with synthetic data
- Scores are finite (no NaN/Inf)
- .save() and .load() round-trip correctly
- Only dl_models/ was created/changed

**check_agent_4.py** verifies:
- LOLBins in NEVER_ALLOWLIST are never dampened (test each one)
- Expired allowlist entries skip
- Adaptive thresholds compute correctly for test scenarios
- filter_trace field present on processed records
- Only benign_lists.py, config.py thresholds, push filter sections changed

**check_agent_5.py** verifies:
- InputGuard catches NaN, Inf, 10-sigma values
- DriftMonitor detects shifted distribution (shift mean by 3 sigma)
- AttackGenerator output has is_attack + attack_technique columns
- Only adversarial/ was created

**check_agent_6.py** verifies:
- ATT&CK mapping covers all JOB_CONFIGURATIONS keys
- Correlation produces chains from synthetic data
- Context enrichment adds all required fields
- Circuit breaker state machine works
- Only enrichment/push sections of push_all_anomalies.py, post_correlation.py, realtime_service.py changed

### 2. Attack Simulation Datasets (benchmarks/attack_scenarios/)

Create 5 labeled scenarios as JSON files. Each scenario:
- Contains ES-format event documents (matching your index schemas)
- Has ground truth labels: `is_attack`, `attack_technique`, `attack_phase`
- Includes realistic background noise (80-98% normal events)
- Has a timeline (events ordered by timestamp)

```
benchmarks/attack_scenarios/
├── scenario_01_webshell_exfil.json
├── scenario_02_ssh_bruteforce_lateral.json
├── scenario_03_supply_chain_c2.json
├── scenario_04_insider_threat.json
├── scenario_05_lolbin_chain.json
└── README.md  # Describes each scenario, expected detections
```

**Scenario 1: Webshell → Discovery → PrivEsc → Exfil**
- Apache spawns /bin/bash (T1059.004)
- whoami, id, cat /etc/passwd (T1033, T1087)
- sudo -l, then exploit (T1548)
- curl POST to external IP with encoded data (T1048)
- ~500 events total, ~20 attack events

**Scenario 2: SSH Brute Force → Credential Access → Lateral Movement**
- 50 failed SSH logins from external IP (T1110.001)
- 1 successful login (T1078)
- SSH to 3 internal hosts in sequence (T1021.004)
- ~300 events total, ~60 attack events

**Scenario 3: Supply Chain — Malicious Cron → C2 Beacon → Data Staging**
- New crontab entry at 3AM (T1053.003)
- Periodic curl to DGA domain every 5 minutes (T1071.001, T1568.002)
- tar + base64 of /var/log (T1560.001)
- ~400 events total, ~15 attack events

**Scenario 4: Insider Threat**
- Auth from unusual location at unusual time (T1078)
- Mass file access (T1005)
- Large rsync to external host (T1048)
- ~200 events total, ~10 attack events

**Scenario 5: LOLBin Chain**
- bash → python3 → wget → chmod → execute → netcat (T1059, T1105, T1571)
- All legitimate binaries, no malware on disk
- ~150 events total, ~8 attack events

### 3. Benchmark Framework (benchmarks/evaluate.py)

```python
class PipelineBenchmark:
    def __init__(self, scenario_dir: str, pipeline_config: dict):
        ...
    
    def run(self) -> BenchmarkReport:
        """Run all scenarios through the pipeline, compute metrics."""
        ...
    
    def compare(self, baseline_report: BenchmarkReport,
                current_report: BenchmarkReport) -> ComparisonReport:
        """Diff two benchmark runs to catch regressions."""
        ...

@dataclass
class BenchmarkReport:
    # Per-job metrics
    per_job: dict[str, JobMetrics]
    # Per-scenario metrics
    per_scenario: dict[str, ScenarioMetrics]
    # Overall
    overall_auc_pr: float
    overall_auc_roc: float
    mean_time_to_detect_minutes: float
    alerts_per_day: float
    # Metadata
    timestamp: str
    pipeline_config_hash: str
    
@dataclass
class ScenarioMetrics:
    scenario_name: str
    attack_events_total: int
    attack_events_detected: int
    detection_rate: float  # recall
    false_alarms: int
    precision: float
    f1: float
    time_to_first_detection_sec: float
    kill_chain_phases_detected: list[str]
    kill_chain_completeness: float
```

Output: `benchmarks/results/{timestamp}_report.json` + markdown summary.

### 4. Performance Benchmarks (benchmarks/performance.py)

Measure:
- Training time per model per data group (wall clock)
- Inference latency: p50, p95, p99 per detection job (on 10k rows)
- Memory peak during training (via tracemalloc)
- End-to-end latency: data load → score → push (simulated)

Output: `benchmarks/results/{timestamp}_performance.json`

### 5. Regression Test Suite (tests/)

```
tests/
├── conftest.py               # Shared fixtures: synthetic data, mock ES
├── test_models.py            # Model interface compliance
├── test_features.py          # Feature transformer correctness
├── test_dl_models.py         # DL model interface compliance
├── test_detection.py         # Detection job output format
├── test_push_filtering.py    # Allowlist, dedup, threshold logic
├── test_push_enrichment.py   # MITRE mapping, context fields
├── test_correlation.py       # Chain detection correctness
├── test_adversarial.py       # Drift, input guard, synthetic attacks
├── test_integration.py       # End-to-end: synthetic data → alert output
└── test_no_regression.py     # Snapshot tests against known-good outputs
```

Key fixtures in conftest.py:
```python
@pytest.fixture
def synthetic_process_df():
    """100-row DataFrame matching process event schema."""
    ...

@pytest.fixture
def synthetic_network_df():
    """100-row DataFrame matching network event schema."""
    ...

@pytest.fixture
def mock_es(monkeypatch):
    """Mock Elasticsearch client that returns canned responses."""
    ...

@pytest.fixture
def attack_scenario_1():
    """Load webshell exfil scenario."""
    ...
```

### 6. CI Hook (benchmarks/ci_hook.py)

```bash
python benchmarks/ci_hook.py --baseline benchmarks/results/baseline_report.json
```

- Runs full benchmark suite
- Compares against baseline
- Fails (exit 1) if ANY metric regresses beyond tolerance:
  - AUC-PR drops > 0.02
  - Detection rate drops > 0.05 on any scenario
  - Alert volume increases > 20%
  - Inference latency p95 increases > 50%
- Prints clear report of what passed/failed

## Self-Validation
```bash
python validation/check_agent_7.py
```
Self-checks:
- All test files pass py_compile
- pytest collection succeeds (no import errors)
- All 5 scenarios are valid JSON with required fields
- Benchmark framework instantiates without error
- All other validation scripts (check_agent_1 through 6) exist and are executable
- No modifications to files outside tests/, benchmarks/, scripts/, validation/
