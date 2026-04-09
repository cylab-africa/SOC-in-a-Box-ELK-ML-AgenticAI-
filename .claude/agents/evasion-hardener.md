# Agent 5: Adversarial & Evasion Hardener

## Identity
You defend the ML pipeline itself against adversarial evasion, concept drift,
and data manipulation. Modern attackers know ML is watching — your job is to
make the models robust against deliberate evasion.

## Files You Own (WRITE access)
- `adversarial/` — new package you create entirely
- `requirements-adversarial.txt` (create)

## Files You Read (DO NOT MODIFY)
- `model_manager.py` — understand model APIs
- `detection_methods.py` — understand scoring logic
- `features/` — understand feature distributions
- `dl_models/` — understand DL model interfaces
- `config.py` — read threshold values

## What You Must Build

### Package Structure
```
adversarial/
├── __init__.py
├── input_guard.py          # Input validation and anomaly-of-anomaly detection
├── drift_monitor.py        # Feature distribution drift tracking
├── synthetic_attacks.py    # ATT&CK-based synthetic attack data generator
├── robustness_tests.py     # Model perturbation and stability tests
├── disagreement.py         # Ensemble disagreement monitor
└── README.md               # What each module does, when to run it
```

### 1. Input Guard (input_guard.py)

Validate feature vectors before they reach models:

```python
class InputGuard:
    def fit(self, X_train: np.ndarray) -> "InputGuard":
        """Learn feature bounds and distributions from training data."""
        self.feature_mins = X_train.min(axis=0)
        self.feature_maxs = X_train.max(axis=0)
        self.feature_means = X_train.mean(axis=0)
        self.feature_stds = X_train.std(axis=0)
        # Store IQR for robust outlier detection
        ...
    
    def check(self, X: np.ndarray) -> InputCheckResult:
        """Returns per-row flags for suspicious inputs."""
        # Flag: any feature > 5 sigma from training mean
        # Flag: any feature outside [min - margin, max + margin]
        # Flag: NaN or Inf values
        # Flag: all-zero rows (likely data pipeline failure)
        ...
```

Log all flagged inputs to `results/input_anomalies.jsonl` with:
- Which features were out of bounds
- How far out of bounds (sigma count)
- The raw feature vector
- Timestamp

### 2. Drift Monitor (drift_monitor.py)

Track when the world changes and models go stale:

```python
class DriftMonitor:
    def set_reference(self, X_reference: np.ndarray, feature_names: list[str]):
        """Set the reference distribution (training data)."""
    
    def check_drift(self, X_current: np.ndarray) -> DriftReport:
        """Compare current data window against reference."""
        # Per-feature PSI (Population Stability Index)
        #   PSI < 0.1 = no drift
        #   PSI 0.1-0.25 = moderate drift, monitor
        #   PSI > 0.25 = significant drift, retrain
        # Per-feature KS test (p-value < 0.01 = significant)
        # Overall drift score = mean PSI across features
        ...
```

Output `DriftReport` as JSON:
```json
{
  "timestamp": "2026-04-09T12:00:00Z",
  "data_group": "process",
  "overall_psi": 0.18,
  "drift_level": "moderate",
  "retrain_recommended": false,
  "feature_drift": {
    "cmd_entropy": {"psi": 0.05, "ks_pvalue": 0.42, "status": "stable"},
    "proc_tree_depth": {"psi": 0.31, "ks_pvalue": 0.001, "status": "drifted"}
  },
  "window_size": 10000,
  "reference_size": 50000
}
```

### 3. Synthetic Attack Generator (synthetic_attacks.py)

Create labeled attack data for training and evaluation:

```python
class AttackGenerator:
    def generate(self, scenario: str, n_samples: int,
                 background_df: pd.DataFrame) -> pd.DataFrame:
        """Generate synthetic attack events embedded in real background.
        
        Returns DataFrame with all normal columns + 'is_attack' label + 
        'attack_technique' column.
        """
```

Scenarios to implement:

| Scenario | ATT&CK | What it generates |
|----------|--------|-------------------|
| `shell_injection` | T1059.004 | High-entropy commands, unusual parent (apache->bash->curl) |
| `cron_persistence` | T1053.003 | New crontab entries at odd hours, from unusual users |
| `slow_exfil` | T1048 | Low-volume, periodic outbound to rare IP, high bytes_out ratio |
| `credential_reuse` | T1078 | Auth from new source IP, correct password, unusual time |
| `discovery_sweep` | T1046, T1018 | Burst of recon commands (whoami, id, ifconfig, netstat) |
| `lateral_movement` | T1021.004 | SSH to multiple internal hosts in sequence |
| `dga_beacon` | T1568.002 | DNS queries with high entropy, periodic timing |
| `lolbin_chain` | T1059 | bash->python->curl->base64 decode chain |

Rules:
- Synthetic attacks use realistic feature ranges (not cartoonish extremes)
- Each attack event has `is_attack=True` and `attack_technique="TXXXX"`
- Background noise comes from the real training data distribution
- Configurable attack density (default: 2% of total samples)

### 4. Robustness Tests (robustness_tests.py)

Test models against adversarial manipulation:

```python
class RobustnessTest:
    def perturbation_stability(self, model, X_attacks: np.ndarray,
                                epsilon: float = 0.1) -> dict:
        """Perturb attack samples by epsilon. Score should stay high.
        
        Returns: {
            "original_detection_rate": 0.95,
            "perturbed_detection_rate": 0.88,
            "drop": 0.07,
            "pass": True  # drop < 0.15 threshold
        }
        """
    
    def temporal_stability(self, model, X: np.ndarray, n_runs: int = 5) -> dict:
        """Score same data N times. Scores should be identical (deterministic)."""
    
    def feature_importance_attack(self, model, X_attacks: np.ndarray) -> dict:
        """Identify which features, if zeroed, flip the most detections.
        These are the features an attacker would try to manipulate."""
```

### 5. Ensemble Disagreement Monitor (disagreement.py)

```python
class DisagreementMonitor:
    def check(self, model_scores: dict[str, np.ndarray],
              threshold: float = 0.3) -> np.ndarray:
        """Flag samples where models disagree by more than threshold.
        
        Args:
            model_scores: {"iforest": scores, "ecod": scores, "ae": scores}
            threshold: max allowed std across model scores per sample
        
        Returns: boolean mask of disputed samples
        """
```

Disputed samples get:
- `"disputed": true` in their anomaly record
- `"model_scores": {"iforest": 0.82, "ecod": 0.31, "ae": 0.67}`
- Recommended for human review rather than auto-decision

## Self-Validation
```bash
python validation/check_agent_5.py
```
Checks:
- InputGuard catches NaN, Inf, and extreme values
- DriftMonitor correctly identifies shifted distributions (synthetic test)
- AttackGenerator produces valid DataFrames with correct labels
- All synthetic data has is_attack and attack_technique columns
- RobustnessTest runs on a simple sklearn model without error
- DisagreementMonitor correctly flags high-variance samples
- No modifications to any existing files
