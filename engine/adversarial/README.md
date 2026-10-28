# Adversarial Hardening Package

> **Experimental:** the running detection engine does not use these yet.

Defenses against model evasion, input manipulation, and concept drift
for the Linux anomaly detection pipeline.

## Components

### Input Guard (`input_guard.py`)
Pre-processing validation that catches malformed or adversarial inputs
before they reach the models. Detects NaN, Inf, extreme outliers (>10 sigma),
and type mismatches.

**ATT&CK**: Guards against T1059 (obfuscated commands), T1036 (masquerading inputs)

### Drift Monitor (`drift_monitor.py`)
Detects distribution shift between training and production data using
Population Stability Index (PSI) and Kolmogorov-Smirnov tests per feature.

**ATT&CK**: Guards against gradual evasion where attackers slowly shift
feature distributions to avoid detection thresholds.

### Synthetic Attack Generator (`synthetic_attacks.py`)
Generates labeled attack scenarios for testing pipeline detection coverage.
Supports 8 attack patterns mapped to MITRE ATT&CK techniques.

### Robustness Tests (`robustness_tests.py`)
Verifies model stability under:
- Small input perturbations (Gaussian noise)
- Temporal consistency (repeated identical input)
- Feature importance attacks (zeroing top-k influential features)

### Disagreement Monitor (`disagreement.py`)
Monitors ensemble disagreement per sample. High disagreement between models
may indicate adversarial samples targeting a specific model's blind spot.

Accepts both `np.ndarray` (n_samples, n_models) and `dict[str, np.ndarray]`
for flexible integration with the model ensemble.

## Usage

```python
from adversarial.input_guard import InputGuard
from adversarial.drift_monitor import DriftMonitor
from adversarial.robustness_tests import RobustnessTest
from adversarial.disagreement import DisagreementMonitor

# Validate inputs before scoring
guard = InputGuard()
guard.fit(X_train)
clean, report = guard.check(X_new)

# Check for distribution drift
monitor = DriftMonitor()
monitor.fit(X_train)
drift_report = monitor.check(X_production)

# Test model robustness
tester = RobustnessTest()
results = tester.run_all(model, X_test)

# Monitor ensemble disagreement
dm = DisagreementMonitor(threshold=0.4)
scores_dict = {"model_a": scores_a, "model_b": scores_b}
disagreement = dm.check(scores_dict)
```
