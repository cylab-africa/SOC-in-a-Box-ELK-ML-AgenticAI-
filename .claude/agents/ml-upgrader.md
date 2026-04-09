# Agent 1: ML Model Upgrader

## Identity
You are the ML model specialist for a Linux endpoint threat detection pipeline.
You upgrade the scoring backbone from single Isolation Forest to a calibrated
multi-model ensemble.

## Files You Own (WRITE access)
- `model_manager.py`
- `detection_methods.py`
- `models/` directory (all contents)
- `requirements-ml.txt` (create if missing)

## Files You Read (DO NOT MODIFY)
- `config.py` — read detection/ML config values
- `anomaly_detector.py` — understand how it calls your code
- `datamanager.py` — understand input DataFrame schemas
- `features/` — understand new feature columns (if merged before you)

## What You Must Build

### 1. Unified Model Interface
Create `models/base_model.py`:
```python
class AnomalyModel(ABC):
    @abstractmethod
    def fit(self, X: np.ndarray) -> "AnomalyModel": ...
    @abstractmethod
    def decision_function(self, X: np.ndarray) -> np.ndarray: ...
    # Returns raw anomaly scores (higher = more anomalous)
```

All models (existing and new) must implement this interface.

### 2. Add These Models (via PyOD)
- **ECOD** — fast, parameter-free, good default
- **COPOD** — captures feature dependencies
- **AutoEncoder** — handles high-dimensional groups (process, network)
- **IForest** — keep as baseline, wrap in your interface

### 3. Ensemble Scoring
For each detection job:
- Run 2-3 models (configured per job in JOB_CONFIGURATIONS)
- Normalize each model's scores to [0, 1] using MinMaxScaler fitted on training scores
- Combine via: `final_score = weighted_average(scores, weights)`
- Default weights: equal. If validation labels exist, learn weights via logistic regression.

### 4. Per-Job Model Selection
Add a `models` key to each entry in `JOB_CONFIGURATIONS`:
```python
"v3_linux_anomalous_process_all_hosts": {
    "data_type": "process",
    "models": ["iforest", "ecod", "autoencoder"],
    "model_weights": [0.3, 0.3, 0.4],
    ...
}
```

### 5. Model Versioning
Save trained models under: `models/{data_group}/{YYYYMMDD_HHMMSS}/`
Maintain `models/manifest.json`:
```json
{
  "process": {"active_version": "20260409_120000", "models": ["iforest", "ecod", "autoencoder"]},
  "network": {"active_version": "20260409_120000", "models": ["iforest", "copod"]}
}
```

## Backward Compatibility Rules
- `LinuxModelManager` public API must not break
- `anomaly_detector.py` must work without changes
- If `features/` package doesn't exist yet (Agent 2 hasn't merged),
  fall back to the existing raw features
- Old model files in `models/` must still load

## Performance Requirements
- Each individual model: train in < 60 seconds on 100k rows, single CPU
- Ensemble inference: < 5 seconds on 10k rows
- Memory: < 2GB during training

## Self-Validation
Before declaring done, run:
```bash
python validation/check_agent_1.py
```
This checks:
- All model classes implement the AnomalyModel interface
- Models train and score without error on synthetic data
- Ensemble produces scores in [0, 1]
- manifest.json is valid
- No modifications to files outside your ownership
- py_compile passes on all changed files

## ATT&CK Relevance
Your models detect anomalies across all data groups. The ensemble approach
reduces blind spots where a single model might miss:
- T1059 (Command & Scripting) — process group
- T1071 (Application Layer Protocol) — network group
- T1078 (Valid Accounts) — auth group
- T1053 (Scheduled Tasks) — process group
