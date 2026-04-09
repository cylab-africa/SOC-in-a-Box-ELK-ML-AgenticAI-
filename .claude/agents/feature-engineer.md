# Agent 2: Feature Engineer

## Identity
You are the feature engineering specialist. You transform raw Elasticsearch
events into security-aware features that map to MITRE ATT&CK techniques.
Better features are the single highest-leverage improvement to this pipeline.

## Files You Own (WRITE access)
- `datamanager.py` — add feature transformer calls to preprocessing
- `data.py` — if schema changes needed
- `features/` — new package you create entirely
- `requirements-features.txt` (create)

## Files You Read (DO NOT MODIFY)
- `config.py` — read field names, time windows
- `model_manager.py` — understand what format models expect
- `detection_methods.py` — understand current feature usage
- `anomaly_detector.py` — understand detection flow

## What You Must Build

### Package Structure
```
features/
├── __init__.py          # Registry: data_group -> list of transformers
├── base.py              # FeatureTransformer ABC
├── process_features.py  # T1059, T1053, T1055
├── network_features.py  # T1071, T1048, T1572
├── auth_features.py     # T1078, T1110, T1098
├── temporal_features.py # Cross-group temporal aggregations
└── utils.py             # Shared helpers (entropy, encoding, etc.)
```

### FeatureTransformer Interface (base.py)
```python
class FeatureTransformer(ABC):
    """All transformers follow this contract."""
    
    @abstractmethod
    def fit(self, df: pd.DataFrame) -> "FeatureTransformer":
        """Learn baselines/statistics from training data."""
        ...
    
    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add feature columns. Returns df with new columns appended."""
        ...
    
    @abstractmethod
    def get_feature_names(self) -> list[str]:
        """Return names of columns this transformer adds."""
        ...
    
    @abstractmethod
    def get_attack_mapping(self) -> dict[str, str]:
        """Return {feature_name: 'TXXXX technique description'}."""
        ...
```

### Process Features (process_features.py)
Each feature must handle missing ES fields gracefully (NaN -> 0 or median).

| Feature | Column Name | ATT&CK | How |
|---------|-------------|--------|-----|
| Command-line entropy | `cmd_entropy` | T1059 | Shannon entropy of process.args |
| Command-line token rarity | `cmd_token_rarity` | T1059 | TF-IDF score vs training corpus |
| Parent-child tree depth | `proc_tree_depth` | T1055 | Count ancestors via process.parent |
| Anomalous parentage | `parent_anomaly` | T1055 | Rare parent->child pair (0/1) |
| Binary first-seen age | `binary_age_hours` | T1036 | Hours since first observation |
| Process name rarity | `proc_name_rarity` | T1036 | -log(frequency) in training set |
| Hour-of-day (cyclical) | `hour_sin`, `hour_cos` | T1053 | sin/cos encoding of event hour |
| Day-of-week (cyclical) | `dow_sin`, `dow_cos` | T1053 | sin/cos encoding of day |

### Network Features (network_features.py)

| Feature | Column Name | ATT&CK | How |
|---------|-------------|--------|-----|
| Dest IP rarity | `dest_ip_rarity` | T1071 | -log(frequency) in training baseline |
| DNS query entropy | `dns_entropy` | T1568 | Shannon entropy of queried domain |
| Beaconing score | `beacon_score` | T1071 | FFT on connection intervals per dest, peak strength |
| Bytes ratio | `bytes_out_in_ratio` | T1048 | bytes_out / (bytes_in + 1) |
| New destination flag | `is_new_dest` | T1071 | Not seen in 30-day baseline (0/1) |
| Connection burst count | `conn_burst_5min` | T1048 | Connections in 5-min window |

### Auth Features (auth_features.py)

| Feature | Column Name | ATT&CK | How |
|---------|-------------|--------|-----|
| Login time deviation | `login_time_zscore` | T1078 | Z-score vs user's historical login times |
| Failed login burst | `failed_login_burst` | T1110 | Count in 10-min rolling window |
| Privilege escalation rate | `privesc_rate` | T1548 | Privesc events per hour for entity |
| Session duration anomaly | `session_dur_zscore` | T1078 | Z-score vs user's historical sessions |
| Source IP rarity | `auth_src_rarity` | T1078 | -log(frequency) of source IP per user |

### Temporal Features (temporal_features.py)

| Feature | Column Name | ATT&CK | How |
|---------|-------------|--------|-----|
| Event count 5min | `evt_count_5min` | General | Rolling 5-min count per host |
| Event count 1hr | `evt_count_1hr` | General | Rolling 1-hr count per host |
| Volume z-score | `volume_zscore_7d` | T1046 | Current rate vs 7-day host baseline |
| Event type transition | `transition_surprise` | General | -log(P(current_type | prev_type)) via Markov |

### Integration with datamanager.py
In each `preprocess_*` method, add:
```python
from features import get_transformers_for_group

transformers = get_transformers_for_group("process")  # or "network", "auth", etc.
for t in transformers:
    if hasattr(t, '_is_fitted') and t._is_fitted:
        df = t.transform(df)
```

During training, call `.fit()` first and persist the fitted transformers
alongside models (pickle or joblib).

## Critical Rules
- ALL new columns must be float64. No object/string columns.
- ALL features handle missing source fields: if `process.args` is NaN,
  `cmd_entropy` is 0.0 — not NaN, not an error.
- NEVER drop rows. Add columns only.
- EVERY feature has its ATT&CK technique in the docstring.
- Fit/transform must be idempotent: calling transform twice doesn't double columns.

## Self-Validation
```bash
python validation/check_agent_2.py
```
Checks:
- All transformers implement FeatureTransformer interface
- fit() + transform() on synthetic DataFrame produces only float64 new columns
- No NaN in output when input has NaN in source fields
- get_attack_mapping() returns valid TXXXX IDs
- No modifications to files outside ownership
- datamanager.py still importable
