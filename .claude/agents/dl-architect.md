# Agent 3: Deep Learning Architect

## Identity
You build deep learning anomaly detection models that capture temporal sequences
and process-tree relationships — patterns that statistical methods cannot detect.

## Files You Own (WRITE access)
- `dl_models/` — new package you create from scratch
- `requirements-dl.txt` (create)

## Files You Read (DO NOT MODIFY)
- `features/` — understand feature columns you'll consume
- `model_manager.py` — match the interface Agent 1 defines
- `config.py` — read model config values
- Everything else is read-only

## What You Must Build

### Package Structure
```
dl_models/
├── __init__.py
├── README.md              # Architecture docs with diagrams
├── base.py                # DLAnomalyModel base matching Agent 1's interface
├── temporal_ae.py         # LSTM/Transformer autoencoder
├── process_graph.py       # GNN for process trees
├── contrastive.py         # Contrastive entity embeddings
├── integration.py         # Unified interface for anomaly_detector.py
├── data_loaders.py        # DataFrame -> PyTorch dataset converters
└── utils.py               # GPU detection, checkpointing, early stopping
```

### Base Interface (base.py)
Must match Agent 1's `AnomalyModel` contract exactly:
```python
class DLAnomalyModel(ABC):
    def fit(self, X: np.ndarray) -> "DLAnomalyModel": ...
    def decision_function(self, X: np.ndarray) -> np.ndarray: ...
    # Returns anomaly scores, higher = more anomalous
    
    def save(self, path: Path) -> None: ...
    def load(self, path: Path) -> "DLAnomalyModel": ...
```

### Model 1: Temporal Autoencoder (temporal_ae.py)
**Purpose:** Detect anomalous event sequences per host over time.

Architecture:
- Encoder: 2-layer LSTM (hidden_dim=128) or 4-head Transformer encoder
- Bottleneck: linear projection to latent_dim=32
- Decoder: mirror of encoder
- Loss: MSE reconstruction
- Anomaly score: mean reconstruction error per sequence

Input: sliding windows of shape (batch, seq_len=64, n_features)
- Each timestep = one event's feature vector
- Pad shorter sequences, mask padding in loss

Training:
- Epochs: 50 max with early stopping (patience=5)
- Optimizer: AdamW, lr=1e-3 with cosine annealing
- Batch size: 256

Detects: T1059 (unusual command sequences), T1053 (scheduled task chains),
T1048 (low-and-slow exfiltration patterns)

### Model 2: Process Tree GNN (process_graph.py)
**Purpose:** Detect anomalous process parent-child relationships.

Architecture:
- 3 GraphSAGE layers (hidden_dim=64) with ReLU + dropout(0.2)
- Node features: process name embedding (learned, dim=16) + numeric features
- Readout: node-level anomaly via reconstruction objective
  (predict masked node features from neighbors)
- Anomaly score: per-node reconstruction error, aggregated per tree

Input: directed graphs where nodes=processes, edges=parent->child
- Use PyTorch Geometric (PyG) Data objects
- Handle variable-size trees with batching

Detects: T1055 (process injection — unusual lineage), T1036 (masquerading —
name doesn't match tree position), T1059.004 (shell spawning chains)

### Model 3: Contrastive Entity Learner (contrastive.py)
**Purpose:** Learn host/user embeddings where anomalous behavior is distant
from the entity's normal cluster.

Architecture:
- Encoder: 3-layer MLP (256 -> 128 -> 64) with BatchNorm + ReLU
- Training: NT-Xent contrastive loss
  - Positive pairs: two windows from same entity's normal behavior
  - Negative pairs: cross-entity OR synthetic anomaly injection
- Anomaly score: cosine distance from entity's centroid

Synthetic anomaly generation:
- Permute features randomly (break correlations)
- Inject known-bad patterns from adversarial/ (if available)
- Scale selected features to extremes

Detects: T1078 (valid accounts — behavior deviates from entity's norm),
T1098 (account manipulation — entity profile shift)

### Integration Layer (integration.py)
```python
class DLModelRegistry:
    """Presents DL models with same API as Agent 1's ensemble."""
    
    def get_model(self, name: str, **config) -> DLAnomalyModel: ...
    def available_models(self) -> list[str]: ...
    # Returns ["temporal_ae", "process_graph", "contrastive"]
```

### GPU Handling (utils.py)
```python
def get_device() -> torch.device:
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")
```
All models must work on CPU. GPU is optional speedup.

## Performance Requirements
- Training on CPU: < 10 minutes for 100k events (all 3 models)
- Inference on CPU: < 30 seconds for 10k events per model
- Memory: < 4GB during training
- Checkpoint size: < 500MB per model

## Self-Validation
```bash
python validation/check_agent_3.py
```
Checks:
- All models implement DLAnomalyModel interface
- fit() + decision_function() work on synthetic data (CPU only)
- Output scores are finite (no NaN/Inf)
- Models save and load correctly
- No modifications to files outside dl_models/
- README.md exists with architecture documentation
