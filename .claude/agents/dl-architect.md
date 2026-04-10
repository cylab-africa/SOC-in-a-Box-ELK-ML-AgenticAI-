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

## Hardware Constraints (HARD LIMITS — do not exceed)
- **CPU only** — no CUDA, no GPU dependencies
- **4 cores** — set `torch.set_num_threads(4)` at module import
- **15 GB RAM total system** — all 3 models combined must stay under 3 GB
- **No PyTorch Geometric** — too heavy; use pure PyTorch or numpy for graphs

### Model 1: Temporal Autoencoder (temporal_ae.py)
**Purpose:** Detect anomalous event sequences per host over time.

Architecture (CPU-lightweight):
- Encoder: 1-layer GRU (hidden_dim=64, NOT LSTM — GRU is faster on CPU)
- Bottleneck: linear projection to latent_dim=16
- Decoder: 1-layer GRU mirror
- Loss: MSE reconstruction
- Anomaly score: mean reconstruction error per sequence

Input: sliding windows of shape (batch, seq_len=32, n_features)
- Reduced from 64 to 32 to cut memory in half
- Pad shorter sequences, mask padding in loss

Training:
- Epochs: 20 max with early stopping (patience=3)
- Optimizer: Adam, lr=1e-3
- Batch size: 64 (NOT 256 — keeps memory under 500MB during training)
- Use `torch.no_grad()` during inference always

Detects: T1059 (unusual command sequences), T1053 (scheduled task chains),
T1048 (low-and-slow exfiltration patterns)

### Model 2: Process Tree MLP Anomaly Detector (process_graph.py)
**Purpose:** Detect anomalous process parent-child relationships.

Architecture (CPU-lightweight — NO PyTorch Geometric):
- Represent each process tree as a fixed-length feature vector:
  - Tree depth, branching factor, unique process count, known-bad name flags
  - Aggregate parent/child name hashes into bag-of-words style features
- 2-layer MLP autoencoder (input -> 32 -> 16 -> 32 -> input) with ReLU
- Anomaly score: reconstruction error of the tree feature vector

Input: DataFrame rows where each row = one process tree summary
- No graph objects needed — pure numpy/pandas aggregation

Detects: T1055 (process injection — unusual lineage), T1036 (masquerading —
name doesn't match tree position), T1059.004 (shell spawning chains)

### Model 3: Contrastive Entity Learner (contrastive.py)
**Purpose:** Learn host/user embeddings where anomalous behavior is distant
from the entity's normal cluster.

Architecture (CPU-lightweight):
- Encoder: 2-layer MLP (input -> 64 -> 32) with ReLU — NOT 256/128/64
- Training: simplified contrastive loss (cosine similarity with margin)
  - Positive pairs: two windows from same entity's normal behavior
  - Negative pairs: cross-entity samples
- Anomaly score: cosine distance from entity's centroid in 32-dim space

Synthetic anomaly generation:
- Permute features randomly (break correlations)
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
- Training on CPU (4 cores, 15GB system RAM): < 5 minutes for 100k events (all 3 models)
- Inference on CPU: < 15 seconds for 10k events per model
- Memory: < 3GB combined across all 3 models during training
- Checkpoint size: < 100MB per model
- Always call `torch.set_num_threads(4)` at the top of every model file

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
