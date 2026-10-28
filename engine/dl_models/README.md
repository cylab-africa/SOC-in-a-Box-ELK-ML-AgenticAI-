# Deep Learning Anomaly Detection Models

> **Experimental:** the running detection engine does not use these yet.

CPU-only deep learning models for Linux endpoint anomaly detection.
All models implement the `DLAnomalyModel` interface and produce scores
normalized to [0.0, 1.0].

## Architecture

### Model 1: Temporal Autoencoder (`temporal_ae.py`)

GRU-based sequence autoencoder that detects unusual temporal patterns.

- **Encoder**: 1-layer GRU (hidden\_dim=64) -> linear projection to latent\_dim=16
- **Decoder**: 1-layer GRU mirror reconstructing the input sequence
- **Loss**: MSE reconstruction error
- **Anomaly score**: Mean per-step reconstruction error, normalized to [0, 1]
- **Input**: Sliding windows of shape (batch, seq\_len=32, n\_features)

**ATT&CK Coverage**: T1059, T1053, T1048

### Model 2: Process Tree MLP (`process_graph.py`)

2-layer MLP autoencoder for process lineage anomaly detection.

- **Featurizer**: Converts process events to fixed-length vectors
  (tree depth, branching factor, unique count, known-bad flags, name hash BoW)
- **Architecture**: input -> 32 -> 16 -> 32 -> input with ReLU
- **Anomaly score**: Reconstruction error of the tree feature vector

**ATT&CK Coverage**: T1055, T1036, T1059.004

### Model 3: Contrastive Entity Learner (`contrastive.py`)

Learns entity behavioural embeddings via contrastive loss.

- **Encoder**: 2-layer MLP (input -> 64 -> 32)
- **Training**: Cosine similarity with margin-based contrastive loss
  - Positive pairs: real samples from normal data
  - Negative pairs: real sample + feature-permuted synthetic anomaly
- **Anomaly score**: Cosine distance from global centroid in 32-dim space

**ATT&CK Coverage**: T1078, T1098

## Integration

Use `DLModelRegistry` from `integration.py`:

```python
from dl_models.integration import DLModelRegistry

registry = DLModelRegistry()
model = registry.get_model("temporal_ae", seq_len=32, max_epochs=20)
model.fit(X_train)
scores = model.decision_function(X_test)
```

Available models: `temporal_ae`, `process_graph`, `contrastive`

## Data Loading

Use converters from `data_loaders.py`:

```python
from dl_models.data_loaders import SequenceDataset, TreeFeatureDataset, dataframe_to_numpy

# For temporal autoencoder
seq_dataset = SequenceDataset.from_dataframe(df, seq_len=32)

# For process tree MLP
tree_dataset = TreeFeatureDataset.from_dataframe(df)

# Generic conversion
X = dataframe_to_numpy(df)
```

## Constraints

- CPU only: `torch.set_num_threads(4)` at module import
- Combined memory: < 3 GB across all 3 models
- Training: < 5 minutes for 100k events
- Inference: < 15 seconds for 10k events per model
- Checkpoint size: < 100 MB per model
