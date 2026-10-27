"""Process-tree MLP autoencoder for detecting anomalous process lineage.

Represents each process tree as a fixed-length feature vector (depth,
branching factor, unique process count, name-hash bag-of-words) and trains
a 2-layer MLP autoencoder on those vectors.  No graph library is required.

MITRE ATT&CK coverage:
    T1055 — Process Injection (unusual parent-child lineage)
    T1036 — Masquerading (process name vs. tree-position mismatch)
    T1059.004 — Unix Shell (shell spawning chains)
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from dl_models.base import DLAnomalyModel
from dl_models.utils import (
    EarlyStopping,
    get_device,
    load_checkpoint,
    save_checkpoint,
    set_seed,
)

torch.set_num_threads(4)

logger = logging.getLogger(__name__)

HIDDEN_DIM = 32
BOTTLENECK_DIM = 16
BATCH_SIZE = 64
MAX_EPOCHS = 20
LEARNING_RATE = 1e-3
EARLY_STOPPING_PATIENCE = 3
CHECKPOINT_FILENAME = "process_graph.pt"

KNOWN_BAD_NAMES: frozenset[str] = frozenset(
    {
        "mimikatz",
        "meterpreter",
        "nc",
        "netcat",
        "ncat",
        "socat",
        "cryptominer",
        "xmrig",
        "wget",
        "curl",
    }
)


class _MLPAutoencoder(nn.Module):
    """2-layer MLP autoencoder: input -> hidden -> bottleneck -> hidden -> input."""

    def __init__(
        self, input_dim: int, hidden_dim: int, bottleneck_dim: int
    ) -> None:
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, bottleneck_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(bottleneck_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, input_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode then decode an input feature vector.

        Args:
            x: Tensor of shape (batch, input_dim).

        Returns:
            Reconstructed tensor of shape (batch, input_dim).
        """
        return self.decoder(self.encoder(x))


class ProcessTreeFeaturizer:
    """Convert a DataFrame of process events into fixed-length feature vectors.

    Each row in the input DataFrame is expected to describe one process event.
    The featurizer aggregates rows into a single fixed-length vector suitable
    for the MLP autoencoder.
    """

    HASH_BUCKETS: int = 64

    def _name_to_bucket(self, name: str) -> int:
        """Map a process name string to a hash-bucket index.

        Args:
            name: Process name string.

        Returns:
            Integer bucket index in [0, HASH_BUCKETS).
        """
        return hash(name.lower()) % self.HASH_BUCKETS

    def featurize_row(self, row: dict) -> np.ndarray:
        """Convert a single process-event dict to a feature vector.

        Features:
        - tree_depth (1): depth of the process in its process tree.
        - branching_factor (1): estimated children count.
        - unique_process_count (1): distinct process names in lineage.
        - known_bad_flag (1): 1.0 if any ancestor/self name matches bad list.
        - name_hash_bow (HASH_BUCKETS): bag-of-words over process names.

        Args:
            row: Dict with keys such as 'process.name', 'process.parent.name',
                 'process.args_count', 'process.args'.

        Returns:
            Float32 array of length (4 + HASH_BUCKETS).
        """
        tree_depth = float(row.get("process.parent.entity_id", "").count("/") + 1)
        branching = float(row.get("process.args_count", 1))
        names = [
            str(row.get("process.name", "")),
            str(row.get("process.parent.name", "")),
        ]
        unique_count = float(len(set(n for n in names if n)))
        known_bad = float(any(n.lower() in KNOWN_BAD_NAMES for n in names if n))

        bow = np.zeros(self.HASH_BUCKETS, dtype=np.float32)
        for name in names:
            if name:
                bow[self._name_to_bucket(name)] += 1.0

        scalar_features = np.array(
            [tree_depth, branching, unique_count, known_bad], dtype=np.float32
        )
        return np.concatenate([scalar_features, bow])

    def featurize_matrix(self, X: np.ndarray) -> np.ndarray:
        """Return input unchanged — assumes X is already a feature matrix.

        For DataFrame inputs use featurize_row() per row.  This method
        exists so the featurizer can be used uniformly in fit/predict.

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            X unchanged.
        """
        return X.astype(np.float32)


class ProcessTreeAnomalyDetector(DLAnomalyModel):
    """MLP autoencoder trained on process-tree feature vectors.

    Learns normal process lineage patterns and flags rows where reconstruction
    error is high as potential injection, masquerading, or shell-spawning events.

    MITRE ATT&CK: T1055, T1036, T1059.004
    """

    attack_techniques: list[str] = ["T1055", "T1036", "T1059.004"]

    def __init__(
        self,
        hidden_dim: int = HIDDEN_DIM,
        bottleneck_dim: int = BOTTLENECK_DIM,
        batch_size: int = BATCH_SIZE,
        max_epochs: int = MAX_EPOCHS,
        lr: float = LEARNING_RATE,
        patience: int = EARLY_STOPPING_PATIENCE,
        seed: int = 42,
    ) -> None:
        """Initialise hyperparameters (model not yet built).

        Args:
            hidden_dim: Size of the hidden MLP layers.
            bottleneck_dim: Size of the bottleneck (latent) layer.
            batch_size: Training mini-batch size.
            max_epochs: Maximum number of training epochs.
            lr: Adam learning rate.
            patience: Early-stopping patience in epochs.
            seed: Random seed for reproducibility.
        """
        self.hidden_dim = hidden_dim
        self.bottleneck_dim = bottleneck_dim
        self.batch_size = batch_size
        self.max_epochs = max_epochs
        self.lr = lr
        self.patience = patience
        self.seed = seed

        self.n_features: int | None = None
        self._model: _MLPAutoencoder | None = None
        self._threshold: float = 0.0
        self._device: torch.device = get_device()

    def _build_model(self, n_features: int) -> None:
        """Instantiate the MLP autoencoder for a given feature count.

        Args:
            n_features: Number of input features per sample.
        """
        self.n_features = n_features
        self._model = _MLPAutoencoder(
            n_features, self.hidden_dim, self.bottleneck_dim
        ).to(self._device)

    def fit(self, X: np.ndarray) -> ProcessTreeAnomalyDetector:
        """Train the MLP autoencoder on normal process-tree feature vectors.

        Args:
            X: Array of shape (n_samples, n_features) representing normal
               process telemetry (one row per process event or tree summary).

        Returns:
            self
        """
        set_seed(self.seed)
        X = X.astype(np.float32)
        n_samples, n_features = X.shape
        self._build_model(n_features)

        dataset = TensorDataset(torch.from_numpy(X))
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.lr)
        criterion = nn.MSELoss()
        stopper = EarlyStopping(patience=self.patience)

        self._model.train()
        for epoch in range(self.max_epochs):
            epoch_loss = 0.0
            n_batches = 0
            for (batch,) in loader:
                batch = batch.to(self._device)
                optimizer.zero_grad()
                recon = self._model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1
            avg_loss = epoch_loss / max(n_batches, 1)
            logger.debug(
                f"ProcessTreeAE epoch {epoch+1}/{self.max_epochs} loss={avg_loss:.6f}"
            )
            if stopper.step(avg_loss):
                logger.info(f"ProcessTreeAE early stop at epoch {epoch+1}")
                break

        self._threshold = self._compute_threshold(X)
        return self

    def _reconstruction_errors(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample reconstruction MSE.

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) with per-sample MSE values.
        """
        self._model.eval()
        errors = []
        loader = DataLoader(
            TensorDataset(torch.from_numpy(X.astype(np.float32))),
            batch_size=self.batch_size,
        )
        with torch.no_grad():
            for (batch,) in loader:
                batch = batch.to(self._device)
                recon = self._model(batch)
                mse = ((recon - batch) ** 2).mean(dim=1)
                errors.append(mse.cpu().numpy())
        return np.concatenate(errors)

    def _compute_threshold(self, X: np.ndarray) -> float:
        """Estimate anomaly threshold as 95th-percentile of training errors.

        Args:
            X: Training data.

        Returns:
            Float threshold.
        """
        errors = self._reconstruction_errors(X)
        return float(np.percentile(errors, 95))

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample anomaly scores in [0, 1].

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) with scores in [0.0, 1.0].
        """
        if self._model is None:
            raise RuntimeError("Model is not fitted — call fit() first")
        X = X.astype(np.float32)
        errors = self._reconstruction_errors(X)
        return self._validate_scores(self._normalize_scores(errors))

    def save(self, path: Path) -> None:
        """Persist model weights and hyperparameters to disk.

        Args:
            path: Directory where the checkpoint is written.
        """
        if self._model is None:
            raise RuntimeError("Model is not fitted — call fit() first")
        meta = {
            "n_features": self.n_features,
            "hidden_dim": self.hidden_dim,
            "bottleneck_dim": self.bottleneck_dim,
            "batch_size": self.batch_size,
            "max_epochs": self.max_epochs,
            "lr": self.lr,
            "patience": self.patience,
            "threshold": self._threshold,
        }
        save_checkpoint(self._model.state_dict(), meta, Path(path), CHECKPOINT_FILENAME)
        logger.info(f"ProcessTreeAnomalyDetector saved to {path}")

    def load(self, path: Path) -> ProcessTreeAnomalyDetector:
        """Restore model weights and hyperparameters from disk.

        Args:
            path: Directory previously written by save().

        Returns:
            self
        """
        state_dict, meta = load_checkpoint(Path(path), CHECKPOINT_FILENAME)
        self.n_features = meta["n_features"]
        self.hidden_dim = meta["hidden_dim"]
        self.bottleneck_dim = meta["bottleneck_dim"]
        self.batch_size = meta["batch_size"]
        self.max_epochs = meta["max_epochs"]
        self.lr = meta["lr"]
        self.patience = meta["patience"]
        self._threshold = meta["threshold"]
        self._build_model(self.n_features)
        self._model.load_state_dict(state_dict)
        self._model.eval()
        logger.info(f"ProcessTreeAnomalyDetector loaded from {path}")
        return self
