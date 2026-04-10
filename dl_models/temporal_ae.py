"""Temporal GRU autoencoder for detecting anomalous event sequences.

Detects unusual temporal patterns in endpoint telemetry using a GRU-based
sequence autoencoder.  Anomaly score is the mean per-step reconstruction
error, normalised to [0, 1].

MITRE ATT&CK coverage:
    T1059 — Command and Scripting Interpreter (unusual command sequences)
    T1053 — Scheduled Task/Job (scheduled task chains)
    T1048 — Exfiltration Over Alternative Protocol (low-and-slow patterns)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

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

SEQ_LEN = 32
HIDDEN_DIM = 64
LATENT_DIM = 16
BATCH_SIZE = 64
MAX_EPOCHS = 20
LEARNING_RATE = 1e-3
EARLY_STOPPING_PATIENCE = 3
CHECKPOINT_FILENAME = "temporal_ae.pt"


class _GRUEncoder(nn.Module):
    """Single-layer GRU encoder that projects to a fixed latent vector."""

    def __init__(self, n_features: int, hidden_dim: int, latent_dim: int) -> None:
        super().__init__()
        self.gru = nn.GRU(n_features, hidden_dim, batch_first=True)
        self.proj = nn.Linear(hidden_dim, latent_dim)

    def forward(self, x: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        """Encode a sequence batch to a latent vector.

        Args:
            x: Tensor of shape (batch, seq_len, n_features).

        Returns:
            Tuple of (latent, hidden):
            - latent: (batch, latent_dim)
            - hidden: last GRU hidden state (1, batch, hidden_dim)
        """
        outputs, hidden = self.gru(x)
        latent = self.proj(hidden.squeeze(0))
        return latent, hidden


class _GRUDecoder(nn.Module):
    """Single-layer GRU decoder that reconstructs a sequence from a latent vector."""

    def __init__(
        self, latent_dim: int, hidden_dim: int, n_features: int, seq_len: int
    ) -> None:
        super().__init__()
        self.seq_len = seq_len
        self.hidden_proj = nn.Linear(latent_dim, hidden_dim)
        self.gru = nn.GRU(latent_dim, hidden_dim, batch_first=True)
        self.out = nn.Linear(hidden_dim, n_features)

    def forward(self, latent: torch.Tensor) -> torch.Tensor:
        """Reconstruct a sequence from a latent vector.

        Args:
            latent: Tensor of shape (batch, latent_dim).

        Returns:
            Reconstructed sequence of shape (batch, seq_len, n_features).
        """
        hidden = self.hidden_proj(latent).unsqueeze(0)
        repeated = latent.unsqueeze(1).expand(-1, self.seq_len, -1)
        outputs, _ = self.gru(repeated, hidden)
        return self.out(outputs)


class _GRUAutoencoder(nn.Module):
    """Full encoder-decoder GRU autoencoder."""

    def __init__(
        self, n_features: int, hidden_dim: int, latent_dim: int, seq_len: int
    ) -> None:
        super().__init__()
        self.encoder = _GRUEncoder(n_features, hidden_dim, latent_dim)
        self.decoder = _GRUDecoder(latent_dim, hidden_dim, n_features, seq_len)

    def forward(
        self, x: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """Run encoder then decoder on input sequences.

        Args:
            x: Tensor of shape (batch, seq_len, n_features).

        Returns:
            Tuple of (reconstruction, latent):
            - reconstruction: (batch, seq_len, n_features)
            - latent: (batch, latent_dim)
        """
        latent, _ = self.encoder(x)
        recon = self.decoder(latent)
        return recon, latent


class TemporalAutoencoder(DLAnomalyModel):
    """GRU-based temporal autoencoder for sequence anomaly detection.

    Trains on normal event-sequence windows and flags sequences that
    have high reconstruction error as anomalous.

    MITRE ATT&CK: T1059, T1053, T1048
    """

    attack_techniques: list[str] = ["T1059", "T1053", "T1048"]

    def __init__(
        self,
        seq_len: int = SEQ_LEN,
        hidden_dim: int = HIDDEN_DIM,
        latent_dim: int = LATENT_DIM,
        batch_size: int = BATCH_SIZE,
        max_epochs: int = MAX_EPOCHS,
        lr: float = LEARNING_RATE,
        patience: int = EARLY_STOPPING_PATIENCE,
        seed: int = 42,
    ) -> None:
        """Initialise hyperparameters (model not yet built).

        Args:
            seq_len: Number of time steps per sequence window.
            hidden_dim: GRU hidden state size.
            latent_dim: Bottleneck dimension.
            batch_size: Mini-batch size during training.
            max_epochs: Maximum training epochs.
            lr: Adam learning rate.
            patience: Early-stopping patience in epochs.
            seed: Random seed for reproducibility.
        """
        self.seq_len = seq_len
        self.hidden_dim = hidden_dim
        self.latent_dim = latent_dim
        self.batch_size = batch_size
        self.max_epochs = max_epochs
        self.lr = lr
        self.patience = patience
        self.seed = seed

        self.n_features: Optional[int] = None
        self._model: Optional[_GRUAutoencoder] = None
        self._threshold: float = 0.0
        self._device: torch.device = get_device()

    def _build_model(self, n_features: int) -> None:
        """Instantiate the GRU autoencoder for a given feature count.

        Args:
            n_features: Number of input features per time step.
        """
        self.n_features = n_features
        self._model = _GRUAutoencoder(
            n_features, self.hidden_dim, self.latent_dim, self.seq_len
        ).to(self._device)

    def _make_windows(self, X: np.ndarray) -> np.ndarray:
        """Slice a 2-D feature matrix into overlapping seq-len windows.

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            Array of shape (n_windows, seq_len, n_features).
        """
        n, f = X.shape
        if n < self.seq_len:
            pad = np.zeros((self.seq_len - n, f), dtype=np.float32)
            X = np.vstack([X, pad])
            n = self.seq_len
        windows = []
        for start in range(0, n - self.seq_len + 1, self.seq_len // 2):
            windows.append(X[start : start + self.seq_len])
        return np.array(windows, dtype=np.float32)

    def fit(self, X: np.ndarray) -> "TemporalAutoencoder":
        """Train the GRU autoencoder on normal event sequences.

        Args:
            X: Array of shape (n_samples, n_features) representing normal
               endpoint event logs.  Internally split into sliding windows.

        Returns:
            self
        """
        set_seed(self.seed)
        X = X.astype(np.float32)
        windows = self._make_windows(X)
        n_windows, _, n_features = windows.shape
        self._build_model(n_features)

        dataset = TensorDataset(torch.from_numpy(windows))
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
                recon, _ = self._model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1
            avg_loss = epoch_loss / max(n_batches, 1)
            logger.debug(f"TemporalAE epoch {epoch+1}/{self.max_epochs} loss={avg_loss:.6f}")
            if stopper.step(avg_loss):
                logger.info(f"TemporalAE early stop at epoch {epoch+1}")
                break

        self._threshold = self._compute_threshold(windows)
        return self

    def _reconstruction_errors(self, windows: np.ndarray) -> np.ndarray:
        """Compute mean reconstruction error for each window.

        Args:
            windows: Array of shape (n_windows, seq_len, n_features).

        Returns:
            Array of shape (n_windows,) with per-window MSE values.
        """
        self._model.eval()
        errors = []
        loader = DataLoader(
            TensorDataset(torch.from_numpy(windows.astype(np.float32))),
            batch_size=self.batch_size,
        )
        with torch.no_grad():
            for (batch,) in loader:
                batch = batch.to(self._device)
                recon, _ = self._model(batch)
                mse = ((recon - batch) ** 2).mean(dim=(1, 2))
                errors.append(mse.cpu().numpy())
        return np.concatenate(errors)

    def _compute_threshold(self, windows: np.ndarray) -> float:
        """Estimate anomaly threshold as 95th-percentile of training errors.

        Args:
            windows: Training windows array.

        Returns:
            Float threshold value.
        """
        errors = self._reconstruction_errors(windows)
        return float(np.percentile(errors, 95))

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample anomaly scores in [0, 1].

        Each input sample is assigned the score of the window it belongs to.
        Windows with high reconstruction error score near 1.0.

        Args:
            X: Array of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) with scores in [0.0, 1.0].
        """
        if self._model is None:
            raise RuntimeError("Model is not fitted — call fit() first")

        X = X.astype(np.float32)
        windows = self._make_windows(X)
        errors = self._reconstruction_errors(windows)

        raw_scores = self._normalize_scores(errors)

        n_samples = len(X)
        sample_scores = np.zeros(n_samples, dtype=np.float32)
        idx = 0
        step = self.seq_len // 2
        for w_idx in range(len(windows)):
            start = w_idx * step
            end = min(start + self.seq_len, n_samples)
            sample_scores[start:end] = np.maximum(
                sample_scores[start:end], raw_scores[w_idx]
            )
        return self._validate_scores(sample_scores)

    def save(self, path: Path) -> None:
        """Persist model weights and hyperparameters to disk.

        Args:
            path: Directory where the checkpoint is written.
        """
        if self._model is None:
            raise RuntimeError("Model is not fitted — call fit() first")
        meta = {
            "n_features": self.n_features,
            "seq_len": self.seq_len,
            "hidden_dim": self.hidden_dim,
            "latent_dim": self.latent_dim,
            "batch_size": self.batch_size,
            "max_epochs": self.max_epochs,
            "lr": self.lr,
            "patience": self.patience,
            "threshold": self._threshold,
        }
        save_checkpoint(self._model.state_dict(), meta, Path(path), CHECKPOINT_FILENAME)
        logger.info(f"TemporalAutoencoder saved to {path}")

    def load(self, path: Path) -> "TemporalAutoencoder":
        """Restore model weights and hyperparameters from disk.

        Args:
            path: Directory previously written by save().

        Returns:
            self
        """
        state_dict, meta = load_checkpoint(Path(path), CHECKPOINT_FILENAME)
        self.n_features = meta["n_features"]
        self.seq_len = meta["seq_len"]
        self.hidden_dim = meta["hidden_dim"]
        self.latent_dim = meta["latent_dim"]
        self.batch_size = meta["batch_size"]
        self.max_epochs = meta["max_epochs"]
        self.lr = meta["lr"]
        self.patience = meta["patience"]
        self._threshold = meta["threshold"]
        self._build_model(self.n_features)
        self._model.load_state_dict(state_dict)
        self._model.eval()
        logger.info(f"TemporalAutoencoder loaded from {path}")
        return self
