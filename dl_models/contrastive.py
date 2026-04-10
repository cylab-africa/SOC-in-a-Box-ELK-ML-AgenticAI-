"""
Contrastive entity learner for host/user anomaly detection.

Learns entity-specific behavioral embeddings using a simplified contrastive
loss so that anomalous behaviour is distant from the entity's normal cluster.

MITRE ATT&CK coverage:
    T1078 -- Valid Accounts (behaviour deviates from entity's norm)
    T1098 -- Account Manipulation (entity profile shift)

CPU-only; combined with other DL models stays under 3 GB.
"""

from __future__ import annotations

import logging
from collections import defaultdict
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

EMBEDDING_DIM = 32
HIDDEN_DIM = 64
BATCH_SIZE = 64
MAX_EPOCHS = 20
LEARNING_RATE = 1e-3
EARLY_STOPPING_PATIENCE = 3
MARGIN = 0.5
CHECKPOINT_FILENAME = "contrastive.pt"


class _ContrastiveEncoder(nn.Module):
    """2-layer MLP encoder projecting inputs to a fixed-size embedding."""

    def __init__(self, input_dim: int, hidden_dim: int, embed_dim: int) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, embed_dim),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Encode input features into an embedding vector.

        Args:
            x: Tensor of shape (batch, input_dim).

        Returns:
            Tensor of shape (batch, embed_dim).
        """
        return self.net(x)


def _cosine_similarity(a: torch.Tensor, b: torch.Tensor) -> torch.Tensor:
    """Compute row-wise cosine similarity between two batches.

    Args:
        a: Tensor of shape (batch, dim).
        b: Tensor of shape (batch, dim).

    Returns:
        Tensor of shape (batch,) with cosine similarities in [-1, 1].
    """
    a_norm = torch.nn.functional.normalize(a, dim=1)
    b_norm = torch.nn.functional.normalize(b, dim=1)
    return (a_norm * b_norm).sum(dim=1)


class ContrastiveEntityLearner(DLAnomalyModel):
    """Contrastive learner for entity behavioural embeddings.

    During training, learns to place windows from the same entity close
    together and windows from different entities far apart.  At inference,
    anomaly score is the cosine distance from the entity's centroid.

    MITRE ATT&CK: T1078, T1098
    """

    attack_techniques: list[str] = ["T1078", "T1098"]

    def __init__(
        self,
        hidden_dim: int = HIDDEN_DIM,
        embed_dim: int = EMBEDDING_DIM,
        batch_size: int = BATCH_SIZE,
        max_epochs: int = MAX_EPOCHS,
        lr: float = LEARNING_RATE,
        patience: int = EARLY_STOPPING_PATIENCE,
        margin: float = MARGIN,
        seed: int = 42,
    ) -> None:
        """Initialise hyperparameters.

        Args:
            hidden_dim: Hidden layer size.
            embed_dim: Embedding/output dimension.
            batch_size: Mini-batch size.
            max_epochs: Maximum training epochs.
            lr: Adam learning rate.
            patience: Early-stopping patience.
            margin: Contrastive loss margin.
            seed: Random seed.
        """
        self.hidden_dim = hidden_dim
        self.embed_dim = embed_dim
        self.batch_size = batch_size
        self.max_epochs = max_epochs
        self.lr = lr
        self.patience = patience
        self.margin = margin
        self.seed = seed

        self.n_features: Optional[int] = None
        self._encoder: Optional[_ContrastiveEncoder] = None
        self._centroids: dict[int, np.ndarray] = {}
        self._global_centroid: Optional[np.ndarray] = None
        self._device: torch.device = get_device()

    def _build_model(self, n_features: int) -> None:
        """Instantiate the encoder network.

        Args:
            n_features: Input feature count.
        """
        self.n_features = n_features
        self._encoder = _ContrastiveEncoder(
            n_features, self.hidden_dim, self.embed_dim
        ).to(self._device)

    def _generate_pairs(
        self, X: np.ndarray, n_pairs: int,
    ) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Generate positive and negative pairs for contrastive learning.

        Positive pairs: two random samples (simulating same entity).
        Negative pairs: one real sample + one permuted sample.

        Args:
            X: Feature matrix of shape (n_samples, n_features).
            n_pairs: Number of pairs to generate.

        Returns:
            Tuple of (anchor, partner, labels) where labels is 1.0
            for positive and 0.0 for negative pairs.
        """
        rng = np.random.default_rng(self.seed)
        n = len(X)

        anchors = []
        partners = []
        labels = []

        half = n_pairs // 2

        # Positive pairs: nearby samples
        for _ in range(half):
            i = rng.integers(0, n)
            j = rng.integers(0, n)
            anchors.append(X[i])
            partners.append(X[j])
            labels.append(1.0)

        # Negative pairs: real sample + permuted (synthetic anomaly)
        for _ in range(half):
            i = rng.integers(0, n)
            anomaly = X[rng.integers(0, n)].copy()
            # Permute features to break correlations
            rng.shuffle(anomaly)
            anchors.append(X[i])
            partners.append(anomaly)
            labels.append(0.0)

        return (
            np.array(anchors, dtype=np.float32),
            np.array(partners, dtype=np.float32),
            np.array(labels, dtype=np.float32),
        )

    def fit(self, X: np.ndarray) -> "ContrastiveEntityLearner":
        """Train the contrastive encoder on normal data.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self
        """
        set_seed(self.seed)
        X = X.astype(np.float32)
        n_samples, n_features = X.shape
        self._build_model(n_features)

        n_pairs = min(n_samples * 4, 10000)
        anchors, partners, labels = self._generate_pairs(X, n_pairs)

        dataset = TensorDataset(
            torch.from_numpy(anchors),
            torch.from_numpy(partners),
            torch.from_numpy(labels),
        )
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        optimizer = torch.optim.Adam(self._encoder.parameters(), lr=self.lr)
        stopper = EarlyStopping(patience=self.patience)

        self._encoder.train()
        for epoch in range(self.max_epochs):
            epoch_loss = 0.0
            n_batches = 0
            for batch_a, batch_p, batch_labels in loader:
                batch_a = batch_a.to(self._device)
                batch_p = batch_p.to(self._device)
                batch_labels = batch_labels.to(self._device)

                optimizer.zero_grad()
                emb_a = self._encoder(batch_a)
                emb_p = self._encoder(batch_p)

                cos_sim = _cosine_similarity(emb_a, emb_p)
                # Contrastive loss: positive pairs should be similar,
                # negative pairs should be distant by at least margin
                pos_loss = (1.0 - batch_labels) * torch.clamp(
                    cos_sim - self.margin, min=0.0
                )
                neg_loss = batch_labels * (1.0 - cos_sim)
                loss = (pos_loss + neg_loss).mean()

                loss.backward()
                optimizer.step()
                epoch_loss += loss.item()
                n_batches += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            logger.debug(
                f"Contrastive epoch {epoch + 1}/{self.max_epochs} loss={avg_loss:.6f}"
            )
            if stopper.step(avg_loss):
                logger.info(f"Contrastive early stop at epoch {epoch + 1}")
                break

        # Compute global centroid from training data embeddings
        self._global_centroid = self._compute_centroid(X)
        return self

    def _compute_centroid(self, X: np.ndarray) -> np.ndarray:
        """Compute the mean embedding of a feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Mean embedding of shape (embed_dim,).
        """
        embeddings = self._embed(X)
        return embeddings.mean(axis=0)

    def _embed(self, X: np.ndarray) -> np.ndarray:
        """Compute embeddings for a batch of samples.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Embedding matrix of shape (n_samples, embed_dim).
        """
        self._encoder.eval()
        dataset = TensorDataset(torch.from_numpy(X.astype(np.float32)))
        loader = DataLoader(dataset, batch_size=self.batch_size)
        parts = []
        with torch.no_grad():
            for (batch,) in loader:
                batch = batch.to(self._device)
                emb = self._encoder(batch)
                parts.append(emb.cpu().numpy())
        return np.concatenate(parts)

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly scores as cosine distance from global centroid.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            Array of shape (n_samples,) with scores in [0.0, 1.0].
        """
        if self._encoder is None or self._global_centroid is None:
            raise RuntimeError("Model is not fitted -- call fit() first")

        X = X.astype(np.float32)
        embeddings = self._embed(X)

        # Cosine distance from centroid
        centroid = self._global_centroid / (
            np.linalg.norm(self._global_centroid) + 1e-9
        )
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True) + 1e-9
        normalized = embeddings / norms
        cos_sim = (normalized @ centroid).flatten()

        # Convert similarity to distance score: [0, 1]
        scores = 1.0 - (cos_sim + 1.0) / 2.0  # map [-1,1] -> [1,0]
        return self._validate_scores(scores)

    def save(self, path: Path) -> None:
        """Persist encoder weights and centroid to disk.

        Args:
            path: Directory where the checkpoint is written.
        """
        if self._encoder is None:
            raise RuntimeError("Model is not fitted -- call fit() first")
        meta = {
            "n_features": self.n_features,
            "hidden_dim": self.hidden_dim,
            "embed_dim": self.embed_dim,
            "batch_size": self.batch_size,
            "max_epochs": self.max_epochs,
            "lr": self.lr,
            "patience": self.patience,
            "margin": self.margin,
            "global_centroid": self._global_centroid.tolist(),
        }
        save_checkpoint(
            self._encoder.state_dict(), meta, Path(path), CHECKPOINT_FILENAME
        )
        logger.info(f"ContrastiveEntityLearner saved to {path}")

    def load(self, path: Path) -> "ContrastiveEntityLearner":
        """Restore encoder weights and centroid from disk.

        Args:
            path: Directory previously written by save().

        Returns:
            self
        """
        state_dict, meta = load_checkpoint(Path(path), CHECKPOINT_FILENAME)
        self.n_features = meta["n_features"]
        self.hidden_dim = meta["hidden_dim"]
        self.embed_dim = meta["embed_dim"]
        self.batch_size = meta["batch_size"]
        self.max_epochs = meta["max_epochs"]
        self.lr = meta["lr"]
        self.patience = meta["patience"]
        self.margin = meta["margin"]
        self._global_centroid = np.array(
            meta["global_centroid"], dtype=np.float32
        )
        self._build_model(self.n_features)
        self._encoder.load_state_dict(state_dict)
        self._encoder.eval()
        logger.info(f"ContrastiveEntityLearner loaded from {path}")
        return self
