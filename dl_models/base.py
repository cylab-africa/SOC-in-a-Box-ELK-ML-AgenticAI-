"""Base interface for all deep learning anomaly detection models.

Every model in dl_models/ must inherit from DLAnomalyModel and implement
fit(), decision_function(), save(), and load().

All anomaly scores are normalized to [0.0, 1.0], where 1.0 is most anomalous.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


class DLAnomalyModel(ABC):
    """Abstract base class for deep learning anomaly detection models.

    Matches Agent 1's AnomalyModel contract so models can be used
    interchangeably in the ensemble.

    ATT&CK coverage must be declared by each subclass.
    """

    attack_techniques: list[str] = []

    @abstractmethod
    def fit(self, X: np.ndarray) -> DLAnomalyModel:
        """Train the model on normal (benign) data.

        Args:
            X: Feature matrix of shape (n_samples, n_features) containing
               only normal/benign observations.

        Returns:
            self — allows method chaining.
        """

    @abstractmethod
    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample anomaly scores.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of shape (n_samples,) with scores in [0.0, 1.0].
            Higher values indicate more anomalous behaviour.
        """

    @abstractmethod
    def save(self, path: Path) -> None:
        """Persist model weights and config to disk.

        Args:
            path: Directory or file path where the model will be written.
        """

    @abstractmethod
    def load(self, path: Path) -> DLAnomalyModel:
        """Restore model weights and config from disk.

        Args:
            path: Directory or file path previously written by save().

        Returns:
            self — allows method chaining.
        """

    def _validate_scores(self, scores: np.ndarray) -> np.ndarray:
        """Clip and sanitize score array to [0, 1] with no NaN/Inf values.

        Args:
            scores: Raw anomaly scores of any range.

        Returns:
            Scores clamped to [0.0, 1.0] with non-finite values replaced by 1.0.
        """
        scores = np.where(np.isfinite(scores), scores, 1.0)
        return np.clip(scores, 0.0, 1.0).astype(np.float32)

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Min-max normalize scores to [0, 1].

        Args:
            scores: Raw anomaly scores.

        Returns:
            Normalized scores in [0.0, 1.0].
        """
        scores = np.where(np.isfinite(scores), scores, np.nanmax(scores) if np.any(np.isfinite(scores)) else 1.0)
        lo, hi = float(np.min(scores)), float(np.max(scores))
        if hi - lo < 1e-9:
            return np.zeros_like(scores, dtype=np.float32)
        normalized = (scores - lo) / (hi - lo)
        return normalized.astype(np.float32)
