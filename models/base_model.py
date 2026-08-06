"""
Abstract base class for all anomaly detection models.

Every model in the pipeline must implement this interface so that
model_manager.py and the ensemble can treat them interchangeably.

ATT&CK alignment: each concrete model declares which techniques it covers
via the attack_techniques class attribute.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)


class AnomalyModel(ABC):
    """Unified interface for all anomaly detection models.

    Concrete implementations must:
    - Normalize decision_function output to [0.0, 1.0]
    - Declare attack_techniques as a list of T-IDs
    - Support save/load for model versioning
    """

    # Subclasses override with list of MITRE ATT&CK technique IDs
    attack_techniques: list[str] = []
    model_name: str = "base"

    @abstractmethod
    def fit(self, X: np.ndarray) -> AnomalyModel:
        """Train the model on feature matrix X (normal/benign data).

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self for method chaining.
        """

    @abstractmethod
    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute per-sample anomaly scores.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of shape (n_samples,) with scores in [0.0, 1.0].
        """

    def save(self, path: Path) -> None:
        """Persist model to disk. Override for model-specific serialization.

        Args:
            path: Directory where model files will be written.
        """
        path.mkdir(parents=True, exist_ok=True)
        meta = {
            "model_name": self.model_name,
            "attack_techniques": self.attack_techniques,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        (path / "meta.json").write_text(json.dumps(meta, indent=2))

    def load(self, path: Path) -> AnomalyModel:
        """Restore model from disk. Override for model-specific loading.

        Args:
            path: Directory previously written by save().

        Returns:
            self for method chaining.
        """
        return self

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Min-max normalize raw scores to [0.0, 1.0].

        Args:
            scores: Raw anomaly scores of arbitrary range.

        Returns:
            Normalized scores clipped to [0.0, 1.0].
        """
        scores = np.where(np.isfinite(scores), scores, 0.0)
        lo, hi = float(np.min(scores)), float(np.max(scores))
        if hi - lo < 1e-9:
            return np.zeros_like(scores, dtype=np.float64)
        normalized = (scores - lo) / (hi - lo)
        return np.clip(normalized, 0.0, 1.0).astype(np.float64)
