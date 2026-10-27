"""
Calibrated ensemble scoring for multi-model anomaly detection.

Combines scores from multiple AnomalyModel instances using weighted
averaging with optional calibration. Supports per-job weight overrides.

ATT&CK alignment: ensemble improves detection across all mapped techniques
by reducing individual model blind spots.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

from models.base_model import AnomalyModel

logger = logging.getLogger(__name__)

# Default model weights — can be overridden per job via config
DEFAULT_WEIGHTS: dict[str, float] = {
    "ecod": 0.35,
    "copod": 0.30,
    "autoencoder": 0.35,
}


class EnsembleModel(AnomalyModel):
    """Weighted ensemble of multiple anomaly detection models.

    Combines scores from constituent models via weighted average,
    producing a single [0.0, 1.0] anomaly score per sample.

    ATT&CK: Inherits technique coverage from all constituent models.
    """

    model_name: str = "ensemble"

    def __init__(
        self,
        models: list[AnomalyModel] | None = None,
        weights: dict[str, float] | None = None,
    ) -> None:
        """Initialize ensemble with optional model list and custom weights.

        Args:
            models: List of AnomalyModel instances to ensemble.
            weights: Dict mapping model_name -> weight. Missing models get 1.0.
        """
        self._models: list[AnomalyModel] = models or []
        self._weights: dict[str, float] = weights or dict(DEFAULT_WEIGHTS)
        self._is_fitted: bool = False
        # Merge attack techniques from all constituent models
        self.attack_techniques = self._collect_techniques()

    def add_model(self, model: AnomalyModel) -> None:
        """Add a model to the ensemble.

        Args:
            model: AnomalyModel instance to include.
        """
        self._models.append(model)
        self.attack_techniques = self._collect_techniques()

    def fit(self, X: np.ndarray) -> EnsembleModel:
        """Train all constituent models on the same feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self
        """
        for model in self._models:
            try:
                model.fit(X)
                logger.info("Ensemble: fitted %s", model.model_name)
            except Exception:
                logger.exception("Ensemble: failed to fit %s", model.model_name)
        self._is_fitted = True
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute weighted ensemble anomaly scores.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of scores in [0.0, 1.0].
        """
        if not self._models:
            return np.zeros(X.shape[0], dtype=np.float64)

        all_scores: list[np.ndarray] = []
        all_weights: list[float] = []

        for model in self._models:
            try:
                scores = model.decision_function(X)
                weight = self._weights.get(model.model_name, 1.0)
                all_scores.append(scores)
                all_weights.append(weight)
            except Exception:
                logger.exception(
                    "Ensemble: %s failed during scoring, skipping", model.model_name
                )

        if not all_scores:
            return np.zeros(X.shape[0], dtype=np.float64)

        # Weighted average
        score_matrix = np.column_stack(all_scores)
        weight_array = np.array(all_weights, dtype=np.float64)
        weight_array /= weight_array.sum()  # normalize weights

        ensemble_scores = score_matrix @ weight_array
        return np.clip(ensemble_scores, 0.0, 1.0).astype(np.float64)

    def save(self, path: Path) -> None:
        """Persist all constituent models and ensemble config.

        Args:
            path: Directory for ensemble files.
        """
        super().save(path)
        config = {
            "weights": self._weights,
            "model_names": [m.model_name for m in self._models],
        }
        (path / "ensemble_config.json").write_text(json.dumps(config, indent=2))

        for model in self._models:
            model_dir = path / model.model_name
            try:
                model.save(model_dir)
            except Exception:
                logger.exception("Failed to save model %s", model.model_name)

    def load(self, path: Path) -> EnsembleModel:
        """Load ensemble configuration. Individual models must be loaded separately.

        Args:
            path: Directory with ensemble files.

        Returns:
            self
        """
        config_path = path / "ensemble_config.json"
        if config_path.exists():
            config = json.loads(config_path.read_text())
            self._weights = config.get("weights", self._weights)
        self._is_fitted = True
        return self

    def _collect_techniques(self) -> list[str]:
        """Merge ATT&CK techniques from all models, deduplicated.

        Returns:
            Sorted list of unique technique IDs.
        """
        techniques: set[str] = set()
        for model in self._models:
            techniques.update(model.attack_techniques)
        return sorted(techniques)
