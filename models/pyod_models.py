"""
PyOD-backed anomaly detection models: ECOD, COPOD, AutoEncoder.

These wrap pyod algorithms with the AnomalyModel interface, adding
score normalization, save/load, and ATT&CK technique declarations.

ATT&CK alignment:
  ECOD  - T1059 (scripting), T1071 (network), broad outlier detection
  COPOD - T1036 (masquerading), T1078 (valid accounts), copula outliers
  AutoEncoder - T1055 (injection), T1048 (exfiltration), reconstruction error
"""

from __future__ import annotations

import importlib
import json
import logging
from pathlib import Path

import numpy as np

from models.base_model import AnomalyModel

logger = logging.getLogger(__name__)


def _import_pyod(class_name: str, module_path: str):
    """Lazily import a PyOD class to avoid hard dependency at import time.

    Args:
        class_name: Name of the class to import.
        module_path: Dotted module path (e.g. 'pyod.models.ecod').

    Returns:
        The imported class.

    Raises:
        ImportError: If pyod is not installed.
    """
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


class ECODModel(AnomalyModel):
    """Empirically-Cumulative-distribution-based Outlier Detection (ECOD).

    Non-parametric, no hyperparameters, fast training. Good general-purpose
    outlier detector for tabular security features.

    ATT&CK: T1059, T1071 — broad anomaly coverage.
    """

    attack_techniques: list[str] = ["T1059", "T1071"]
    model_name: str = "ecod"

    def __init__(self) -> None:
        """Initialize ECOD model wrapper."""
        ECOD = _import_pyod("ECOD", "pyod.models.ecod")
        self._model = ECOD(contamination=0.05)
        self._is_fitted: bool = False

    def fit(self, X: np.ndarray) -> "ECODModel":
        """Train ECOD on feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self
        """
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self._model.fit(X_clean)
        self._is_fitted = True
        logger.info("ECOD model fitted on %d samples, %d features", X.shape[0], X.shape[1])
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute normalized anomaly scores via ECOD.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of scores in [0.0, 1.0].
        """
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        raw_scores = self._model.decision_function(X_clean)
        return self._normalize_scores(raw_scores)

    def save(self, path: Path) -> None:
        """Persist ECOD model to disk.

        Args:
            path: Directory for model files.
        """
        import joblib
        super().save(path)
        joblib.dump(self._model, path / "ecod.joblib")

    def load(self, path: Path) -> "ECODModel":
        """Load ECOD model from disk.

        Args:
            path: Directory with saved model files.

        Returns:
            self
        """
        import joblib
        self._model = joblib.load(path / "ecod.joblib")
        self._is_fitted = True
        return self


class COPODModel(AnomalyModel):
    """Copula-Based Outlier Detection (COPOD).

    Parameter-free, captures feature dependencies via empirical copulas.
    Effective for detecting masquerading and credential abuse patterns.

    ATT&CK: T1036, T1078 — dependency-aware outlier detection.
    """

    attack_techniques: list[str] = ["T1036", "T1078"]
    model_name: str = "copod"

    def __init__(self) -> None:
        """Initialize COPOD model wrapper."""
        COPOD = _import_pyod("COPOD", "pyod.models.copod")
        self._model = COPOD(contamination=0.05)
        self._is_fitted: bool = False

    def fit(self, X: np.ndarray) -> "COPODModel":
        """Train COPOD on feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self
        """
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        self._model.fit(X_clean)
        self._is_fitted = True
        logger.info("COPOD model fitted on %d samples, %d features", X.shape[0], X.shape[1])
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute normalized anomaly scores via COPOD.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of scores in [0.0, 1.0].
        """
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        raw_scores = self._model.decision_function(X_clean)
        return self._normalize_scores(raw_scores)

    def save(self, path: Path) -> None:
        """Persist COPOD model to disk.

        Args:
            path: Directory for model files.
        """
        import joblib
        super().save(path)
        joblib.dump(self._model, path / "copod.joblib")

    def load(self, path: Path) -> "COPODModel":
        """Load COPOD model from disk.

        Args:
            path: Directory with saved model files.

        Returns:
            self
        """
        import joblib
        self._model = joblib.load(path / "copod.joblib")
        self._is_fitted = True
        return self


class AutoEncoderModel(AnomalyModel):
    """PyOD AutoEncoder-based anomaly detection.

    Uses reconstruction error as anomaly score. Effective at detecting
    complex multi-feature anomalies like process injection and exfiltration.

    ATT&CK: T1055, T1048 — reconstruction-based anomaly detection.
    """

    attack_techniques: list[str] = ["T1055", "T1048"]
    model_name: str = "autoencoder"

    # Default architecture — adjusted at runtime based on input features
    _DEFAULT_HIDDEN: list[int] = [64, 32, 32, 64]
    _DEFAULT_EPOCHS: int = 50
    _DEFAULT_BATCH: int = 256

    def __init__(
        self,
        hidden_neurons: list[int] | None = None,
        epochs: int | None = None,
        batch_size: int | None = None,
    ) -> None:
        """Initialize AutoEncoder model wrapper.

        Args:
            hidden_neurons: Layer sizes for encoder/decoder. Default [64,32,32,64].
            epochs: Training epochs. Default 50.
            batch_size: Training batch size. Default 256.
        """
        self._hidden = hidden_neurons or self._DEFAULT_HIDDEN
        self._epochs = epochs or self._DEFAULT_EPOCHS
        self._batch = batch_size or self._DEFAULT_BATCH
        self._model = None
        self._is_fitted: bool = False

    def fit(self, X: np.ndarray) -> "AutoEncoderModel":
        """Train AutoEncoder on feature matrix.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            self
        """
        AutoEncoder = _import_pyod("AutoEncoder", "pyod.models.auto_encoder")
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        self._model = AutoEncoder(
            hidden_neurons=self._hidden,
            epochs=self._epochs,
            batch_size=self._batch,
            contamination=0.05,
            verbose=0,
        )
        self._model.fit(X_clean)
        self._is_fitted = True
        logger.info(
            "AutoEncoder fitted on %d samples, %d features, %d epochs",
            X.shape[0], X.shape[1], self._epochs,
        )
        return self

    def decision_function(self, X: np.ndarray) -> np.ndarray:
        """Compute normalized anomaly scores via reconstruction error.

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            1-D array of scores in [0.0, 1.0].
        """
        X_clean = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0).astype(np.float32)
        raw_scores = self._model.decision_function(X_clean)
        return self._normalize_scores(raw_scores)

    def save(self, path: Path) -> None:
        """Persist AutoEncoder model to disk.

        Args:
            path: Directory for model files.
        """
        import joblib
        super().save(path)
        config = {
            "hidden_neurons": self._hidden,
            "epochs": self._epochs,
            "batch_size": self._batch,
        }
        (path / "ae_config.json").write_text(json.dumps(config))
        if self._model is not None:
            joblib.dump(self._model, path / "autoencoder.joblib")

    def load(self, path: Path) -> "AutoEncoderModel":
        """Load AutoEncoder model from disk.

        Args:
            path: Directory with saved model files.

        Returns:
            self
        """
        import joblib
        config_path = path / "ae_config.json"
        if config_path.exists():
            config = json.loads(config_path.read_text())
            self._hidden = config.get("hidden_neurons", self._DEFAULT_HIDDEN)
            self._epochs = config.get("epochs", self._DEFAULT_EPOCHS)
            self._batch = config.get("batch_size", self._DEFAULT_BATCH)
        self._model = joblib.load(path / "autoencoder.joblib")
        self._is_fitted = True
        return self
