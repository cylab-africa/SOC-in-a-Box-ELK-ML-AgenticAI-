"""Tests for the models/ package (Agent 1).

Validates AnomalyModel interface, ensemble scoring, model versioning,
and per-job model selection.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import numpy as np
import pytest


class TestAnomalyModelInterface:
    """Validate the AnomalyModel ABC contract."""

    def test_base_model_is_abstract(self) -> None:
        """AnomalyModel cannot be instantiated directly."""
        from models.base_model import AnomalyModel

        with pytest.raises(TypeError):
            AnomalyModel()

    def test_normalize_scores_range(self) -> None:
        """_normalize_scores produces values in [0, 1]."""
        from models.base_model import AnomalyModel

        # Create a concrete subclass for testing
        class _TestModel(AnomalyModel):
            def fit(self, X):
                return self
            def decision_function(self, X):
                return np.zeros(X.shape[0])

        model = _TestModel()
        raw = np.array([-10.0, 0.0, 5.0, 100.0, np.inf, -np.inf])
        normalized = model._normalize_scores(raw)
        assert np.all(normalized >= 0.0)
        assert np.all(normalized <= 1.0)
        assert np.all(np.isfinite(normalized))


class TestEnsembleModel:
    """Test the ensemble scoring mechanism."""

    def _make_dummy_model(self, name: str, score: float):
        """Create a model that always returns a fixed score."""
        from models.base_model import AnomalyModel

        class _Dummy(AnomalyModel):
            model_name = name
            attack_techniques = ["T1059"]
            def fit(self, X):
                return self
            def decision_function(self, X):
                return np.full(X.shape[0], score, dtype=np.float64)

        return _Dummy()

    def test_ensemble_weighted_average(self) -> None:
        """Ensemble produces correct weighted average of constituent scores."""
        from models.ensemble import EnsembleModel

        m1 = self._make_dummy_model("m1", 0.2)
        m2 = self._make_dummy_model("m2", 0.8)

        ensemble = EnsembleModel(
            models=[m1, m2],
            weights={"m1": 0.5, "m2": 0.5},
        )
        X = np.random.default_rng(42).random((10, 5))
        ensemble.fit(X)
        scores = ensemble.decision_function(X)

        assert scores.shape == (10,)
        assert np.allclose(scores, 0.5, atol=0.01)

    def test_ensemble_handles_failed_model(self) -> None:
        """Ensemble gracefully skips models that throw during scoring."""
        from models.ensemble import EnsembleModel
        from models.base_model import AnomalyModel

        class _Broken(AnomalyModel):
            model_name = "broken"
            def fit(self, X):
                return self
            def decision_function(self, X):
                raise RuntimeError("Model crashed")

        good = self._make_dummy_model("good", 0.6)
        broken = _Broken()

        ensemble = EnsembleModel(models=[good, broken])
        X = np.random.default_rng(42).random((5, 3))
        ensemble.fit(X)
        scores = ensemble.decision_function(X)
        assert np.all(np.isfinite(scores))

    def test_ensemble_empty(self) -> None:
        """Ensemble with no models returns zeros."""
        from models.ensemble import EnsembleModel

        ensemble = EnsembleModel()
        X = np.random.default_rng(42).random((5, 3))
        scores = ensemble.decision_function(X)
        assert np.all(scores == 0.0)

    def test_ensemble_collects_techniques(self) -> None:
        """Ensemble merges ATT&CK techniques from all models."""
        from models.ensemble import EnsembleModel
        from models.base_model import AnomalyModel

        class _M1(AnomalyModel):
            model_name = "m1"
            attack_techniques = ["T1059", "T1036"]
            def fit(self, X): return self
            def decision_function(self, X): return np.zeros(X.shape[0])

        class _M2(AnomalyModel):
            model_name = "m2"
            attack_techniques = ["T1071", "T1059"]
            def fit(self, X): return self
            def decision_function(self, X): return np.zeros(X.shape[0])

        ensemble = EnsembleModel(models=[_M1(), _M2()])
        assert set(ensemble.attack_techniques) == {"T1036", "T1059", "T1071"}


class TestModelRegistry:
    """Test per-job model selection."""

    def test_known_job_returns_ensemble(self) -> None:
        """get_models_for_job returns an EnsembleModel for known jobs."""
        from models.registry import get_models_for_job
        from models.ensemble import EnsembleModel

        with patch("models.pyod_models._import_pyod") as mock_pyod:
            # Mock PyOD so we don't need it installed
            mock_pyod.return_value = type("MockModel", (), {
                "__init__": lambda self, **kw: None,
                "fit": lambda self, X: None,
                "decision_function": lambda self, X: np.zeros(X.shape[0]),
            })
            ensemble = get_models_for_job("v3_linux_anomalous_process_all_hosts")
            assert isinstance(ensemble, EnsembleModel)

    def test_unknown_job_returns_default(self) -> None:
        """Unknown job names get a default ensemble."""
        from models.registry import get_models_for_job
        from models.ensemble import EnsembleModel

        with patch("models.pyod_models._import_pyod") as mock_pyod:
            mock_pyod.return_value = type("MockModel", (), {
                "__init__": lambda self, **kw: None,
                "fit": lambda self, X: None,
                "decision_function": lambda self, X: np.zeros(X.shape[0]),
            })
            ensemble = get_models_for_job("nonexistent_job_xyz")
            assert isinstance(ensemble, EnsembleModel)


class TestModelVersioning:
    """Test model manifest creation and loading."""

    def test_create_and_load_manifest(self, tmp_path: Path) -> None:
        """Manifest round-trips through create/load."""
        from models.versioning import create_manifest, load_manifest

        manifest = create_manifest(
            model_dir=tmp_path,
            job_name="v3_linux_anomalous_process_all_hosts",
            model_names=["ecod", "copod"],
            training_samples=1000,
            training_features=10,
            attack_techniques=["T1059", "T1036"],
            metrics={"auc_pr": 0.95},
        )

        loaded = load_manifest(tmp_path)
        assert loaded is not None
        assert loaded["job_name"] == "v3_linux_anomalous_process_all_hosts"
        assert loaded["training_samples"] == 1000
        assert "T1059" in loaded["attack_techniques"]
        assert loaded["metrics"]["auc_pr"] == 0.95

    def test_load_missing_manifest(self, tmp_path: Path) -> None:
        """Loading from a directory without manifest returns None."""
        from models.versioning import load_manifest

        assert load_manifest(tmp_path / "nonexistent") is None
