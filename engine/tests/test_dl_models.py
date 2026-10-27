"""
Tests for DL model interface compliance and basic correctness.

Verifies that all deep learning models in dl_models/ implement the
DLAnomalyModel interface and produce valid outputs on synthetic data.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest


def _skip_if_no_torch() -> None:
    """Skip test module if PyTorch is not installed."""
    pytest.importorskip("torch", reason="PyTorch not installed")


_skip_if_no_torch()


class TestTemporalAutoencoder:
    """Tests for the GRU temporal autoencoder."""

    def test_fit_and_predict(self) -> None:
        """TemporalAutoencoder.fit() and decision_function() produce valid scores."""
        from dl_models.temporal_ae import TemporalAutoencoder

        model = TemporalAutoencoder(seq_len=16, max_epochs=2, hidden_dim=16, latent_dim=8)
        X = np.random.default_rng(42).normal(size=(100, 10)).astype(np.float32)
        model.fit(X)
        scores = model.decision_function(X)

        assert scores.shape == (100,)
        assert np.all(np.isfinite(scores))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        """TemporalAutoencoder save/load produces consistent scores."""
        from dl_models.temporal_ae import TemporalAutoencoder

        model = TemporalAutoencoder(seq_len=16, max_epochs=2, hidden_dim=16, latent_dim=8)
        X = np.random.default_rng(42).normal(size=(64, 8)).astype(np.float32)
        model.fit(X)
        scores_before = model.decision_function(X)

        model.save(tmp_path)

        model2 = TemporalAutoencoder()
        model2.load(tmp_path)
        scores_after = model2.decision_function(X)

        np.testing.assert_allclose(scores_before, scores_after, atol=1e-5)


class TestProcessTreeDetector:
    """Tests for the process tree MLP autoencoder."""

    def test_fit_and_predict(self) -> None:
        """ProcessTreeAnomalyDetector produces valid scores."""
        from dl_models.process_graph import ProcessTreeAnomalyDetector

        model = ProcessTreeAnomalyDetector(max_epochs=2, hidden_dim=16, bottleneck_dim=8)
        X = np.random.default_rng(43).normal(size=(80, 20)).astype(np.float32)
        model.fit(X)
        scores = model.decision_function(X)

        assert scores.shape == (80,)
        assert np.all(np.isfinite(scores))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        """ProcessTreeAnomalyDetector save/load produces consistent scores."""
        from dl_models.process_graph import ProcessTreeAnomalyDetector

        model = ProcessTreeAnomalyDetector(max_epochs=2, hidden_dim=16, bottleneck_dim=8)
        X = np.random.default_rng(43).normal(size=(50, 15)).astype(np.float32)
        model.fit(X)
        scores_before = model.decision_function(X)

        model.save(tmp_path)

        model2 = ProcessTreeAnomalyDetector()
        model2.load(tmp_path)
        scores_after = model2.decision_function(X)

        np.testing.assert_allclose(scores_before, scores_after, atol=1e-5)


class TestContrastiveEntityLearner:
    """Tests for the contrastive entity embedding learner."""

    def test_fit_and_predict(self) -> None:
        """ContrastiveEntityLearner produces valid scores."""
        from dl_models.contrastive import ContrastiveEntityLearner

        model = ContrastiveEntityLearner(max_epochs=2, hidden_dim=32, embed_dim=16)
        X = np.random.default_rng(44).normal(size=(100, 12)).astype(np.float32)
        model.fit(X)
        scores = model.decision_function(X)

        assert scores.shape == (100,)
        assert np.all(np.isfinite(scores))
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_save_load_roundtrip(self, tmp_path: Path) -> None:
        """ContrastiveEntityLearner save/load produces consistent scores."""
        from dl_models.contrastive import ContrastiveEntityLearner

        model = ContrastiveEntityLearner(max_epochs=2, hidden_dim=32, embed_dim=16)
        X = np.random.default_rng(44).normal(size=(60, 10)).astype(np.float32)
        model.fit(X)
        scores_before = model.decision_function(X)

        model.save(tmp_path)

        model2 = ContrastiveEntityLearner()
        model2.load(tmp_path)
        scores_after = model2.decision_function(X)

        np.testing.assert_allclose(scores_before, scores_after, atol=1e-5)


class TestDLModelRegistry:
    """Tests for the unified DL model registry."""

    def test_available_models(self) -> None:
        """Registry lists all expected models."""
        from dl_models.integration import DLModelRegistry

        registry = DLModelRegistry()
        models = registry.available_models()
        assert "temporal_ae" in models
        assert "process_graph" in models
        assert "contrastive" in models

    def test_get_model_returns_correct_type(self) -> None:
        """Registry returns correct model types."""
        from dl_models.base import DLAnomalyModel
        from dl_models.integration import DLModelRegistry

        registry = DLModelRegistry()
        for name in registry.available_models():
            model = registry.get_model(name, max_epochs=1)
            assert isinstance(model, DLAnomalyModel)

    def test_unknown_model_raises(self) -> None:
        """Registry raises KeyError for unknown model names."""
        from dl_models.integration import DLModelRegistry

        registry = DLModelRegistry()
        with pytest.raises(KeyError):
            registry.get_model("nonexistent_model")
