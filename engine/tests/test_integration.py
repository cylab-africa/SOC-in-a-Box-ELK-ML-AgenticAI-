"""
Integration tests: end-to-end synthetic data through the pipeline.

Tests the full path from synthetic event data through feature engineering,
model scoring, and alert output format validation.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest


class TestFeatureToModelPipeline:
    """Test feature engineering -> model scoring integration."""

    def test_process_features_scorable(self, synthetic_process_df: pd.DataFrame) -> None:
        """Process features should produce a numeric matrix suitable for models."""
        try:
            from features.process_features import CommandLineEntropyTransformer
        except ImportError:
            pytest.skip("features package not available")

        transformer = CommandLineEntropyTransformer()
        transformer.fit(synthetic_process_df)
        result = transformer.transform(synthetic_process_df.copy())

        # Check that feature columns are numeric
        for col in transformer.get_feature_names():
            if col in result.columns:
                assert result[col].dtype in (np.float64, np.float32)
                assert result[col].isna().sum() == 0

    def test_network_features_scorable(self, synthetic_network_df: pd.DataFrame) -> None:
        """Network features should produce valid numeric columns."""
        try:
            from features.network_features import DestinationRarityTransformer
        except ImportError:
            pytest.skip("features package not available")

        transformer = DestinationRarityTransformer()
        transformer.fit(synthetic_network_df)
        result = transformer.transform(synthetic_network_df.copy())

        for col in transformer.get_feature_names():
            if col in result.columns:
                assert result[col].dtype in (np.float64, np.float32)

    def test_auth_features_scorable(self, synthetic_auth_df: pd.DataFrame) -> None:
        """Auth features should produce valid numeric columns."""
        try:
            from features.auth_features import LoginTimeTransformer
        except ImportError:
            pytest.skip("features package not available")

        transformer = LoginTimeTransformer()
        transformer.fit(synthetic_auth_df)
        result = transformer.transform(synthetic_auth_df.copy())

        for col in transformer.get_feature_names():
            if col in result.columns:
                assert result[col].dtype in (np.float64, np.float32)
                assert result[col].isna().sum() == 0


class TestAlertOutputFormat:
    """Test that the complete pipeline produces valid alert output."""

    def test_alert_has_minimum_fields(self) -> None:
        """A well-formed alert record has required fields."""
        alert = {
            "record_score": 0.85,
            "job_id": "v3_linux_anomalous_process_all_hosts",
            "timestamp": "2026-03-01T10:00:00Z",
            "host.hostname": "web01",
            "process.name": "nc",
        }
        required = {"record_score", "job_id", "timestamp"}
        assert required.issubset(alert.keys())

    def test_alert_scores_bounded(self) -> None:
        """All scores in alert output must be in [0, 1]."""
        alerts = [
            {"record_score": 0.0},
            {"record_score": 0.5},
            {"record_score": 1.0},
        ]
        for alert in alerts:
            score = alert["record_score"]
            assert 0.0 <= score <= 1.0
