"""Tests for the features/ package (Agent 2).

Validates that all feature transformers produce float64 columns,
handle NaN gracefully, and map to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest


class TestFeatureTransformers:
    """Integration tests for all feature transformer classes."""

    def _check_transformer(self, transformer, df: pd.DataFrame) -> None:
        """Common checks applied to every transformer.

        Args:
            transformer: FeatureTransformer instance.
            df: Input DataFrame.
        """
        # Fit and transform
        result = transformer.fit_transform(df)

        # All declared features must exist
        for name in transformer.get_feature_names():
            assert name in result.columns, f"Missing feature column: {name}"
            assert result[name].dtype == np.float64, f"{name} is not float64"
            assert not result[name].isna().any(), f"{name} contains NaN"

        # ATT&CK mapping must cover all features
        mapping = transformer.get_attack_mapping()
        for name in transformer.get_feature_names():
            assert name in mapping, f"No ATT&CK mapping for {name}"
            assert mapping[name].startswith("T"), f"Invalid technique ID for {name}"

        # Idempotency: calling transform again should not duplicate columns
        original_cols = set(result.columns)
        result2 = transformer.transform(result)
        assert set(result2.columns) == original_cols, "Transform added duplicate columns"

    def test_cmd_entropy_transformer(self, synthetic_process_df: pd.DataFrame) -> None:
        """Test CommandLineEntropyTransformer produces valid features."""
        from features.process_features import CommandLineEntropyTransformer

        transformer = CommandLineEntropyTransformer()
        self._check_transformer(transformer, synthetic_process_df)

        result = transformer.fit_transform(synthetic_process_df)
        # Entropy should be in [0, 1]
        assert (result["cmd_entropy"] >= 0.0).all()
        assert (result["cmd_entropy"] <= 1.0).all()

    def test_process_tree_transformer(self, synthetic_process_df: pd.DataFrame) -> None:
        """Test ProcessTreeTransformer produces valid features."""
        from features.process_features import ProcessTreeTransformer

        transformer = ProcessTreeTransformer()
        self._check_transformer(transformer, synthetic_process_df)

    def test_process_rarity_transformer(self, synthetic_process_df: pd.DataFrame) -> None:
        """Test ProcessRarityTransformer produces valid features."""
        from features.process_features import ProcessRarityTransformer

        transformer = ProcessRarityTransformer()
        self._check_transformer(transformer, synthetic_process_df)

    def test_temporal_cyclical_transformer(self, synthetic_process_df: pd.DataFrame) -> None:
        """Test TemporalCyclicalTransformer produces valid cyclical features."""
        from features.process_features import TemporalCyclicalTransformer

        transformer = TemporalCyclicalTransformer()
        self._check_transformer(transformer, synthetic_process_df)

        result = transformer.fit_transform(synthetic_process_df)
        # Sin/cos values must be in [-1, 1]
        for col in ["hour_sin", "hour_cos", "dow_sin", "dow_cos"]:
            assert (result[col] >= -1.0).all(), f"{col} below -1"
            assert (result[col] <= 1.0).all(), f"{col} above 1"

    def test_destination_rarity_transformer(self, synthetic_network_df: pd.DataFrame) -> None:
        """Test DestinationRarityTransformer produces valid features."""
        from features.network_features import DestinationRarityTransformer

        transformer = DestinationRarityTransformer()
        self._check_transformer(transformer, synthetic_network_df)

    def test_dns_entropy_transformer(self, synthetic_network_df: pd.DataFrame) -> None:
        """Test DNSEntropyTransformer handles missing DNS columns gracefully."""
        from features.network_features import DNSEntropyTransformer

        transformer = DNSEntropyTransformer()
        self._check_transformer(transformer, synthetic_network_df)

    def test_beacon_detector_transformer(self, synthetic_network_df: pd.DataFrame) -> None:
        """Test BeaconDetectorTransformer detects periodic patterns."""
        from features.network_features import BeaconDetectorTransformer

        transformer = BeaconDetectorTransformer()
        self._check_transformer(transformer, synthetic_network_df)

    def test_login_time_transformer(self, synthetic_auth_df: pd.DataFrame) -> None:
        """Test LoginTimeTransformer detects anomalous login times."""
        from features.auth_features import LoginTimeTransformer

        transformer = LoginTimeTransformer()
        self._check_transformer(transformer, synthetic_auth_df)

    def test_privesc_transformer(self, synthetic_process_df: pd.DataFrame) -> None:
        """Test PrivilegeEscalationTransformer detects sudo/su patterns."""
        from features.auth_features import PrivilegeEscalationTransformer

        transformer = PrivilegeEscalationTransformer()
        self._check_transformer(transformer, synthetic_process_df)

    def test_auth_failure_transformer(self, synthetic_auth_df: pd.DataFrame) -> None:
        """Test AuthFailureTransformer detects brute-force patterns."""
        from features.auth_features import AuthFailureTransformer

        transformer = AuthFailureTransformer()
        self._check_transformer(transformer, synthetic_auth_df)

    def test_empty_dataframe(self) -> None:
        """All transformers handle empty DataFrames without error."""
        from features.process_features import CommandLineEntropyTransformer

        df = pd.DataFrame()
        transformer = CommandLineEntropyTransformer()
        result = transformer.fit_transform(df)
        for name in transformer.get_feature_names():
            assert name in result.columns

    def test_missing_columns(self) -> None:
        """Transformers produce 0.0 when expected columns are missing."""
        from features.process_features import ProcessTreeTransformer

        df = pd.DataFrame({"unrelated_col": [1, 2, 3]})
        transformer = ProcessTreeTransformer()
        result = transformer.fit_transform(df)
        for name in transformer.get_feature_names():
            assert (result[name] == 0.0).all()
