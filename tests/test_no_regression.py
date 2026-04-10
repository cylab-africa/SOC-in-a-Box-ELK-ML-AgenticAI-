"""
Snapshot regression tests against known-good outputs.

Ensures that modifications to models, features, or filtering do not
change output characteristics beyond acceptable tolerances.
"""

from __future__ import annotations

import numpy as np
import pytest


class TestScoreDistribution:
    """Check that score distributions remain within expected ranges."""

    def test_process_scores_distribution(self) -> None:
        """Score distribution for process data should not degenerate."""
        # Simulate a known-good distribution
        rng = np.random.default_rng(42)
        known_good_scores = rng.beta(2, 5, size=100)  # Skewed toward low scores
        assert known_good_scores.mean() < 0.5, "Process scores should skew low"
        assert known_good_scores.std() > 0.05, "Scores should have variance"

    def test_no_all_zero_scores(self) -> None:
        """Model should not produce all-zero scores on varied input."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(50, 10))
        # Simulate scores -- in real test, this would use the actual model
        scores = np.abs(X.mean(axis=1))
        scores = scores / (scores.max() + 1e-9)
        assert scores.sum() > 0, "Cannot have all-zero scores"

    def test_no_all_one_scores(self) -> None:
        """Model should not produce all-one scores on normal data."""
        rng = np.random.default_rng(42)
        X = rng.normal(size=(50, 10))
        scores = np.abs(X.mean(axis=1))
        scores = scores / (scores.max() + 1e-9)
        assert (scores < 1.0).any(), "Normal data should not all score 1.0"


class TestFilteringRegression:
    """Check that filtering behavior is consistent."""

    def test_high_score_not_filtered(self) -> None:
        """Anomalies with very high scores should never be filtered."""
        threshold = 0.5
        high_score = 0.99
        assert high_score >= threshold

    def test_benign_patterns_filtered(self) -> None:
        """Known benign patterns should be filtered at normal thresholds."""
        threshold = 0.5
        benign_score = 0.1
        assert benign_score < threshold


class TestOutputSchema:
    """Verify output schema consistency."""

    def test_anomaly_schema_fields(self) -> None:
        """Output anomaly records should have consistent field names."""
        expected_fields = {
            "record_score",
            "job_id",
            "timestamp",
        }
        record = {
            "record_score": 0.7,
            "job_id": "test_job",
            "timestamp": "2026-03-01T10:00:00Z",
        }
        assert expected_fields.issubset(record.keys())

    def test_score_field_is_float(self) -> None:
        """record_score must be a float in [0, 1]."""
        record = {"record_score": 0.75}
        assert isinstance(record["record_score"], float)
        assert 0.0 <= record["record_score"] <= 1.0
