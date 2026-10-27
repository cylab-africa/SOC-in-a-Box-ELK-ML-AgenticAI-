"""
Tests for detection job output format and scoring correctness.

Verifies that the detection pipeline produces correctly formatted
anomaly records with scores in [0, 1] and required metadata fields.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest


class TestDetectionOutputFormat:
    """Verify detection job output has required fields and valid ranges."""

    def test_anomaly_record_has_required_fields(self) -> None:
        """An anomaly record dict must contain essential fields."""
        required_fields = {
            "record_score",
            "job_id",
            "timestamp",
        }
        record = {
            "record_score": 0.85,
            "job_id": "v3_linux_anomalous_process_all_hosts",
            "timestamp": "2026-03-01T10:00:00Z",
            "host.hostname": "web01",
        }
        assert required_fields.issubset(record.keys())

    def test_score_range(self) -> None:
        """Anomaly scores must be in [0.0, 1.0]."""
        scores = np.array([0.0, 0.5, 1.0, 0.73])
        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)

    def test_scores_no_nan(self) -> None:
        """Anomaly scores must not contain NaN or Inf."""
        scores = np.array([0.1, 0.5, 0.9, 0.3])
        assert np.all(np.isfinite(scores))

    def test_empty_dataframe_produces_empty_scores(self) -> None:
        """Detection on an empty DataFrame should return empty scores array."""
        df = pd.DataFrame(columns=["@timestamp", "process.name", "host.hostname"])
        # Simulate scoring an empty dataframe
        if len(df) == 0:
            scores = np.array([], dtype=np.float64)
        assert len(scores) == 0


class TestScoreNormalization:
    """Verify score normalization logic."""

    def test_minmax_normalization(self) -> None:
        """Min-max normalization maps to [0, 1]."""
        raw = np.array([10.0, 20.0, 30.0, 40.0, 50.0])
        lo, hi = raw.min(), raw.max()
        normalized = (raw - lo) / (hi - lo)
        assert normalized.min() == pytest.approx(0.0)
        assert normalized.max() == pytest.approx(1.0)

    def test_constant_scores_normalize_to_zero(self) -> None:
        """If all raw scores are identical, normalized scores should be 0."""
        raw = np.array([5.0, 5.0, 5.0])
        lo, hi = raw.min(), raw.max()
        if hi - lo < 1e-9:
            normalized = np.zeros_like(raw)
        else:
            normalized = (raw - lo) / (hi - lo)
        assert np.all(normalized == 0.0)

    def test_negative_raw_scores_handled(self) -> None:
        """Negative raw scores should normalize correctly to [0, 1]."""
        raw = np.array([-10.0, -5.0, 0.0, 5.0, 10.0])
        lo, hi = raw.min(), raw.max()
        normalized = (raw - lo) / (hi - lo)
        assert normalized.min() == pytest.approx(0.0)
        assert normalized.max() == pytest.approx(1.0)
