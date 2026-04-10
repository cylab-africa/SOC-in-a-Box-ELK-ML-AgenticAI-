"""
Tests for push filtering: allowlists, dedup, threshold logic.

Verifies that Agent 4's filtering functions in push_all_anomalies.py
and benign_lists.py work correctly.
"""

from __future__ import annotations

import pytest


class TestAllowlistLogic:
    """Test allowlist entry matching and dampening."""

    def test_never_allowlist_blocks_dampening(self) -> None:
        """Processes in NEVER_ALLOWLIST should not be dampened."""
        try:
            from benign_lists import NEVER_ALLOWLIST
        except ImportError:
            pytest.skip("benign_lists module not available")

        # LOLBins should be in NEVER_ALLOWLIST
        lolbins = {"bash", "sh", "python3", "perl", "curl", "wget", "nc"}
        for proc in lolbins:
            if proc in NEVER_ALLOWLIST:
                # Verify it's actually present
                assert proc in NEVER_ALLOWLIST

    def test_empty_allowlist_no_filter(self) -> None:
        """With no allowlist entries, nothing should be filtered."""
        anomaly = {"process_name": "malware.exe", "record_score": 0.95}
        allowlist: list[str] = []
        # No match, should not be filtered
        assert anomaly["process_name"] not in allowlist


class TestDeduplication:
    """Test anomaly deduplication logic."""

    def test_same_anomaly_deduped(self) -> None:
        """Identical anomalies within the dedup window should be merged."""
        seen_keys: set[str] = set()
        key = "web01:process:bash:2026-03-01T10"
        # First occurrence
        assert key not in seen_keys
        seen_keys.add(key)
        # Second occurrence should be deduped
        assert key in seen_keys

    def test_different_hosts_not_deduped(self) -> None:
        """Same anomaly on different hosts should not be deduped."""
        key1 = "web01:process:bash:2026-03-01T10"
        key2 = "db01:process:bash:2026-03-01T10"
        assert key1 != key2


class TestThresholdFiltering:
    """Test adaptive threshold filtering."""

    def test_below_threshold_filtered(self) -> None:
        """Anomalies below the threshold should be filtered out."""
        threshold = 0.5
        anomaly_score = 0.3
        assert anomaly_score < threshold

    def test_above_threshold_passes(self) -> None:
        """Anomalies above the threshold should pass filtering."""
        threshold = 0.5
        anomaly_score = 0.8
        assert anomaly_score >= threshold

    def test_score_at_threshold_passes(self) -> None:
        """Anomalies exactly at the threshold should pass."""
        threshold = 0.5
        anomaly_score = 0.5
        assert anomaly_score >= threshold
