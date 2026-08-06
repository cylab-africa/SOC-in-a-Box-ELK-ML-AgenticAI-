"""Tests for the benign_lists and adaptive threshold modules (Agent 4).

Validates graduated allowlisting, LOLBin protection, and threshold computation.
"""

from __future__ import annotations

from datetime import datetime, timezone


class TestAllowlistManager:
    """Validate graduated allowlist with dampening."""

    def test_dampening_applied(self) -> None:
        """AllowlistManager dampen scores for matched processes."""
        from benign_lists import AllowlistManager

        manager = AllowlistManager()
        # systemd is in DEFAULT_ALLOWLIST with dampening 0.3
        score, trace = manager.apply("systemd-resolved", 0.8)

        assert score < 0.8, "Score should be dampened"
        assert trace["allowlist_match"] is not None
        assert trace["dampening_applied"] < 1.0

    def test_lolbin_protection(self) -> None:
        """LOLBin processes are never dampened regardless of allowlist."""
        from benign_lists import NEVER_ALLOWLIST, AllowlistManager

        manager = AllowlistManager()
        for lolbin in ["sudo", "curl", "wget", "python3", "bash"]:
            assert lolbin in NEVER_ALLOWLIST
            score, trace = manager.apply(lolbin, 0.9)
            assert score == 0.9, f"{lolbin} should not be dampened"
            assert trace["lolbin_protected"] is True

    def test_expired_entry_skipped(self) -> None:
        """Expired allowlist entries are not applied."""
        from benign_lists import AllowlistEntry, AllowlistManager

        expired = AllowlistEntry(
            pattern="old_service",
            match_type="exact",
            dampening_factor=0.1,
            category="custom",
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
        )
        manager = AllowlistManager(extra_entries=[expired])
        score, trace = manager.apply("old_service", 0.8)

        assert score == 0.8, "Expired entry should not dampen"

    def test_stale_entry_flagged(self) -> None:
        """Stale entries (no hits in 90 days) are flagged for review."""
        from benign_lists import AllowlistEntry, AllowlistManager

        stale = AllowlistEntry(
            pattern="stale_process",
            match_type="exact",
            dampening_factor=0.5,
            category="custom",
            created_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        manager = AllowlistManager(extra_entries=[stale])
        flagged = manager.flag_stale_entries()

        assert len(flagged) > 0


class TestAdaptiveThreshold:
    """Validate adaptive threshold computation."""

    def test_default_threshold(self) -> None:
        """Default threshold is returned for unknown jobs."""
        from adaptive_threshold import compute_effective_threshold

        threshold, trace = compute_effective_threshold("unknown_job_xyz")
        assert threshold == 0.65

    def test_per_job_override(self) -> None:
        """Known jobs get their specific threshold override."""
        from adaptive_threshold import compute_effective_threshold

        threshold, trace = compute_effective_threshold(
            "v3_linux_anomalous_network_activity"
        )
        assert threshold == 0.55

    def test_off_hours_reduction(self) -> None:
        """Off-hours timestamp lowers the threshold."""
        from adaptive_threshold import compute_effective_threshold

        # 3 AM = off hours
        ts = datetime(2026, 3, 1, 3, 0, 0, tzinfo=timezone.utc)
        threshold, trace = compute_effective_threshold(
            "v3_linux_anomalous_process_all_hosts", timestamp=ts
        )
        assert threshold < 0.65
        assert trace["off_hours_applied"] is True

    def test_high_value_host_reduction(self) -> None:
        """High-value hosts get lower thresholds."""
        from adaptive_threshold import compute_effective_threshold

        threshold, trace = compute_effective_threshold(
            "v3_linux_anomalous_process_all_hosts",
            hostname="web01",
            high_value_hosts=["web01", "db01"],
        )
        assert threshold < 0.65
        assert trace["high_value_applied"] is True

    def test_filter_trace_structure(self) -> None:
        """build_filter_trace produces valid audit trace."""
        from adaptive_threshold import build_filter_trace

        trace = build_filter_trace(
            anomaly_doc={"job_id": "test_job", "record_score": 0.7},
            is_fp=True,
            fp_reason="Rule 1: loopback traffic",
        )
        assert trace["filtered"] is True
        assert trace["reason"] == "Rule 1: loopback traffic"
        assert "timestamp" in trace
