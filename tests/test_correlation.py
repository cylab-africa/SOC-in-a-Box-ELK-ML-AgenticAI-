"""
Tests for kill-chain correlation logic.

Verifies that the KillChainCorrelator in post_correlation.py correctly
groups anomalies into attack chains and assigns priorities.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest


def _make_anomaly(
    host: str,
    ts_offset_min: int,
    phase: str,
    user: str = "",
    process: str = "",
    dest_ip: str = "",
    score: float = 0.7,
) -> dict:
    """Create a synthetic anomaly dict for testing.

    Args:
        host: Host name.
        ts_offset_min: Minutes offset from base time.
        phase: Kill chain phase.
        user: Optional user name.
        process: Optional process name.
        dest_ip: Optional destination IP.
        score: Anomaly score.

    Returns:
        Anomaly dict.
    """
    base = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
    ts = base + timedelta(minutes=ts_offset_min)
    anom: dict = {
        "host.name": host,
        "@timestamp": ts.isoformat(),
        "mitre": {"kill_chain_phase": phase},
        "record_score": score,
    }
    if user:
        anom["user.name"] = user
    if process:
        anom["process.name"] = process
    if dest_ip:
        anom["destination.ip"] = dest_ip
    return anom


class TestKillChainCorrelator:
    """Test the KillChainCorrelator from post_correlation.py."""

    def _get_correlator(self):
        """Import and return KillChainCorrelator, skipping if unavailable."""
        try:
            from post_correlation import KillChainCorrelator
            return KillChainCorrelator
        except ImportError:
            pytest.skip("post_correlation module not available")

    def test_single_host_chain(self) -> None:
        """Anomalies on the same host within the time window form a chain."""
        Correlator = self._get_correlator()
        anomalies = [
            _make_anomaly("web01", 0, "execution", user="alice", process="bash"),
            _make_anomaly("web01", 10, "discovery", user="alice", process="whoami"),
            _make_anomaly("web01", 25, "lateral_movement", user="alice", dest_ip="10.0.1.5"),
        ]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)

        assert len(chains) >= 1
        chain = chains[0]
        assert chain.host == "web01"
        assert len(chain.phases_observed) >= 2
        assert chain.chain_score > 0

    def test_different_hosts_separate_chains(self) -> None:
        """Anomalies on different hosts should form separate chains."""
        Correlator = self._get_correlator()
        anomalies = [
            _make_anomaly("web01", 0, "execution"),
            _make_anomaly("web01", 10, "discovery"),
            _make_anomaly("db01", 5, "execution"),
            _make_anomaly("db01", 15, "credential_access"),
        ]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)

        hosts = {c.host for c in chains}
        assert len(hosts) == 2

    def test_time_window_separation(self) -> None:
        """Anomalies outside the time window should form separate chains."""
        Correlator = self._get_correlator()
        anomalies = [
            _make_anomaly("web01", 0, "execution"),
            _make_anomaly("web01", 10, "discovery"),
            # 2 hours later - should be a separate chain
            _make_anomaly("web01", 120, "exfiltration"),
            _make_anomaly("web01", 130, "impact"),
        ]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)

        assert len(chains) >= 2

    def test_critical_priority_assignment(self) -> None:
        """Chain with 3+ phases including exfil should be critical."""
        Correlator = self._get_correlator()
        anomalies = [
            _make_anomaly("web01", 0, "execution", process="bash"),
            _make_anomaly("web01", 10, "discovery", process="whoami"),
            _make_anomaly("web01", 20, "exfiltration", dest_ip="evil.com"),
        ]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)

        assert len(chains) >= 1
        assert chains[0].investigation_priority == "critical"

    def test_empty_input_returns_no_chains(self) -> None:
        """Empty anomaly list should produce no chains."""
        Correlator = self._get_correlator()
        correlator = Correlator()
        chains = correlator.correlate([])
        assert chains == []

    def test_single_anomaly_no_chain(self) -> None:
        """A single anomaly should not form a chain (below min_chain_length)."""
        Correlator = self._get_correlator()
        anomalies = [_make_anomaly("web01", 0, "execution")]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)
        assert len(chains) == 0

    def test_chain_has_linked_entities(self) -> None:
        """Chains should track linked users, processes, and IPs."""
        Correlator = self._get_correlator()
        anomalies = [
            _make_anomaly("web01", 0, "execution", user="alice", process="bash"),
            _make_anomaly("web01", 10, "lateral_movement", user="alice", dest_ip="10.0.1.5"),
        ]
        correlator = Correlator(time_window_minutes=60)
        chains = correlator.correlate(anomalies)

        assert len(chains) >= 1
        entities = chains[0].linked_entities
        assert "alice" in entities.get("users", [])
        assert "bash" in entities.get("processes", [])
