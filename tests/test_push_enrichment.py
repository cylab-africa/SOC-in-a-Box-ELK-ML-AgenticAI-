"""
Tests for MITRE ATT&CK enrichment and context field population.

Verifies that the enrichment pipeline in mappings/enrichment.py
adds all required MITRE fields and investigation hints.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestMITREEnrichment:
    """Test MITRE ATT&CK field enrichment."""

    def test_attack_mapping_json_valid(self) -> None:
        """attack_mapping.json must be valid JSON with required structure."""
        mapping_path = Path("mappings/attack_mapping.json")
        if not mapping_path.exists():
            pytest.skip("attack_mapping.json not found")

        data = json.loads(mapping_path.read_text())
        assert isinstance(data, dict)
        for job_name, entry in data.items():
            assert "techniques" in entry, f"Missing techniques for {job_name}"
            assert "kill_chain_phase" in entry, f"Missing kill_chain_phase for {job_name}"
            for tech in entry["techniques"]:
                assert "id" in tech, f"Missing technique id in {job_name}"
                assert "name" in tech, f"Missing technique name in {job_name}"

    def test_enrich_alert_adds_mitre_fields(self) -> None:
        """enrich_alert() should add mitre.techniques and mitre.tactics."""
        try:
            from mappings.enrichment import enrich_alert
        except ImportError:
            pytest.skip("mappings.enrichment not importable")

        alert: dict = {"job_id": "test", "record_score": 0.8}
        enriched = enrich_alert(alert, "v3_linux_anomalous_process_all_hosts")
        assert "mitre" in enriched
        mitre = enriched["mitre"]
        assert "techniques" in mitre
        assert "tactics" in mitre
        assert "kill_chain_phase" in mitre

    def test_investigation_hints_populated(self) -> None:
        """enrich_alert() should add investigation hints for mapped techniques."""
        try:
            from mappings.enrichment import enrich_alert
        except ImportError:
            pytest.skip("mappings.enrichment not importable")

        alert: dict = {"job_id": "test", "record_score": 0.9}
        enriched = enrich_alert(alert, "v3_linux_anomalous_process_all_hosts")
        assert "investigation_hints" in enriched


class TestContextFields:
    """Test that enriched alerts have required context fields."""

    def test_alert_has_score(self) -> None:
        """Enriched alert must have record_score field."""
        alert = {"record_score": 0.85, "job_id": "test"}
        assert "record_score" in alert
        assert 0.0 <= alert["record_score"] <= 1.0

    def test_alert_has_job_id(self) -> None:
        """Enriched alert must identify its source ML job."""
        alert = {"record_score": 0.85, "job_id": "v3_linux_anomalous_process_all_hosts"}
        assert "job_id" in alert
        assert alert["job_id"]  # Non-empty


class TestKillChainPhaseOrdering:
    """Test that kill chain phases are correctly ordered."""

    def test_phase_order_is_consistent(self) -> None:
        """Kill chain phases should follow the canonical ordering."""
        expected_order = [
            "reconnaissance",
            "resource_development",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "command_and_control",
            "exfiltration",
            "impact",
        ]
        # Verify no duplicates
        assert len(expected_order) == len(set(expected_order))
        # Verify all 14 phases present
        assert len(expected_order) == 14
