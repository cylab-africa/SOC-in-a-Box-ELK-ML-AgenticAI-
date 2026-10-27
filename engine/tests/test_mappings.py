"""Tests for the mappings/ enrichment module (Agent 6).

Validates MITRE ATT&CK enrichment, job-to-technique mapping,
and alert context package generation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

_ENGINE_DIR = Path(__file__).resolve().parent.parent


class TestAttackMapping:
    """Validate the attack mapping JSON and enrichment functions."""

    def test_mapping_file_valid_json(self) -> None:
        """attack_mapping.json is valid JSON with expected structure."""
        mapping_path = _ENGINE_DIR / "mappings" / "attack_mapping.json"
        if not mapping_path.exists():
            pytest.skip("attack_mapping.json not found")

        data = json.loads(mapping_path.read_text())
        assert isinstance(data, dict)
        for _job_name, entry in data.items():
            assert "techniques" in entry
            assert "kill_chain_phase" in entry
            assert isinstance(entry["techniques"], list)
            for tech in entry["techniques"]:
                assert "id" in tech
                assert "name" in tech
                assert tech["id"].startswith("T")

    def test_enrich_alert_adds_mitre_fields(self) -> None:
        """enrich_alert adds mitre techniques, tactics, and hints."""
        from mappings.enrichment import enrich_alert

        alert = {"job_id": "v3_linux_anomalous_process_all_hosts", "score": 0.8}
        enriched = enrich_alert(alert, "v3_linux_anomalous_process_all_hosts")

        assert "mitre" in enriched
        assert "techniques" in enriched["mitre"]
        assert len(enriched["mitre"]["techniques"]) > 0
        assert enriched["mitre"]["techniques"][0].startswith("T")
        assert "investigation_hints" in enriched

    def test_enrich_alert_unknown_job(self) -> None:
        """Unknown job names produce empty but valid enrichment."""
        from mappings.enrichment import enrich_alert

        alert = {"job_id": "unknown_job", "score": 0.5}
        enriched = enrich_alert(alert, "unknown_job")

        assert "mitre" in enriched
        assert enriched["mitre"]["techniques"] == []
        assert enriched["mitre"]["kill_chain_phase"] == "unknown"

    def test_get_techniques_for_job(self) -> None:
        """get_techniques_for_job returns technique list for known jobs."""
        from mappings.enrichment import get_techniques_for_job

        techniques = get_techniques_for_job("v3_linux_anomalous_network_activity")
        assert len(techniques) > 0
        assert any(t["id"] == "T1071" for t in techniques)

    def test_investigation_hints_coverage(self) -> None:
        """All technique IDs in the mapping have investigation hints."""
        from mappings.enrichment import INVESTIGATION_HINTS

        mapping_path = _ENGINE_DIR / "mappings" / "attack_mapping.json"
        if not mapping_path.exists():
            pytest.skip("attack_mapping.json not found")

        data = json.loads(mapping_path.read_text())
        all_tech_ids = set()
        for entry in data.values():
            for tech in entry["techniques"]:
                all_tech_ids.add(tech["id"])

        missing = all_tech_ids - set(INVESTIGATION_HINTS.keys())
        assert not missing, f"Missing investigation hints for: {missing}"


class TestESTemplates:
    """Validate Elasticsearch index templates."""

    def test_custom_template_valid(self) -> None:
        """ml-anomalies-custom.json is valid mapping template."""
        path = _ENGINE_DIR / "mappings" / "ml-anomalies-custom.json"
        if not path.exists():
            pytest.skip("ml-anomalies-custom.json not found")

        data = json.loads(path.read_text())
        has_mappings = "mappings" in data or "properties" in data
        has_composable = "template" in data and "mappings" in data.get("template", {})
        assert has_mappings or has_composable

    def test_correlated_template_valid(self) -> None:
        """ml-anomalies-correlated.json is valid mapping template."""
        path = _ENGINE_DIR / "mappings" / "ml-anomalies-correlated.json"
        if not path.exists():
            pytest.skip("ml-anomalies-correlated.json not found")

        data = json.loads(path.read_text())
        has_mappings = "mappings" in data or "properties" in data
        has_composable = "template" in data and "mappings" in data.get("template", {})
        assert has_mappings or has_composable
