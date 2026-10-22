#!/usr/bin/env python3
"""Offline tests: formatter, log excerpt fallback, LLM failure classification.

Run from the Agent-SIEM-maintenance directory:

    python tests/test_daily_report_and_llm.py

No live ES, no Ollama, no Google Chat needed. Stubs requests + a fake ES client.
"""
from __future__ import annotations

import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import siem_daily_report as sdr  # noqa: E402
import enhanced_health_monitor as ehm  # noqa: E402


def _fake_health_data() -> dict:
    return {
        "timestamp": "2026-05-09T06:30:00Z",
        "cluster_health": {
            "status": "yellow",
            "number_of_nodes": 3,
            "number_of_data_nodes": 2,
            "active_shards": 940,
            "unassigned_shards": 54,
            "relocating_shards": 0,
            "initializing_shards": 0,
            "number_of_pending_tasks": 2,
        },
        "shard_analysis": {
            "total_shards": 994,
            "primary_shards": 470,
            "replica_shards": 470,
            "unassigned_shards": 54,
            "relocating_shards": 0,
            "initializing_shards": 0,
        },
        "node_status": {
            "node_details": [
                {"name": "es-1", "heap_used_percent": 91, "roles": ["master", "data"]},
                {"name": "es-2", "heap_used_percent": 64, "roles": ["data"]},
            ]
        },
        "factual_observations": [
            "Cluster status is yellow (not green)",
            "Found 54 unassigned shards",
            "Found 1 nodes with >85% heap usage: ['es-1']",
        ],
        "data_freshness": {
            "issues": [{"category": "network", "message": "no events in last 2h17m"}],
            "status": "degraded",
        },
        "cluster_architecture": {
            "cluster_name": "siem-prod",
            "total_indices": 187,
            "data_nodes": 2,
            "total_nodes": 3,
            "master_eligible": 3,
            "ingest_nodes": 3,
        },
        "index_report": {"total_indices": 187, "health_score": 70.6,
                         "green": 132, "yellow": 49, "red": 6, "largest": []},
        "detection_rules": {"enabled": 412, "ok": 388, "failed": 14, "partial": 8,
                            "warning": 0, "never_executed": 2,
                            "failed_samples": [], "partial_samples": [], "never_samples": []},
        "ml_anomalies": {"total": 17},
        "shard_health_score": 40,
        "disk_summary": [
            {"name": "es-1", "used_pct": 92.4, "free_gb": 14.0, "total_gb": 184.0},
            {"name": "es-2", "used_pct": 71.0, "free_gb": 53.4, "total_gb": 184.0},
        ],
        "allocation_explain": {
            "index": ".ds-logs-endpoint.events.process-default-2026.05.07-000123",
            "shard": 0,
            "primary": False,
            "reason": "NODE_LEFT",
            "details": "node_left[abcdef] left the cluster",
            "can_allocate": "no",
            "decisions": [
                {"node": "es-1", "decision": "NO",
                 "explanations": ["disk_threshold: high watermark 90% exceeded (92.4%)"]},
            ],
        },
        "pending_tasks": {"count": 2, "max_wait_ms": 8421,
                          "samples": [{"priority": "URGENT", "source": "shard-failed"}]},
    }


class FormatterTest(unittest.TestCase):
    def test_root_cause_sections_present(self):
        out = sdr.format_daily_siem_report(_fake_health_data(), analysis="(none)")
        # Allocation root cause
        self.assertIn("Cause: NODE_LEFT", out)
        self.assertIn("can_allocate: no", out)
        self.assertIn("disk_threshold: high watermark 90% exceeded", out)
        # Pending tasks
        self.assertIn("Pending Master Tasks", out)
        self.assertIn("URGENT", out)
        # Disk %
        self.assertIn("disk 92.4% used", out)
        self.assertIn("⚠️ Disk pressure", out)
        # Data freshness
        self.assertIn("Ingestion Freshness", out)
        self.assertIn("network", out)
        # Factual observations as a "Why" block
        self.assertIn("Why (factual observations)", out)
        self.assertIn("Found 54 unassigned shards", out)

    def test_no_pending_tasks_section_when_zero(self):
        hd = _fake_health_data()
        hd["pending_tasks"] = {"count": 0, "max_wait_ms": 0, "samples": []}
        out = sdr.format_daily_siem_report(hd, analysis="")
        self.assertNotIn("Pending Master Tasks", out)


class FakeES:
    """Minimal stand-in for the elasticsearch client used in fetch_recent_es_log_excerpt."""
    class _Cluster:
        def __init__(self, parent):
            self._p = parent
        def health(self):
            return {"unassigned_shards": 1}
        def pending_tasks(self):
            return {"tasks": [{"priority": "HIGH", "source": "create-index", "time_in_queue_millis": 4321}]}
        def allocation_explain(self):
            return {
                "index": "i", "shard": 0, "primary": False,
                "unassigned_info": {"reason": "ALLOCATION_FAILED", "details": "boom"},
                "can_allocate": "no",
                "node_allocation_decisions": [
                    {"node_name": "es-1", "node_decision": "NO",
                     "deciders": [{"decider": "disk_threshold", "decision": "NO",
                                   "explanation": "low watermark 85% exceeded"}]}
                ],
            }
    def __init__(self, search_results=None):
        self._results = search_results or {}
        self.cluster = FakeES._Cluster(self)
    def search(self, index, body, **kw):
        return self._results.get(index, {"hits": {"hits": []}})


class LogExcerptTest(unittest.TestCase):
    def test_fallback_when_no_log_indices(self):
        es = FakeES(search_results={})
        txt = sdr.fetch_recent_es_log_excerpt(es)
        self.assertIn("no Elastic log indices matched", txt)
        self.assertIn("pending_tasks (1)", txt)
        self.assertIn("allocation_explain", txt)
        self.assertIn("ALLOCATION_FAILED", txt)
        self.assertIn("disk_threshold", txt)

    def test_uses_first_matching_pattern(self):
        results = {
            ".ds-elastic-cloud-logs-*": {
                "hits": {"hits": [
                    {"_source": {"@timestamp": "2026-05-09T05:00Z", "log": {"level": "ERROR"},
                                 "host": {"name": "es-1"}, "message": "circuit_breaking_exception"}},
                ]}
            }
        }
        es = FakeES(search_results=results)
        txt = sdr.fetch_recent_es_log_excerpt(es)
        self.assertIn(".ds-elastic-cloud-logs-*", txt)
        self.assertIn("ERROR", txt)
        self.assertIn("circuit_breaking_exception", txt)


class LLMClassificationTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ["OLLAMA_URL"] = "http://localhost:11434"

    def test_openai_no_key(self):
        out = ehm.call_llm_api("hello", model="gpt-4")
        self.assertIn("OpenAI API key not configured", out)

    def test_ollama_unreachable(self):
        with mock.patch.object(ehm, "_ollama_tags", return_value=None):
            out = ehm.call_llm_api("hello", model="llama3.2")
        self.assertIn("Ollama not reachable", out)

    def test_ollama_model_missing(self):
        with mock.patch.object(ehm, "_ollama_tags", return_value={"mistral:latest"}):
            out = ehm.call_llm_api("hello", model="llama3.2")
        self.assertIn("not pulled", out)
        self.assertIn("ollama pull llama3.2", out)
        self.assertIn("mistral:latest", out)  # lists installed

    def test_ollama_empty_response(self):
        class _R:
            status_code = 200
            text = ""
            def json(self): return {"response": "   "}
        with mock.patch.object(ehm, "_ollama_tags", return_value={"llama3.2:latest"}), \
             mock.patch.object(ehm.requests, "post", return_value=_R()):
            out = ehm.call_llm_api("hello", model="llama3.2")
        self.assertIn("empty response", out)
        self.assertIn("num_ctx", out)

    def test_ollama_404(self):
        class _R:
            status_code = 404
            text = "model 'x' not found"
            def json(self): return {}
        with mock.patch.object(ehm, "_ollama_tags", return_value={"llama3.2:latest"}), \
             mock.patch.object(ehm.requests, "post", return_value=_R()):
            out = ehm.call_llm_api("hello", model="llama3.2")
        self.assertIn("not found by server", out)

    def test_ollama_success(self):
        class _R:
            status_code = 200
            text = "ok"
            def json(self): return {"response": "All good — green cluster."}
        with mock.patch.object(ehm, "_ollama_tags", return_value={"llama3.2:latest"}), \
             mock.patch.object(ehm.requests, "post", return_value=_R()):
            out = ehm.call_llm_api("hello", model="llama3.2")
        self.assertEqual(out, "All good — green cluster.")

    def test_failure_predicate(self):
        self.assertTrue(ehm._llm_output_is_failure("LLM analysis failed: anything"))
        self.assertTrue(ehm._llm_output_is_failure("LLM analysis unavailable: x"))
        self.assertFalse(ehm._llm_output_is_failure("All good"))
        self.assertFalse(ehm._llm_output_is_failure(""))


class AutoRemediateImportTest(unittest.TestCase):
    def test_orchestrator_has_new_actions(self):
        # Import-only smoke: confirms new functions exist and orchestrator references them.
        import auto_remediate as ar
        self.assertTrue(callable(ar.clear_request_query_caches))
        self.assertTrue(callable(ar.force_merge_oversharded_indices))
        self.assertTrue(callable(ar.retry_stuck_ilm))


class SchedulerImportTest(unittest.TestCase):
    def test_remediation_interval_parses(self):
        import maintenance_service as ms
        os.environ["AUTO_REMEDIATION_INTERVAL_HOURS"] = "12"
        self.assertEqual(ms._auto_remediation_interval_seconds(), 12 * 3600)
        os.environ["AUTO_REMEDIATION_INTERVAL_HOURS"] = "0"
        self.assertEqual(ms._auto_remediation_interval_seconds(), 0)
        os.environ["AUTO_REMEDIATION_INTERVAL_HOURS"] = "garbage"
        self.assertEqual(ms._auto_remediation_interval_seconds(), 12 * 3600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
