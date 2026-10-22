#!/usr/bin/env python3
"""End-to-end integration test for the feedback loop.

Simulates the full flow:
1. Alert generated -> alert_context saved
2. User clicks feedback button -> row appended to Sheet (mocked as direct call)
3. Poller reads pending row -> invokes judge -> updates SYSTEM_MEMORY.md
4. Subsequent alert prompt -> includes learned rules

All external services (Sheets, LLM) are mocked.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import alert_context as ac
import feedback_judge as fj
import system_memory as sm


class TestFullFeedbackLoop(unittest.TestCase):
    """Verify alert -> click -> judge -> memory -> next-alert-prompt flow."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_mem = sm.SYSTEM_MEMORY_PATH
        self._orig_ctx = ac.ALERT_CONTEXT_PATH
        self._orig_results = ac.RESULTS_DIR
        self._orig_threshold = sm.PROMOTION_THRESHOLD

        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"
        ac.RESULTS_DIR = Path(self._tmpdir)
        ac.ALERT_CONTEXT_PATH = Path(self._tmpdir) / "feedback_alert_context.json"
        sm.PROMOTION_THRESHOLD = 2
        sm.initialize_system_memory()

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_mem
        ac.ALERT_CONTEXT_PATH = self._orig_ctx
        ac.RESULTS_DIR = self._orig_results
        sm.PROMOTION_THRESHOLD = self._orig_threshold
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    @mock.patch("feedback_judge.llm_chat_complete")
    def test_full_cycle_promotes_to_active(self, mock_llm: mock.Mock) -> None:
        """Two negative feedbacks promote a hypothesis to active, next prompt includes it."""
        alert_id_1 = ac.generate_alert_id()
        ac.save_alert_context(
            alert_id=alert_id_1,
            scenario="heap_pressure",
            issues=[{"severity": "warning", "node": "es-1", "note": "heap 92%"}],
            recommendations=["Reduce heap"],
            llm_analysis={"what_it_means": "High heap pressure"},
            card_title="ES Alert: Heap",
        )

        mock_llm.return_value = json.dumps({
            "action": "add_hypothesis",
            "rule_id": None,
            "rule_text": "Heap above 90% during indexing bursts is acceptable",
            "reasoning": "Operator says this is expected during bulk loads",
            "confidence": 0.85,
        })
        result1 = fj.process_feedback(
            alert_context=ac.load_alert_context(alert_id_1),
            feedback_type="not_helpful",
            alert_id=alert_id_1,
        )
        self.assertIn("pending hypothesis", result1)

        mem_after_1 = sm.read_system_memory()
        self.assertEqual(len(mem_after_1.pending_hypotheses), 1)
        self.assertEqual(len(mem_after_1.active_rules), 0)
        new_hyp_id = mem_after_1.pending_hypotheses[0].rule_id

        alert_id_2 = ac.generate_alert_id()
        ac.save_alert_context(
            alert_id=alert_id_2,
            scenario="heap_pressure",
            issues=[{"severity": "warning", "node": "es-2", "note": "heap 91%"}],
            recommendations=["Reduce heap"],
            llm_analysis={"what_it_means": "Heap pressure on es-2"},
            card_title="ES Alert: Heap",
        )

        mock_llm.return_value = json.dumps({
            "action": "confirm_existing",
            "rule_id": new_hyp_id,
            "rule_text": None,
            "reasoning": "Same pattern as before",
            "confidence": 0.9,
        })
        result2 = fj.process_feedback(
            alert_context=ac.load_alert_context(alert_id_2),
            feedback_type="not_helpful",
            alert_id=alert_id_2,
        )

        mem_final = sm.read_system_memory()
        self.assertEqual(len(mem_final.active_rules), 1)
        self.assertEqual(len(mem_final.pending_hypotheses), 0)
        self.assertIn("Heap above 90%", mem_final.active_rules[0].text)

        import es_health_monitor as ehm
        prompt = ehm._build_system_prompt_for_health()
        self.assertIn("Heap above 90%", prompt)
        self.assertIn("IMPORTANT - Apply these learned rules", prompt)

    @mock.patch("feedback_judge.llm_chat_complete")
    def test_helpful_feedback_reinforces_pending(self, mock_llm: mock.Mock) -> None:
        """Helpful feedback on alert matching a pending hypothesis bumps confidence."""
        alert_id = ac.generate_alert_id()
        rule = sm.MemoryRule("h1", "Disk alerts during backups are expected", "2026-05-19", 1, [alert_id])
        sm.add_pending_hypothesis(rule)

        ac.save_alert_context(
            alert_id=alert_id,
            scenario="disk_alerts during backups",
            issues=[{"severity": "warning", "node": "es-1", "note": "disk 88%"}],
            recommendations=[],
            llm_analysis=None,
            card_title="Disk Alert",
        )

        result = fj.process_feedback(
            alert_context=ac.load_alert_context(alert_id),
            feedback_type="helpful",
            alert_id=alert_id,
        )

        self.assertIn("reinforced", result.lower())
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 1)
        self.assertEqual(mem.active_rules[0].text, "Disk alerts during backups are expected")

    @mock.patch("feedback_judge.llm_chat_complete")
    def test_incorrect_feedback_rejects_rule(self, mock_llm: mock.Mock) -> None:
        """Incorrect feedback on alert matching an active rule rejects it."""
        rule = sm.MemoryRule("r1", "CPU above 80% is always benign", "2026-05-19", 3, [])
        mem = sm.SystemMemory(active_rules=[rule])
        sm.write_system_memory(mem)

        alert_id = ac.generate_alert_id()
        ac.save_alert_context(
            alert_id=alert_id,
            scenario="cpu_pressure",
            issues=[{"severity": "warning", "node": "es-1", "note": "CPU 85%"}],
            recommendations=[],
            llm_analysis=None,
            card_title="CPU Alert",
        )

        mock_llm.return_value = json.dumps({
            "action": "reject_existing",
            "rule_id": "r1",
            "rule_text": None,
            "reasoning": "Rule contradicted - this CPU pressure was a real issue",
            "confidence": 0.85,
        })
        result = fj.process_feedback(
            alert_context=ac.load_alert_context(alert_id),
            feedback_type="incorrect",
            alert_id=alert_id,
        )

        self.assertIn("Rejected", result)
        mem_final = sm.read_system_memory()
        self.assertEqual(len(mem_final.active_rules), 0)
        self.assertEqual(len(mem_final.rejected_patterns), 1)

    def test_alert_context_ttl_cleanup_doesnt_lose_pending(self) -> None:
        """Verify alert context TTL doesn't lose hypotheses already in memory."""
        rule = sm.MemoryRule("h1", "Test rule", "2026-05-19", 1, ["old_alert_id"])
        sm.add_pending_hypothesis(rule)

        ac.save_alert_context(
            alert_id="old_alert_id",
            scenario="test",
            issues=[],
            recommendations=None,
            llm_analysis=None,
            card_title="Old",
        )
        removed = ac.cleanup_expired_contexts(ttl_hours=0)
        self.assertEqual(removed, 1)

        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 1)
        self.assertEqual(mem.pending_hypotheses[0].text, "Test rule")


if __name__ == "__main__":
    unittest.main(verbosity=2)
