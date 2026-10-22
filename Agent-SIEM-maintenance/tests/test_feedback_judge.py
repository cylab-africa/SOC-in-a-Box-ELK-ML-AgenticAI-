#!/usr/bin/env python3
"""Offline tests for feedback_judge.py.

Run from the Agent-SIEM-maintenance directory:
    python -m pytest tests/test_feedback_judge.py -v
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import feedback_judge as fj
import system_memory as sm


def _sample_alert_context() -> dict:
    return {
        "alert_id": "abc12345",
        "scenario": "heap_pressure",
        "issues": [
            {"severity": "warning", "node": "es-1", "note": "heap at 92%"},
        ],
        "recommendations": ["Reduce heap usage"],
        "llm_analysis": {
            "what_it_means": "High JVM heap pressure on es-1",
            "what_is_at_risk": ["Data loss risk", "Search degradation"],
            "root_cause": "Heavy aggregation queries",
            "recommendations": [{"priority": "P0", "action": "Clear caches"}],
        },
        "card_title": "ES Alert: Heap Pressure",
    }


class TestJudgePromptBuilding(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"
        sm.initialize_system_memory()

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_prompt_includes_alert_context(self) -> None:
        memory = sm.read_system_memory()
        system_msg, user_msg = fj.build_judge_prompt(
            _sample_alert_context(), "not_helpful", None, memory
        )
        self.assertIn("heap_pressure", user_msg)
        self.assertIn("ES Alert: Heap Pressure", user_msg)
        self.assertIn("heap at 92%", user_msg)

    def test_prompt_includes_current_memory(self) -> None:
        rule = sm.MemoryRule("r1", "Existing active rule", "2026-05-18", 2, [])
        mem = sm.SystemMemory(active_rules=[rule])
        sm.write_system_memory(mem)

        memory = sm.read_system_memory()
        _, user_msg = fj.build_judge_prompt(
            _sample_alert_context(), "incorrect", None, memory
        )
        self.assertIn("Existing active rule", user_msg)
        self.assertIn("rule_id=r1", user_msg)

    def test_prompt_includes_feedback_text(self) -> None:
        memory = sm.read_system_memory()
        _, user_msg = fj.build_judge_prompt(
            _sample_alert_context(), "incorrect", "This was a false positive", memory
        )
        self.assertIn("This was a false positive", user_msg)
        self.assertIn("incorrect", user_msg)

    def test_prompt_empty_memory(self) -> None:
        memory = sm.SystemMemory()
        _, user_msg = fj.build_judge_prompt(
            _sample_alert_context(), "not_helpful", None, memory
        )
        self.assertIn("(none)", user_msg)


class TestJudgeVerdictParsing(unittest.TestCase):

    def test_parse_add_hypothesis_verdict(self) -> None:
        raw = json.dumps({
            "action": "add_hypothesis",
            "rule_id": None,
            "rule_text": "Heap alerts below 90% are normal during indexing bursts",
            "reasoning": "Operator feedback suggests threshold too sensitive",
            "confidence": 0.8,
        })
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "add_hypothesis")
        self.assertEqual(verdict.rule_text, "Heap alerts below 90% are normal during indexing bursts")
        self.assertEqual(verdict.confidence, 0.8)

    def test_parse_confirm_existing_verdict(self) -> None:
        raw = json.dumps({
            "action": "confirm_existing",
            "rule_id": "h1",
            "rule_text": None,
            "reasoning": "Matches existing hypothesis about heap thresholds",
            "confidence": 0.9,
        })
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "confirm_existing")
        self.assertEqual(verdict.rule_id, "h1")

    def test_parse_reject_existing_verdict(self) -> None:
        raw = json.dumps({
            "action": "reject_existing",
            "rule_id": "r1",
            "rule_text": None,
            "reasoning": "Rule no longer valid after cluster upgrade",
            "confidence": 0.75,
        })
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "reject_existing")
        self.assertEqual(verdict.rule_id, "r1")

    def test_parse_no_action_verdict(self) -> None:
        raw = json.dumps({
            "action": "no_action",
            "rule_id": None,
            "rule_text": None,
            "reasoning": "One-off event, not a pattern",
            "confidence": 0.3,
        })
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "no_action")

    def test_low_confidence_forces_no_action(self) -> None:
        raw = json.dumps({
            "action": "add_hypothesis",
            "rule_id": None,
            "rule_text": "Some rule",
            "reasoning": "Uncertain",
            "confidence": 0.4,
        })
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "no_action")

    def test_malformed_json_returns_no_action(self) -> None:
        verdict = fj._parse_verdict("this is not json at all")
        self.assertEqual(verdict.action, "no_action")
        self.assertEqual(verdict.confidence, 0.0)

    def test_json_in_code_fence(self) -> None:
        raw = '```json\n{"action": "no_action", "rule_id": null, "rule_text": null, "reasoning": "ok", "confidence": 0.6}\n```'
        verdict = fj._parse_verdict(raw)
        self.assertEqual(verdict.action, "no_action")
        self.assertEqual(verdict.confidence, 0.6)


class TestVerdictApplication(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        self._orig_threshold = sm.PROMOTION_THRESHOLD
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"
        sm.PROMOTION_THRESHOLD = 2
        sm.initialize_system_memory()

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        sm.PROMOTION_THRESHOLD = self._orig_threshold
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_hypothesis_creates_pending_rule(self) -> None:
        verdict = fj.JudgeVerdict(
            action="add_hypothesis",
            rule_id=None,
            rule_text="New pattern: disk alerts during backup windows are expected",
            reasoning="Operator confirmed backup schedule",
            confidence=0.85,
        )
        summary = fj.apply_verdict(verdict, "alert_001")
        self.assertIn("pending hypothesis", summary)

        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 1)
        self.assertIn("disk alerts during backup windows", mem.pending_hypotheses[0].text)

    def test_confirm_increments_count(self) -> None:
        rule = sm.MemoryRule("h1", "Test hypothesis", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)

        verdict = fj.JudgeVerdict("confirm_existing", "h1", None, "Confirmed", 0.9)
        summary = fj.apply_verdict(verdict, "a2")
        self.assertIn("Confirmed", summary)

    def test_confirm_promotes_at_threshold(self) -> None:
        rule = sm.MemoryRule("h1", "Promote me", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)

        verdict = fj.JudgeVerdict("confirm_existing", "h1", None, "Second confirmation", 0.9)
        fj.apply_verdict(verdict, "a2")

        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 1)
        self.assertEqual(mem.active_rules[0].text, "Promote me")

    def test_reject_moves_to_rejected(self) -> None:
        rule = sm.MemoryRule("r1", "Bad rule", "2026-05-18", 3, [])
        mem = sm.SystemMemory(active_rules=[rule])
        sm.write_system_memory(mem)

        verdict = fj.JudgeVerdict("reject_existing", "r1", None, "No longer valid", 0.8)
        summary = fj.apply_verdict(verdict, "a3")
        self.assertIn("Rejected", summary)

        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 0)
        self.assertEqual(len(mem.rejected_patterns), 1)

    def test_no_action_returns_summary(self) -> None:
        verdict = fj.JudgeVerdict("no_action", None, None, "One-off event", 0.3)
        summary = fj.apply_verdict(verdict, "a4")
        self.assertIn("No action", summary)

    def test_add_hypothesis_missing_text(self) -> None:
        verdict = fj.JudgeVerdict("add_hypothesis", None, None, "No text", 0.8)
        summary = fj.apply_verdict(verdict, "a5")
        self.assertIn("missing rule_text", summary)


class TestDynamicPromptInjection(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_health_monitor_prompt_includes_active_rules(self) -> None:
        mem = sm.SystemMemory(
            active_rules=[sm.MemoryRule("r1", "Always check disk before heap", "2026-05-18", 2, [])],
            rejected_patterns=[sm.MemoryRule("x1", "Never ignore yellow status", "2026-05-18", 1, [])],
        )
        sm.write_system_memory(mem)

        sys.path.insert(0, str(ROOT))
        import es_health_monitor as ehm
        prompt = ehm._build_system_prompt_for_health()
        self.assertIn("Always check disk before heap", prompt)
        self.assertIn("Never ignore yellow status", prompt)
        self.assertIn("IMPORTANT - Apply these learned rules", prompt)
        self.assertIn("Do NOT follow these rejected patterns", prompt)

    def test_auto_remediate_prompt_includes_active_rules(self) -> None:
        mem = sm.SystemMemory(
            active_rules=[sm.MemoryRule("r1", "Prefer cache clear over restart", "2026-05-18", 2, [])],
        )
        sm.write_system_memory(mem)

        sys.path.insert(0, str(ROOT))
        import auto_remediate as ar
        prompt = ar._build_system_prompt_for_remediation()
        self.assertIn("Prefer cache clear over restart", prompt)

    def test_empty_memory_uses_base_prompt_only(self) -> None:
        sm.initialize_system_memory()

        sys.path.insert(0, str(ROOT))
        import es_health_monitor as ehm
        prompt = ehm._build_system_prompt_for_health()
        self.assertIn("expert Elasticsearch", prompt)
        self.assertNotIn("IMPORTANT - Apply these learned rules", prompt)
        self.assertNotIn("Do NOT follow these rejected patterns", prompt)


class TestProcessFeedbackIntegration(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        self._orig_threshold = sm.PROMOTION_THRESHOLD
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"
        sm.PROMOTION_THRESHOLD = 2
        sm.initialize_system_memory()

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        sm.PROMOTION_THRESHOLD = self._orig_threshold
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_helpful_feedback_no_hypothesis(self) -> None:
        result = fj.process_feedback(_sample_alert_context(), "helpful", alert_id="a1")
        self.assertIn("no matching hypothesis", result)

    def test_helpful_feedback_reinforces_hypothesis(self) -> None:
        rule = sm.MemoryRule("h1", "Test hyp", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)
        result = fj.process_feedback(_sample_alert_context(), "helpful", alert_id="a1")
        self.assertIn("reinforced", result)

    @mock.patch("feedback_judge.llm_chat_complete")
    def test_not_helpful_invokes_judge(self, mock_llm: mock.Mock) -> None:
        mock_llm.return_value = json.dumps({
            "action": "add_hypothesis",
            "rule_id": None,
            "rule_text": "Heap 92% is normal for this cluster",
            "reasoning": "Operator says this is expected",
            "confidence": 0.85,
        })
        result = fj.process_feedback(
            _sample_alert_context(), "not_helpful", alert_id="a1"
        )
        self.assertIn("pending hypothesis", result)
        mock_llm.assert_called_once()

    @mock.patch("feedback_judge.llm_chat_complete", return_value=None)
    def test_llm_unavailable_returns_no_action(self, mock_llm: mock.Mock) -> None:
        result = fj.process_feedback(
            _sample_alert_context(), "incorrect", alert_id="a1"
        )
        self.assertIn("No action", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
