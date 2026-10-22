#!/usr/bin/env python3
"""Offline tests for system_memory.py.

Run from the Agent-SIEM-maintenance directory:
    python -m pytest tests/test_system_memory.py -v
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import system_memory as sm


class TestSystemMemoryParsing(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_missing_file_returns_empty_memory(self) -> None:
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 0)
        self.assertEqual(len(mem.pending_hypotheses), 0)
        self.assertEqual(len(mem.rejected_patterns), 0)

    def test_parse_empty_sections(self) -> None:
        sm.initialize_system_memory()
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 0)
        self.assertEqual(len(mem.pending_hypotheses), 0)
        self.assertEqual(len(mem.rejected_patterns), 0)

    def test_parse_populated_file(self) -> None:
        content = """# SYSTEM MEMORY

## Active Rules & Guidelines
<!-- comment -->
- [2026-05-18] rule_id=r1 | Prioritize disk over shards when heap >85%. (confirmed: 3, source: a1, a2, a3)

## Pending Hypotheses/Refinements
<!-- comment -->
- [2026-05-18] hypothesis_id=h1 | Weekend maintenance windows are normal. (feedback_count: 1, source: a4)

## Rejected Patterns
<!-- comment -->
- [2026-05-18] REJECTED: Always escalate yellow to P0.
"""
        sm.SYSTEM_MEMORY_PATH.write_text(content, encoding="utf-8")
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 1)
        self.assertEqual(mem.active_rules[0].rule_id, "r1")
        self.assertEqual(mem.active_rules[0].feedback_count, 3)
        self.assertIn("a1", mem.active_rules[0].source_alert_ids)

        self.assertEqual(len(mem.pending_hypotheses), 1)
        self.assertEqual(mem.pending_hypotheses[0].rule_id, "h1")
        self.assertEqual(mem.pending_hypotheses[0].feedback_count, 1)

        self.assertEqual(len(mem.rejected_patterns), 1)
        self.assertIn("Always escalate yellow to P0", mem.rejected_patterns[0].text)

    def test_roundtrip_write_read(self) -> None:
        mem = sm.SystemMemory(
            active_rules=[sm.MemoryRule("r1", "Test active rule", "2026-05-18", 2, ["a1"])],
            pending_hypotheses=[sm.MemoryRule("h1", "Test hypothesis", "2026-05-18", 1, ["a2"])],
            rejected_patterns=[sm.MemoryRule("x1", "Test rejected", "2026-05-18", 1, [])],
        )
        sm.write_system_memory(mem)
        loaded = sm.read_system_memory()

        self.assertEqual(len(loaded.active_rules), 1)
        self.assertEqual(loaded.active_rules[0].rule_id, "r1")
        self.assertEqual(loaded.active_rules[0].text, "Test active rule")
        self.assertEqual(loaded.active_rules[0].feedback_count, 2)

        self.assertEqual(len(loaded.pending_hypotheses), 1)
        self.assertEqual(loaded.pending_hypotheses[0].rule_id, "h1")

        self.assertEqual(len(loaded.rejected_patterns), 1)
        self.assertIn("Test rejected", loaded.rejected_patterns[0].text)


class TestSystemMemoryOperations(unittest.TestCase):

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
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_add_pending_hypothesis(self) -> None:
        rule = sm.MemoryRule("h1", "New hypothesis text", "2026-05-18", 1, ["alert1"])
        sm.add_pending_hypothesis(rule)
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 1)
        self.assertEqual(mem.pending_hypotheses[0].rule_id, "h1")
        self.assertEqual(mem.pending_hypotheses[0].text, "New hypothesis text")

    def test_promote_hypothesis_to_active(self) -> None:
        rule = sm.MemoryRule("h1", "Promote me", "2026-05-18", 2, ["a1"])
        sm.add_pending_hypothesis(rule)
        result = sm.promote_hypothesis("h1")
        self.assertTrue(result)
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 0)
        self.assertEqual(len(mem.active_rules), 1)
        self.assertEqual(mem.active_rules[0].text, "Promote me")

    def test_promote_nonexistent_returns_false(self) -> None:
        result = sm.promote_hypothesis("nonexistent")
        self.assertFalse(result)

    def test_reject_hypothesis(self) -> None:
        rule = sm.MemoryRule("h1", "Reject me", "2026-05-18", 1, [])
        sm.add_pending_hypothesis(rule)
        result = sm.reject_hypothesis("h1", "contradicted by operator feedback")
        self.assertTrue(result)
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 0)
        self.assertEqual(len(mem.rejected_patterns), 1)
        self.assertIn("contradicted by operator feedback", mem.rejected_patterns[0].text)

    def test_reject_active_rule(self) -> None:
        rule = sm.MemoryRule("r1", "Active rule to reject", "2026-05-18", 3, [])
        mem = sm.read_system_memory()
        mem.active_rules.append(rule)
        sm.write_system_memory(mem)

        result = sm.reject_hypothesis("r1", "no longer valid")
        self.assertTrue(result)
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.active_rules), 0)
        self.assertEqual(len(mem.rejected_patterns), 1)

    def test_reject_nonexistent_returns_false(self) -> None:
        result = sm.reject_hypothesis("nonexistent", "reason")
        self.assertFalse(result)

    def test_increment_confirmation_count(self) -> None:
        rule = sm.MemoryRule("h1", "Count me", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)
        new_count = sm.increment_hypothesis_confirmation("h1", "a2")
        self.assertEqual(new_count, 2)

    def test_increment_nonexistent_returns_zero(self) -> None:
        count = sm.increment_hypothesis_confirmation("nonexistent", "a1")
        self.assertEqual(count, 0)

    def test_auto_promotion_at_threshold(self) -> None:
        rule = sm.MemoryRule("h1", "Auto promote me", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)
        sm.increment_hypothesis_confirmation("h1", "a2")
        mem = sm.read_system_memory()
        self.assertEqual(len(mem.pending_hypotheses), 0)
        self.assertEqual(len(mem.active_rules), 1)
        self.assertEqual(mem.active_rules[0].text, "Auto promote me")

    def test_duplicate_alert_id_not_added_to_sources(self) -> None:
        rule = sm.MemoryRule("h1", "Dedup sources", "2026-05-18", 1, ["a1"])
        sm.add_pending_hypothesis(rule)
        sm.increment_hypothesis_confirmation("h1", "a1")
        mem = sm.read_system_memory()
        if mem.active_rules:
            self.assertEqual(len(mem.active_rules[0].source_alert_ids), 1)


class TestSystemMemoryTextOutput(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_path = sm.SYSTEM_MEMORY_PATH
        sm.SYSTEM_MEMORY_PATH = Path(self._tmpdir) / "SYSTEM_MEMORY.md"
        sm.initialize_system_memory()

    def tearDown(self) -> None:
        sm.SYSTEM_MEMORY_PATH = self._orig_path
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_get_active_rules_text_empty(self) -> None:
        text = sm.get_active_rules_text()
        self.assertEqual(text, "")

    def test_get_active_rules_text_populated(self) -> None:
        mem = sm.SystemMemory(
            active_rules=[
                sm.MemoryRule("r1", "First rule", "2026-05-18", 2, []),
                sm.MemoryRule("r2", "Second rule", "2026-05-18", 3, []),
            ]
        )
        sm.write_system_memory(mem)
        text = sm.get_active_rules_text()
        self.assertIn("First rule", text)
        self.assertIn("Second rule", text)
        self.assertTrue(text.startswith("- "))

    def test_get_rejected_patterns_text_empty(self) -> None:
        text = sm.get_rejected_patterns_text()
        self.assertEqual(text, "")

    def test_get_rejected_patterns_text_populated(self) -> None:
        mem = sm.SystemMemory(
            rejected_patterns=[
                sm.MemoryRule("x1", "Bad pattern", "2026-05-18", 1, []),
            ]
        )
        sm.write_system_memory(mem)
        text = sm.get_rejected_patterns_text()
        self.assertIn("Bad pattern", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
