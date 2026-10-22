#!/usr/bin/env python3
"""Offline tests for feedback_server.py.

Run from the Agent-SIEM-maintenance directory:
    python -m pytest tests/test_feedback_server.py -v
"""
from __future__ import annotations

import json
import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

import alert_context as ac
import feedback_server as fs


class TestFeedbackEndpoint(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_ctx_path = ac.ALERT_CONTEXT_PATH
        self._orig_results_dir = ac.RESULTS_DIR
        self._orig_log_path = fs.FEEDBACK_LOG_PATH
        self._orig_token = os.environ.pop("GOOGLE_CHAT_VERIFICATION_TOKEN", None)
        ac.RESULTS_DIR = Path(self._tmpdir)
        ac.ALERT_CONTEXT_PATH = Path(self._tmpdir) / "feedback_alert_context.json"
        fs.FEEDBACK_LOG_PATH = Path(self._tmpdir) / "feedback_log.jsonl"

        self.app = fs.create_app()
        self.client = self.app.test_client()

        ac.save_alert_context(
            alert_id="test1234",
            scenario="heap_pressure",
            issues=[{"severity": "warning", "node": "es-1", "note": "heap 92%"}],
            recommendations=["Reduce heap usage"],
            llm_analysis={"what_it_means": "High heap pressure"},
            card_title="ES Alert: Heap Pressure",
        )

    def tearDown(self) -> None:
        ac.ALERT_CONTEXT_PATH = self._orig_ctx_path
        ac.RESULTS_DIR = self._orig_results_dir
        fs.FEEDBACK_LOG_PATH = self._orig_log_path
        if self._orig_token is not None:
            os.environ["GOOGLE_CHAT_VERIFICATION_TOKEN"] = self._orig_token
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_health_check(self) -> None:
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "ok")

    def test_card_clicked_helpful(self) -> None:
        payload = {
            "type": "CARD_CLICKED",
            "action": {
                "actionMethodName": "feedback_response",
                "parameters": [
                    {"key": "alert_id", "value": "test1234"},
                    {"key": "feedback_type", "value": "helpful"},
                ],
            },
            "user": {"displayName": "TestUser", "email": "test@example.com"},
        }
        with mock.patch("feedback_server.process_feedback", return_value="Positive feedback recorded"):
            resp = self.client.post(
                "/google-chat/feedback",
                data=json.dumps(payload),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("Feedback recorded", data["text"])

    @mock.patch("feedback_server.process_feedback", return_value="Added pending hypothesis")
    def test_card_clicked_not_helpful_triggers_judge(self, mock_pf: mock.Mock) -> None:
        payload = {
            "type": "CARD_CLICKED",
            "action": {
                "actionMethodName": "feedback_response",
                "parameters": [
                    {"key": "alert_id", "value": "test1234"},
                    {"key": "feedback_type", "value": "not_helpful"},
                ],
            },
            "user": {"displayName": "TestUser", "email": "test@example.com"},
        }
        resp = self.client.post(
            "/google-chat/feedback",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        mock_pf.assert_called_once()
        call_kwargs = mock_pf.call_args
        self.assertEqual(call_kwargs[1]["feedback_type"], "not_helpful")

    @mock.patch("feedback_server.process_feedback", return_value="Added pending hypothesis")
    def test_card_clicked_incorrect_triggers_judge(self, mock_pf: mock.Mock) -> None:
        payload = {
            "type": "CARD_CLICKED",
            "action": {
                "actionMethodName": "feedback_response",
                "parameters": [
                    {"key": "alert_id", "value": "test1234"},
                    {"key": "feedback_type", "value": "incorrect"},
                ],
            },
            "user": {"displayName": "TestUser", "email": "test@example.com"},
        }
        resp = self.client.post(
            "/google-chat/feedback",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        mock_pf.assert_called_once()

    def test_message_reply_in_thread(self) -> None:
        ac.save_alert_context(
            alert_id="thread01",
            scenario="disk_pressure",
            issues=[],
            recommendations=None,
            llm_analysis=None,
            card_title="Disk Alert",
            thread_name="spaces/ABC/threads/123",
        )

        payload = {
            "type": "MESSAGE",
            "message": {
                "text": "This was a false positive due to backup job",
                "thread": {"name": "spaces/ABC/threads/123"},
            },
            "user": {"displayName": "Operator", "email": "op@example.com"},
        }
        with mock.patch("feedback_server.process_feedback", return_value="Hypothesis added"):
            resp = self.client.post(
                "/google-chat/feedback",
                data=json.dumps(payload),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)

    def test_unknown_event_type_returns_200(self) -> None:
        payload = {"type": "ADDED_TO_SPACE"}
        resp = self.client.post(
            "/google-chat/feedback",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)

    def test_missing_alert_id_returns_message(self) -> None:
        payload = {
            "type": "CARD_CLICKED",
            "action": {
                "actionMethodName": "feedback_response",
                "parameters": [{"key": "feedback_type", "value": "helpful"}],
            },
            "user": {},
        }
        resp = self.client.post(
            "/google-chat/feedback",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Missing", resp.get_json()["text"])

    def test_expired_context_returns_graceful_message(self) -> None:
        payload = {
            "type": "CARD_CLICKED",
            "action": {
                "actionMethodName": "feedback_response",
                "parameters": [
                    {"key": "alert_id", "value": "nonexistent"},
                    {"key": "feedback_type", "value": "helpful"},
                ],
            },
            "user": {"displayName": "TestUser", "email": "test@example.com"},
        }
        with mock.patch("feedback_server.process_feedback", return_value="recorded"):
            resp = self.client.post(
                "/google-chat/feedback",
                data=json.dumps(payload),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("expired", resp.get_json()["text"])

    def test_verification_token_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"GOOGLE_CHAT_VERIFICATION_TOKEN": "secret123"}):
            app = fs.create_app()
            client = app.test_client()
            payload = {"type": "MESSAGE", "message": {"text": "hi", "thread": {"name": "t"}}}
            resp = client.post(
                "/google-chat/feedback",
                data=json.dumps(payload),
                content_type="application/json",
                headers={"Authorization": "Bearer wrong_token"},
            )
        self.assertEqual(resp.status_code, 401)

    def test_verification_token_accepted(self) -> None:
        with mock.patch.dict(os.environ, {"GOOGLE_CHAT_VERIFICATION_TOKEN": "secret123"}):
            app = fs.create_app()
            client = app.test_client()
            payload = {"type": "ADDED_TO_SPACE"}
            resp = client.post(
                "/google-chat/feedback",
                data=json.dumps(payload),
                content_type="application/json",
                headers={"Authorization": "Bearer secret123"},
            )
        self.assertEqual(resp.status_code, 200)


class TestAlertContextOperations(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_ctx_path = ac.ALERT_CONTEXT_PATH
        self._orig_results_dir = ac.RESULTS_DIR
        ac.RESULTS_DIR = Path(self._tmpdir)
        ac.ALERT_CONTEXT_PATH = Path(self._tmpdir) / "feedback_alert_context.json"

    def tearDown(self) -> None:
        ac.ALERT_CONTEXT_PATH = self._orig_ctx_path
        ac.RESULTS_DIR = self._orig_results_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_save_and_load(self) -> None:
        ac.save_alert_context("abc12345", "test_scenario", [{"issue": 1}], None, None, "Test Title")
        ctx = ac.load_alert_context("abc12345")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["scenario"], "test_scenario")
        self.assertEqual(ctx["card_title"], "Test Title")

    def test_load_nonexistent_returns_none(self) -> None:
        ctx = ac.load_alert_context("nonexistent")
        self.assertIsNone(ctx)

    def test_ttl_cleanup(self) -> None:
        ac.save_alert_context("old_alert", "old", [], None, None, "Old")
        removed = ac.cleanup_expired_contexts(ttl_hours=0)
        self.assertEqual(removed, 1)
        ctx = ac.load_alert_context("old_alert")
        self.assertIsNone(ctx)

    def test_find_by_thread(self) -> None:
        ac.save_alert_context("t1", "scenario", [], None, None, "Title", thread_name="spaces/X/threads/1")
        ctx = ac.find_context_by_thread("spaces/X/threads/1")
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx["alert_id"], "t1")

    def test_find_by_thread_nonexistent(self) -> None:
        ctx = ac.find_context_by_thread("spaces/X/threads/999")
        self.assertIsNone(ctx)

    def test_generate_alert_id_format(self) -> None:
        aid = ac.generate_alert_id()
        self.assertEqual(len(aid), 8)
        int(aid, 16)


class TestFeedbackLogging(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.mkdtemp()
        self._orig_log_path = fs.FEEDBACK_LOG_PATH
        fs.FEEDBACK_LOG_PATH = Path(self._tmpdir) / "feedback_log.jsonl"

    def tearDown(self) -> None:
        fs.FEEDBACK_LOG_PATH = self._orig_log_path
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_feedback_logged_to_jsonl(self) -> None:
        fs.log_feedback_event({"type": "test", "alert_id": "a1"})
        fs.log_feedback_event({"type": "test", "alert_id": "a2"})

        lines = fs.FEEDBACK_LOG_PATH.read_text().strip().split("\n")
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["alert_id"], "a1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
