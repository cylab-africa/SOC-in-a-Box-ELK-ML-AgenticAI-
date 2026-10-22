#!/usr/bin/env python3
"""Flask HTTP endpoint for receiving Google Chat feedback events.

Handles CARD_CLICKED (button feedback) and MESSAGE (thread reply) events
from a registered Google Chat App. Runs as a separate process from the
maintenance scheduler.

Usage:
    python feedback_server.py --host 0.0.0.0 --port 8090
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except Exception:
    pass

from flask import Flask, Request, request, jsonify

from alert_context import (
    cleanup_expired_contexts,
    find_context_by_thread,
    load_alert_context,
)
from feedback_judge import process_feedback

LOG = logging.getLogger("feedback_server")

FEEDBACK_LOG_PATH = Path(__file__).resolve().parent / "results" / "feedback_log.jsonl"


def create_app() -> Flask:
    """Factory function for the Flask app."""
    app = Flask(__name__)

    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    @app.route("/health", methods=["GET"])
    def health_check() -> Tuple[Dict[str, Any], int]:
        """Simple health check endpoint."""
        return {"status": "ok", "service": "siem-feedback"}, 200

    @app.route("/feedback/submit", methods=["GET"])
    def handle_link_feedback() -> Tuple[Dict[str, Any], int]:
        """Handle feedback via browser link (opened from card button).

        Query params: alert_id, feedback_type
        """
        alert_id = request.args.get("alert_id", "")
        feedback_type = request.args.get("feedback_type", "")

        if not alert_id or not feedback_type:
            return {"text": "Missing alert_id or feedback_type."}, 400

        timestamp = datetime.now(timezone.utc).isoformat()
        result = process_card_feedback(alert_id, feedback_type, "link_user", "", timestamp)
        msg = result.get("message", "Feedback received.")
        return f"<html><body><h2>Feedback Recorded</h2><p>{msg}</p><p>You can close this tab.</p></body></html>", 200, {"Content-Type": "text/html"}

    @app.route("/google-chat/feedback", methods=["POST"])
    def handle_google_chat_event() -> Tuple[Dict[str, Any], int]:
        """Handle incoming Google Chat App events.

        Supports event types:
        - CARD_CLICKED: Button feedback (Helpful/Not Helpful/Incorrect)
        - MESSAGE: Thread reply with free-text feedback
        - ADDED_TO_SPACE / REMOVED_FROM_SPACE: Acknowledged only
        """
        try:
            payload = request.get_json(force=True)
        except Exception:
            return {"error": "Invalid JSON"}, 400

        event_type = payload.get("type", "")
        LOG.info("Received Google Chat event: type=%s payload_keys=%s", event_type, list(payload.keys()))

        if not _verify_request(request, payload):
            LOG.warning("Token verification failed for event type=%s", event_type)
            return {"error": "Unauthorized"}, 401

        if event_type == "CARD_CLICKED":
            return _handle_card_clicked(payload)
        elif event_type == "MESSAGE":
            return _handle_message(payload)
        elif event_type in ("ADDED_TO_SPACE", "REMOVED_FROM_SPACE"):
            return {"text": "SIEM Maintenance feedback receiver acknowledged."}, 200
        else:
            LOG.debug("Unhandled event type: %s", event_type)
            return {"text": ""}, 200

    return app


def _handle_card_clicked(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Process a CARD_CLICKED event from Google Chat."""
    action = payload.get("action", {})
    action_method = action.get("actionMethodName", "")

    if action_method != "feedback_response":
        LOG.debug("Unknown action method: %s", action_method)
        return {"text": ""}, 200

    params = {p["key"]: p["value"] for p in action.get("parameters", [])}
    alert_id = params.get("alert_id", "")
    feedback_type = params.get("feedback_type", "")

    if not alert_id or not feedback_type:
        return {"text": "Missing alert_id or feedback_type in action parameters."}, 200

    user_info = payload.get("user", {})
    user_name = user_info.get("displayName", "unknown")
    user_email = user_info.get("email", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()

    result = process_card_feedback(alert_id, feedback_type, user_name, user_email, timestamp)
    msg = result.get("message", "Feedback received.")
    return {
        "actionResponse": {"type": "NEW_MESSAGE"},
        "text": msg,
    }, 200


def _handle_message(payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Process a MESSAGE event (thread reply) from Google Chat."""
    message = payload.get("message", {})
    text = message.get("text", "").strip()
    thread_name = message.get("thread", {}).get("name", "")

    if not text or not thread_name:
        return {"text": ""}, 200

    user_info = payload.get("user", {})
    user_name = user_info.get("displayName", "unknown")
    user_email = user_info.get("email", "unknown")
    timestamp = datetime.now(timezone.utc).isoformat()

    result = process_text_feedback(thread_name, text, user_name, user_email, timestamp)
    return {"text": result.get("message", "Feedback received.")}, 200


def process_card_feedback(
    alert_id: str,
    feedback_type: str,
    user_name: str,
    user_email: str,
    timestamp: str,
) -> Dict[str, Any]:
    """Process structured card button feedback.

    Args:
        alert_id: The alert identifier from the card button parameters.
        feedback_type: One of 'helpful', 'not_helpful', 'incorrect'.
        user_name: Display name of the user who clicked.
        user_email: Email of the user who clicked.
        timestamp: ISO timestamp of the event.

    Returns:
        Dict with 'message' key containing acknowledgment text.
    """
    log_feedback_event({
        "type": "card_feedback",
        "alert_id": alert_id,
        "feedback_type": feedback_type,
        "user_name": user_name,
        "user_email": user_email,
        "timestamp": timestamp,
    })

    alert_context = load_alert_context(alert_id)
    if alert_context is None:
        LOG.warning("Alert context not found or expired: alert_id=%s", alert_id)
        return {"message": f"Thanks for your feedback ({feedback_type}). Alert context has expired; feedback logged but cannot refine rules."}

    summary = process_feedback(
        alert_context=alert_context,
        feedback_type=feedback_type,
        alert_id=alert_id,
    )

    return {"message": f"Feedback recorded ({feedback_type}). {summary}"}


def process_text_feedback(
    thread_name: str,
    text: str,
    user_name: str,
    user_email: str,
    timestamp: str,
) -> Dict[str, Any]:
    """Process free-text thread reply feedback.

    Args:
        thread_name: The Google Chat thread name for correlation.
        text: The free-text reply content.
        user_name: Display name of the replying user.
        user_email: Email of the replying user.
        timestamp: ISO timestamp of the event.

    Returns:
        Dict with 'message' key containing acknowledgment text.
    """
    alert_context = find_context_by_thread(thread_name)
    alert_id = alert_context.get("alert_id", "") if alert_context else ""

    log_feedback_event({
        "type": "text_feedback",
        "alert_id": alert_id,
        "thread_name": thread_name,
        "text": text,
        "user_name": user_name,
        "user_email": user_email,
        "timestamp": timestamp,
    })

    if alert_context is None:
        LOG.warning("No alert context found for thread: %s", thread_name)
        return {"message": "Thanks for your feedback. Could not correlate to a specific alert; feedback logged."}

    summary = process_feedback(
        alert_context=alert_context,
        feedback_type="not_helpful",
        feedback_text=text,
        alert_id=alert_id,
    )

    return {"message": f"Thread feedback processed. {summary}"}


def _verify_request(request_obj: Request, payload: Dict[str, Any]) -> bool:
    """Verify a Google Chat request using token from body or header.

    Google Chat HTTP endpoints receive the verification token in the
    JSON body ``token`` field. We also accept it in the Authorization
    header for backward compatibility and manual testing.
    """
    expected = os.getenv("GOOGLE_CHAT_VERIFICATION_TOKEN", "")
    if not expected:
        return True

    if payload.get("token") == expected:
        return True

    auth_header = request_obj.headers.get("Authorization", "")
    if auth_header.startswith("Bearer ") and auth_header[7:] == expected:
        return True

    LOG.debug("Token mismatch: body_token=%s header=%s", payload.get("token", "(none)"), auth_header[:20])
    return False


def verify_google_chat_token(request_obj: Request) -> bool:
    """Verify incoming Google Chat request.

    Google Chat sends the verification token in EITHER:
    1. The Authorization header as ``Bearer <token>``
    2. The ``token`` field in the JSON body

    If GOOGLE_CHAT_VERIFICATION_TOKEN is not set, verification is skipped
    (dev mode).

    Args:
        request_obj: The Flask request object.

    Returns:
        True if verified or if verification is disabled.
    """
    expected_token = os.getenv("GOOGLE_CHAT_VERIFICATION_TOKEN", "")
    if not expected_token:
        return True

    auth_header = request_obj.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token == expected_token:
            return True

    try:
        body = request_obj.get_json(silent=True) or {}
        if body.get("token") == expected_token:
            return True
    except Exception:
        pass

    return False


def log_feedback_event(event: Dict[str, Any]) -> None:
    """Append a structured feedback event to the feedback log (JSONL format).

    Args:
        event: The feedback event dict to log.
    """
    FEEDBACK_LOG_PATH.parent.mkdir(exist_ok=True)
    try:
        with open(FEEDBACK_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")
    except OSError as e:
        LOG.warning("Failed to write feedback log: %s", e)


def main() -> None:
    """CLI entrypoint: parse args and start Flask."""
    parser = argparse.ArgumentParser(description="SIEM feedback server (Google Chat events)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=int(os.getenv("FEEDBACK_SERVER_PORT", "8090")),
                        help="Port (default: 8090)")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    cleanup_expired_contexts()

    app = create_app()
    LOG.info("Starting feedback server on %s:%d", args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
