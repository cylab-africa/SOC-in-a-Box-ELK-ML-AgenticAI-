#!/usr/bin/env python3
"""Poll a Google Sheet for pending feedback and process it through the judge.

The Apps Script relay writes feedback rows to the Sheet. This poller reads
pending rows, runs the feedback judge, and marks them as processed.

Usage:
    python feedback_poller.py              # one-shot poll
    python feedback_poller.py --loop 60    # poll every 60 seconds
"""
from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path
from typing import List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except Exception:
    pass

from google.oauth2 import service_account
from googleapiclient.discovery import build

from alert_context import load_alert_context
from feedback_judge import process_feedback

LOG = logging.getLogger("feedback_poller")

SHEET_ID = os.getenv(
    "FEEDBACK_SHEET_ID",
    "1uOqnq1HYOocLlqcZdJAJrZUWYIbPHuPasKVp0d4tXgM",
)
SA_KEY_PATH = os.getenv(
    "GOOGLE_CHAT_SA_KEY",
    str(Path(__file__).resolve().parent / "siem-chat-bot-key.json"),
)
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]


def _get_sheets_service():
    """Build a Google Sheets API service."""
    creds = service_account.Credentials.from_service_account_file(
        SA_KEY_PATH, scopes=SCOPES,
    )
    return build("sheets", "v4", credentials=creds)


def poll_and_process() -> int:
    """Read pending rows from the Sheet, process them, mark as done.

    Returns the number of rows processed.
    """
    svc = _get_sheets_service()
    sheet = svc.spreadsheets()

    result = sheet.values().get(
        spreadsheetId=SHEET_ID,
        range="Sheet1!A:H",
    ).execute()
    rows = result.get("values", [])

    processed = 0
    for i, row in enumerate(rows):
        if len(row) < 6:
            continue
        timestamp, alert_id, feedback_type, user_name, user_email, status = row[:6]
        # Column G holds free-text for custom instructions (column H is the poller summary)
        custom_text = row[6] if len(row) > 6 else ""
        if status != "pending":
            continue

        LOG.info("Processing row %d: alert_id=%s feedback=%s user=%s",
                 i + 1, alert_id, feedback_type, user_name)

        alert_context = load_alert_context(alert_id)
        if alert_context is None:
            LOG.warning("No alert context for %s — logging only", alert_id)
            summary = "Alert context expired; feedback logged"
        elif feedback_type == "custom":
            # A custom instruction is operator guidance: route through the judge
            # as not_helpful with the text so it becomes a hypothesis/rule.
            summary = process_feedback(
                alert_context=alert_context,
                feedback_type="not_helpful",
                feedback_text=custom_text,
                alert_id=alert_id,
            )
        else:
            summary = process_feedback(
                alert_context=alert_context,
                feedback_type=feedback_type,
                alert_id=alert_id,
            )

        status_value = "processed" if "No action" not in summary else "no_action"
        if "Error" in summary or "expired" in summary.lower():
            status_value = "error"

        sheet.values().update(
            spreadsheetId=SHEET_ID,
            range=f"Sheet1!F{i + 1}",
            valueInputOption="RAW",
            body={"values": [[status_value]]},
        ).execute()

        # Write the judge summary to column H (column G is reserved for custom text)
        sheet.values().update(
            spreadsheetId=SHEET_ID,
            range=f"Sheet1!H{i + 1}",
            valueInputOption="RAW",
            body={"values": [[summary[:200]]]},
        ).execute()

        LOG.info("Row %d processed: %s", i + 1, summary[:100])
        processed += 1

    return processed


def main() -> None:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(description="Poll Google Sheet for feedback")
    parser.add_argument("--loop", type=int, default=0,
                        help="Poll interval in seconds (0 = one-shot)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if args.loop > 0:
        LOG.info("Polling every %ds from sheet %s", args.loop, SHEET_ID)
        while True:
            try:
                n = poll_and_process()
                if n:
                    LOG.info("Processed %d feedback rows", n)
            except Exception as exc:
                LOG.error("Poll error: %s", exc)
            time.sleep(args.loop)
    else:
        n = poll_and_process()
        LOG.info("Processed %d feedback rows", n)


if __name__ == "__main__":
    main()
