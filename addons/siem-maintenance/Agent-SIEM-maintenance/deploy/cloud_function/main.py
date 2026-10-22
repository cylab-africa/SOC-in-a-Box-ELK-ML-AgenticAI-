"""Cloud Function: receive Google Chat feedback button clicks and store to Sheet."""
import json
import os
from datetime import datetime, timezone

import functions_framework
from google.auth import default as _default_creds
from googleapiclient.discovery import build

SHEET_ID = "1uOqnq1HYOocLlqcZdJAJrZUWYIbPHuPasKVp0d4tXgM"


def _append_row(values):
    """Append a row to the feedback Sheet using ambient service account."""
    creds, _ = _default_creds(scopes=["https://www.googleapis.com/auth/spreadsheets"])
    svc = build("sheets", "v4", credentials=creds, cache_discovery=False)
    svc.spreadsheets().values().append(
        spreadsheetId=SHEET_ID,
        range="Sheet1!A1",
        valueInputOption="RAW",
        insertDataOption="INSERT_ROWS",
        body={"values": [values]},
    ).execute()


def _html_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


_FORM_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Custom Instruction</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#202124}}
h2{{color:#1a73e8}} textarea{{width:100%;height:160px;font-size:15px;padding:10px;box-sizing:border-box}}
button{{background:#1a73e8;color:#fff;border:0;padding:12px 24px;font-size:15px;border-radius:6px;cursor:pointer;margin-top:12px}}
.ok{{color:#188038;font-size:18px}} .meta{{color:#5f6368;font-size:13px}}
</style></head><body>
<h2>Custom instruction</h2>
<p class="meta">Alert ID: <b>{alert_id}</b></p>
<form method="POST" action="/custom">
<input type="hidden" name="alert_id" value="{alert_id}">
<textarea name="custom_text" placeholder="e.g. Always escalate heap-pressure alerts to Tier 2 before restarting nodes" required></textarea>
<br><button type="submit">Submit instruction</button>
</form></body></html>"""

_DONE_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Recorded</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:60px auto;text-align:center;color:#202124}}
.ok{{color:#188038;font-size:22px}}</style></head><body>
<p class="ok">Instruction recorded</p>
<p>The agent will apply it on the next cycle. You can close this tab.</p></body></html>"""


@functions_framework.http
def chat_feedback(request):
    """HTTP entry point for Google Chat events and the custom-instruction form."""
    # Browser form for custom instructions (opened from the card's button)
    if request.path.rstrip("/").endswith("/custom") or request.path.rstrip("/") == "/custom":
        if request.method == "GET":
            alert_id = _html_escape(request.args.get("alert_id", "unknown"))
            return (_FORM_PAGE.format(alert_id=alert_id), 200, {"Content-Type": "text/html"})
        if request.method == "POST":
            alert_id = request.form.get("alert_id", "unknown")
            custom_text = request.form.get("custom_text", "")
            ts = datetime.now(timezone.utc).isoformat()
            try:
                _append_row([ts, alert_id, "custom", "web_form", "", "pending", custom_text[:1000]])
            except Exception as exc:
                return (f"Failed to record: {exc}", 500)
            return (_DONE_PAGE, 200, {"Content-Type": "text/html"})

    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}

    event_type = payload.get("type", "")

    if event_type == "ADDED_TO_SPACE":
        return {"text": "SIEM Maintenance Bot ready to receive feedback."}

    if event_type == "REMOVED_FROM_SPACE":
        return ("", 200)

    if event_type == "MESSAGE":
        msg = payload.get("message", {}) or {}
        text = (msg.get("text") or "").strip()
        thread = (msg.get("thread") or {}).get("name", "")
        user = payload.get("user", {}) or {}
        ts = datetime.now(timezone.utc).isoformat()
        try:
            _append_row([ts, thread, "text_reply", user.get("displayName", ""), user.get("email", ""), text[:500]])
        except Exception as exc:
            return {"text": f"Got your reply but failed to record: {exc}"}
        return {"text": "Feedback received. Thank you."}

    if event_type == "CARD_CLICKED":
        action = payload.get("action", {}) or {}
        params = {p["key"]: p["value"] for p in action.get("parameters", []) if "key" in p}
        alert_id = params.get("alert_id", "")
        feedback_type = params.get("feedback_type", "")
        user = payload.get("user", {}) or {}
        ts = datetime.now(timezone.utc).isoformat()

        if not alert_id or not feedback_type:
            return {"text": "Missing alert_id or feedback_type."}

        try:
            _append_row([ts, alert_id, feedback_type, user.get("displayName", ""), user.get("email", ""), "pending"])
        except Exception as exc:
            return {"text": f"Feedback received ({feedback_type}) but failed to record: {exc}"}

        return {
            "text": f"Feedback recorded: {feedback_type} for alert {alert_id}. Thanks!"
        }

    return {"text": ""}
