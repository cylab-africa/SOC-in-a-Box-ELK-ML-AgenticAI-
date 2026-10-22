"""
Creates a Kibana dashboard with an alert table wired to the triage agent.

The dashboard lists open Elastic Security alerts; clicking an Alert ID cell
offers an "Investigate with Agent" drilldown that opens the agent's
deep-link page (/investigate/<alert_id>) in a new tab and auto-runs the
full investigation.

Reads connection details from environment variables (or your .env file).
Run from the project root:
    python deploy/create_investigate_dashboard.py
"""

import base64
import json
import os
import ssl
import sys
import urllib.request
import urllib.error
from pathlib import Path

# Load .env if present
_env = Path(__file__).parent.parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

KIBANA_URL  = os.environ.get("KIBANA_URL") or os.environ.get("ELASTIC_URL", "").replace(":9200", ":5601").replace(":9243", ":5601")
TRIAGE_URL  = (os.environ.get("PUBLIC_URL") or f"http://{KIBANA_URL.split('//')[1].split(':')[0]}:8000").rstrip("/")
USERNAME    = os.environ.get("ELASTIC_USERNAME", "")
PASSWORD    = os.environ.get("ELASTIC_PASSWORD", "")
ALERT_INDEX = os.environ.get("ELASTIC_INDEX", ".alerts-security.alerts-default")

if not KIBANA_URL or not USERNAME or not PASSWORD:
    sys.exit(
        "ERROR: Set KIBANA_URL (or ELASTIC_URL), ELASTIC_USERNAME, and "
        "ELASTIC_PASSWORD in your .env file before running this script."
    )

_token  = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
HEADERS = {"Authorization": f"Basic {_token}", "kbn-xsrf": "true", "Content-Type": "application/json"}
_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode    = ssl.CERT_NONE


def _req(method, path, body=None):
    url  = KIBANA_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req, context=_SSL) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}


# ── Saved object IDs ─────────────────────────────────────────────────────────

DATAVIEW_ID = "ata-alerts-dataview"
VIS_ID      = "viz-ata-investigate-table"
DASH_ID     = "dashboard-ata-investigate"

DRILLDOWN_URL = f"{TRIAGE_URL}/investigate/{{{{event.value}}}}"

# ── Data view for the alerts index ───────────────────────────────────────────

DATAVIEW_BODY = {
    "data_view": {
        "id": DATAVIEW_ID,
        "title": ALERT_INDEX,
        "name": "Security Alerts (Triage Agent)",
        "timeFieldName": "@timestamp",
        "allowNoIndex": True,
    },
    "override": False,
}

# ── Classic aggregation table of open alerts ────────────────────────────────

VIS_STATE = {
    "title": "Open Security Alerts — click Alert ID to investigate",
    "type": "table",
    "aggs": [
        {"id": "1", "enabled": True, "type": "count",
         "params": {"customLabel": "Docs"}, "schema": "metric"},
        {"id": "2", "enabled": True, "type": "terms",
         "params": {"field": "kibana.alert.uuid", "orderBy": "1", "order": "desc",
                    "size": 100, "otherBucket": False, "missingBucket": False,
                    "customLabel": "Alert ID (click → Investigate with Agent)"},
         "schema": "bucket"},
        {"id": "3", "enabled": True, "type": "terms",
         "params": {"field": "kibana.alert.rule.name", "orderBy": "1", "order": "desc",
                    "size": 100, "otherBucket": False, "missingBucket": False,
                    "customLabel": "Rule"},
         "schema": "bucket"},
        {"id": "4", "enabled": True, "type": "terms",
         "params": {"field": "kibana.alert.severity", "orderBy": "1", "order": "desc",
                    "size": 10, "otherBucket": False, "missingBucket": False,
                    "customLabel": "Severity"},
         "schema": "bucket"},
        {"id": "5", "enabled": True, "type": "terms",
         "params": {"field": "host.name", "orderBy": "1", "order": "desc",
                    "size": 100, "otherBucket": False, "missingBucket": True,
                    "customLabel": "Host"},
         "schema": "bucket"},
    ],
    "params": {
        "perPage": 25, "showPartialRows": False, "showMetricsAtAllLevels": False,
        "showTotal": False, "totalFunc": "sum", "percentageCol": "",
    },
}

VIS_ATTRS = {
    "title": "Open Security Alerts — Investigate with Agent",
    "visState": json.dumps(VIS_STATE),
    "uiStateJSON": "{}",
    "description": "Open alerts; the Alert ID column drills down to the triage agent.",
    "kibanaSavedObjectMeta": {
        "searchSourceJSON": json.dumps({
            "query": {"language": "kuery",
                      "query": 'kibana.alert.workflow_status : "open"'},
            "filter": [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        })
    },
}

VIS_REFS = [{
    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
    "type": "index-pattern",
    "id": DATAVIEW_ID,
}]

# ── Dashboard with the URL drilldown attached to the panel ──────────────────

PANEL_CONFIG = {
    "enhancements": {
        "dynamicActions": {
            "events": [{
                "eventId": "ata-investigate-drilldown",
                "triggers": ["VALUE_CLICK_TRIGGER"],
                "action": {
                    "factoryId": "URL_DRILLDOWN",
                    "name": "Investigate with Agent",
                    "config": {
                        "url": {"template": DRILLDOWN_URL},
                        "openInNewTab": True,
                        "encodeUrl": True,
                    },
                },
            }]
        }
    }
}

DASH_ATTRS = {
    "title": "Security Alerts — Investigate with Agent",
    "description": "Open Elastic Security alerts; click an Alert ID and choose "
                   "'Investigate with Agent' to run the full AI investigation.",
    "panelsJSON": json.dumps([{
        "gridData": {"x": 0, "y": 0, "w": 48, "h": 24, "i": "1"},
        "panelIndex": "1",
        "embeddableConfig": PANEL_CONFIG,
        "panelRefName": "panel_1",
    }]),
    "optionsJSON": '{"hidePanelTitles":false,"useMargins":true}',
    "timeRestore": False,
    "kibanaSavedObjectMeta": {
        "searchSourceJSON": '{"query":{"language":"kuery","query":""},"filter":[]}'
    },
}

DASH_REFS = [{"name": "panel_1", "type": "visualization", "id": VIS_ID}]


def main():
    print(f"Kibana : {KIBANA_URL}")
    print(f"Triage : {TRIAGE_URL}")
    print(f"Index  : {ALERT_INDEX}\n")

    print("Creating data view ...")
    s, r = _req("POST", "/api/data_views/data_view", DATAVIEW_BODY)
    if s == 409 or (s == 400 and "Duplicate" in str(r.get("message", ""))):
        print("  data view already exists — keeping it")
    elif s not in (200, 201):
        print(f"  WARNING: data view create returned {s}: {r.get('message', r)}")
        print("  (continuing — the visualization may still work if a data view "
              f"for {ALERT_INDEX} already exists under id {DATAVIEW_ID})")
    else:
        print("  data view: ok")

    print("Creating alert table visualization ...")
    s, r = _req("POST", f"/api/saved_objects/visualization/{VIS_ID}",
                {"attributes": VIS_ATTRS, "references": VIS_REFS})
    if s == 409:
        s, r = _req("PUT", f"/api/saved_objects/visualization/{VIS_ID}",
                    {"attributes": VIS_ATTRS, "references": VIS_REFS})
    print(f"  vis: {s}")
    if s not in (200, 201):
        sys.exit(f"ERROR: {r.get('message', r)}")

    print("Creating dashboard with 'Investigate with Agent' drilldown ...")
    s, r = _req("POST", f"/api/saved_objects/dashboard/{DASH_ID}",
                {"attributes": DASH_ATTRS, "references": DASH_REFS})
    if s == 409:
        s, r = _req("PUT", f"/api/saved_objects/dashboard/{DASH_ID}",
                    {"attributes": DASH_ATTRS, "references": DASH_REFS})
    print(f"  dashboard: {s}")
    if s not in (200, 201):
        sys.exit(f"ERROR: {r.get('message', r)}")

    print(f"""
Done. Open: {KIBANA_URL}/app/dashboards#/view/{DASH_ID}

How to use it:
  1. Open the dashboard and pick a time range that covers your alerts.
  2. Click any value in the "Alert ID" column.
  3. Choose "Investigate with Agent" from the popup menu.
  4. The agent opens in a new tab and runs the full investigation
     (asset context, threat intel, related events, AI verdict).

Drilldown URL template used:
  {DRILLDOWN_URL}

If your Kibana version rejects the pre-built drilldown, you can add it
manually in ~30 seconds: edit the dashboard, open the panel menu on the
alert table -> "Create drilldown" -> "Go to URL", paste the template above,
enable "Open in new tab", and save.
""")


if __name__ == "__main__":
    main()
