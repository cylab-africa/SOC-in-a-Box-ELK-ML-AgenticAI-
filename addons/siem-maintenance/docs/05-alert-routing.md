# 5. From Breach to Google Chat

> **This repository:** Chat payloads and cooldown mechanics live in **`es_health_monitor.py`** and **`enhanced_health_monitor.py`** (`results/es_alert_state.json`, `ES_ALERT_COOLDOWN_HOURS`). They follow the *spirit* of this chapter but **not** always the same filenames or `cardsV2` shape — see [**docs/00**](00-design-spec-vs-this-repo.md).

A threshold transition does not immediately page. Before a card lands
in the SIEM-MAINTENANCE channel, the alert passes through:

1. A **classification** step (band transition — see [§3](03-thresholds-and-alert-bands.md)).
2. A **transition check** (is this genuinely a new state?).
3. A **cooldown gate** (has this category paged recently?).
4. A **category routing** step.

Each stage exists to suppress a specific class of noise.

## 5.1 The cooldown gate

Every alert has a category, and every category has its own four-hour
cooldown timer. When an alert fires, the subsystem checks the time
elapsed since the last alert in the same category. If less than four
hours have passed, the new alert is suppressed — logged for audit
but not sent. This is the main defence against the failure mode
where an ongoing infrastructure issue produces a continuous stream
of identical pages.

Five categories cover the subsystem:

- `cluster_health`
- `node_pressure`
- `data_freshness`
- `model_staleness`
- `agent_down`

Each runs its own independent timer, so a `cluster_health` alert does
not suppress an `agent_down` alert even if both fire in the same
window.

**`siem_maint/alerting/cooldown.py`**

```python
import time
import json
from pathlib import Path

COOLDOWN_FILE  = Path("/var/lib/siem-maint/cooldowns.json")
COOLDOWN_HOURS = 4

def cooldown_passed(category):
    state = json.loads(COOLDOWN_FILE.read_text()) if COOLDOWN_FILE.exists() else {}
    last = state.get(category, 0)
    return (time.time() - last) > COOLDOWN_HOURS * 3600

def record_alert(category):
    state = json.loads(COOLDOWN_FILE.read_text()) if COOLDOWN_FILE.exists() else {}
    state[category] = time.time()
    COOLDOWN_FILE.write_text(json.dumps(state))
```

## 5.2 Posting the card to Google Chat

Alerts are posted as Google Chat cards via an incoming-webhook URL.
The card carries:

- a severity header (coloured by tier)
- a timestamp
- a human-readable description
- the affected host or node
- the metric value that triggered the alert
- the band it crossed into
- for critical alerts, a button linking to a log view

Remediation outcomes are posted as a **second** card after the
verification stage completes.

**`siem_maint/alerting/chat.py`**

```python
import requests
import time

CHAT_WEBHOOK = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=...&token=..."

def post_alert_card(severity, title, description, host, metric, value, band):
    card = {
        "cardsV2": [{
            "cardId": f"alert-{int(time.time())}",
            "card": {
                "header": {
                    "title":    f"[{severity.upper()}] {title}",
                    "subtitle": f"{host} - {metric}={value} - band={band}",
                },
                "sections": [{
                    "widgets": [
                        {"textParagraph": {"text": description}},
                        {"decoratedText": {
                            "topLabel": "host",
                            "text":     host,
                        }},
                        {"decoratedText": {
                            "topLabel": "metric",
                            "text":     f"{metric} = {value} ({band})",
                        }},
                    ],
                }],
            },
        }]
    }
    requests.post(CHAT_WEBHOOK, json=card, timeout=10)
```

## 5.3 Google Chat destination

Alerts and daily reports from this subsystem are posted only to the
**infrastructure maintenance** space whose webhook you configure
(**`CHAT_WEBHOOK`** in the packaged layout, **`GC_ALERT_WEBHOOK`** in
this Git tree — see [**docs/10**](10-agent-siem-maintenance-map.md)).

## 5.4 Escalation ladder in this Git repository

When running from the **`Agent-SIEM-maintenance/`** tree (instead of the packaged
`siem_maint` install), see [**docs/10 §10.3**](10-agent-siem-maintenance-map.md#103-escalation-and-routing-who-gets-paged) for
the concrete Google Chat destinations, environment variables, and stage ordering.

---

Previous: [← 4. The remediation loop](04-remediation-loop.md)
Next: [6. Operational notes →](06-operational-notes.md)
