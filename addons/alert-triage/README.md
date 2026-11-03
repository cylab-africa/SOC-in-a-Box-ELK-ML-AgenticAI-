# Alert Triage Agent

Investigates Elastic Security alerts for you. For each alert it gathers the
related events, IP and file reputation, and what you know about the host, then
asks an AI model whether it looks like a real attack or a false alarm, and why.

Use it from a web page, a REST API, or as an MCP server so AI clients (Claude,
Claude Code, or any MCP client) can run the investigation tools themselves.

- Live alert list, filtered by severity, host, rule, user and date
- One-click investigation: host context, threat intelligence (AbuseIPDB,
  VirusTotal), related events, AI verdict
- AI model of your choice: local Ollama, Anthropic Claude, any OpenAI-compatible
  API, or none (investigation report only)
- A link per alert (`/investigate/<alert_id>`) to open from Kibana, Slack or
  anywhere else
- No telemetry

> **It has no login.** Anyone who can reach its port can read your alerts and
> use its Elasticsearch login and AI quota. Keep it on `127.0.0.1` and use an
> SSH tunnel (`ssh -L 8000:127.0.0.1:8000 YOUR_SERVER`), or put it behind a
> reverse proxy with authentication.

## Requirements

- Python 3.10+
- Elasticsearch 8.x with Elastic Security (Kibana Security) enabled
- An Elasticsearch user with read access to the alerts index
  (`.alerts-security.alerts-default`) and your event indices

## Install with SOC-in-a-Box

From the repository root:

```bash
./deploy.sh --only triage
```

It reuses the Elasticsearch settings, asks which AI model to use and for
optional AbuseIPDB and VirusTotal keys, installs the agent and starts it on
`127.0.0.1:8000`. Settings are in `addons/alert-triage/.env`.

| To... | Run |
|---|---|
| Open it | `http://127.0.0.1:8000/` |
| Check its status | `systemctl status alert-triage` |
| Restart after editing `.env` | `sudo systemctl restart alert-triage` |
| Stop it | `sudo systemctl disable --now alert-triage` |

## Install on its own

```bash
python3 install.py
```

The wizard checks your machine, installs the dependencies, asks for your
Elasticsearch login and AI model (it can install an Ollama model for you), and
writes `.env` and `start.sh`. Then:

```bash
bash start.sh       # Linux / macOS
start.bat           # Windows
```

To run it as a systemd service, edit the paths and user in
`deploy/elastic-triage.service`, then:

```bash
sudo cp deploy/elastic-triage.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now elastic-triage
```

When run on its own it listens on all interfaces (`HOST=0.0.0.0`) by default.
Set `HOST=127.0.0.1` in `.env` unless it sits behind an authenticating proxy.

## Settings

All in `.env`. Copy `.env.example` to start, or run `python3 install.py`.

**Elasticsearch**

| Setting | Default | What it is |
|---|---|---|
| `ELASTIC_URL` | | Address with `https://` and port |
| `ELASTIC_API_KEY` | | Login with an API key (recommended; read-only is enough). Wins over the username and password |
| `ELASTIC_USERNAME`, `ELASTIC_PASSWORD` | | Login with a username and password instead |
| `ELASTIC_VERIFY_SSL` | `false` | Check the certificate. Set `true` in production, with the CA installed |
| `ELASTIC_INDEX` | `.alerts-security.alerts-default` | Alerts index |
| `ELASTIC_EVENT_INDICES` | `logs-*,filebeat-*,winlogbeat-*,auditbeat-*` | Where related events are searched |

**AI model:** set `AI_PROVIDER` to `claude`, `ollama`, `openai_compat` or `none`.

```env
# Anthropic Claude
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...
CLAUDE_MODEL=claude-haiku-4-5-20251001

# Ollama, local (run: ollama pull llama3.2)
AI_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2

# OpenAI-compatible: LM Studio, vLLM, Groq, Together AI, ...
AI_PROVIDER=openai_compat
OPENAI_COMPAT_URL=http://localhost:1234/v1
OPENAI_COMPAT_KEY=
OPENAI_COMPAT_MODEL=mistral
```

**Threat intelligence (optional):** leave empty to skip these lookups.

```env
ABUSEIPDB_API_KEY=...
VIRUSTOTAL_API_KEY=...
```

**Host inventory (optional, improves verdicts):** copy `assets.example.yml` to
`assets.yml` and describe your hosts:

```yaml
hosts:
  WIN-DC01:
    criticality: critical
    environment: production
    role: domain_controller
    owner: infra@example.com
    notes: >
      Tier-0 asset. PowerShell with -enc is almost always malicious here.
```

## MCP server

The endpoint is `http://127.0.0.1:8000/mcp/mcp`.

**Claude Code** (`~/.claude.json`):

```json
{
  "mcpServers": {
    "elastic-triage": {
      "type": "http",
      "url": "http://localhost:8000/mcp/mcp"
    }
  }
}
```

**Claude.ai:** Settings → Connectors → Add custom connector → paste the URL.
This needs an HTTPS address reachable from the internet. Only publish one
behind authentication, and set `PUBLIC_URL` in `.env` to that address.

| Tool | What it does |
|---|---|
| `triage_recent_alerts` | Lists open alerts with their IDs (optional `rule` filter) |
| `list_alert_rules` | Rules with open alerts, with counts per severity |
| `investigate_alert` | Full investigation and AI verdict |
| `get_host_context` | Looks up a host in the inventory |
| `lookup_indicator` | Threat-intelligence check of an IP, hash or domain |
| `get_related_events` | Events on the same host or user around a time |

## Investigate from Kibana

Every alert has a link that opens the agent and runs the investigation:

```
http://<triage-host>:8000/investigate/<alert_id>
```

`<alert_id>` is the alert's `kibana.alert.uuid`. Copy it from the alert's
details in **Security → Alerts**.

**Option A: a ready-made dashboard.** This creates a "Security Alerts —
Investigate with Agent" dashboard. Click a value in its **Alert ID** column and
choose **Investigate with Agent**:

```bash
python deploy/create_investigate_dashboard.py
```

**Option B: your own dashboard.** On any panel that shows `kibana.alert.uuid`:
panel menu → **Create drilldown** → **Go to URL**, with
`http://<triage-host>:8000/investigate/{{event.value}}`, and **Open in new tab**
on.

Kibana's own Security → Alerts table cannot have custom buttons without a
Kibana plugin. Instead, you can put the agent's address in each rule's
**Investigation guide**, which shows in every alert's details.

These links open in the analyst's browser, so the agent must be reachable from
it: use the reverse proxy above.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `401` from Elasticsearch | Check the login, and that the user can read the alerts index |
| No alerts listed | Check the index name in Kibana Dev Tools with `GET _cat/indices/.alerts-security*`, then set `ELASTIC_INDEX` |
| Certificate (SSL) errors | Self-signed cluster: `ELASTIC_VERIFY_SSL=false` for a lab, or install its CA and set `true` |
| MCP client cannot connect | Open `<address>/health` in a browser. If it works, check you added `/mcp/mcp`, not just `/mcp` |
| Ollama timeout | Check `ollama serve` is running and the model is pulled; raise `THREAT_INTEL_TIMEOUT` |
| Alert list stuck at 50 | An old version is running. `curl http://<triage-host>:8000/health` should show `"limits": {"max_fetch_limit": 10000}`. If not, update the code and restart |

## License

[MIT](LICENSE). Copyright (c) 2024 Alert Triage Agent contributors.
