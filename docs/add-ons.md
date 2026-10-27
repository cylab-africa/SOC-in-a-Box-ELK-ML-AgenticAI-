# Add-ons

Two optional agents ship with SOC-in-a-Box. Each runs as its own process, with
its own venv, `.env`, and service, and shares nothing with the detection engine
except the Elasticsearch cluster. They can be added, upgraded, or removed
without touching detection.

| Add-on | What it does | Install |
|---|---|---|
| [SIEM Maintenance Agent](#siem-maintenance-agent) | Watches the SOC itself: cluster health, ingestion freshness, a daily Google Chat report, guarded auto-remediation | `./deploy.sh --with-maintenance` |
| [Alert Triage Agent](#alert-triage-agent) | AI-assisted investigation of Elastic Security alerts, with a TP/FP verdict; web UI, REST API, and MCP server | `./deploy.sh --with-triage` |

## SIEM Maintenance Agent

[`addons/siem-maintenance/`](../addons/siem-maintenance/) watches the health of
the cluster the detection engine depends on (node heap/disk/CPU, thread-pool
rejections, ingestion freshness on the same endpoint indices), sends a daily
Google Chat report, and can run guarded auto-remediation. It is off unless you
choose it:

```bash
./deploy.sh --with-maintenance            # reuses the ES settings from .env
./deploy.sh --maintenance-wizard          # the add-on's full installer (feedback loop, Chat app, LLM presets)
```

**✅ Worked if:** `systemctl status siem-maintenance` shows `active (running)`,
and a one-off poll completes:

```bash
addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py --once-poll
```

- **Configure:** `addons/siem-maintenance/.env`. The agent also reads
  `addons/siem-maintenance/Agent-SIEM-maintenance/.env`; `deploy.sh` keeps the
  two identical, so after editing by hand copy the root one over the other.
  Full variable list: [addons/siem-maintenance/README.md](../addons/siem-maintenance/README.md).
- **Auto-remediation:** clears caches, restarts stopped ML jobs, and removes
  old snapshots / empty non-essential indices. `deploy.sh` starts it in
  **dry-run** mode (`AUTO_REMEDIATION_DRY_RUN=true`); review the dry-run entries
  in `Agent-SIEM-maintenance/results/auto_remediation_log.jsonl` before setting
  it to `false`.
- **Docker + Ollama:** inside a container `localhost` is the container itself;
  point `OLLAMA_URL` at `http://host.docker.internal:11434` or the host IP.
- **Disable:** `sudo systemctl disable --now siem-maintenance.service`, or run
  compose without `--profile maintenance`.

## Alert Triage Agent

[`addons/alert-triage/`](../addons/alert-triage/) investigates Elastic Security
alerts. Give it an alert ID and it pulls the alert, the related process and
network events around it, AbuseIPDB / VirusTotal reputation for its indicators,
and your asset inventory, then asks an LLM (local Ollama, Claude, or any
OpenAI-compatible API) for a true-positive / false-positive verdict with its
reasoning. You use it through a web UI, a REST API (`/api/triage`,
`/api/investigate/<alert_id>`), or as an MCP server, so an AI client such as
Claude Desktop can run the investigation tools itself.

```bash
./deploy.sh --with-triage                        # reuses the ES settings from .env
./deploy.sh --with-triage --triage-port 8080     # different port
```

`deploy.sh` writes `addons/alert-triage/.env` from the engine's ES settings,
asks for an AI backend (`none`, `ollama`, `claude`, `openai_compat`) and
optional AbuseIPDB / VirusTotal keys, installs it, and starts
`alert-triage.service`.

**✅ Worked if:** `http://127.0.0.1:8000/` opens the web UI (MCP endpoint:
`http://127.0.0.1:8000/mcp/mcp`).

> **It has no login.** Anyone who can reach its port can read every open alert,
> run investigations with its Elasticsearch credentials, and spend your LLM API
> quota. `deploy.sh` therefore binds it to `127.0.0.1` only. Reach it from
> another machine with an SSH tunnel (`ssh -L 8000:127.0.0.1:8000 <host>`), or
> put it behind a reverse proxy that does authentication. Only use
> `--triage-listen 0.0.0.0` on a network you trust.

- **Least privilege:** it only calls `_search` on the alerts index and event
  indices. Create a read-only role for those indices and enter that user when
  `deploy.sh` asks for the triage agent's credentials.
- **TLS:** it follows the engine's setting (`ELASTIC_VERIFY_SSL` mirrors
  `ES_VERIFY_CERTS`). With `ES_CA_CERT`, `deploy.sh` builds
  `addons/alert-triage/certs/ca-bundle.pem` (system CAs plus your cluster CA)
  and points `SSL_CERT_FILE` at it.
- **Asset inventory:** for better verdicts, copy `assets.example.yml` to
  `assets.yml` in the add-on directory and describe your hosts (criticality,
  role, owner). That file stays out of git. In Docker it is baked into the image
  at build time, so rebuild after editing it.
- **Kibana integration:** `deploy/create_investigate_dashboard.py` and
  `deploy/create_canvas.py` in the add-on add an "Investigate with Agent"
  drilldown to Kibana. Those links open the agent in the analyst's browser, so
  they need the reverse-proxy setup above.
- **Dependency pin:** `addons/alert-triage.constraints.txt` pins `mcp<2`; MCP
  SDK 2.x renamed `FastMCP` and the agent fails to start with it.
- **Disable:** `sudo systemctl disable --now alert-triage.service`, or run
  compose without `--profile triage`.
