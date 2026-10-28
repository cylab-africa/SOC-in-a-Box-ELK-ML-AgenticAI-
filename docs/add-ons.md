# Add-ons

Three optional add-ons build on the detection engine. Each has its own `.env`
and service, and shares only the Elasticsearch cluster with the engine, so you
can add or remove one without touching detection.

| Add-on | What it does | Add it with |
|---|---|---|
| [SIEM Maintenance Agent](#siem-maintenance-agent) | Watches Elasticsearch itself: cluster health, logs still arriving, a daily Google Chat report, optional automatic fixes | `./deploy.sh --only maintenance` |
| [Alert Triage Agent](#alert-triage-agent) | Investigates Elastic Security alerts and says whether each looks like a real attack or a false alarm, and why | `./deploy.sh --only triage` |
| [Greenbone scan results](#greenbone-scan-results) | Sends Greenbone (OpenVAS) vulnerability scans to Elasticsearch weekly, labelled new, fixed or unchanged | `./deploy.sh --only greenbone` |

`./deploy.sh` asks about each add-on during the main install. `--only` adds
one later: it reuses the Elasticsearch settings in `.env` and leaves everything
else as it is.

## SIEM Maintenance Agent

Watches the cluster the detection engine depends on: node heap, disk and CPU,
rejected requests, and whether endpoint data is still arriving. It sends a
daily report and alerts to Google Chat, and can fix common problems itself.

```bash
./deploy.sh --only maintenance
```

You need a Google Chat webhook URL
([how to get one](../addons/siem-maintenance/README.md#get-a-google-chat-webhook)).
An AI model for the report text is optional.

**Check it works:**

```bash
systemctl status siem-maintenance     # active (running)
addons/siem-maintenance/.venv/bin/python addons/siem-maintenance/Agent-SIEM-maintenance/maintenance_service.py --once-poll
```

| | |
|---|---|
| Settings | `addons/siem-maintenance/.env` (`deploy.sh` copies it to `Agent-SIEM-maintenance/.env`; copy it again after editing by hand) |
| Automatic fixes | Off unless you choose them. With "only report" (the default), it logs what it would do in `Agent-SIEM-maintenance/results/auto_remediation_log.jsonl` |
| Ollama in Docker | `localhost` is the container itself: set `OLLAMA_URL=http://host.docker.internal:11434` or the host's IP |
| Full installer | `./deploy.sh --maintenance-wizard` also sets up the Chat feedback buttons and LLM presets |
| Stop | `sudo systemctl disable --now siem-maintenance` |

More: [addons/siem-maintenance/README.md](../addons/siem-maintenance/README.md).

## Alert Triage Agent

Give it an Elastic Security alert and it gathers the related events, IP
reputation (AbuseIPDB, VirusTotal) and your host inventory, then asks an AI
model whether the alert looks like a real attack or a false alarm, with its
reasons. Use it from a web page, a REST API, or as an MCP server for AI
clients such as Claude.

```bash
./deploy.sh --only triage
./deploy.sh --only triage --triage-port 8080    # another port
```

The script asks which AI model to use (`ollama`, `claude`, `openai_compat`, or
`none`) and for optional AbuseIPDB and VirusTotal keys.

**Check it works:** open `http://127.0.0.1:8000/`. The MCP endpoint is
`http://127.0.0.1:8000/mcp/mcp`.

> **It has no login.** Anyone who can reach its port can read your alerts and
> use its Elasticsearch login and AI quota. It therefore listens on
> `127.0.0.1` only. From another computer, use an SSH tunnel:
>
> ```bash
> ssh -L 8000:127.0.0.1:8000 YOUR_SERVER
> ```
>
> or put it behind a reverse proxy with authentication. Use
> `--triage-listen 0.0.0.0` only on a network you trust.

| | |
|---|---|
| Settings | `addons/alert-triage/.env` |
| Least privilege | It only searches the alerts and event indices: give it a read-only Elasticsearch user |
| Better verdicts | Copy `addons/alert-triage/assets.example.yml` to `assets.yml` and describe your hosts (criticality, role, owner). In Docker, rebuild after editing it |
| Kibana links | `addons/alert-triage/deploy/create_investigate_dashboard.py` adds an "Investigate with Agent" link to Kibana (needs the reverse proxy above) |
| Stop | `sudo systemctl disable --now alert-triage` |

More: [addons/alert-triage/README.md](../addons/alert-triage/README.md).

## Greenbone scan results

Sends finished [Greenbone (OpenVAS)](https://www.greenbone.net/) vulnerability
scans to Elasticsearch, so you can search them in Kibana next to the alerts.
Each finding is labelled `new`, `same`, `changed` or `fixed` compared with the
previous scan.

### Install Greenbone first

This add-on does not install Greenbone. It reads the results of a Greenbone
that already runs **on the same server**. If you choose the add-on and
Greenbone is not found, `deploy.sh` skips it and shows these commands. They
are Greenbone's own setup script and need Docker:

```bash
curl -f -O -L https://greenbone.github.io/docs/latest/_static/setup-and-start-greenbone-community-edition.sh
chmod u+x setup-and-start-greenbone-community-edition.sh
./setup-and-start-greenbone-community-edition.sh
```

Guide: [Greenbone Community Containers](https://greenbone.github.io/docs/latest/22.4/container/).
The vulnerability feed takes from minutes to a few hours to download.

### Add the add-on

```bash
./deploy.sh --only greenbone
```

The script finds Greenbone's socket, asks for your Greenbone username and
password, tests the connection, and schedules a push **every Sunday at 06:00**.
The push runs as root, because Greenbone's socket belongs to root.

To choose another day or time:

```bash
GREENBONE_DAY=Sat GREENBONE_TIME=03:00 ./deploy.sh --only greenbone
```

**Check it works:**

```bash
systemctl list-timers gvm-siem-push.timer      # next push
sudo systemctl start gvm-siem-push.service     # push now
journalctl -u gvm-siem-push.service            # what the last push did
```

After the first push, add `gvm-vulnerabilities` as a data view in Kibana.

| | |
|---|---|
| Settings | `addons/greenbone/.env` |
| Kibana queries, settings, errors | [addons/greenbone/README.md](../addons/greenbone/README.md) |
| Stop | `sudo systemctl disable --now gvm-siem-push.timer` |
