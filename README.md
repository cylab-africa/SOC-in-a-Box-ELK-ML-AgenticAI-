# SOC-in-a-Box

**An open-source, AI-enabled security operations platform for Digital Public Infrastructure, built by the Upanzi Network at CMU-Africa.**

SOC-in-a-Box packages what an organization needs to run a Security Operations
Center into something that can be deployed and adapted quickly. It is aimed at
Digital Public Infrastructure (DPI), Digital Public Goods (DPGs), e-government
platforms, and financial services across African markets, where security teams
are small and most organizations cannot build a SOC from scratch for every system
they run.

- **Runs on modest hardware.** Lightweight, containerized, and resource-efficient
  enough for local CPU infrastructure, so data can stay in-country.
- **AI assists the analyst, it does not replace them.** Machine learning and
  agents handle triage, correlation, and routine maintenance. High-impact actions
  stay behind human approval or dry-run defaults.
- **One core, many plugins.** DPI- and sector-specific telemetry, detection rules,
  dashboards, and playbooks (for example, for MOSIP) plug into the core without
  changing it.
- **A training lab as well as a platform.** The same tools serve as a hands-on
  defensive-security lab for students and SOC analysts.

```mermaid
flowchart LR
  AGENT["Your Linux hosts<br/>Elastic Agent + Elastic Defend"] -->|events| ES["Elasticsearch"]
  ES -->|"reads each cycle"| ENGINE["SOC-in-a-Box<br/>detection engine"]
  ENGINE -->|"triaged, ATT&CK-mapped alerts"| ES
  ES --> KIBANA["Kibana<br/>analyst queue"]
```

## What's included

| Component | What it does | |
|---|---|---|
| **Detection engine** | Learns normal behavior per host, user, and process, and turns what does not fit into filtered, enriched, ATT&CK-mapped alerts in Kibana | Core |
| **SIEM Maintenance Agent** | Watches the SOC itself: cluster health, ingestion freshness, a daily Google Chat report, guarded auto-remediation | Optional |
| **Alert Triage Agent** | AI-assisted investigation of Elastic Security alerts with a true/false-positive verdict; web UI, REST API, and MCP server | Optional |

All of it sits on top of the Elastic Stack (Elasticsearch, Kibana, Fleet, and
Elastic Agent with Elastic Defend).

## Requirements

| | |
|---|---|
| Host | Linux with Python 3.10+, or Docker Compose v2 |
| Elastic Stack | Elasticsearch 8.x with Kibana and Fleet |
| Data | Elastic Agent with **Elastic Defend** and **System** on the Linux hosts you want to watch, and about 7 days of their data |

No cluster yet? See [Step 1 of the installation guide](docs/installation.md#step-1--have-an-elastic-stack-with-endpoint-data).

## Quick start

**1. Check that endpoint data is reaching Elasticsearch**

```bash
curl -u "$ES_USERNAME:$ES_PASSWORD" "$ES_HOST/.ds-logs-endpoint.events.process-default-*/_count"
```

✅ A count in the thousands or more. `{"count":0}` means Elastic Agent isn't
shipping data yet; fix that first.

**2. Install**

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
./deploy.sh
```

It asks for your Elasticsearch URL and credentials, checks the connection,
offers each add-on, and starts the service.

✅ `[ OK ]` lines for each stage, ending in:

```
== Done ==
  Detection pipeline:   venv
```

**3. See the alerts**

Models train on the first cycle; detections start once training finishes. Then:

```bash
curl -u "$ES_USERNAME:$ES_PASSWORD" "$ES_HOST/ml-anomalies-custom-*/_count"
```

✅ A count above zero. Add `ml-anomalies-custom-*` as a data view in Kibana to
work the alerts.

Something not right? See [Troubleshooting](docs/troubleshooting.md).

## Documentation

| Guide | What's in it |
|---|---|
| [Installation](docs/installation.md) | Prerequisites, `deploy.sh`, Docker, manual install, running as a service |
| [Configuration](docs/configuration.md) | `.env` settings, index names, false-positive lists |
| [Detection engine](docs/detection-engine.md) | What it detects and how it works |
| [Add-ons](docs/add-ons.md) | SIEM Maintenance Agent and Alert Triage Agent |
| [Troubleshooting](docs/troubleshooting.md) | Common errors and what to do |
| [Architecture](docs/architecture.md) | Pipeline stages and where this sits in a SOC |
| [Technical reference](docs/technical-reference.md) | In-depth reference for the detection engine |
| [Development](docs/development.md) | Project layout, tests, and linting |

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Never post credentials, hostnames, or IP addresses from your environment in a
public issue.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

The detection engine, its add-ons, and the documentation this project is built
on were designed and written by Noah Shumba at the Upanzi Network, CMU-Africa.
