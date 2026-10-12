# Linux Security Anomaly Detection

**Finds suspicious activity on Linux servers that rule-based detection misses, and sends it to Kibana as triaged alerts.**

Security rules catch things that are *known* to be bad. This catches things that
are *unusual for your environment* — a process that has never run on that host
before, a login at an hour that user never works, an outbound connection on a
port nothing else uses. It learns what normal looks like from your own logs,
then reports what does not fit.

It is built to reduce noise, not add to it. Anomalies are filtered against
allowlists, enriched with the actual command line and IP addresses behind them,
mapped to MITRE ATT&CK techniques, and grouped into a single story per host
rather than arriving as a dozen separate alerts.

Here is where it sits. It does not run on the machines being watched — it reads
their logs out of Elasticsearch and writes alerts back:

```
  Your Linux hosts          Elasticsearch           This project            Kibana
 +----------------+       +----------------+     +----------------+     +------------+
 | Elastic Agent  | ----> | raw endpoint   | --> | learns what is | --> | triaged    |
 | (Elastic       | ships | event data     |reads| normal, flags  |write| alerts for |
 |  Defend)       | logs  |                |     | what is not    |     | an analyst |
 +----------------+       +----------------+     +----------------+     +------------+
```

**New here?** Read [Before you start](#before-you-start) first. It takes two
minutes and tells you whether this will work in your environment — most setup
problems are really "the data isn't there yet."

- [Before you start](#before-you-start)
- [Quickstart](#quickstart)
- [Did it work?](#did-it-work)
- [Troubleshooting](#troubleshooting)
- [Configuration](#configuration)
- [What it detects](#what-it-detects)
- [How it works](#how-it-works)

---

## Before you start

This is **not** a standalone tool. It reads from an existing Elasticsearch
cluster and does nothing useful without one. Here is the honest list.

### You must have

| Requirement | Why | How to check |
|---|---|---|
| **Python 3.10 or newer** | Uses 3.10+ type syntax | `python3 --version` |
| **An Elasticsearch 8.x cluster** you can reach, with a username and password | This is both the input and the output | `curl -u USER:PASS https://YOUR_ES:9200` |
| **Elastic Agent installed on the Linux machines you want to watch**, with the **Elastic Defend** integration enabled | Produces the process and network events the models learn from | See the next section |
| **At least 7 days of that data already collected** | Models need history to learn "normal"; 7 days is the default training window for process data | See the next section |

### The part people miss

The models do not read `/var/log` or run on the machine being monitored. They
read **Elastic Agent data streams** out of Elasticsearch. Specifically:

| Data stream | Comes from | Used for |
|---|---|---|
| `.ds-logs-endpoint.events.process-default-*` | Elastic Defend integration | process detection |
| `.ds-logs-endpoint.events.network-default-*` | Elastic Defend integration | network detection |
| `.ds-logs-endpoint.events.file-default-*` | Elastic Defend integration | file activity |
| `.ds-logs-system.auth-default-*` | System integration | login / sudo detection |

So before anything here will work, you need Elastic Agent enrolled in Fleet on
your Linux hosts with **Elastic Defend** (for endpoint events) and **System**
(for auth logs) added to its policy. That is standard Elastic setup and is
documented by Elastic — this project assumes it is already done.

Run this to confirm you have the data. It should return a non-zero count:

```bash
curl -u "$ES_USERNAME:$ES_PASSWORD" \
  "$ES_HOST/.ds-logs-endpoint.events.process-default-*/_count"
```

- **A number in the thousands or more** → you are ready.
- **`{"count":0,...}`** → Elastic Agent is not shipping endpoint data yet. Fix
  that first; nothing downstream will produce results.
- **`index_not_found_exception`** → the integration has never run, or your
  cluster names its indices differently (see [Step 3](#step-3--check-your-index-names-match)).

### If you don't have this yet

Be aware of what each shortcut does and does not give you:

- **No Elasticsearch at all?** The bundled Docker setup starts Elasticsearch
  8.12 and Kibana 8.12 for you (see [Docker](#docker)). It does **not** include
  Elastic Agent, so you will still need to enroll an agent against it to get
  endpoint data.
- **Have the cluster but no history yet?** Install the agent, then come back in
  a week. You can still complete steps 1-3 now and verify your configuration
  with `--dry-run`, which needs no data.
- **Just want to read the code?** Steps 1-2 plus the
  [architecture guide](docs/ARCHITECTURE.md) will make sense without a cluster.

## Quickstart

Six steps. Each one ends with how to tell it worked before you move on.

### Step 1 — Install

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

**Worked if:** `python -c "import anomaly_detector"` prints nothing (no error).

### Step 2 — Point it at Elasticsearch

```bash
cp .env.example .env
```

Open `.env` and set these three. Everything else has a working default:

| Variable | What to put |
|---|---|
| `ES_HOST` | Full URL including scheme and port, e.g. `https://10.0.0.5:9200` |
| `ES_USERNAME` | An ES user that can read your log indices and write new ones |
| `ES_PASSWORD` | That user's password |

`DAGSHUB_*` is for optional MLflow experiment tracking. Leave it as-is if you
don't use MLflow.

**Worked if:** the `curl` command in
[The part people miss](#the-part-people-miss) returns a count using these
credentials.

### Step 3 — Check your index names match

This is the single most common reason a run produces nothing. The defaults in
`.env.example` match a standard Elastic Agent install. If your cluster names
things differently, change these to match:

```
ES_PROCESS_INDEX=.ds-logs-endpoint.events.process-default-*
ES_NETWORK_INDEX=.ds-logs-endpoint.events.network-default-*
ES_DISCOVERY_INDEX=logs-endpoint.events.process-*
ES_METADATA_INDEX=logs-endpoint.events.process-*,logs-endpoint.events.network-*
ES_ALERTS_INDEX=.internal.alerts-security.alerts-default-*
```

List what your cluster actually has:

```bash
curl -u "$ES_USERNAME:$ES_PASSWORD" "$ES_HOST/_cat/indices/*endpoint*?h=index"
```

**Worked if:** every pattern above matches at least one real index on your
cluster. `DEPLOYMENT.md` section 2 walks through field-name differences too.

### Step 4 — Train the models

Start with a dry run. It confirms the tool and your data-group configuration
load correctly without touching Elasticsearch or training anything:

```bash
python train_models_background.py --all --dry-run
```

Then train for real. This reads up to 7 days of history and takes a while:

```bash
python train_models_background.py --all
```

Useful flags: `--groups process network` to train only some groups,
`--skip-existing` to resume, `--restart-on-fail` to retry automatically.

**Worked if:** `logs/trainer.log` contains lines like:

```
Successfully trained and saved models for process
 Saved 3 baselines
```

Seeing `Insufficient samples for <name>: 1 < 50` is **normal** — that entity
doesn't have enough history for its own model yet. Only worry if *every* entity
reports it, which means not enough data overall.

### Step 5 — Run detection once

```bash
python main.py
```

Add `--data-groups process` to test a single group first, or
`--detection-mode single --job v3_linux_anomalous_process_all_hosts` for one
job. Job IDs are the `v3_*` names that appear in your logs and in `results/`
filenames — the short names in the ATT&CK table below are descriptions, not
job IDs.

**Worked if:** `logs/linux_anomaly_detection.log` contains a summary like:

```
Detection Summary:
  Total records: 2,301
  Anomalies detected: 270
  Anomaly rate: 11.73%
```

and new files appear in `results/` named `ml_only_<group>_data_*.csv` and
`ml_only_<group>_report_*.md`.

### Step 6 — Send alerts to Kibana

```bash
python push_all_anomalies.py
```

This is the step that applies false-positive filtering, adds context, maps to
ATT&CK, correlates into kill chains, and writes to Elasticsearch.

**Worked if:** the `ml-anomalies-custom-*` indices exist and have documents:

```bash
curl -u "$ES_USERNAME:$ES_PASSWORD" "$ES_HOST/ml-anomalies-custom-*/_count"
```

Then add `ml-anomalies-custom-*` as a data view in Kibana to see them.

### Running it continuously

Once a one-shot run works, run it as a service instead:

```bash
python realtime_service.py
```

It loops detection, pushes results, retrains in the background, and cleans up
its own old output.

For a permanent install, run it under systemd. Save this as
`/etc/systemd/system/realtime_service.service`, adjusting `User` and the paths:

```ini
[Unit]
Description=Realtime Anomaly Detection Service
After=network.target

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=/opt/SOC-in-a-Box-ELK-ML-AgenticAI-
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/python3 -u /opt/SOC-in-a-Box-ELK-ML-AgenticAI-/realtime_service.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then `sudo systemctl enable --now realtime_service`. Note that with
`StandardOutput=journal` this service is very chatty; consider adding
`StandardOutput=null` and reading `logs/` instead, or capping journal size with
`SystemMaxUse` in `/etc/systemd/journald.conf`.

## Did it work?

Check these four in order. The first one that fails tells you where to look.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | Input data exists | `curl -u U:P "$ES_HOST/.ds-logs-endpoint.events.process-default-*/_count"` | count > 0 |
| 2 | Models trained | `grep "Successfully trained" logs/trainer.log` | one line per group |
| 3 | Detection ran | `grep "Anomalies detected" logs/linux_anomaly_detection.log \| tail -1` | a non-zero number |
| 4 | Output reached ES | `curl -u U:P "$ES_HOST/ml-anomalies-custom-*/_count"` | count > 0 |

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| `index_not_found_exception` | Index pattern in `.env` doesn't match your cluster | Run the `_cat/indices` command in [Step 3](#step-3--check-your-index-names-match) and correct the patterns |
| `{"count":0}` on the input check | Elastic Agent isn't shipping endpoint data | Confirm the agent is healthy in Fleet and that **Elastic Defend** is in its policy |
| `ERROR - process_detection: no results produced for v3_...` | The job found no matching data | Usually wrong index pattern, or the time window has no events. Check 1 and 3 in [Did it work?](#did-it-work) |
| `Insufficient samples for X: 1 < 50` | That entity lacks history for its own model | Normal in small or new environments. Collect more data, or lower `ml.min_samples` in `config/default.yaml` |
| `ERROR - Missing model for entity <name>` | Scoring ran before that group was trained | Run `python train_models_background.py --all` and re-run detection |
| `401 Unauthorized` / `AuthenticationException` | Bad credentials | Recheck `ES_USERNAME` / `ES_PASSWORD`; confirm with the `curl` command in Step 2 |
| Detection runs but no alerts in Kibana | Step 6 not run, or no data view | Run `push_all_anomalies.py`, then add `ml-anomalies-custom-*` as a Kibana data view |
| `results/` growing to tens of GB | Old output not being cleaned | `realtime_service.py` prunes automatically; if you run `main.py` on a cron, delete `results/ml_only_*` files older than a few days yourself |
| Logs full of `Context enrichment partial failure ... unexpected keyword argument 'size'` | **Known issue.** Alert context enrichment is failing against newer `elasticsearch-py` clients | Detection still works; the `score_percentile` and `entity_anomaly_count_7d` fields will be missing from alerts |

Still stuck? Open an issue with your Python version, Elasticsearch version, and
the last 50 lines of `logs/linux_anomaly_detection.log`.

## Configuration

Start with [DEPLOYMENT.md](DEPLOYMENT.md) — it walks through every file you need
to touch, which are required and which are optional, and what to put in each.

**Tuning false positives.** Plain text files, one entry per line. Edit these to
match your environment; they are the fastest way to cut noise:

| File | What goes in it |
|---|---|
| `config/benign_processes.txt` | Infrastructure daemons (kubelet, sshd, ...) |
| `config/service_accounts.txt` | Non-interactive accounts (www-data, ...) |
| `config/infrastructure_hosts.txt` | Known infrastructure hostnames |
| `config/public_facing_hosts.txt` | Internet-facing hosts |
| `config/internal_ip_prefixes.txt` | Your private IP ranges |
| `config/cloud_ip_prefixes.txt` | Cloud / CDN provider ranges |
| `config/public_service_ports.txt` | Ports you expect to be open |

**Detection thresholds and ML parameters.** See
[config/default.yaml](config/default.yaml). In small environments the key one to
change is `min_samples` — how many observations an entity needs before it gets
its own model. It is not in the file by default; add it under the existing `ml:`
section to override the built-in default of 50:

```yaml
ml:
  min_samples: 20
```

**All environment variables.** See [.env.example](.env.example).

## Docker

Starts Elasticsearch 8.12, Kibana 8.12, and the detection container together:

```bash
docker compose --env-file .env -f docker/docker-compose.yml up
```

This does **not** include Elastic Agent, so you still need to enroll an agent
to get endpoint data into it. See
[DEPLOYMENT.md](DEPLOYMENT.md#5-docker-deployment) for pointing the detection
container at an existing production cluster instead.

## What it detects

7 data groups (process, network, user, discovery, metadata, auth, host) across
20 detection jobs, using an ensemble of Isolation Forest, Local Outlier Factor,
One-Class SVM, PCA, and an AutoEncoder. Every detection maps to at least one
MITRE ATT&CK technique:

| Technique | ID | Detection Job |
|-----------|----|---------------|
| Command and Scripting Interpreter | T1059 | rare_process_on_host, suspicious_cmd_chains |
| Valid Accounts | T1078 | rare_user_activity, anomalous_login_times |
| Abuse Elevation Control | T1548 | rare_sudo_usage |
| Network Service Scanning | T1046 | host_discovery_patterns |
| Application Layer Protocol | T1071 | unusual_connections |
| Non-Standard Port | T1571 | anomalous_ports |
| Ingress Tool Transfer | T1105 | (suspicious command regex) |
| Brute Force | T1110 | brute_force_detection |
| Masquerading | T1036 | rare_process_host_combo, rare_metadata_process |
| DNS over Application Layer | T1071.004 | rare_dns_queries |
| Protocol Tunneling | T1572 | unusual_connections |

Other capabilities: source-event enrichment (pulls the real command line and IPs
behind each anomaly), graduated allowlists that dampen repeat benign behavior
instead of permanently whitelisting it, kill-chain correlation across ATT&CK
stages, and adaptive thresholds that account for business hours and recent
false-positive pressure.

## How it works

For the detection pipeline stage by stage, where this sits in a full SOC
deployment, and the module map, see
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Project structure

```
linux-anomaly-detection/
├── anomaly_detector.py     # Core detection engine
├── config.py               # Dataclass-based configuration
├── datamanager.py          # Elasticsearch data fetching
├── detection_methods.py    # ML model implementations
├── main.py                 # One-shot detection CLI
├── model_manager.py        # Model training/loading/versioning
├── push_all_anomalies.py   # FP classification, enrichment, push
├── post_correlation.py     # Kill-chain correlation
├── realtime_service.py     # Continuous detection service
├── train_models_background.py  # Background training with checkpoints
├── benign_lists.py         # Graduated allowlist with dampening
├── backends/               # SIEM backend interface (Elasticsearch)
├── features/               # Modular feature extractors
├── models/                 # ML model wrappers (PyOD, ensemble)
├── dl_models/              # Deep learning models (AutoEncoder)
├── adversarial/            # Robustness / evasion testing
├── config/                 # FP lists and reference configuration
├── docker/                 # Dockerfile and docker-compose
├── docs/                   # Architecture, reproduction guides, diagrams
├── tests/                  # Pytest test suite
├── validation/             # Quality gate scripts
└── benchmarks/             # Performance benchmarking
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -x --tb=short

# Lint
ruff check .

# Type check
mypy --ignore-missing-imports *.py
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
