# Linux Security Anomaly Detection

**MITRE ATT&CK-aligned anomaly detection for Linux endpoints, backed by Elasticsearch.**

Detects suspicious process execution, network activity, authentication anomalies, and host behavior using an ensemble of ML models (Isolation Forest, LOF, OCSVM, PCA, AutoEncoder). Enriches alerts with source-event context, classifies false positives, correlates into kill chains, and pushes to Elasticsearch ML anomaly indices for Kibana dashboards.

---

## Features

- **Multi-model ensemble** — Isolation Forest, Local Outlier Factor, One-Class SVM, PCA, AutoEncoder
- **7 data groups** — process, network, user, discovery, metadata, auth, host
- **20 detection jobs** covering MITRE ATT&CK techniques
- **Source-event enrichment** — cross-references raw logs (process, network, auth) for IP/user/command context
- **False-positive classification** — configurable rules with benign-process lists, service accounts, IP reputation
- **Kill-chain correlation** — links anomalies across MITRE ATT&CK stages per entity
- **Adaptive thresholds** — business-hours modifiers, recent-FP dampening, score escalation
- **Pluggable backends** — Elasticsearch (default), file-output (for testing/offline analysis)
- **Configurable everything** — FP lists, thresholds, index patterns via text files and YAML

## Architecture

```
                    +------------------+
                    |  Data Sources    |
                    |  (ES Indices)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Data Manager    |
                    |  (datamanager.py)|
                    +--------+---------+
                             |
               +-------------+-------------+
               |                           |
    +----------v----------+     +----------v----------+
    |  Feature Extraction |     |  Model Training     |
    |  (features/)        |     |  (model_manager.py) |
    +----------+----------+     +----------+----------+
               |                           |
               +-------------+-------------+
                             |
                    +--------v---------+
                    | Anomaly Detector |
                    | (anomaly_        |
                    |  detector.py)    |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
+---------v------+ +--------v-------+ +--------v--------+
| FP Classifier  | | Source Enrich  | | MITRE Enrichment|
| (push_all_     | | (push_all_     | | (push_all_      |
|  anomalies.py) | |  anomalies.py) | |  anomalies.py)  |
+---------+------+ +--------+-------+ +--------+--------+
          |                  |                  |
          +------------------+------------------+
                             |
                    +--------v---------+
                    | Kill-Chain       |
                    | Correlation      |
                    | (post_           |
                    |  correlation.py) |
                    +--------+---------+
                             |
                    +--------v---------+
                    | Backend Push     |
                    | (ES / File)      |
                    +------------------+
```

## Quickstart

### 1. Clone and install

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
pip install -e ".[dev]"
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env with your Elasticsearch credentials and settings
```

### 3. Train models

```bash
python train_models_background.py
```

### 4. Run detection

```bash
# One-shot detection
python main.py

# Continuous service
python realtime_service.py

# Push anomalies to ES ML indices
python push_all_anomalies.py
```

### 5. Docker (optional)

```bash
docker compose --env-file .env -f docker/docker-compose.yml up
```

See [DEPLOYMENT.md](DEPLOYMENT.md#5-docker-deployment) for what the bundled services do and how to point at an existing production cluster instead.

## Configuration

For a full walkthrough of every file you need to edit when deploying
against your own environment — required vs. optional, exact format, and
what to put in each (including the IP-range/hostname allowlists below) —
see [DEPLOYMENT.md](DEPLOYMENT.md).

### Environment Variables

See [.env.example](.env.example) for all available settings. Key variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `ES_HOST` | Elasticsearch URL | Yes |
| `ES_USERNAME` | ES username | Yes |
| `ES_PASSWORD` | ES password | Yes |
| `DAGSHUB_TOKEN` | MLflow tracking token | No |

### FP Classification Lists

Edit files in `config/` to customize false-positive filtering for your environment:

| File | Purpose |
|------|---------|
| `config/benign_processes.txt` | Infrastructure daemons (kubelet, sshd, etc.) |
| `config/service_accounts.txt` | Non-interactive accounts (www-data, etc.) |
| `config/infrastructure_hosts.txt` | Known infra hostnames |
| `config/public_facing_hosts.txt` | Internet-facing hosts |
| `config/internal_ip_prefixes.txt` | Private IP ranges |
| `config/cloud_ip_prefixes.txt` | Cloud/CDN provider IPs |
| `config/public_service_ports.txt` | Expected public ports |

### Reference Configuration

See [config/default.yaml](config/default.yaml) for all detection thresholds, ML parameters, and correlation settings.

## MITRE ATT&CK Coverage

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

## Project Structure

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
├── backends/               # Pluggable SIEM backends
│   ├── base.py             # Abstract interface
│   ├── elasticsearch_backend.py
│   └── file_backend.py
├── features/               # Modular feature extractors
├── models/                 # ML model wrappers (PyOD, ensemble)
├── dl_models/              # Deep learning models (AutoEncoder)
├── adversarial/            # Robustness / evasion testing
├── config/                 # FP lists and reference configuration
├── docker/                 # Dockerfile and docker-compose
├── docs/                   # Reproduction guides and supplementary docs
├── tests/                  # Pytest test suite
├── validation/             # Quality gate scripts per agent
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
