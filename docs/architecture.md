# Architecture

How SOC-in-a-Box is built and where it sits in a SOC. This is background: to
install it, see the [installation guide](installation.md).

- [Where this fits in a SOC](#where-this-fits-in-a-soc)
- [Detection pipeline](#detection-pipeline)
- [Feedback loops](#feedback-loops)
- [Add-ons](#add-ons)

## Where this fits in a SOC

![SOC platform data flow — from lab infrastructure through Elasticsearch and the ML engine to Kibana and the SOC analyst](images/securityflow.png)

SOC-in-a-Box is the **ML / Agentic AI Engine** in the middle column. The
reference deployment protects a Digital Public Infrastructure (DPI) lab in three
stages.

**1. Data sources (left)**

| Source | Examples |
|---|---|
| DPI platforms (the workloads being defended) | MOSIP (digital identity), Mojaloop (payments), Mifos (core banking), OpenCRVS (civil registration), OpenG2P (government payments), Tazama (fraud monitoring), Matrix/Element (messaging) |
| Demo and test applications (realistic traffic, attack simulations) | Mojashop (demo merchant), UPMS (user and provider management), Appkit |
| Security telemetry | Suricata (network IDS/IPS), a honeypot |

Each sends host and application logs, plus indicators of compromise, to
Elasticsearch.

**2. Detection (middle)**

| Layer | Catches |
|---|---|
| **Elasticsearch** (3 nodes) | Stores everything. The engine reads its input here and writes its alerts back |
| **Elastic Security rules** | What is *known* to be bad: matching indicators and documented attack techniques |
| **SOC-in-a-Box engine** | What is *unusual for this environment*: new and living-off-the-land activity that rules miss |

Rules give precision on known threats; the engine gives coverage of the rest.
The engine does not forward every model hit: it filters false positives, merges
related anomalies into one story, and adds the context an analyst needs.

**3. Response (right)**

The engine's alerts land in Elasticsearch, so they appear in **Kibana** next to
rule-based alerts. The **SOC analyst** reviews, investigates and responds. The
filtering and correlation exist to keep that queue small enough for a person to
work.

## Detection pipeline

![Detection pipeline — ingestion, preprocessing, feature engineering, modeling, anomaly detection, classification/enrichment/threat mapping, correlation, and output](images/ml-soc.png)

What runs between "logs land in Elasticsearch" and "an alert reaches Kibana".
All modules are in `engine/`.

| # | Stage | What it does | Module |
|---|---|---|---|
| 1 | Ingestion | Reads a time window from Elasticsearch. Index patterns and windows come from `.env` ([configuration](configuration.md)) | `datamanager.py` |
| 2 | Preprocessing | Cleans and normalizes records, aligns timestamps, and resolves each host, user, process and IP to one identity | `datamanager.py` |
| 3 | Feature engineering | Turns events into numbers: rarity per entity, command-line traits, timing, ports and protocols, volumes over rolling windows | `detection_methods.py` |
| 4 | Modeling | Trains and versions two detectors per entity, Isolation Forest and Local Outlier Factor, which catch different kinds of outlier. An entity needs 50 observations to get its own model | `model_manager.py`, `train_models_background.py` |
| 5 | Scoring | Scores live data from 0.0 to 1.0, comparable across models. Thresholds adapt to business hours, recent false-positive levels and rising scores | `anomaly_detector.py`, `push_all_anomalies.py` |
| 6A | False-positive filtering | Recognizes known daemons, service accounts, internal and cloud IPs, and expected ports. Repeat benign behaviour is dampened over time rather than permanently allowlisted, so a compromised "known good" process can still surface | `benign_lists.py`, `push_all_anomalies.py`, `config/*.txt` |
| 6B | Enrichment | Looks up the raw events behind each anomaly, so the alert carries the command line, IPs, parent process and user, not just a score | `push_all_anomalies.py` |
| 6C | Threat mapping | Tags every detection with at least one MITRE ATT&CK technique ([coverage](detection-engine.md#what-it-detects)) | `push_all_anomalies.py`, `config.py` |
| 7 | Correlation | Links related anomalies per entity across ATT&CK stages into one attack story, instead of separate alerts. The biggest saving in analyst time | `post_correlation.py` |
| 8 | Output | Writes alerts to Elasticsearch (`ml-anomalies-custom-*`) and reports to `results/`. Outputs sit behind a backend interface; Elasticsearch is the one implemented | `push_all_anomalies.py`, `backends/` |

6A, 6B and 6C are independent steps over the same anomalies, so the diagram
draws them side by side.

The `models/` (PyOD ensemble) and `dl_models/` (deep learning) packages are
experimental and not used by the pipeline yet.

## Feedback loops

The two dashed arrows in the diagram:

- **Output back to ingestion:** alerts written to Elasticsearch are read on the
  next cycle. Confirmed detections tune the allowlist dampening and the
  thresholds, so the engine gets quieter and more accurate over time.
- **Threat mapping to output:** the ATT&CK technique stays on the alert all the
  way to Kibana and any other system that receives it.

## Add-ons

The optional [add-ons](add-ons.md) run as separate services. They share only the
Elasticsearch cluster with the engine:

| Add-on | Reads | Writes |
|---|---|---|
| SIEM Maintenance Agent | Cluster health APIs, endpoint indices (to check data still arrives) | Google Chat messages; optional fixes on the cluster |
| Alert Triage Agent | Elastic Security alerts and event indices, AbuseIPDB and VirusTotal | Verdicts on its web page, API and MCP server |
| Greenbone scan results | Greenbone's reports, through its local socket | `gvm-vulnerabilities` index |
