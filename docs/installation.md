# Installation

## Prerequisites

- A Linux server with Python 3.10 or newer
- An Elastic Stack 8.x (Elasticsearch, Kibana, Fleet) and its address, plus
  an admin login such as `elastic`. `deploy.sh` uses it once to create a limited
  API key for each part and does not save it ([Elasticsearch API keys](configuration.md#elasticsearch-api-keys)).
  A ready-made API key or a username and password also work. No stack yet? See [Install the Elastic Stack](elastic-stack.md)
  (single-server script, or Elastic's own guides).
- Elastic Agent on the Linux hosts you want to monitor, with the
  **Elastic Defend** and **System** integrations
- About 7 days of their data, for the models to learn from

## Install

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
./deploy.sh
```

The script asks which add-ons you want and for your Elasticsearch address and
login, then installs and starts everything. It ends with a summary: a green
✔ means that part is running.

A self-managed Elasticsearch usually triggers a certificate question. Choose
**1** to trust the certificate (recommended), or **2** to skip the check on a
lab cluster.

To install by hand instead, see the [manual installation](manual-installation.md).

## Useful options

| Command | What it does |
|---|---|
| `./deploy.sh --dry-run` | Shows every step without changing anything |
| `./deploy.sh --only triage` | Adds one add-on later (`maintenance`, `triage` or `greenbone`) |
| `./deploy.sh --reconfigure` | Asks for the settings again |
| `./deploy.sh --help` | Lists every option |

## After the install

In Kibana, add `ml-anomalies-custom-*` as a data view. Alerts appear there once
the models have trained, which the engine does on its first cycle.

To check each stage:

| Check | Command | Expected |
|---|---|---|
| Models trained | `grep "Successfully trained" logs/trainer.log` | one line per group |
| Detection ran | `grep "Anomalies detected" logs/linux_anomaly_detection.log \| tail -1` | a number above 0 |
| Alerts sent | `curl -k -u elastic "$ES_HOST/ml-anomalies-custom-*/_count"` | a count above 0 |

After editing `.env`, restart the engine:

```bash
sudo systemctl restart realtime_service.service
```

On a machine without systemd, run `./deploy.sh` again instead.

Problems? See [troubleshooting](troubleshooting.md).
