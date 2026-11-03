# Troubleshooting

Start with the checks in [After the install](installation.md#after-the-install).
The first one that fails tells you where to look.

## During the install

| What you see | What to do |
|---|---|
| `Could not reach Elasticsearch at https://localhost:9200` | The address is wrong: `localhost` only works when Elasticsearch runs on the same server. Choose 1 and type the right address, e.g. `https://10.0.0.5:9200` |
| `rejected the username or password` | Choose 1 and type the login again, or later run `./deploy.sh --reconfigure` |
| A certificate fingerprint and a 1/2/3 question | Normal for a self-managed cluster. Choose 1 to trust the certificate, or 2 on a lab cluster |
| `Greenbone is not installed on this server` | Install Greenbone first ([commands](add-ons.md#install-greenbone-first)), then run `./deploy.sh --only greenbone` |
| `Could not install python3-venv` or `python3 cannot create a venv` | `deploy.sh` installs `python3-venv` itself with apt. If that fails (no sudo, no network), run `sudo apt install -y python3-venv python3.12-venv` (use your Python version), then run `./deploy.sh` again |
| Any other `[FAIL]` line | It says what went wrong. Fix it and run `./deploy.sh` again; it is safe to repeat |

## After the install

| What you see | Meaning | What to do |
|---|---|---|
| A data pattern marked `!` in the summary | Nothing on your cluster matches it | List your indices with the command the summary prints, fix the pattern in `.env`, restart the engine |
| `index_not_found_exception` | An index pattern in `.env` does not match your cluster | See [index names](configuration.md#index-names-and-field-names) |
| The data patterns exist but have 0 documents | Elastic Agent is not sending endpoint data | In Fleet, check the agent is healthy and **Elastic Defend** is in its policy |
| `no results produced for v3_...` | The job found no matching data | Usually a wrong index pattern, or no events in the time window. Check the index patterns in `.env` |
| `Insufficient samples for X: 1 < 50` | That host or user has too little history for its own model | Normal at first. It needs 50 observations |
| `Missing model for entity <name>` | Detection ran before training | `.venv/bin/python engine/train_models_background.py --all` |
| `TLS certificate verification failed` | This server does not trust the cluster's certificate | `./deploy.sh --reconfigure` and answer the certificate question |
| `401 Unauthorized` / `AuthenticationException` | Wrong login | Check `ES_USERNAME` and `ES_PASSWORD` in `.env` |
| Detection runs but no alerts in Kibana | Alerts not sent, or no data view | `.venv/bin/python engine/push_all_anomalies.py`, then add `ml-anomalies-custom-*` as a data view |
| Services gone after a restart (no systemd) | Background processes do not survive a restart | Run `./deploy.sh` again |
| `results/` grows to tens of GB | Old output is not being deleted | The service deletes it automatically. If you run `engine/main.py` yourself on a schedule, delete old `results/ml_only_*` files too |

After changing `.env`, restart the engine:

```bash
sudo systemctl restart realtime_service.service
```

Without systemd, run `./deploy.sh` again instead.

Add-on problems: see the troubleshooting section of the
[SIEM Maintenance Agent](../addons/siem-maintenance/README.md#troubleshooting),
[Alert Triage Agent](../addons/alert-triage/README.md#troubleshooting) or
[Greenbone](../addons/greenbone/README.md#troubleshooting) README.

## Still stuck?

Open an issue with your Python and Elasticsearch versions and the last 50 lines
of `logs/linux_anomaly_detection.log`. Remove hostnames, IP addresses and
usernames first.
