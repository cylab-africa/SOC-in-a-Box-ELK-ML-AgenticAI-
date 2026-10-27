# Troubleshooting

Start with the four checks in
[installation.md](installation.md#step-3--confirm-alerts-reach-kibana). The first
one that fails tells you where to look.

| What you see | What it means | What to do |
|---|---|---|
| `index_not_found_exception` | Index pattern in `.env` doesn't match your cluster | Run the `_cat/indices` command in [configuration.md](configuration.md#index-names-and-field-names) and correct the patterns |
| `{"count":0}` on the input check | Elastic Agent isn't shipping endpoint data | Confirm the agent is healthy in Fleet and that **Elastic Defend** is in its policy |
| `ERROR - process_detection: no results produced for v3_...` | The job found no matching data | Usually wrong index pattern, or the time window has no events. Run checks 1 and 3 in [installation.md](installation.md#step-3--confirm-alerts-reach-kibana) |
| `Insufficient samples for X: 1 < 50` | That entity lacks history for its own model | Normal in small or new environments. Collect more data; the 50-observation minimum is fixed in this release |
| `ERROR - Missing model for entity <name>` | Scoring ran before that group was trained | Run `python engine/train_models_background.py --all` and re-run detection |
| `TLS certificate verification failed. Set ES_CA_CERT=...` | The cluster's certificate is signed by a CA this host doesn't trust (the default for self-managed Elasticsearch) | Copy the node's `config/certs/http_ca.crt` to `config/certs/ca.pem` and set `ES_CA_CERT=config/certs/ca.pem` in `.env`. `ES_VERIFY_CERTS=false` also works but is lab-only |
| `401 Unauthorized` / `AuthenticationException` | Bad credentials | Recheck `ES_USERNAME` / `ES_PASSWORD`; confirm with the `curl` check in [installation.md](installation.md#step-1--have-an-elastic-stack-with-endpoint-data) |
| `[FAIL]` from `deploy.sh` | A preflight or connectivity check failed | The line says which; fix it and re-run `./deploy.sh` (it is safe to re-run) |
| Detection runs but no alerts in Kibana | Alerts not pushed, or no data view | Run `python engine/push_all_anomalies.py`, then add `ml-anomalies-custom-*` as a Kibana data view |
| `results/` growing to tens of GB | Old output not being cleaned | `engine/realtime_service.py` prunes automatically; if you run `engine/main.py` on a cron, delete `results/ml_only_*` files older than a few days yourself |

Still stuck? Open an issue with your Python version, Elasticsearch version, and
the last 50 lines of `logs/linux_anomaly_detection.log`. Remove hostnames, IP
addresses, and usernames from your environment before posting.
