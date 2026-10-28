# Configuration

The detection engine reads its settings from two places:

| File | What it holds | Needed? |
|---|---|---|
| `.env` | Elasticsearch connection, index names, schedules. `deploy.sh` writes it; [.env.example](../.env.example) lists every setting | Yes |
| `config/*.txt` | False-positive lists describing your own infrastructure | No, but they cut noisy alerts |

After changing either, restart the engine:

```bash
sudo systemctl restart realtime_service.service    # or run ./deploy.sh again without systemd
```

## Connection: `.env`

| Setting | What to put |
|---|---|
| `ES_HOST` | Elasticsearch address with `https://` and port, e.g. `https://10.0.4.12:9200` |
| `ES_USERNAME`, `ES_PASSWORD` | A user that can read your endpoint, network and auth indices, and write `ml-anomalies-custom-*` |
| `ES_CA_CERT` | The certificate authority of a self-managed cluster, e.g. `config/certs/ca.pem` (`deploy.sh` saves it there when you choose to trust it). Not needed for a public certificate |
| `ES_VERIFY_CERTS` | `true` by default. `false` turns off certificate checks: lab use only |
| `ES_*_INDEX` | Index patterns: see [below](#index-names-and-field-names) |
| `DAGSHUB_*` | Optional, for MLflow experiment tracking. Leave empty |

`.env` holds passwords: it is never committed to git.

## Index names and field names

Wrong index patterns are the most common reason a run produces nothing. The
defaults match a standard Elastic Agent install:

```
ES_PROCESS_INDEX=.ds-logs-endpoint.events.process-default-*
ES_NETWORK_INDEX=.ds-logs-endpoint.events.network-default-*
ES_DISCOVERY_INDEX=logs-endpoint.events.process-*
ES_METADATA_INDEX=logs-endpoint.events.process-*,logs-endpoint.events.network-*
ES_ALERTS_INDEX=.internal.alerts-security.alerts-default-*
```

`deploy.sh` checks each one against your cluster. To see what your cluster
has:

```bash
curl -k -u elastic "https://YOUR_ES:9200/_cat/indices/*endpoint*,*alerts*?h=index&expand_wildcards=all"
```

The engine expects Elastic Common Schema field names (`process.name`,
`host.name`, `user.name`, `source.ip`, `destination.ip`, `destination.port`,
...). A data source with other field names needs code changes in the
`fetch_*_data` functions of `engine/datamanager.py`.

## False-positive lists: `config/*.txt`

These lists tell the engine what is normal on your network, so it does not
raise alerts for it. The files in `config/` are defaults. **Don't edit them:**
put your own version in `config/local/` with the same name. It replaces the
default and stays out of git.

```bash
mkdir -p config/local
cp config/internal_ip_prefixes.txt config/local/       # copy first to extend a default
echo "infra-01" >> config/local/infrastructure_hosts.txt
```

Format: one entry per line; `#` starts a comment; blank lines are ignored.

Two kinds of match:

- **Exact:** the value must equal a line.
- **Prefix:** the value must start with a line. For an IP range, write the
  start: `10.20.30.` covers `10.20.30.0/24`; `10.20.30.5` is one address.

| File | Match | What to put |
|---|---|---|
| `internal_ip_prefixes.txt` | IP, prefix | Your private ranges. The standard ones (`10.`, `172.16.`–`172.31.`, `192.168.`) are already there; add Kubernetes, VPN or other internal ranges |
| `platform_public_ips.txt` | IP, prefix | The public IPs your own servers use (e.g. your NAT gateway). Treated as internal. Empty if all traffic stays private |
| `cloud_ip_prefixes.txt` | IP, prefix | Cloud and CDN ranges (AWS, GCP, Azure, Cloudflare). Already filled; edit only for a provider not listed |
| `infrastructure_hosts.txt` | host name, exact | Your own servers that run service accounts and daemons (Elasticsearch nodes, proxies, CI runners). Service-account activity on other hosts is treated as more suspicious |
| `public_facing_hosts.txt` | host name, exact | Hosts meant to receive internet traffic (load balancers, public APIs). Used with `public_service_ports.txt` |
| `public_service_ports.txt` | port, exact | Ports those hosts serve: `80`, `443`, and any others you expose |
| `service_accounts.txt` | user name, exact | Non-interactive accounts (`kibana`, `elasticsearch`, daemons). Do **not** add `root` or admin logins |
| `benign_processes.txt` | process name, exact | Infrastructure daemons (agents, sidecars). Do **not** add general tools such as `bash`, `curl` or `nmap`: attackers use them too |
| `benign_process_prefixes.txt` | process name, prefix | Names with changing suffixes, e.g. `kworker/`, `containerd-shim`, `rcu_` |

**Start with** `internal_ip_prefixes.txt` and `infrastructure_hosts.txt`: those
two remove most of the noise from your own infrastructure. Add the others once
you see which alerts come from expected traffic.

## Schedules and sensitivity

All in `.env`. The defaults suit a first install.

| Setting | Default | What it controls |
|---|---|---|
| `ML_CONTAMINATION` | `0.05` | Expected share of anomalies: lower means fewer alerts |
| `DETECTION_INTERVAL_SECONDS` | `300` | Time between detection cycles |
| `RETRAIN_INTERVAL_HOURS` | `72` | Time between retrains |
| `ML_CLEANUP_INTERVAL_HOURS` | `1` | How often old output is deleted |
| `RESULT_ARTIFACT_MAX_AGE_HOURS` | `72` | How long files in `results/` are kept |
| `RESULT_ARTIFACT_MAX_FILES` | `6000` | Files kept per type in `results/` |

Other detection settings in `.env.example` (such as `SENSITIVITY`,
`THRESHOLD_MULTIPLIER`, `ML_N_ESTIMATORS` and `*_TRAINING_PERIOD_DAYS`) are
fixed in code in this release: changing them has no effect. A host or user needs
at least 50 observations to get its own model; this is also fixed.
