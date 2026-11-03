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
| `ES_API_KEY` | An API key for the engine (recommended): see [Elasticsearch API keys](#elasticsearch-api-keys). Wins over the username and password when both are set |
| `ES_USERNAME`, `ES_PASSWORD` | Or a user that can read your endpoint, network and auth indices, and write `ml-anomalies-custom-*` |
| `ES_CA_CERT` | The certificate authority of a self-managed cluster, e.g. `config/certs/ca.pem` (`deploy.sh` saves it there when you choose to trust it). Not needed for a public certificate |
| `ES_VERIFY_CERTS` | `true` by default. `false` turns off certificate checks: lab use only |
| `ES_*_INDEX` | Index patterns: see [below](#index-names-and-field-names) |
| `DAGSHUB_*` | Optional, for MLflow experiment tracking. Leave empty |

`.env` holds passwords and keys: it is never committed to git.

## Elasticsearch API keys

Every part of SOC-in-a-Box can log in to Elasticsearch in either of two ways:

- **An API key (recommended).** Give each part its own key with only the
  privileges it needs. If a key leaks, revoke it in Kibana; no user account or
  password changes, and the other parts keep working.
- **A username and password.** Simpler for a lab. Avoid the `elastic`
  superuser: a leaked superuser password exposes the whole cluster.

`./deploy.sh` asks which one each part should use. Press Enter at an add-on's
question to reuse the detection engine's login.

| Part | Setting | File |
|---|---|---|
| Detection engine | `ES_API_KEY`, or `ES_USERNAME` + `ES_PASSWORD` | `.env` |
| SIEM Maintenance Agent | `ES_API_KEY` (with `ES_AUTH_TYPE=apikey`), or `ES_USERNAME` + `ES_PASSWORD` | `addons/siem-maintenance/.env` |
| Alert Triage Agent | `ELASTIC_API_KEY`, or `ELASTIC_USERNAME` + `ELASTIC_PASSWORD` | `addons/alert-triage/.env` |
| Greenbone results push | `ES_API_KEY`, or `ES_USERNAME` + `ES_PASSWORD` | `addons/greenbone/.env` |

For `./deploy.sh --non-interactive`, set `ES_API_KEY` for the engine and
`MAINTENANCE_ES_API_KEY`, `TRIAGE_ES_API_KEY` or `GREENBONE_ES_API_KEY` for the
add-ons. Use `*_ES_USERNAME` and `*_ES_PASSWORD` for a username and password instead.

### Create the keys

Open Kibana, go to **Dev Tools**, and run the request for each part you
install. Copy the `encoded` value from the response: it is shown only once,
and it is what `deploy.sh` asks for. Run the requests as a user that holds
these privileges itself, because a key can never do more than its creator.

**Detection engine.** Reads the endpoint, auth and alert data, and writes its own results.

```
POST /_security/api_key
{
  "name": "soc-in-a-box-engine",
  "role_descriptors": {
    "soc_engine": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["logs-endpoint.events.*", ".ds-logs-endpoint.events.*",
                    "logs-system.auth-*", ".ds-logs-system.auth-*",
                    ".alerts-security.alerts-*", ".internal.alerts-security.alerts-*"],
          "privileges": ["read", "view_index_metadata"]
        },
        {
          "names": ["ml-anomalies-custom*", "ml-anomalies-correlated*", ".ml-anomalies-custom-*"],
          "privileges": ["read", "view_index_metadata", "create_index", "index"]
        }
      ]
    }
  }
}
```

If you changed the `ES_*_INDEX` patterns in `.env`, put the same patterns in the first `names` list.

**Alert Triage Agent.** Read-only: it searches alerts and related events.

```
POST /_security/api_key
{
  "name": "soc-in-a-box-triage",
  "role_descriptors": {
    "soc_triage": {
      "indices": [
        {
          "names": [".alerts-security.alerts-*", ".internal.alerts-security.alerts-*",
                    "logs-*", "filebeat-*", "winlogbeat-*", "auditbeat-*"],
          "privileges": ["read", "view_index_metadata"]
        }
      ]
    }
  }
}
```

**SIEM Maintenance Agent, report only** (the default, `AUTO_REMEDIATION_DRY_RUN=true`).
Reads cluster health and checks that logs are still arriving.

```
POST /_security/api_key
{
  "name": "soc-in-a-box-maintenance",
  "role_descriptors": {
    "soc_maintenance": {
      "cluster": ["monitor", "monitor_ml", "monitor_transform", "monitor_watcher",
                  "monitor_snapshot", "read_ilm", "read_slm"],
      "indices": [
        {
          "names": ["*"],
          "privileges": ["monitor", "view_index_metadata"]
        },
        {
          "names": ["logs-*", ".ds-logs-*", ".ds-elastic-cloud-logs-*", ".monitoring-es-*",
                    ".ml-anomalies-*", "ml-anomalies-*"],
          "privileges": ["read"]
        }
      ]
    }
  }
}
```

**SIEM Maintenance Agent, with automatic fixes** (`AUTO_REMEDIATION_DRY_RUN=false`).
The fixes change the cluster: they clear caches, reroute shards, restart ML jobs
and transforms, and delete old snapshots and empty indices. In the request
above, add these to `cluster`:

```
"manage", "manage_ml", "manage_transform", "manage_watcher", "manage_ilm", "manage_slm"
```

and add this entry to `indices`:

```
{ "names": ["*"], "privileges": ["manage", "delete_index"] }
```

**Greenbone results push.** Writes scan results to its own index.

```
POST /_security/api_key
{
  "name": "soc-in-a-box-greenbone",
  "role_descriptors": {
    "soc_greenbone": {
      "cluster": ["monitor"],
      "indices": [
        {
          "names": ["gvm-vulnerabilities*"],
          "privileges": ["create_index", "index", "read", "view_index_metadata", "manage"]
        }
      ]
    }
  }
}
```

You can also create keys in Kibana: **Stack Management > Security > API keys >
Create API key**. Turn on **Control security privileges** and paste the
`role_descriptors` object from the matching request above.

### Revoke a key

In Kibana, go to **Stack Management > Security > API keys**, select the key and
choose **Delete**. Or in Dev Tools:

```
DELETE /_security/api_key
{ "name": "soc-in-a-box-triage" }
```

Then create a new key, put it in that part's `.env` file and restart the part,
for example `sudo systemctl restart alert-triage`.

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
