# Configuration

Everything the detection engine reads comes from two places:

- **`.env`** — connection settings and every detection, training, and service
  setting. `deploy.sh` writes it for you; [.env.example](../.env.example) lists
  every variable with its default.
- **`config/*.txt`** — the false-positive lists that describe your own
  infrastructure.

Two tiers:

- **Required** — the engine will not connect to Elasticsearch or will produce
  meaningless results without these.
- **Tuning** — the engine runs fine with defaults; tuning just means fewer noisy
  alerts on your own infrastructure.

## Required: `.env`

```bash
cp .env.example .env
```

| Variable | What to put | Required |
|---|---|---|
| `ES_HOST` | Your Elasticsearch URL, e.g. `https://10.0.4.12:9200` | Yes |
| `ES_USERNAME` / `ES_PASSWORD` | Credentials for an account with read access to your endpoint/network/auth indices and write access to `.ml-anomalies-custom-*` | Yes |
| `ES_CA_CERT` | Path to the CA that signed the cluster's HTTP certificate. For a self-managed cluster copy the node's `config/certs/http_ca.crt` to `config/certs/ca.pem` (gitignored, and visible inside the Docker image because `config/` is bind-mounted) and set `ES_CA_CERT=config/certs/ca.pem`. Not needed if the certificate is from a public CA | If your cluster uses a private or self-signed CA |
| `ES_VERIFY_CERTS` | TLS certificate verification, on by default. `false` disables it and logs a warning: credentials then go to whoever answers on `ES_HOST`, so use it only for lab clusters | No |
| `ES_PROCESS_INDEX`, `ES_NETWORK_INDEX`, `ES_DISCOVERY_INDEX`, `ES_METADATA_INDEX`, `ES_ALERTS_INDEX` | Index patterns matching your data source naming. See [below](#index-names-and-field-names) | Yes, if your index names differ from the defaults |
| `DAGSHUB_USERNAME` / `DAGSHUB_REPO_NAME` / `DAGSHUB_TOKEN` | Only needed for MLflow experiment tracking via DagsHub (install with `pip install -e ".[ops]"`). Leave blank to skip; pass `--disable-mlflow` to `main.py` to skip the connection attempt entirely | No |

`.env` is gitignored — it is never meant to be committed.

## Index names and field names

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

The engine assumes ECS-style field names (`process.name`, `host.name`,
`user.name`, `destination.ip`, `destination.port`, `source.ip`, ...). If your
data source uses different field names, you'll need to adjust the field
references in `datamanager.py` (`fetch_*_data` functions) or add a mapping
layer — this is the one piece of "editing Python, not config" that's likely
unavoidable for a non-Elastic-Agent data source.

## Tuning: false-positive lists (`config/*.txt`)

These are plain text files consumed by `push_all_anomalies.py`. The copies in
`config/` are generic defaults, and the environment-specific ones
(`infrastructure_hosts.txt`, `public_facing_hosts.txt`,
`platform_public_ips.txt`) ship empty. **Don't edit the defaults:** put your
version in `config/local/<same name>.txt`, which is gitignored and replaces the
default entirely. That keeps your network layout out of version control and out
of merge conflicts on upgrade.

```bash
mkdir -p config/local
cp config/internal_ip_prefixes.txt config/local/   # copy first if you want to extend a default
echo "infra-01" >> config/local/infrastructure_hosts.txt
```

Format rules for all of them:

- One entry per line
- Lines starting with `#` are comments
- Blank lines are ignored
- No quoting needed

They fall into two matching modes:

- **Exact match** (`benign_processes.txt`, `service_accounts.txt`,
  `infrastructure_hosts.txt`, `public_facing_hosts.txt`,
  `public_service_ports.txt`) — the field must equal a line exactly.
- **Prefix match** (`benign_process_prefixes.txt`,
  `internal_ip_prefixes.txt`, `platform_public_ips.txt`,
  `cloud_ip_prefixes.txt`) — the field just needs to *start with* a line.
  This is how you express a CIDR-ish range without real CIDR math: a `/24`
  is written as the first three octets plus a trailing dot (`10.20.30.`),
  a `/32` (single host) is written in full (`10.20.30.5`).

| File | Matches against | What to put |
|---|---|---|
| `internal_ip_prefixes.txt` | `source.ip` / `destination.ip` (prefix) | Your private IP ranges: RFC1918 blocks (`10.`, `172.16.`–`172.31.`, `192.168.`) are already there. Add your Kubernetes pod/service CIDRs, VPN ranges, or any other internal-only subnet allocation your org uses that isn't standard RFC1918. |
| `platform_public_ips.txt` | `source.ip` / `destination.ip` (prefix) | The **public** IPs your own infrastructure is seen from — e.g. your NAT gateway's egress IP, or your servers' public WAN IPs if they're not behind NAT. Traffic to/from these is treated as internal even though it's not RFC1918. Leave empty if all your traffic stays on private IPs. |
| `cloud_ip_prefixes.txt` | `source.ip` / `destination.ip` (prefix) | Cloud/CDN provider ranges (AWS, GCP, Azure, Cloudflare, etc.) — pre-populated with common public ranges. You generally don't need to edit this unless you use a cloud provider not already covered. |
| `infrastructure_hosts.txt` | `host.name` (exact) | Hostnames of your own servers — anything that legitimately runs service accounts and infra daemons (your ES nodes, reverse proxies, CI runners, etc.). Anomalies from service accounts on hosts *not* in this list are treated as more suspicious, not less. |
| `public_facing_hosts.txt` | `host.name` (exact) | Hostnames that are meant to receive inbound internet traffic (load balancers, public APIs, edge proxies). Combined with `public_service_ports.txt`, this suppresses noise from expected inbound connections on those hosts. |
| `public_service_ports.txt` | `destination.port` (exact) | Ports your public-facing hosts legitimately listen on: `80`, `443`, and anything else you expose (e.g. `8443`, a custom API port). `22`, `53`, and `123` are always treated as benign on cloud-provider IPs regardless of this list. |
| `service_accounts.txt` | `user.name` (exact) | Non-interactive/system account usernames (`kibana`, `elasticsearch`, service daemons). Deliberately **exclude** high-privilege accounts like `root` or admin logins — those should always be reviewed on their own merits, not allowlisted. |
| `benign_processes.txt` | `process.name` (exact) | Infrastructure daemon process names you want to always treat as benign when combined with internal-only traffic (agents, sidecars). Deliberately does **not** include general-purpose tools/LOLBins (`bash`, `curl`, `nmap`, etc.) — allowlisting those would blind the detector to real living-off-the-land activity. |
| `benign_process_prefixes.txt` | `process.name` (prefix) | Process name prefixes for things with variable suffixes, e.g. `kworker/`, `containerd-shim`, `rcu_` (kernel worker threads), or a sensor agent's versioned binary name. |

**Recommendation for a first deployment:** start with `internal_ip_prefixes.txt`
and `infrastructure_hosts.txt` — those two alone eliminate most of the
"known-infra chatter" false positives. Add to `platform_public_ips.txt`,
`public_facing_hosts.txt`, and `service_accounts.txt` once you've identified
which of your alerts are coming from expected infrastructure rather than
iterating on all eight files up front.

## Tuning: detection, training, and the service

All set in `.env`; the shipped defaults are reasonable starting points and a
first run needs none of them.

| Variable | Default | What it controls |
|---|---|---|
| `ML_CONTAMINATION` | `0.05` | Expected share of anomalies in training data; lower means fewer alerts |
| `DETECTION_INTERVAL_SECONDS` | `300` | Seconds between detection cycles (`realtime_service.py`) |
| `RETRAIN_INTERVAL_HOURS` | `72` | Hours between background retrains |
| `ML_CLEANUP_INTERVAL_HOURS` | `1` | How often the service prunes its own output |
| `RESULT_ARTIFACT_MAX_AGE_HOURS` | `72` | How long the service keeps files in `results/` |
| `RESULT_ARTIFACT_MAX_FILES` | `6000` | Files kept per output pattern in `results/` |

In the current release the training windows, model sizes, and the remaining
detection thresholds in `.env.example` (for example `SENSITIVITY`,
`THRESHOLD_MULTIPLIER`, `ML_N_ESTIMATORS`, `*_TRAINING_PERIOD_DAYS`) are fixed
in code, and setting them has no effect.

An entity needs at least 50 observations before it gets its own model; entities
with fewer are skipped during training. That minimum is also fixed.
