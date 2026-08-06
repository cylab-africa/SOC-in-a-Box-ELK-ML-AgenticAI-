# Deployment Guide

This guide is for anyone standing up this pipeline against **their own**
Elasticsearch cluster and environment. It covers every file you need to
edit, what format it expects, and what happens if you leave it at its
default.

Two tiers of configuration:

- **Required** — the pipeline will not connect to Elasticsearch or will
  produce meaningless results without these.
- **Tuning** — false-positive (FP) classification lists. The pipeline runs
  fine with these empty or default; skipping them just means more noisy
  alerts on your own infrastructure until you fill them in.

---

## 1. Required: `.env`

```bash
cp .env.example .env
```

Then edit `.env`. The fields that matter most:

| Variable | What to put | Required |
|---|---|---|
| `ES_HOST` | Your Elasticsearch URL, e.g. `https://10.0.4.12:9200` | Yes |
| `ES_USERNAME` / `ES_PASSWORD` | Credentials for an account with read access to your endpoint/network/auth indices and write access to `.ml-anomalies-custom-*` | Yes |
| `ES_PROCESS_INDEX`, `ES_NETWORK_INDEX`, `ES_DISCOVERY_INDEX`, `ES_METADATA_INDEX`, `ES_ALERTS_INDEX` | Index patterns matching your data source naming. Defaults assume Elastic Agent/Endpoint's standard `logs-endpoint.events.*` naming — change these if your ingest pipeline names indices differently | Yes, if your index names differ from the defaults |
| `DAGSHUB_USERNAME` / `DAGSHUB_REPO_NAME` / `DAGSHUB_TOKEN` | Only needed if you want MLflow experiment tracking via DagsHub. Leave blank to skip — `setup_mlflow()` in `main.py` will attempt the connection, fail, log a warning, and detection continues without MLflow tracking (this adds a short connection-timeout delay at startup rather than failing instantly; pass `--disable-mlflow` to skip the attempt entirely) | No |
| `TRAINING_PERIOD_DAYS`, `THRESHOLD_MULTIPLIER`, `SENSITIVITY`, etc. | Detection tuning knobs — safe to leave at defaults for a first run | No |

`.env` is gitignored — it is never meant to be committed. Everything in it
is read by `config.py`'s `ConfigManager`, which is also what
`linux_anomaly_detection_config.yaml` reads through via `${VAR}`
interpolation (e.g. `password: "${ES_PASSWORD}"`), so you should not need
to touch that YAML file directly — just set the env vars.

---

## 2. Required: verify your Elasticsearch index/field naming

The pipeline assumes ECS-style field names (`process.name`, `host.name`,
`user.name`, `destination.ip`, `destination.port`, `source.ip`, ...). If
your data source uses different field names, you'll need to adjust the
field references in `datamanager.py` (`fetch_*_data` functions) or add a
mapping layer — this is the one piece of "editing Python, not config"
that's likely unavoidable for a non-Elastic-Agent data source.

---

## 3. Tuning: false-positive classification lists (`config/*.txt`)

These are plain text files consumed by `push_all_anomalies.py`. Format
rules for all of them:

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
| `config/internal_ip_prefixes.txt` | `source.ip` / `destination.ip` (prefix) | Your private IP ranges: RFC1918 blocks (`10.`, `172.16.`–`172.31.`, `192.168.`) are already there. Add your Kubernetes pod/service CIDRs, VPN ranges, or any other internal-only subnet allocation your org uses that isn't standard RFC1918. |
| `config/platform_public_ips.txt` | `source.ip` / `destination.ip` (prefix) | The **public** IPs your own infrastructure is seen from — e.g. your NAT gateway's egress IP, or your servers' public WAN IPs if they're not behind NAT. Traffic to/from these is treated as internal even though it's not RFC1918. Leave empty if all your traffic stays on private IPs. |
| `config/cloud_ip_prefixes.txt` | `source.ip` / `destination.ip` (prefix) | Cloud/CDN provider ranges (AWS, GCP, Azure, Cloudflare, etc.) — pre-populated with common public ranges. You generally don't need to edit this unless you use a cloud provider not already covered. |
| `config/infrastructure_hosts.txt` | `host.name` (exact) | Hostnames of your own servers — anything that legitimately runs service accounts and infra daemons (your ES nodes, reverse proxies, CI runners, etc.). Anomalies from service accounts on hosts *not* in this list are treated as more suspicious, not less. |
| `config/public_facing_hosts.txt` | `host.name` (exact) | Hostnames that are meant to receive inbound internet traffic (load balancers, public APIs, edge proxies). Combined with `public_service_ports.txt`, this suppresses noise from expected inbound connections on those hosts. |
| `config/public_service_ports.txt` | `destination.port` (exact) | Ports your public-facing hosts legitimately listen on: `80`, `443`, and anything else you expose (e.g. `8443`, a custom API port). `22`, `53`, and `123` are always treated as benign on cloud-provider IPs regardless of this list. |
| `config/service_accounts.txt` | `user.name` (exact) | Non-interactive/system account usernames (`kibana`, `elasticsearch`, service daemons). Deliberately **exclude** high-privilege accounts like `root` or admin logins — those should always be reviewed on their own merits, not allowlisted. |
| `config/benign_processes.txt` | `process.name` (exact) | Infrastructure daemon process names you want to always treat as benign when combined with internal-only traffic (agents, sidecars). Deliberately does **not** include general-purpose tools/LOLBins (`bash`, `curl`, `nmap`, etc.) — allowlisting those would blind the detector to real living-off-the-land activity. |
| `config/benign_process_prefixes.txt` | `process.name` (prefix) | Process name prefixes for things with variable suffixes, e.g. `kworker/`, `containerd-shim`, `rcu_` (kernel worker threads), or a sensor agent's versioned binary name. |

**Recommendation for a first deployment:** start with `internal_ip_prefixes.txt` and `infrastructure_hosts.txt` — those two alone eliminate most of the "known-infra chatter" false positives. Add to `platform_public_ips.txt`, `public_facing_hosts.txt`, and `service_accounts.txt` once you've identified which of your alerts are coming from expected infrastructure rather than iterating on all eight files up front.

---

## 4. Tuning: detection thresholds (`config/default.yaml`)

Copy and edit if you want to change ML thresholds, training windows, or
per-data-group sensitivity without touching `.env`. Values here are
overridden by the matching environment variable if both are set (see
`.env.example` for the full list) — `config/default.yaml` is the
lower-precedence, more structured place to set them if you'd rather edit
YAML than a flat env file. Not required for a first run; the shipped
defaults are reasonable starting points.

---

## 5. Docker deployment

```bash
cp .env.example .env   # fill in as above
docker compose --env-file .env -f docker/docker-compose.yml up
```

This starts three services (`docker/docker-compose.yml`):

- `elasticsearch` / `kibana` — a local ES + Kibana stack, useful for a
  demo/dev environment. **Skip or remove these services** if you're
  pointing at an existing production Elasticsearch cluster — just run
  the `detection` service with `ES_HOST` in `.env` pointed at your real
  cluster.
- `detection` — builds from `docker/Dockerfile`, reads `.env` via
  `env_file: ../.env`, and runs `realtime_service.py` by default.

Passing `--env-file .env` explicitly (as above) avoids version-dependent
ambiguity in where Compose looks for `.env` for `${VAR}` substitution in
the compose file itself (e.g. `${ES_PASSWORD}`) — always run it from the
repo root.

`config/` is bind-mounted into the container
(`../config:/app/config`), so editing the `.txt` files on the host takes
effect without rebuilding the image — only code changes require a
rebuild.

---

## 6. Sanity-check before going live

```bash
python main.py --list-jobs          # confirms ES connectivity and job registration
python main.py --data-group process --train-models   # trains on your data
python main.py --data-group process                  # runs detection, no push
python push_all_anomalies.py --dry-run                # shows what would be pushed, pushes nothing
```

Once those look right, drop `--dry-run` and/or switch to
`realtime_service.py` for continuous operation.
