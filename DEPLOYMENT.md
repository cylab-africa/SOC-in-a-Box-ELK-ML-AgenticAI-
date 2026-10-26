# Deployment Guide

This guide is for anyone standing up this pipeline against **their own**
Elasticsearch cluster and environment. It covers every file you need to
edit, what format it expects, and what happens if you leave it at its
default.

## 0. Automated deployment (`deploy.sh`)

`deploy.sh` at the repo root automates sections 1, 5 and 6's setup work. It
is safe to re-run: existing `.env` files are kept unless you pass
`--reconfigure`, and existing systemd units that point at a different
checkout are never replaced without confirmation (or `--replace-units`).

| What | venv mode (default) | `--mode docker` |
|---|---|---|
| Detection pipeline | `.venv/`, `pip install -e .`, `realtime_service.service` | `detection` container |
| Maintenance add-on (`--with-maintenance`) | `addons/siem-maintenance/.venv/`, `siem-maintenance.service` | `siem-maintenance` container (`maintenance` profile) |
| Triage add-on (`--with-triage`) | `addons/alert-triage/.venv/`, `alert-triage.service` on `127.0.0.1:8000` | `alert-triage` container (`triage` profile), published on `127.0.0.1:8000` |
| Elastic Security (base) | installed on this host with `--install-elastic` (`installers/elastic-soc.sh`), or your cluster (`ES_HOST`, `--external-es`) | the same, or the bundled demo cluster with `--local-es` |

Steps it runs:

1. Preflight: Python 3.10+ and venv support (or Docker Compose v2), curl.
   Decides the base: install Elastic Security here, reuse an earlier install
   (`/etc/elastic-soc/connection.env` exists), or use an existing cluster (an
   `ES_HOST` is already set, or Elasticsearch already runs here). If none of
   those applies, it asks. `--install-elastic` / `--external-es` skip the
   question; `--non-interactive` never installs Elastic unless you pass
   `--install-elastic`.
2. Asks whether to add the SIEM Maintenance Agent (skip with
   `--with-maintenance` / `--no-maintenance`) and the Alert Triage Agent
   (`--with-triage` / `--no-triage`).
3. Base install (`--install-elastic`): runs `sudo bash installers/elastic-soc.sh`,
   which installs Elasticsearch and Kibana from Elastic's apt repository,
   serves Kibana over HTTPS with a certificate from a private SOC CA, installs
   Elastic Agent as Fleet Server with Elastic Defend and System on its policy,
   creates a "SOC Linux Endpoints" policy and enrollment token for other hosts,
   and enables Elastic's prebuilt Linux rules (`ELASTIC_RULES=linux|all|none`).
   Secrets stay root-only under `/etc/elastic-soc/`. `deploy.sh` then copies
   the cluster CA to `config/certs/ca.pem` and writes `ES_HOST`, the `elastic`
   credentials, and `ES_CA_CERT` into `.env`. Re-running is safe: finished
   steps are skipped, and it refuses to touch an Elasticsearch it did not
   install. It targets Ubuntu 24.04 (`ELASTIC_SOC_ALLOW_UNSUPPORTED_OS=1` to
   try another release).
4. Writes `.env` from `.env.example` with your ES URL, credentials, and index
   patterns, then checks the cluster answers. Credentials are passed to curl
   on stdin, never on the command line, and are only sent over a verified TLS
   connection. For a private CA set `ES_CA_CERT=/path/to/ca.pem`; for a lab
   cluster with a self-signed certificate pass `--insecure-tls` (or
   `ES_INSECURE_TLS=1`). Without either, an untrusted certificate is reported
   and no credentials are sent.
5. If the add-on is chosen: writes `addons/siem-maintenance/.env` reusing the
   same ES settings, plus Chat webhook, timezone, report time, and an optional
   LLM provider. Auto-remediation starts in dry-run unless you opt in.
6. Installs dependencies and (venv mode) systemd units, or builds and starts
   the containers.

Unattended examples (CI, Ansible, cloud-init):

```bash
# New Ubuntu 24.04 host: Elastic Security + detection engine + triage agent
SOC_ADVERTISE_ADDR=soc.example.org ./deploy.sh --non-interactive --install-elastic --with-triage
```

```bash
ES_HOST=https://10.0.4.12:9200 ES_USERNAME=detector ES_PASSWORD="$ES_PASSWORD" \
GC_ALERT_WEBHOOK="$CHAT_WEBHOOK" MAINTENANCE_IANA_TIMEZONE=Africa/Kigali \
  ./deploy.sh --non-interactive --with-maintenance
```

In `--non-interactive` mode every prompt takes its value from the environment
variable of the same name (`ES_HOST`, `ES_USERNAME`, `ES_PASSWORD`,
`ES_PROCESS_INDEX`, `KIBANA_HOST`, `GC_ALERT_WEBHOOK`, `LLM_PROVIDER`,
`LLM_MODEL`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AUTO_REMEDIATION_DRY_RUN`,
...) or its default. Use `--dry-run` to print every action without changing
anything.

The rest of this guide describes what the script configures, for when you
want to set things up by hand or tune past the defaults.

---

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
| `ES_CA_CERT` | Path to the CA that signed the cluster's HTTP certificate. For a self-managed cluster copy the node's `config/certs/http_ca.crt` to `config/certs/ca.pem` (gitignored, and visible inside the Docker image because `config/` is bind-mounted) and set `ES_CA_CERT=config/certs/ca.pem`. Not needed if the certificate is from a public CA | If your cluster uses a private or self-signed CA |
| `ES_VERIFY_CERTS` | TLS certificate verification, on by default. `false` disables it and logs a warning: credentials then go to whoever answers on `ES_HOST`, so use it only for lab clusters | No |
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

---

## 7. Optional add-on: SIEM Maintenance Agent

`addons/siem-maintenance/` is a `git subtree` of
[Siem-Maintenance-Agent-Monitoring](https://github.com/cylab-africa/Siem-Maintenance-Agent-Monitoring).
It is a separate process with its own venv, `.env`, and service, and shares
nothing with the detection pipeline except the Elasticsearch cluster.

- **Enable:** `./deploy.sh --with-maintenance` (short setup) or
  `./deploy.sh --maintenance-wizard` (the add-on's own `install.sh`, which
  also sets up the Google Chat app, feedback loop, and feedback services).
- **Configure:** `addons/siem-maintenance/.env`. The agent also reads
  `addons/siem-maintenance/Agent-SIEM-maintenance/.env`; `deploy.sh` keeps the
  two identical, so after editing by hand copy the root one over the other.
  Full variable list: [addons/siem-maintenance/README.md](addons/siem-maintenance/README.md).
- **Auto-remediation:** clears caches, restarts stopped ML jobs, and removes
  old snapshots / empty non-essential indices. `deploy.sh` sets
  `AUTO_REMEDIATION_DRY_RUN=true`; review the dry-run entries in
  `Agent-SIEM-maintenance/results/auto_remediation_log.jsonl` before setting
  it to `false`.
- **Docker + Ollama:** inside a container `localhost` is the container itself;
  point `OLLAMA_URL` at `http://host.docker.internal:11434` or the host IP.
- **Disable:** `sudo systemctl disable --now siem-maintenance.service`, or run
  compose without `--profile maintenance`.
- **Update from upstream:**

  ```bash
  git subtree pull --prefix=addons/siem-maintenance --squash \
    https://github.com/cylab-africa/Siem-Maintenance-Agent-Monitoring.git main
  ```

  Keep local edits under `addons/` to a minimum so these pulls merge cleanly;
  fix bugs upstream instead.

---

## 8. Optional add-on: Alert Triage Agent

`addons/alert-triage/` is a `git subtree` of
[Alert-Triage-Agent](https://github.com/masterlion-hash/Alert-Triage-Agent): AI-assisted
investigation of Elastic Security alerts, served as a web UI, a REST API
(`/api/triage`, `/api/investigate/<alert_id>`), and an MCP server at `/mcp/mcp`.
It is a separate process with its own venv, `.env`, and service.

- **Enable:** `./deploy.sh --with-triage`. It writes `addons/alert-triage/.env`
  from the pipeline's ES settings (the agent uses its own variable names:
  `ELASTIC_URL`, `ELASTIC_USERNAME`, ...), asks for an AI backend
  (`none`, `ollama`, `claude`, `openai_compat`) and optional AbuseIPDB /
  VirusTotal keys, installs it, and starts `alert-triage.service`.
- **Access control:** the agent has **no authentication**, allows any CORS
  origin, and disables MCP DNS-rebinding protection. Anyone who can reach the
  port can list alerts, run investigations with its ES credentials, and spend
  your LLM API quota. `deploy.sh` binds it to `127.0.0.1` (and the container to
  `127.0.0.1:<port>` on the host); `--triage-listen ADDR` widens that after a
  warning. To share it with analysts, put an authenticating reverse proxy in
  front of the loopback port rather than exposing it directly.
- **Least privilege:** it only calls `_search` on the alerts index and event
  indices. Create a read-only role for those indices and enter that user when
  `deploy.sh` asks for the triage agent's credentials.
- **TLS:** it follows the pipeline's setting (`ELASTIC_VERIFY_SSL` mirrors
  `ES_VERIFY_CERTS`). With `ES_CA_CERT`, `deploy.sh` builds
  `addons/alert-triage/certs/ca-bundle.pem` (system CAs plus your cluster CA) and
  points `SSL_CERT_FILE` at it. A bundle containing only the cluster CA would
  break the agent's HTTPS calls to threat-intel and LLM APIs.
- **Dependency pin:** `addons/alert-triage.constraints.txt` pins `mcp<2`.
  Upstream requires `mcp>=1.2.0`, which now installs MCP SDK 2.x, where
  `FastMCP` was renamed, and the agent fails to start. Remove the pin once
  upstream pins it.
- **Asset inventory:** copy `assets.example.yml` to `assets.yml` in the add-on
  directory (gitignored). In Docker it is baked into the image at build time,
  so rebuild after editing it.
- **Kibana integration:** `deploy/create_investigate_dashboard.py` and
  `deploy/create_canvas.py` in the add-on add an "Investigate with Agent"
  drilldown to Kibana. Those links open the agent in the analyst's browser, so
  they need the reverse-proxy setup above.
- **Disable:** `sudo systemctl disable --now alert-triage.service`, or run
  compose without `--profile triage`.
- **Update from upstream:**

  ```bash
  git subtree pull --prefix=addons/alert-triage --squash \
    https://github.com/masterlion-hash/Alert-Triage-Agent.git main
  ```
