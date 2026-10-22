# 9. Deployment Guide — Fresh Ubuntu Host

> **This Git repository:** you can deploy **`maintenance_service.py`** with **`deploy/install-systemd-service.sh`** (installs **`siem-maintenance.service`** on Linux, survives reboot), or manually with a **systemd** `ExecStart` pointing at your venv **`python`** and **`Agent-SIEM-maintenance/maintenance_service.py`**. Env is read from **`.env`** via **`python-dotenv`**. Full mapping from this chapter’s **`python -m siem_maint`** layout: [**docs/00**](00-design-spec-vs-this-repo.md).

This section walks through a full install on a clean **Ubuntu 22.04 or
24.04 LTS** host. A host with **2 vCPU, 4 GB of RAM, and 20 GB of
disk** is sufficient — the RAM and disk requirements are driven by
Ollama and the Gemma 4 E4B model, not by the monitoring code itself.

## Before starting

**Getting the source.** The module is maintained by the
SIEM-MAINTENANCE platform team as an internal project. The release
tarball `siem-maint-<version>.tar.gz` is published to the internal
artifact server at the URL distributed by the platform team when a
new version is cut; request access through the normal internal
channels if this is a first-time deployment. The tarball contains the
full `siem_maint/` package, a pinned `requirements.txt`, a
`setup.cfg` that makes the package installable, and this deployment
guide as a `README`.

> Do not try to reconstruct the tarball by copying snippets out of
> [`docs/01`](01-what-is-watched.md) through
> [`docs/05`](05-alert-routing.md) — those snippets are excerpts of
> the hot path, not complete source.

**Everything else.** You will also need:

- An **Elasticsearch endpoint URL** (8.x) and a service-account
  username and password with read access to `.fleet-agents`, the
  `.ds-logs-endpoint.events.*` data streams, and the
  `_cluster/health`, `_nodes/stats`, and `_cat/shards` APIs — plus
  write access to `_cluster/settings`, `_cache/clear`, `_forcemerge`,
  `_ilm/retry`, and `_cluster/reroute` if remediation is enabled.
- The **CA bundle path** on the host if the cluster uses a
  self-signed or internal-CA certificate. The env file in Step 5 has
  an `ES_CA_CERT` variable for this.
- The **Google Chat incoming-webhook URL** for your **infrastructure
  maintenance** space.

## Step 1 — system packages

Ubuntu 22.04 and 24.04 both ship a usable Python 3 by default. The
module targets Python 3.10 or newer. Only the venv module, pip, and
build tooling for native wheels need to be added.

```bash
sudo apt-get update
sudo apt-get install -y \
  python3 python3-venv python3-pip python3-dev \
  build-essential ca-certificates curl
```

> On Ubuntu 24.04, `pip install` outside a venv fails with
> `error: externally-managed-environment` (PEP 668). The deployment
> below uses a venv throughout, so this does not apply — but it is a
> common surprise on first contact with a 24.04 host.

## Step 2 — install Ollama and pull the model

Ollama runs the local LLM used by the recommendation agent
([§8.3](08-agentic-behaviors.md#83-agent-3--the-llm-recommendation-agent)).
It listens on `127.0.0.1:11434` only, has no inbound auth requirement,
and runs as its own systemd service.

```bash
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
```

Pull the default model. `gemma4:e4b` is the right size for the
recommendation prompt — short input, three commands of output, and
it runs on CPU without a GPU:

```bash
ollama pull gemma4:e4b
```

Verify the server is reachable:

```bash
curl -s http://127.0.0.1:11434/api/tags | head
```

If the host has a GPU and you want stronger reasoning, pull a larger
variant (e.g. `gemma4:26b-a4b`) and set `OLLAMA_MODEL` accordingly in
Step 5. Do not change the default unless you have benchmarked
latency on the host — the recommendation agent's timeout budget is
short.

## Step 3 — service user and install tree

The module runs as a non-login service user, `siem-maint`, matching
the `User=` directive in the systemd unit. The service user owns
`/opt/siem-maint/` and `/var/lib/siem-maint/`; **root** owns
`/etc/siem-maint/` so that a compromised service cannot rewrite its
own credentials.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin siem-maint

sudo mkdir -p /opt/siem-maint /var/lib/siem-maint /etc/siem-maint
sudo chown -R siem-maint:siem-maint /opt/siem-maint /var/lib/siem-maint
sudo chown -R root:siem-maint /etc/siem-maint
sudo chmod 750 /etc/siem-maint
```

## Step 4 — install the module

Unpack the release tarball into `/opt/siem-maint/`, create a
virtualenv, install the pinned dependencies from `requirements.txt`,
and install the `siem_maint` package itself with `pip install -e`.

The editable install is the critical step: it registers `siem_maint`
as an importable package inside the venv so that
`python -m siem_maint.monitor` works from any working directory,
which is what the systemd unit in Step 7 relies on. **Skipping the
editable install will cause systemd to fail with `ModuleNotFoundError`
because the venv's `sys.path` does not include `/opt/siem-maint/`.**

```bash
sudo tar -xzf siem-maint-<version>.tar.gz -C /opt/siem-maint --strip-components=1
sudo chown -R siem-maint:siem-maint /opt/siem-maint

sudo -u siem-maint python3 -m venv /opt/siem-maint/venv
sudo -u siem-maint /opt/siem-maint/venv/bin/pip install --upgrade pip

# install pinned runtime dependencies
sudo -u siem-maint /opt/siem-maint/venv/bin/pip install \
  -r /opt/siem-maint/requirements.txt

# install the siem_maint package itself (editable — picks up setup.cfg)
sudo -u siem-maint /opt/siem-maint/venv/bin/pip install \
  -e /opt/siem-maint

# verify the package is importable from the venv
sudo -u siem-maint /opt/siem-maint/venv/bin/python -c \
  "import siem_maint; print(siem_maint.__version__)"
```

For reference, the pinned `requirements.txt` shipped in the tarball
contains the versions the module has been tested against. **Do not
raise these pins without re-testing** — `elasticsearch-py` has
introduced breaking auth changes between major releases, and
`apscheduler` 4.x uses a different scheduler API from 3.x.

**`/opt/siem-maint/requirements.txt`** (pinned, ships in tarball)

```text
elasticsearch==8.13.0
apscheduler==3.10.4
requests==2.32.3
python-dotenv==1.0.1
```

A **packaged** `siem_maint` tarball that ships `probes/host.py` may also
pin **`psutil`** (and optionally an Ollama client). This **Git**
repository’s [`requirements.txt`](../requirements.txt) matches the
four lines above — the `Agent-SIEM-maintenance` modules do not import
`psutil` or the `ollama` Python package (Ollama is called via HTTP).

## Step 5 — credentials and tunables

Credentials, TLS settings, and tunables live in a single env file at
`/etc/siem-maint/env`. The systemd unit sources this file through its
`EnvironmentFile=` directive. Changes take effect on `SIGHUP`, no
restart required.

The release tarball ships
[`/opt/siem-maint/.env.example`](../.env.example) as the canonical
template. Copy it into place with the right ownership and permissions
in one step, then edit:

```bash
sudo install -m 640 -o root -g siem-maint \
  /opt/siem-maint/.env.example /etc/siem-maint/env
sudoedit /etc/siem-maint/env
```

A few values need attention before the service can start:

- `ES_HOST`, `ES_USER`, `ES_PASS` — connection details for the
  Elasticsearch service account.
- `ES_CA_CERT` — path to the internal CA bundle, if the cluster uses
  one. `cluster.py` passes this as `ca_certs` to the elasticsearch-py
  client.
- `ES_VERIFY_CERTS=false` — only set in throwaway lab environments.
  The module logs a warning on every startup when verification is
  disabled.
- `CHAT_WEBHOOK` — the incoming-webhook URL for the **infrastructure
  maintenance** Google Chat space.
- `OLLAMA_HOST`, `OLLAMA_MODEL` — defaults match the Ollama install
  from Step 2 and rarely need changing.
- The three tunables (`ES_ALERT_COOLDOWN_HOURS`,
  `DATA_FRESHNESS_CRITICAL_HOURS`, `HOST_CPU_CRITICAL_PERCENT`) ship
  with sensible defaults documented in [`docs/06`](06-operational-notes.md#63-tuning-for-a-new-environment).

## Step 6 — validate before starting

Before handing the module to systemd, run `--check-config` once as
the service user. It reads `/etc/siem-maint/env`, opens an
authenticated connection to Elasticsearch (honoring `ES_CA_CERT` and
`ES_VERIFY_CERTS`), calls `_cluster/health`, pings the Ollama server
at `OLLAMA_HOST`, and posts a one-line test message to the Chat
webhook. Any failure prints a diagnostic and exits non-zero.

**Do not proceed to Step 7 until this passes.**

```bash
sudo -u siem-maint env $(sudo cat /etc/siem-maint/env | xargs) \
  /opt/siem-maint/venv/bin/python -m siem_maint.monitor --check-config
```

Also run a one-shot host probe to confirm `psutil` returns sensible
values on this VM. Some hypervisors do not expose load averages
correctly, and `siem_maint/probes/host.py` will surface that before
the module goes into production:

```bash
sudo -u siem-maint /opt/siem-maint/venv/bin/python \
  -m siem_maint.monitor --once host
```

If remediation will be enabled in production, run
`--dry-run-remediation` once against the live cluster from this host.
It prints what `apply_fix` would have done — including any
`blocked_protected` or `blocked_loop` outcomes — without mutating the
cluster. This is the operator's verification that `SAFE_FIX_TYPES`
and `PROTECTED` are configured correctly for the target environment:

```bash
sudo -u siem-maint env $(sudo cat /etc/siem-maint/env | xargs) \
  /opt/siem-maint/venv/bin/python -m siem_maint.monitor --dry-run-remediation
```

## Step 7 — install the systemd unit

The unit ships in the release tarball at
[`/opt/siem-maint/deploy/siem-maint.service`](../deploy/siem-maint.service).
It extends the simpler one shown in
[`docs/06`](06-operational-notes.md#62-what-happens-when-the-subsystem-itself-fails)
with `EnvironmentFile=` and `ExecReload=` directives. Because the
package was installed with `pip install -e` in Step 4, no
`PYTHONPATH` or `WorkingDirectory` override is needed —
`python -m siem_maint.monitor` resolves to the editable install
inside the venv.

For reference, the shipped unit is:

```ini
[Unit]
Description=SIEM-MAINTENANCE infrastructure monitor
After=network-online.target ollama.service
Wants=network-online.target

[Service]
Type=simple
User=siem-maint
EnvironmentFile=/etc/siem-maint/env
ExecStart=/opt/siem-maint/venv/bin/python -m siem_maint.monitor
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

The `After=ollama.service` ordering matters — without it, the module
can race the Ollama server on boot and fail its `--check-config`
ping during the first restart cycle.

Install and enable:

```bash
sudo cp /opt/siem-maint/deploy/siem-maint.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now siem-maint.service

# confirm
sudo systemctl status siem-maint.service --no-pager

# follow logs
sudo journalctl -u siem-maint.service -f
```

From here on, edits to `/etc/siem-maint/env` can be applied without
restarting the service. The unit's `ExecReload=` directive sends
`SIGHUP`, which the module catches and uses to re-read its
configuration:

```bash
sudo systemctl reload siem-maint
```

## Step 8 — confirm end-to-end

The test message posted during `--check-config` in Step 6 should have
arrived in the SIEM-MAINTENANCE space. The next scheduled daily report
at 08:30 local time should produce a full executive summary card in
the same space — worth waiting for before considering the deployment
finished.

## Step 9 — operational baseline

Two actions belong on the first day of production operation.

**First**, install a logrotate policy for
`/var/lib/siem-maint/audit.jsonl`. The file is append-only by design
and grows proportionally to remediation attempts, which is low in
steady state but unbounded over time. Rotate weekly and retain at
least 90 days so the audit trail covers a full quarter of remediation
decisions. `copytruncate` is important — `apply.py` holds the file
handle open and appends continuously, so moving the file would leave
`apply.py` writing to an orphaned inode.

**`/etc/logrotate.d/siem-maint`**

```text
/var/lib/siem-maint/audit.jsonl {
    weekly
    rotate 13                  # ~90 days of history
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su siem-maint siem-maint
}
```

**Second**, add `siem-maint.service` to the host-level systemd
monitoring that catches any unit in a failed state. The absence of
the 08:30 daily report is the ultimate backstop, but a systemd-level
alarm catches a crash on the same day it happens rather than the
next morning.

## Upgrading

Upgrades follow the same pattern as the initial install. Stop the
service, unpack the new tarball over `/opt/siem-maint/`, re-run
`requirements.txt` and the editable install in case package metadata
or dependencies changed, run `--check-config`, and start the service
again. The three files under `/var/lib/siem-maint/` are preserved.

```bash
sudo systemctl stop siem-maint.service

sudo tar -xzf siem-maint-<new-version>.tar.gz -C /opt/siem-maint --strip-components=1
sudo chown -R siem-maint:siem-maint /opt/siem-maint

sudo -u siem-maint /opt/siem-maint/venv/bin/pip install \
  -r /opt/siem-maint/requirements.txt
sudo -u siem-maint /opt/siem-maint/venv/bin/pip install \
  -e /opt/siem-maint

sudo -u siem-maint env $(sudo cat /etc/siem-maint/env | xargs) \
  /opt/siem-maint/venv/bin/python -m siem_maint.monitor --check-config

sudo systemctl start siem-maint.service
```

## Adapting to a different SIEM

The module was built around Elasticsearch and Elastic Agents, but the
framing is not locked to them. Replacing the backend means rewriting
exactly two files: `siem_maint/probes/cluster.py` (currently wraps
elasticsearch-py) and `siem_maint/probes/freshness.py` (currently
queries `.ds-logs-endpoint.events.*` data streams). The classifier,
the cooldown gate, the chat poster, and the scheduler are all
SIEM-agnostic.

The contract a replacement probe honors is a return tuple of
`(health, nodes, shards, issues)`, where `issues` is a list of
`(type, target, detail)` tuples consumed by `classify.py` and
`apply.py`.

The remediation loop is Elasticsearch-specific — `SAFE_FIX_TYPES` and
`FIX_HANDLERS` map onto Elasticsearch failure modes — so a
non-Elastic deployment should disable remediation entirely and rely
on the alert-and-recommend path until equivalent fix handlers are
written.

---

Previous: [← 8. Agentic behaviors and their guardrails](08-agentic-behaviors.md)
Back to: [README](../README.md)
