# 7. The `siem_maint.monitor` Module

> **This Git repository:** the runnable code lives under
> [`Agent-SIEM-maintenance/`](../Agent-SIEM-maintenance/) (see
> [**docs/00 — Spec vs repo**](00-design-spec-vs-this-repo.md) and [**docs/10**](10-agent-siem-maintenance-map.md)).
> The layout below describes the **packaged** `siem_maint` install under `/opt/siem-maint/`.

The snippets throughout this documentation share a single on-disk
home. The installed package lives at `/opt/siem-maint/siem_maint/` and
is launched by the systemd unit as `python -m siem_maint.monitor`.
Every file referenced in a code-block caption — `probes/host.py`,
`probes/cluster.py`, `probes/agents.py`, `probes/freshness.py`,
`scheduler.py`, `alerting/classify.py`, `alerting/cooldown.py`,
`alerting/chat.py`, `remediation/apply.py`, `remediation/fixes.py` —
is a member of this package. The package's `__main__.py` imports those
modules, constructs the APScheduler, and enters its run loop.

> The snippets in [`docs/01`](01-what-is-watched.md) through
> [`docs/05`](05-alert-routing.md) show the **hot path** of each
> file — enough to understand what it does — rather than the complete
> module. The full source ships in the release tarball described in
> [`docs/09`](09-deployment.md). Do not try to reconstruct the
> package by copy-pasting snippets out of this documentation; use
> the tarball.

## 7.1 File layout on disk

A fresh deployment lays down exactly the files shown below. Paths are
stable across releases. The `setup.cfg` and `requirements.txt` at the
top level of `/opt/siem-maint/` are what make the package installable
— see Step 4 of [`docs/09`](09-deployment.md).

```text
/etc/systemd/system/
└── siem-maint.service              # the unit (docs/09 step 7)

/etc/siem-maint/
└── env                             # credentials + tunables (docs/09 step 5)

/opt/siem-maint/
├── venv/                           # Python virtualenv
├── setup.cfg                       # package metadata (pip install -e)
├── requirements.txt                # pinned runtime dependencies
└── siem_maint/                     # the installed package
    ├── __init__.py
    ├── __main__.py                 # python -m siem_maint.monitor enters here
    ├── scheduler.py                # APScheduler BackgroundScheduler
    ├── probes/
    │   ├── __init__.py
    │   ├── host.py                 # collect_host_metrics (psutil)
    │   ├── cluster.py              # probe_cluster (elasticsearch-py)
    │   ├── agents.py               # find_offline_agents (.fleet-agents)
    │   └── freshness.py            # ingest_lag_seconds (per group)
    ├── alerting/
    │   ├── __init__.py
    │   ├── classify.py             # classify + detect_transition
    │   ├── cooldown.py             # cooldown_passed + record_alert
    │   └── chat.py                 # post_alert_card
    └── remediation/
        ├── __init__.py
        ├── apply.py                # apply_fix dispatcher
        └── fixes.py                # FIX_HANDLERS (the seven fixes)

/var/lib/siem-maint/                # runtime state, written by the module
├── last_bands.json                 # per-metric band (classify.py)
├── cooldowns.json                  # per-category timers (cooldown.py)
└── audit.jsonl                     # remediation audit trail (apply.py)
```

## 7.2 How the module wires together

The entry point in `__main__.py` does four things in order:

1. Loads the environment variables passed in by the systemd
   `EnvironmentFile=` directive.
2. Constructs the `BackgroundScheduler` shown in
   [`scheduler.py`](02-cadence.md#21-scheduler-wiring-with-apscheduler)
   and registers the five jobs at their intervals.
3. Installs a `SIGHUP` handler so that `/etc/siem-maint/env` is re-read
   without a restart.
4. Blocks in the scheduler's run loop until systemd sends `SIGTERM`.

**`siem_maint/__main__.py`** (excerpt)

```python
import os, signal
from .scheduler import build_scheduler, reload_config

def main():
    sched = build_scheduler()                    # registers all 5 jobs
    signal.signal(signal.SIGHUP, reload_config)  # re-read /etc/siem-maint/env
    sched.start()
    signal.pause()                               # block until SIGTERM

if __name__ == "__main__":
    main()
```

## 7.3 Runtime dependencies

The module's imports are the only runtime dependencies:

| Package | Used by | Purpose |
|---------|---------|---------|
| `elasticsearch` | `probes/cluster.py`, `probes/agents.py`, `probes/freshness.py`, `remediation/fixes.py` | Typed Elasticsearch 8.x client |
| `apscheduler` | `scheduler.py` | Cadenced collectors (30 s → 24 h) |
| `psutil` | `probes/host.py` | CPU, memory, disk, FD sampling |
| `requests` | `alerting/chat.py` | Posts cards to Google Chat webhook |
| `ollama` | LLM recommendation path | Local LLM client for the recommendation agent — see [§4.4](04-remediation-loop.md#44-when-the-llm-gets-involved) |

The specific tested versions are pinned in
[`/opt/siem-maint/requirements.txt`](../requirements.txt) and shipped
in the release tarball.

## 7.4 Command-line entry points

The module is invoked four ways. The default mode, run by systemd,
starts the full service. The other three are operator tools — primarily
used during deployment validation (Step 6 of
[`docs/09`](09-deployment.md)) and when triaging issues on a live host.

```bash
# service mode — what systemd runs
/opt/siem-maint/venv/bin/python -m siem_maint.monitor

# one-shot probe — prints JSON, posts nothing
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --once host
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --once cluster
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --once agents
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --once freshness

# validate env vars, ES connection, Ollama reachability, and webhook
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --check-config

# dry-run remediation: investigate + print what apply_fix WOULD do,
# never mutates the cluster — use this on staging before enabling auto-fix
/opt/siem-maint/venv/bin/python -m siem_maint.monitor --dry-run-remediation
```

A short reference for each:

- **`--once <probe>`** — runs one probe to completion, prints the
  result as JSON to stdout, and exits. Posts nothing to chat. The
  main tool for validating a fresh install.
- **`--check-config`** — parses `/etc/siem-maint/env`, opens an
  authenticated connection to Elasticsearch, calls `_cluster/health`,
  pings the Ollama server at `OLLAMA_HOST`, and posts a one-line test
  message to the Chat webhook. Exits non-zero on any failure.
- **`--dry-run-remediation`** — runs `apply.py`'s pre-flight checks
  against live cluster state without executing any fix. The safest way
  to verify `SAFE_FIX_TYPES` and `PROTECTED` are correctly configured
  before enabling remediation in production.

---

Previous: [← 6. Operational notes](06-operational-notes.md)
Next: [8. Agentic behaviors and their guardrails →](08-agentic-behaviors.md)
