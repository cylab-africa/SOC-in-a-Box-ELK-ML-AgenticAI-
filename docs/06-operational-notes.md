# 6. Operational Notes

> **This repository:** persistent state lives under **`Agent-SIEM-maintenance/results/`** (e.g. `es_alert_state.json`, `auto_remediation_*.json`), not necessarily `/var/lib/siem-maint/` — [**docs/00**](00-design-spec-vs-this-repo.md).

## 6.1 Where state is kept

Three files on disk make the subsystem stateful across restarts.

| File | Purpose |
|------|---------|
| `/var/lib/siem-maint/last_bands.json` | current band classification of every watched metric — makes transition detection survive a process crash |
| `/var/lib/siem-maint/cooldowns.json` | last-alert timestamp per category |
| `/var/lib/siem-maint/audit.jsonl` | every auto-fix attempt with its investigate, fix, and verify phases (append-only) |

On startup the subsystem reads all three and resumes where it left
off — it will **not** page for a metric that was already in its
current band before the restart.

```text
/var/lib/siem-maint/last_bands.json     # per-metric band state
/var/lib/siem-maint/cooldowns.json      # per-category last-alert timestamps
/var/lib/siem-maint/audit.jsonl         # remediation audit trail (append-only)
```

## 6.2 What happens when the subsystem itself fails

The monitoring subsystem runs under `systemd` with auto-restart on
failure and a 30-second restart delay. If it crashes, `systemd`
brings it back up; if it crashes repeatedly within a short window,
`systemd` gives up and logs the failure to the journal.

There is no meta-monitor watching the monitor: the platform relies
on the **absence of the daily 08:30 executive report** as the
observable signal that monitoring has stopped working. An operator
who stops receiving the morning report knows to check `systemd`
status on the host.

**systemd unit** — `/etc/systemd/system/siem-maint.service`

The minimal unit shown below is enough to keep the service alive. The
production-grade unit — with `EnvironmentFile=`, `ExecReload=`, and
`After=ollama.service` — is in
[`docs/09 §Step 7`](09-deployment.md#step-7--install-the-systemd-unit)
and is the one new deployments should install.

```ini
[Unit]
Description=SIEM-MAINTENANCE infrastructure monitor
After=network.target

[Service]
Type=simple
ExecStart=/opt/siem-maint/venv/bin/python -m siem_maint.monitor
Restart=on-failure
RestartSec=30
User=siem-maint

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now siem-maint
sudo systemctl status siem-maint
journalctl -u siem-maint -f
```

## 6.3 Tuning for a new environment

Three parameters account for most of the useful tuning space.

| Variable | Default | What it controls |
|----------|---------|------------------|
| `ES_ALERT_COOLDOWN_HOURS` | 4 h | How aggressively infrastructure alerts are suppressed. Lower during active incident response; raise for a quiet environment. |
| `DATA_FRESHNESS_CRITICAL_HOURS` | 3 h | When a stale ingestion pipeline escalates from warning to critical. Tighten if the environment has strict ingestion SLAs. |
| `HOST_CPU_CRITICAL_PERCENT` | 90 % | Main knob for host-level alerting. Raise on hosts that routinely run hot without actually being unhealthy. |

All three are safe to change in place. The subsystem re-reads its
configuration on `SIGHUP`:

```bash
sudo systemctl kill -s SIGHUP siem-maint
```

## 6.4 Recommendations for first-week operation

Two practical recommendations fall out of running this subsystem in
real environments.

**1. Do not tune cooldown down in the first week.**

The temptation is to see a suppressed alert and shorten the window;
the correct action is almost always to fix the underlying issue
instead, because any alert suppressed by cooldown is by definition
one the subsystem already paged you about.

**2. Treat the executive daily report as the primary signal for
baseline drift.**

A slowly rising trend in any metric between consecutive days is
worth investigating even if no individual sample has crossed a
threshold yet, because thresholds catch acute failures and trends
catch chronic ones. The report is not a status summary — it is a
drift signal.

---

Previous: [← 5. From breach to Google Chat](05-alert-routing.md)
Next: [7. The siem_maint.monitor module →](07-module-architecture.md)
