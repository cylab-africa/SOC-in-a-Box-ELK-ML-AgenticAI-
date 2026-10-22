# 2. When Each Check Runs

> **This repository:** `maintenance_service.py` uses **two** timers (daily report + health poll). The **five** cadences in the table below are the **target** design for the packaged `siem_maint` scheduler — see [**docs/00 §0.2**](00-design-spec-vs-this-repo.md).

Infrastructure metrics change at very different rates. A full disk
can appear in 30 seconds; an ingestion pipeline dies on hours, not
seconds; agent fleet composition drifts over days. Running every
collector on the same timer would either hammer the cluster with
useless polls or miss fast failures. Each collector therefore runs
on the cadence matched to how fast its metric can actually change.

| Collector | Cadence | Why |
|-----------|---------|-----|
| Host OS probe (`psutil`) | every **30 s** | A runaway process or exhausted disk needs to be caught on a **minute scale**, before it takes down Elasticsearch. |
| Elastic Agents status | every **30 min** | Roughly half the Fleet check-in interval, so transitions are caught on the next poll. |
| Elasticsearch cluster APIs | every **2 h** | Cluster health, node stats, and shard allocation grouped as one batch. |
| Data freshness (per group) | every **6 h** | Ingestion lag drifts slowly; more frequent polls just add noise. |
| Executive daily report | **08:30** local | Morning delivery so the day starts with a baseline snapshot. |

All five cadences operate on independent timers and do not
synchronise — a host probe firing does not trigger a cluster probe
or vice versa.

## 2.1 Scheduler wiring with `apscheduler`

**`siem_maint/scheduler.py`**

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

# host probe — every 30 seconds
scheduler.add_job(probe_host,        "interval", seconds=30, id="host")

# elastic agents — every 30 minutes
scheduler.add_job(probe_agents,      "interval", minutes=30, id="agents")

# elasticsearch cluster — every 2 hours
scheduler.add_job(probe_cluster,     "interval", hours=2,    id="cluster")

# data freshness — every 6 hours
scheduler.add_job(probe_freshness,   "interval", hours=6,    id="freshness")

# daily executive report — 08:30 local
scheduler.add_job(send_daily_report, "cron", hour=8, minute=30, id="report")

scheduler.start()
```

---

Previous: [← 1. What the subsystem watches](01-what-is-watched.md) · [0. Spec vs this repo](00-design-spec-vs-this-repo.md)  
Next: [3. Thresholds and alert bands →](03-thresholds-and-alert-bands.md)
