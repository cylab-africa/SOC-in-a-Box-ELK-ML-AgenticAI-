# 0. Design specification vs this repository

The long-form narrative you have in mind — **four monitoring surfaces**, **five independent timers**, **`siem_maint/probes/*.py`**, **`alerting/classify.py`** with **`last_bands.json`**, **`/var/lib/siem-maint/cooldowns.json`**, **remediation** as **`siem_maint/remediation/`**, **GPT‑4** recommendation path, and **`python -m siem_maint`** under systemd — describes the **packaged platform** that `docs/01`–`docs/09` are written around (release tarball under `/opt/siem-maint/`).

**This Git repository** is a **maintenance-only slice**: five Python files under `Agent-SIEM-maintenance/` that implement the **same ideas** in fewer, larger modules. Use this page when reconciling the spec with what you can run from this tree today.

---

## 0.1 File / layout mapping

| Specification (`/opt/siem-maint/`) | This repo (`Agent-SIEM-maintenance/`) |
|-----------------------------------|----------------------------------------|
| `siem_maint/scheduler.py` (5 jobs) | `maintenance_service.py` — **APScheduler** with **2** jobs: (1) cron **daily** report at `DAILY_REPORT_TIME_CAT` in `MAINTENANCE_IANA_TIMEZONE`, (2) **interval** `es_health_monitor.py` every `SIEM_HEALTH_POLL_INTERVAL_SECONDS` or `ES_HEALTH_MONITOR_INTERVAL_SECONDS` (default **7200 s ≈ 2 h**). |
| `siem_maint/probes/host.py` (`psutil`) | **Not present** as a standalone probe. **Partial substitute:** JVM heap, disk %, CPU and related signals come from **`_nodes/stats`** inside `es_health_monitor.py` / `enhanced_health_monitor.py` (cluster view, not the monitor host OS). |
| `siem_maint/probes/cluster.py` | **Implemented** in **`es_health_monitor.py`**: `cluster.health`, node stats (jvm/fs/thread_pool), `cat.shards`, slow-query timing, etc. |
| `siem_maint/probes/agents.py` (`.fleet-agents`) | **Not a separate file.** Agent visibility is inferred via **telemetry / cardinality** and freshness checks in **`es_health_monitor.py`** / **`enhanced_health_monitor.py`** (not necessarily the same query as the spec’s offline-agent search). |
| `siem_maint/probes/freshness.py` | **Implemented** in **`es_health_monitor.py`** (`check_data_freshness`, per index patterns from env) and surfaced in **`enhanced_health_monitor.py`**. |
| `send_daily_report` / executive report | **`ultra_siem_monitor.py`** → **`enhanced_health_monitor.py --analyze-alerts`** — LLM + **Google Chat** card + `results/health_analysis_*.json`. |
| `alerting/classify.py` + `last_bands.json` | **Different model.** The spec’s **per-metric band transitions** file is **not** used here. Instead, **`es_health_monitor.py`** builds issues, groups by **scenario**, and uses **`results/es_alert_state.json`** for **cooldown keys** (not the spec’s five category names). |
| `alerting/cooldown.py` + `cooldowns.json` | Cooldown is **`ES_ALERT_COOLDOWN_HOURS`** (default often **2** in `.env`) and persisted under **`results/`**, not **`/var/lib/siem-maint/cooldowns.json`**. |
| `alerting/chat.py` (`cardsV2` example) | **Requests + webhook JSON** in **`es_health_monitor.py`** (`send_chat_card`) and **`enhanced_health_monitor.py`** (`send_enhanced_alert`). Payload shape is **not guaranteed** to match every snippet in `docs/05`; both use Google Chat **HTTP API** with structured cards/sections. |
| `remediation/apply.py` + `fixes.py` | **`auto_remediate.py`** — investigate / optional **auto-fix** (scroll clear, reroute, thread pool, fielddata, ML index cleanup, etc.), **protected** index patterns, **dry-run** and **investigate-only**. Audit is **JSON per run** under `results/auto_remediation_*.json`, not necessarily **`audit.jsonl`** as in the spec. |
| LLM = GPT‑4 only (spec wording) | **OpenAI** when `LLM_MODEL` starts with `gpt-`, else **Ollama** at `OLLAMA_URL` (`enhanced_health_monitor.py`, LLM blocks in `es_health_monitor.py`). |
| `python -m siem_maint` + systemd | Here: **`python maintenance_service.py`** (foreground) or your own **systemd** unit wrapping that script + `WorkingDirectory=.../Agent-SIEM-maintenance`. Env: **`../.env`** then **`./.env`** for `maintenance_service.py` / `ultra_siem_monitor.py`. |

---

## 0.2 Cadence comparison (spec vs repo)

| Spec timer | Spec interval | Closest in this repo |
|------------|---------------|----------------------|
| Host probe | 30 s | *None* (use external host monitoring or extend this repo). |
| Agents | 30 min | *Not a dedicated interval*; health poll bundles agent-related signals when `es_health_monitor` runs. |
| Cluster | 2 h | **Default health poll** `ES_HEALTH_MONITOR_INTERVAL_SECONDS=7200` → **2 h**. |
| Freshness | 6 h | Freshness is checked **whenever** `es_health_monitor.py` runs (same as cluster poll unless you change intervals). |
| Daily report | 08:30 local | **`DAILY_REPORT_TIME_CAT`** + **`MAINTENANCE_IANA_TIMEZONE`** in `maintenance_service.py`. |

To **approximate** the spec’s 30 s / 30 min / 6 h split, you would need **extra scheduled jobs** or a **fork** of `maintenance_service.py` — the stock maintenance daemon intentionally keeps **two** timers.

---

## 0.3 Design principles (how closely we match)

| Principle (spec) | This repo |
|------------------|-----------|
| Monitor actionable surfaces | **Yes** — cluster, shards, latency, freshness, chat guidance. **No** dedicated host `psutil` probe. |
| Alert on transitions / avoid noise | **Partly** — `es_health_monitor` uses **scenario grouping**, **cooldown**, and **imminent** ETA hints; not the same as **`classify.py` + `last_bands.json`**. |
| Cooldown (~4 h in spec) | **Configurable** — **`ES_ALERT_COOLDOWN_HOURS`**; may differ from 4. |
| Conservative auto-remediation + protected indices | **Yes** — **`auto_remediate.py`** mirrors the **spirit** of the seven fixes; verify in code before assuming 1:1 API parity with `fixes.py` snippets. |
| Google Chat (maintenance) | **Yes** — **`GC_ALERT_WEBHOOK`** targets the configured infrastructure maintenance space. |
| LLM = recommendations only (no auto-exec) | **Yes** for LLM output → operator; **`auto_remediate.py`** is separate and explicit. |

---

## 0.4 Reading order

1. **This page (`00`)** — truth for **this Git tree**.  
2. **`docs/10`** — short module list and env vars.  
3. **`docs/01`–`09`** — **target architecture** and operational theory (adjust paths mentally to `Agent-SIEM-maintenance/*.py` using the table above).  

---

Next: [1. What the subsystem watches →](01-what-is-watched.md)
