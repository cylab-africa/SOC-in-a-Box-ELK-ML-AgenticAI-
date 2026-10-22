# 11. QA scope — files in this repository

How this relates to the **`siem_maint` design spec:** [**docs/00**](00-design-spec-vs-this-repo.md).

The **`Agent-SIEM-maintenance/`** directory contains **exactly five** Python programs:

| File | Purpose |
|------|---------|
| `maintenance_service.py` | Long-running scheduler (morning report + periodic `es_health_monitor`) |
| `ultra_siem_monitor.py` | One-shot / daily report wrapper |
| `enhanced_health_monitor.py` | LLM + Chat report |
| `es_health_monitor.py` | Health/freshness monitor (library + CLI) |
| `auto_remediate.py` | Investigate / remediate Elasticsearch (standalone) |

**Smoke check:** run `maintenance_service.py --once-daily` and `--once-poll`, or invoke `ultra_siem_monitor.py` / `es_health_monitor.py` directly.

---

Previous: [← 10. Agent-SIEM-maintenance map](10-agent-siem-maintenance-map.md)
