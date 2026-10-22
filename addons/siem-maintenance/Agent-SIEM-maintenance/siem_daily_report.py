#!/usr/bin/env python3
"""Structured «Daily SIEM Report» text for Google Chat (used by enhanced_health_monitor)."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Tuple

import requests

logger = logging.getLogger("siem_daily_report")


def _tz_datetime() -> Tuple[datetime, str]:
    tz_name = os.getenv("MAINTENANCE_IANA_TIMEZONE", "Africa/Johannesburg").strip() or "UTC"
    try:
        from zoneinfo import ZoneInfo

        zi = ZoneInfo(tz_name)
        now = datetime.now(zi)
        return now, tz_name
    except Exception:
        from datetime import timezone

        now = datetime.now(timezone.utc)
        return now, "UTC"


def _status_emoji(status: str) -> str:
    s = (status or "").lower()
    if s == "green":
        return "🟢"
    if s == "yellow":
        return "🟡"
    return "🔴"


def _shard_health_score(cluster_health: dict, shard_analysis: dict) -> int:
    """Heuristic 0–100 score from status + unassigned burden."""
    ch = cluster_health or {}
    sa = shard_analysis or {}
    base = 100
    st = (ch.get("status") or "").lower()
    if st == "yellow":
        base -= 18
    elif st == "red":
        base -= 45
    unassigned = int(ch.get("unassigned_shards") or 0)
    ts = int(sa.get("total_shards") or 0)
    if ts > 0:
        total = ts
    else:
        total = int(ch.get("active_shards") or 0) + unassigned
    if total <= 0:
        total = 1
    # Penalize unassigned as % of catalogued shards, scaled (user samples ~40/100 for yellow + 54 ua)
    pct = min(1.0, (unassigned / max(total, 1)) * 3.5)
    base -= int(55 * pct)
    return max(0, min(100, base))


def _node_role_counts(nodes_info: dict) -> Tuple[int, int, int, int]:
    """Returns (data_nodes, master_eligible, ingest_nodes, total_nodes)."""
    nodes = (nodes_info or {}).get("nodes") or {}
    total = len(nodes)
    data_n = master_n = ingest_n = 0
    for _nid, info in nodes.items():
        roles = info.get("roles") or []
        if "data" in roles or "data_content" in roles or "data_hot" in roles:
            data_n += 1
        if "master" in roles:
            master_n += 1
        if "ingest" in roles:
            ingest_n += 1
    return data_n, master_n, ingest_n, total


def _gather_index_report(es) -> dict:
    out: dict = {"total_indices": 0, "health_score": 100.0, "green": 0, "yellow": 0, "red": 0, "largest": []}
    try:
        rows = es.cat.indices(format="json", bytes="b", h="index,health,docs.count,store.size")
    except Exception as e:
        logger.warning("cat.indices failed: %s", e)
        out["error"] = str(e)[:200]
        return out
    if not rows:
        return out
    out["total_indices"] = len(rows)
    green = yellow = red = 0
    parsed: List[dict] = []
    for r in rows:
        h = (r.get("health") or "green").lower()
        if h == "green":
            green += 1
        elif h == "yellow":
            yellow += 1
        else:
            red += 1
        try:
            sz_b = int(r.get("store.size") or 0)
        except (TypeError, ValueError):
            sz_b = 0
        try:
            docs = int(r.get("docs.count") or 0)
        except (TypeError, ValueError):
            docs = 0
        parsed.append({"index": r.get("index", ""), "health": h, "bytes": sz_b, "docs": docs})
    out["green"], out["yellow"], out["red"] = green, yellow, red
    n = len(rows)
    if n:
        out["health_score"] = round(100.0 * (green / n), 1)
    parsed.sort(key=lambda x: x["bytes"], reverse=True)
    out["largest"] = parsed[:8]
    return out


def _human_gb(nbytes: int) -> str:
    if nbytes <= 0:
        return "0 B"
    gb = nbytes / (1024**3)
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = nbytes / (1024**2)
    return f"{mb:.2f} MB"


def _fetch_ml_anomaly_counts(es) -> dict:
    total = 0
    try:
        q = {"size": 0, "track_total_hits": True, "query": {"range": {"timestamp": {"gte": "now-24h"}}}}
        r = es.search(index=".ml-anomalies-*", body=q)
        th = r.get("hits", {}).get("total", 0)
        if isinstance(th, dict):
            total = int(th.get("value", 0) or 0)
        else:
            total = int(th or 0)
    except Exception as e:
        logger.debug("ML anomalies count: %s", e)
        total = 0
    return {"total": total}


def _classify_rule_failure(msg: str) -> str:
    m = (msg or "").lower()
    if not m:
        return "ok"
    if "partial" in m or "maximum alert limit" in m or "no index matching" in m:
        return "partial"
    if "never" in m or "not executed" in m:
        return "never"
    if "platinum" in m or "enterprise" in m or "license" in m or "error occurred" in m:
        return "failed"
    return "failed"


def fetch_detection_rules_summary() -> dict:
    """
    Best-effort Kibana Detection Engine summary.
    Authenticates via ES_API_KEY (preferred) or ES_USERNAME/ES_PASSWORD.
    """
    raw: dict = {
        "enabled": 0,
        "ok": 0,
        "failed": 0,
        "partial": 0,
        "warning": 0,
        "never_executed": 0,
        "failed_samples": [],
        "partial_samples": [],
        "never_samples": [],
        "error": "",
    }
    kb = (os.getenv("KIBANA_HOST") or "").strip().rstrip("/")
    if not kb:
        raw["error"] = "KIBANA_HOST not set — rule status skipped."
        return raw
    url = f"{kb}/api/detection_engine/rules/_find"
    headers = {
        "kbn-xsrf": "siem-daily-report",
        "Content-Type": "application/json",
    }
    api_key = os.getenv("ES_API_KEY", "").strip()
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
        req_auth = None
    else:
        user = os.getenv("ES_USERNAME") or ""
        pwd = os.getenv("ES_PASSWORD") or ""
        req_auth = (user, pwd) if user else None
    rules: List[dict] = []
    page = 1
    per_page = 500
    try:
        while page < 400:
            r = requests.get(
                url,
                params={"page": page, "per_page": per_page},
                auth=req_auth,
                headers=headers,
                verify=False,
                timeout=120,
            )
            if r.status_code != 200:
                raw["error"] = f"Kibana detection_engine HTTP {r.status_code}: {r.text[:400]}"
                return raw
            payload = r.json()
            batch = payload.get("data") or []
            rules.extend(batch)
            if len(batch) < per_page:
                break
            page += 1
    except Exception as e:
        raw["error"] = str(e)[:300]
        return raw
    max_fail = int(os.getenv("DAILY_REPORT_RULE_SAMPLES_FAILED", "12"))
    max_part = int(os.getenv("DAILY_REPORT_RULE_SAMPLES_PARTIAL", "8"))
    max_nev = int(os.getenv("DAILY_REPORT_RULE_SAMPLES_NEVER", "4"))

    for rule in rules:
        if not rule.get("enabled", True):
            continue
        raw["enabled"] += 1
        name = rule.get("name") or rule.get("title") or "unknown"
        rtype = rule.get("type") or rule.get("rule_type") or ""
        lfm = rule.get("last_failure_message") or ""
        ex = rule.get("execution_summary") or {}
        last_ex = ex.get("last_execution") or {}
        ex_status = (last_ex.get("status") or "").lower()
        last_ok = rule.get("last_success_at")
        last_bad = rule.get("last_failure_at")

        if ex_status == "succeeded" or (last_ok and not last_bad and not lfm):
            raw["ok"] += 1
            continue
        if ex_status == "partial" or _classify_rule_failure(lfm) == "partial":
            raw["partial"] += 1
            if len(raw["partial_samples"]) < max_part:
                raw["partial_samples"].append(
                    {
                        "name": name,
                        "type": rtype,
                        "reason": (lfm or last_ex.get("reason") or "Partial execution")[:900],
                    }
                )
            continue
        if not last_ok and not last_bad and not lfm:
            raw["never_executed"] += 1
            if len(raw["never_samples"]) < max_nev:
                raw["never_samples"].append({"name": name, "type": rtype})
            continue
        raw["failed"] += 1
        if len(raw["failed_samples"]) < max_fail:
            reason = lfm or last_ex.get("reason") or "Execution failed"
            raw["failed_samples"].append(
                {"name": name, "type": rtype, "reason": reason[:900]}
            )

    return raw


def build_es_snapshot_text(health_data: dict, max_chars: int = 6000) -> str:
    """Compact JSON snapshot (kept for opt-in operator excerpt; default off in favor of log lines)."""
    snap = {
        "timestamp": health_data.get("timestamp"),
        "cluster_health": health_data.get("cluster_health"),
        "cluster_architecture": health_data.get("cluster_architecture"),
        "summary": health_data.get("summary"),
        "node_summary": [
            {"name": n.get("name"), "heap_used_percent": n.get("heap_used_percent")}
            for n in (health_data.get("node_status") or {}).get("node_details", [])[:12]
        ],
        "shard_analysis": {
            k: health_data.get("shard_analysis", {}).get(k)
            for k in ("total_shards", "primary_shards", "unassigned_shards", "relocating_shards", "initializing_shards")
            if isinstance(health_data.get("shard_analysis"), dict)
        },
        "detection_rules_error": (health_data.get("detection_rules") or {}).get("error"),
        "index_report_error": (health_data.get("index_report") or {}).get("error"),
    }
    txt = json.dumps(snap, indent=2, default=str)
    if len(txt) > max_chars:
        txt = txt[: max_chars - 20] + "\n… truncated …"
    return txt


def _allocation_explain(es) -> dict:
    """One-shot allocation explain. Returns minimal {reason, can_allocate, decisions[]} or {}."""
    try:
        raw = es.cluster.allocation_explain()
        d = dict(raw) if hasattr(raw, "__iter__") else {}
        info = d.get("unassigned_info") or {}
        out = {
            "index": d.get("index"),
            "shard": d.get("shard"),
            "primary": d.get("primary"),
            "reason": info.get("reason"),
            "at": info.get("at"),
            "details": (info.get("details") or "")[:300],
            "can_allocate": d.get("can_allocate"),
            "decisions": [],
        }
        for nd in (d.get("node_allocation_decisions") or [])[:3]:
            out["decisions"].append({
                "node": nd.get("node_name"),
                "decision": nd.get("node_decision"),
                "explanations": [
                    f"{x.get('decider')}: {x.get('explanation','')[:140]}"
                    for x in (nd.get("deciders") or []) if x.get("decision") == "NO"
                ][:3],
            })
        return out
    except Exception as e:
        logger.debug("allocation_explain skipped: %s", e)
        return {}


def _node_disk_summary(nodes_stats: dict) -> List[dict]:
    """Per-node disk %, sorted desc. Returns up to 8 entries with name, used_pct, free_gb."""
    out: List[dict] = []
    for _nid, n in (nodes_stats or {}).get("nodes", {}).items():
        fs = n.get("fs", {}).get("total", {}) or {}
        total = int(fs.get("total_in_bytes") or 0)
        avail = int(fs.get("available_in_bytes") or 0)
        if total <= 0:
            continue
        used_pct = round(100.0 * (total - avail) / total, 1)
        out.append({
            "name": n.get("name") or _nid,
            "used_pct": used_pct,
            "free_gb": round(avail / (1024**3), 2),
            "total_gb": round(total / (1024**3), 2),
        })
    out.sort(key=lambda x: x["used_pct"], reverse=True)
    return out[:8]


def fetch_recent_es_log_excerpt(es, max_lines: int = 25, max_chars: int = 3200) -> str:
    """Build a compact, plain-text Elastic log excerpt for the daily Chat follow-up.

    Strategy (best-effort, falls back gracefully):
      1. Search any indexed Elastic logs (data streams or monitoring) for WARN/ERROR
         in the last 24h. Common patterns covered: ``.ds-elastic-cloud-logs-*``,
         ``.monitoring-es-*``, ``logs-elasticsearch.*``, ``logs-elastic_agent*``.
      2. Append ``cluster.pending_tasks`` if any pending master tasks.
      3. Append ``cluster.allocation_explain`` summary when unassigned shards exist.
    """
    lines: List[str] = []
    log_patterns = (os.getenv("ES_LOG_INDEX_PATTERNS")
                    or ".ds-elastic-cloud-logs-*,.monitoring-es-*,logs-elasticsearch.*,"
                       "logs-elastic_agent*,.ds-logs-elastic_agent.*,filebeat-*").split(",")
    log_patterns = [p.strip() for p in log_patterns if p.strip()]

    body = {
        "size": max_lines,
        "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp", "log.level", "level", "message", "host.name", "service.name"],
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}],
                "should": [
                    {"terms": {"log.level": ["ERROR", "WARN", "WARNING", "FATAL"]}},
                    {"terms": {"level": ["ERROR", "WARN", "WARNING", "FATAL"]}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    found = False
    indices_searched = False
    for pat in log_patterns:
        try:
            r = es.search(index=pat, body=body, ignore_unavailable=True, allow_no_indices=True)
        except Exception as e:
            logger.debug("ES log search on %s failed: %s", pat, e)
            continue
        shards = (r.get("_shards") or {}).get("total", 0)
        if shards > 0:
            indices_searched = True
        hits = (r.get("hits") or {}).get("hits") or []
        if not hits:
            continue
        found = True
        lines.append(f"== {pat} (last 24h, top {len(hits)}) ==")
        for h in hits:
            s = h.get("_source") or {}
            ts = s.get("@timestamp", "")
            lvl = (s.get("log", {}).get("level") if isinstance(s.get("log"), dict) else None) or s.get("level", "")
            host = s.get("host", {}).get("name") if isinstance(s.get("host"), dict) else s.get("host.name", "")
            msg = (s.get("message") or "").replace("\n", " ")
            line = f"[{ts}] {lvl:>5} {host or '-'}: {msg}"
            lines.append(line[:280])
        break

    if not found:
        if indices_searched:
            lines.append("No WARN/ERROR entries in Elastic log indices in the last 24h (all clear).")
        else:
            lines.append("(no Elastic log indices matched the configured patterns)")
            lines.append("To enable: set ES_LOG_INDEX_PATTERNS in .env, or enable Stack Monitoring in Kibana")

    try:
        pending = es.cluster.pending_tasks()
        tasks = []
        if hasattr(pending, "get"):
            tasks = pending.get("tasks") or []
        elif hasattr(pending, "__iter__"):
            tasks = (dict(pending) or {}).get("tasks") or []
        if tasks:
            lines.append("")
            lines.append(f"== pending_tasks ({len(tasks)}) ==")
            for t in tasks[:5]:
                lines.append(f"- {t.get('priority','?')} {t.get('source','?')} "
                             f"(waited {t.get('time_in_queue_millis', 0)}ms)")
    except Exception as e:
        logger.debug("pending_tasks skipped: %s", e)

    try:
        h = es.cluster.health()
        if int(h.get("unassigned_shards") or 0) > 0:
            ax = _allocation_explain(es)
            if ax:
                lines.append("")
                lines.append("== allocation_explain ==")
                lines.append(f"index={ax.get('index')} shard={ax.get('shard')} "
                             f"primary={ax.get('primary')} reason={ax.get('reason')} "
                             f"can_allocate={ax.get('can_allocate')}")
                if ax.get("details"):
                    lines.append(f"details: {ax['details']}")
                for d in ax.get("decisions", []):
                    if d.get("explanations"):
                        lines.append(f"- {d['node']} ({d['decision']}): {'; '.join(d['explanations'])}")
    except Exception as e:
        logger.debug("allocation_explain at log-fetch skipped: %s", e)

    txt = "\n".join(lines).strip()
    if not txt:
        return "(no recent Elastic log entries to report)"
    if len(txt) > max_chars:
        txt = txt[: max_chars - 20] + "\n… truncated …"
    return txt


def enrich_health_for_daily_report(es, health_data: dict, nodes_info: dict, cluster_stats: dict) -> None:
    """Populate health_data with keys used by format_daily_siem_report."""
    ch = health_data.get("cluster_health") or {}
    sa = health_data.get("shard_analysis") or {}
    health_data["index_report"] = _gather_index_report(es)
    health_data["shard_health_score"] = _shard_health_score(ch, sa)

    idx_count = (cluster_stats or {}).get("indices", {}).get("count")
    if idx_count is None:
        idx_count = (health_data.get("index_report") or {}).get("total_indices")

    d, mst, ing, tot = _node_role_counts(nodes_info)
    health_data["cluster_architecture"] = {
        "cluster_name": (cluster_stats or {}).get("cluster_name")
        or (cluster_stats or {}).get("cluster_uuid")
        or "unknown",
        "total_indices": idx_count,
        "data_nodes": ch.get("number_of_data_nodes", d),
        "total_nodes": ch.get("number_of_nodes", tot),
        "master_eligible": mst,
        "ingest_nodes": ing,
    }

    health_data["ml_anomalies"] = _fetch_ml_anomaly_counts(es)
    health_data["detection_rules"] = fetch_detection_rules_summary()

    try:
        nodes_stats = es.nodes.stats(metric=["fs"])
        health_data["disk_summary"] = _node_disk_summary(nodes_stats)
    except Exception as e:
        logger.debug("nodes.stats(fs) skipped: %s", e)
        health_data["disk_summary"] = []

    if int(ch.get("unassigned_shards") or 0) > 0:
        health_data["allocation_explain"] = _allocation_explain(es)
    else:
        health_data["allocation_explain"] = {}

    try:
        pending = es.cluster.pending_tasks()
        tasks = []
        if hasattr(pending, "get"):
            tasks = pending.get("tasks") or []
        elif hasattr(pending, "__iter__"):
            tasks = (dict(pending) or {}).get("tasks") or []
        health_data["pending_tasks"] = {
            "count": len(tasks),
            "max_wait_ms": max((t.get("time_in_queue_millis", 0) for t in tasks), default=0),
            "samples": [
                {"priority": t.get("priority"), "source": (t.get("source") or "")[:120]}
                for t in tasks[:3]
            ],
        }
    except Exception as e:
        logger.debug("pending_tasks skipped: %s", e)
        health_data["pending_tasks"] = {"count": 0, "max_wait_ms": 0, "samples": []}


def daily_report_titles() -> Tuple[str, str]:
    """Google Chat card header title and subtitle."""
    now, _tz = _tz_datetime()
    weekday = now.strftime("%A")
    date_long = now.strftime("%B %d, %Y")
    space = os.getenv("GC_ALERT_SPACE_NAME", "SIEM-MAINTENANCE")
    return (f"Daily SIEM Report - {weekday}", f"{space} | {date_long}")


def format_daily_siem_report(
    health_data: dict,
    analysis: str,
    *,
    ai_unavailable_note: bool = False,
    raw_llm_failure: str = "",
) -> str:
    now, _tz_label = _tz_datetime()
    weekday = now.strftime("%A")
    date_long = now.strftime("%B %d, %Y")
    space = os.getenv("GC_ALERT_SPACE_NAME", "SIEM-MAINTENANCE")
    greeting = os.getenv("DAILY_REPORT_GREETING", "Good morning team!").strip()

    ch = health_data.get("cluster_health") or {}
    sa = health_data.get("shard_analysis") or {}
    arch = health_data.get("cluster_architecture") or {}
    idx = health_data.get("index_report") or {}
    dr = health_data.get("detection_rules") or {}
    ml = health_data.get("ml_anomalies") or {}
    score = int(health_data.get("shard_health_score") or 0)

    status = (ch.get("status") or "unknown").upper()
    emoji = _status_emoji(ch.get("status") or "")

    lines: List[str] = []
    lines.append(f"Daily SIEM Report — {weekday}")
    lines.append(f"{space} | {date_long}")
    lines.append("")
    lines.append(greeting)
    lines.append("")
    lines.append("SIEM Daily Report")
    lines.append(f"{weekday}, {date_long}")
    lines.append(f"{emoji} Cluster Health: {status}")
    lines.append("")
    lines.append("Cluster Architecture:")
    cn = arch.get("cluster_name") or "unknown"
    ti = arch.get("total_indices")
    if ti is None:
        ti = idx.get("total_indices", "?")
    lines.append(f"• Cluster Name: {cn}")
    lines.append(f"• Total Nodes: {arch.get('total_nodes', ch.get('number_of_nodes', '?'))}")
    lines.append(f"• Data Nodes: {arch.get('data_nodes', ch.get('number_of_data_nodes', '?'))}")
    lines.append(f"• Master-Eligible: {arch.get('master_eligible', '?')}")
    lines.append(f"• Ingest Nodes: {arch.get('ingest_nodes', '?')}")
    lines.append(f"• Total Indices: {ti}")
    lines.append("")
    lines.append("Shard Statistics:")
    lines.append(f"• Total Shards: {sa.get('total_shards', '?')}")
    lines.append(f"• Primary Shards: {sa.get('primary_shards', '?')}")
    lines.append(f"• Relocating: {ch.get('relocating_shards', sa.get('relocating_shards', '?'))}")
    lines.append(f"• Initializing: {ch.get('initializing_shards', sa.get('initializing_shards', '?'))}")
    ua = ch.get("unassigned_shards", sa.get("unassigned_shards", 0))
    lines.append(f"• ⚠️ Unassigned: {ua}")
    lines.append(f"Shard Health Score: {score}/100")
    lines.append("")
    if int(ua or 0) > 0:
        lines.append("Shard Issues Detected:")
        lines.append(f"{emoji} {ua} unassigned shards detected")
        ax = health_data.get("allocation_explain") or {}
        if ax.get("reason"):
            lines.append(f"   Cause: {ax.get('reason')} on index={ax.get('index')} "
                         f"shard={ax.get('shard')} primary={ax.get('primary')}")
            if ax.get("can_allocate"):
                lines.append(f"   can_allocate: {ax.get('can_allocate')}")
            for d in (ax.get("decisions") or [])[:2]:
                if d.get("explanations"):
                    lines.append(f"   - {d.get('node')} ({d.get('decision')}): "
                                 f"{'; '.join(d['explanations'])}")
        else:
            es_host = (os.getenv("ES_HOST") or "http://localhost:9200").rstrip("/")
            lines.append(f"   Fix: curl -k -u \"$ES_USER:$ES_PASS\" -XGET "
                         f"'{es_host}/_cluster/allocation/explain?pretty'")
        lines.append("")

    pt = health_data.get("pending_tasks") or {}
    if int(pt.get("count") or 0) > 0:
        lines.append("Pending Master Tasks:")
        lines.append(f"• {pt['count']} pending (max wait {pt.get('max_wait_ms', 0)} ms)")
        for s in pt.get("samples") or []:
            lines.append(f"  - {s.get('priority','?')}: {s.get('source','?')}")
        lines.append("")

    df = (health_data.get("data_freshness") or {})
    df_issues = df.get("issues") or []
    if df_issues or df.get("status") == "degraded":
        lines.append("Ingestion Freshness:")
        if df_issues:
            for it in df_issues[:5]:
                if isinstance(it, dict):
                    msg = it.get("message") or it.get("note") or str(it)
                    lines.append(f"• {it.get('category', it.get('source','ingest'))}: {msg}")
                else:
                    lines.append(f"• {it}")
        else:
            lines.append("• Status: degraded (see logs)")
        lines.append("")
    elif df.get("status") == "healthy":
        lines.append("Ingestion Freshness: ✅ all monitored streams fresh")
        lines.append("")
    lines.append("ML Anomaly Detection Results:")
    lines.append(f"• Total Anomalies Detected: {ml.get('total', 0)}")
    lines.append("")

    if dr.get("error"):
        lines.append("🔴 Elastic SIEM Detection Rules")
        lines.append(f"  (Could not load rule status: {dr['error'][:500]})")
        lines.append("")
    else:
        lines.append("🔴 Elastic SIEM Detection Rules")
        lines.append(
            f"Enabled: {dr.get('enabled', 0)} | OK: {dr.get('ok', 0)} | Failed: {dr.get('failed', 0)} | "
            f"Partial: {dr.get('partial', 0)} | Warning: {dr.get('warning', 0)} | "
            f"Never executed: {dr.get('never_executed', 0)}"
        )
        lines.append("")
        if dr.get("failed_samples"):
            lines.append(f"🔴 FAILED Rules ({dr.get('failed', 0)}):")
            for s in dr["failed_samples"]:
                lines.append(f"{s['name']} [{s.get('type', '')}]")
                lines.append(f"  Reason: {s.get('reason', '')}")
                lines.append(
                    "  Fix: Open Kibana > Security > Rules > [rule name] > Last failure message for full details"
                )
                lines.append("")
        if dr.get("partial_samples"):
            lines.append(f"🟡 PARTIAL FAILURE Rules ({dr.get('partial', 0)}):")
            for s in dr["partial_samples"]:
                lines.append(f"{s['name']} [{s.get('type', '')}]")
                lines.append(f"  Reason: {s.get('reason', '')}")
                lines.append(
                    "  Fix: Open Kibana > Security > Rules > [rule name] > Last failure message for full details"
                )
                lines.append("")
        if dr.get("never_samples"):
            lines.append(f"⏸️ Never Executed ({dr.get('never_executed', 0)}):")
            for s in dr["never_samples"]:
                lines.append(f"• {s['name']} [{s.get('type', '')}]")
                lines.append("  → Enabled but never run. Check rule schedule and Kibana Task Manager.")
            lines.append("")

    lines.append("Node Performance Analysis:")
    nd = (health_data.get("node_status") or {}).get("node_details") or []
    disk_by_name = {d.get("name"): d for d in (health_data.get("disk_summary") or [])}
    for n in nd[:6]:
        nm = n.get("name") or n.get("node_id", "?")
        hp = n.get("heap_used_percent", "?")
        d = disk_by_name.get(nm)
        if d:
            lines.append(f"• {nm}: heap ~{hp}% | disk {d['used_pct']}% used "
                         f"({d['free_gb']} GB free of {d['total_gb']} GB)")
        else:
            lines.append(f"• {nm}: heap ~{hp}%")
    if not nd:
        lines.append("• (no node details in this snapshot)")
    hot_disk = [d for d in (health_data.get("disk_summary") or []) if d["used_pct"] >= 85]
    if hot_disk:
        lines.append("⚠️ Disk pressure (≥85% used):")
        for d in hot_disk:
            lines.append(f"   - {d['name']}: {d['used_pct']}% used, {d['free_gb']} GB free")
    lines.append("")

    fobs = health_data.get("factual_observations") or []
    if fobs:
        lines.append("Why (factual observations):")
        for o in fobs[:8]:
            lines.append(f"• {o}")
        lines.append("")

    lines.append("📊 Index Health Analysis:")
    ih = idx.get("health_score", 100)
    lines.append(f"💯 Overall Index Health: {ih}/100")
    lines.append(f"• Total Indices: {idx.get('total_indices', '?')}")
    if idx.get("yellow") or idx.get("red"):
        lines.append(f"• Green: {idx.get('green', 0)} | Yellow: {idx.get('yellow', 0)} | Red: {idx.get('red', 0)}")
    else:
        lines.append("")
        lines.append("✅ All indices are healthy! 🎉")
    lines.append("")
    if idx.get("largest"):
        lines.append("Largest Indices:")
        for row in idx["largest"]:
            nm = row.get("index", "")
            lines.append(f"• {nm}: {_human_gb(row.get('bytes', 0))} ({row.get('docs', 0):,} docs)")
    lines.append("")

    lines.append("AI Analysis & Insights:")
    if analysis and analysis.strip():
        lines.append(analysis.strip())
    elif (raw_llm_failure or "").strip():
        lines.append((raw_llm_failure or "").strip())
    elif ai_unavailable_note:
        lines.append("LLM analysis unavailable for this run (see LLM_MODEL / OPENAI_API_KEY / OLLAMA_URL).")
    else:
        lines.append("(No AI narrative for this run.)")
    lines.append("")
    lines.append(f"Have a productive {weekday}. Stay secure.")

    return "\n".join(lines)


def chat_chunk_text(text: str, chunk_size: int = 3800) -> List[str]:
    """Google Chat textParagraph widgets are safely kept under typical limits."""
    if len(text) <= chunk_size:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        chunks.append(text[start : start + chunk_size])
        start += chunk_size
    return chunks


def post_chat_text_message(webhook_url: str, text: str, *, fenced: bool = False) -> bool:
    """Plain text follow-up (e.g. ES JSON). Incoming webhooks accept `text` field (~4k per message)."""
    if not webhook_url or not text:
        return False
    body = text if not fenced else f"```json\n{text}\n```"
    max_len = 3500
    parts = []
    while body:
        parts.append(body[:max_len])
        body = body[max_len:]
    ok = True
    for i, part in enumerate(parts):
        try:
            prefix = f"(part {i + 1}/{len(parts)})\n" if len(parts) > 1 else ""
            r = requests.post(webhook_url, json={"text": prefix + part}, timeout=30)
            ok = ok and r.status_code == 200
        except Exception as e:
            logger.warning("post_chat_text_message failed: %s", e)
            ok = False
    return ok
