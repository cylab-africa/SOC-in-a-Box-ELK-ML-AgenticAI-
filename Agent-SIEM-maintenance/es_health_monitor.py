#!/usr/bin/env python3
"""Comprehensive Elasticsearch and Elastic Agent health monitor with Google Chat alerting.

Features:
- Monitors Elasticsearch cluster health (status, heap, disk, CPU, query latency)
- Checks data freshness across all indexes to detect stopped agents
- Monitors data ingestion rates and patterns
- Detects memory pressure, disk space, and resource exhaustion
- Identifies stopped or failing Elastic Agents
- Estimates time-to-threshold using linear trend analysis
- LLM-POWERED ANALYSIS: Contextual "what it means", "what's at risk", root cause analysis
- Sends detailed Google Chat cards for critical conditions
- Provides actionable, priority-based recommendations for each issue

Run standalone, from `maintenance_service.py` on a timer, or import as a library from `enhanced_health_monitor.py`.
"""

import os
import json
import time
import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

try:
    from elasticsearch import Elasticsearch
except Exception:
    Elasticsearch = None

try:
    from google.oauth2 import service_account as _sa
    from googleapiclient.discovery import build as _build_svc
    _HAS_GOOGLE_API = True
except ImportError:
    _HAS_GOOGLE_API = False

import requests

LOG = logging.getLogger("es_health_monitor")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s - %(levelname)s - %(message)s")

HISTORY_PATH = os.path.join("results", "es_health_history.json")
FRESHNESS_PATH = os.path.join("results", "es_data_freshness.json")
ALERT_STATE_PATH = os.path.join("results", "es_alert_state.json")
os.makedirs("results", exist_ok=True)

# Alert cooldown period (2 hours by default)
ALERT_COOLDOWN_HOURS = int(os.getenv("ES_ALERT_COOLDOWN_HOURS", "2"))

RECOMMENDATION_LIBRARY = {
    "cluster_red": [
        "Check Elasticsearch master eligibility and shard allocation; ensure at least one master node is healthy.",
        "Run `_cluster/allocation/explain` to identify unassigned shards and resolve index-level blockers.",
        "If nodes dropped, restore connectivity or restart the missing node before forcing allocation."
    ],
    "heap_pressure": [
        "Increase the JVM heap or scale horizontally by adding another data node.",
        "Inspect hot indices for heavy aggregations; consider ILM to shrink or rollover indices.",
        "Restart the node during a maintenance window if heap usage does not drop after mitigation."
    ],
    "disk_threshold": [
        "Free disk space on the node or extend the data volume immediately.",
        "Enable ILM or delete expired indices to reclaim storage.",
        "Consider increasing the watermark thresholds only as a temporary emergency measure."
    ],
    "high_cpu": [
        "Inspect running queries and aggregations via `_nodes/hot_threads`.",
        "Throttle bulk ingest or move heavy tasks to another node.",
        "Add CPU capacity or additional data nodes if sustained high utilisation persists."
    ],
    "index_rejections": [
        "Increase bulk thread pool size or ingest rate limits after analysing workload.",
        "Split large bulk loads into smaller batches and retry failed requests.",
        "Check for slow storage or cluster-wide throttling that may block indexing."
    ],
    "query_latency": [
        "Profile slow searches with `profile=true` and review shard hit counts.",
        "Check nodes flagged in the diagnosis list for resource contention.",
        "Tune search queues or add replicas to spread the search load."
    ],
    "unreachable": [
        "Verify network connectivity and TLS certificates for the Elasticsearch endpoint.",
        "Confirm credentials in ES_USERNAME/ES_PASSWORD are valid and not expired.",
        "Assess whether the cluster is offline due to maintenance or outage."
    ],
    "agent_stopped": [
        "SSH to the affected host and check agent status: `sudo systemctl status elastic-agent`",
        "Restart the agent if stopped: `sudo systemctl start elastic-agent && sudo systemctl enable elastic-agent`",
        "Check agent logs for errors: `sudo tail -100 /var/log/elastic-agent/elastic-agent-*.ndjson`",
        "Verify agent can reach Fleet Server and Elasticsearch endpoints",
        "Check for disk space issues on the endpoint that may have stopped the agent"
    ],
    "data_stale": [
        "Check Elastic Agent status on all monitored endpoints",
        "Verify network connectivity from endpoints to Elasticsearch",
        "Check Fleet Server health and agent enrollment status",
        "Review agent policies for any recent changes that may block ingestion",
        "Verify Elasticsearch ingestion pipeline is not paused or throttled"
    ],
    "no_ingestion": [
        "Verify Elastic Agents are running on all monitored hosts",
        "Check for network connectivity issues between agents and Elasticsearch",
        "Review Elasticsearch ingestion pipeline for errors or throttling",
        "Check disk space on Elasticsearch nodes - full disks block ingestion",
        "Verify agent policies and integrations are properly configured"
    ],
    "memory_pressure": [
        "Check system memory usage on Elasticsearch nodes: `free -h`",
        "Review OS cache and buffer usage - may indicate disk I/O pressure",
        "Reduce Elasticsearch heap if OS memory is constrained (but keep min 50% for OS)",
        "Add more RAM to the server or scale out to additional nodes",
        "Review and optimize memory-intensive queries and aggregations"
    ]
}


def _llm_chat_complete(model: str, system_msg: str, user_msg: str) -> Optional[str]:
    """Route LLM calls: 'gpt-*' -> OpenAI, 'claude-*' -> Anthropic, else Ollama."""
    from llm_common import llm_chat_complete
    return llm_chat_complete(model, system_msg, user_msg)


def _build_system_prompt_for_health() -> str:
    """Build dynamic system prompt with injected SYSTEM_MEMORY rules."""
    base = (
        "You are an expert Elasticsearch and SIEM operations analyst providing "
        "actionable health monitoring insights."
    )
    try:
        from system_memory import get_active_rules_text, get_rejected_patterns_text
        active = get_active_rules_text()
        rejected = get_rejected_patterns_text()
        if active:
            base += f"\n\nIMPORTANT - Apply these learned rules:\n{active}"
        if rejected:
            base += f"\n\nDo NOT follow these rejected patterns:\n{rejected}"
    except Exception:
        LOG.debug("SYSTEM_MEMORY.md not available; using base prompt")
    return base


def analyze_issues_with_llm(issues: List[Dict], cluster_stats: Dict, llm_model: str = "gpt-4o-mini") -> Optional[Dict]:
    """
    Use LLM to analyze health issues and provide:
    - Contextual explanation ("what it means")
    - Impact assessment ("what is at risk")
    - Root cause analysis
    - Priority-based actionable recommendations

    **Routing:** ``gpt-*`` models use OpenAI (``OPENAI_API_KEY``). Any other model
    name uses **Ollama** at ``OLLAMA_URL`` (same as ``enhanced_health_monitor``).

    Returns dict with analysis sections or None if LLM unavailable.
    """
    analysis_text = ""
    try:
        context = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "issues": issues,
            "cluster_status": cluster_stats.get("cluster_status", "unknown"),
            "total_nodes": cluster_stats.get("total_nodes", 0),
            "data_nodes": cluster_stats.get("data_nodes", 0),
            "active_shards": cluster_stats.get("active_shards", 0),
            "unassigned_shards": cluster_stats.get("unassigned_shards", 0),
            "heap_used_percent": cluster_stats.get("heap_used_percent", 0),
            "disk_used_percent": cluster_stats.get("disk_used_percent", 0),
        }

        user_prompt = f"""Analyze these health monitoring issues and provide a comprehensive assessment.

CONTEXT:
{json.dumps(context, indent=2)}

Provide your analysis in the following JSON format:
{{
  "what_it_means": "Clear explanation of what these issues indicate (2-3 sentences)",
  "what_is_at_risk": [
    "Specific risk 1 with business/security impact",
    "Specific risk 2 with business/security impact",
    "Specific risk 3 with business/security impact"
  ],
  "root_cause": "Most likely root cause based on correlated issues (1-2 sentences)",
  "recommendations": [
    {{
      "priority": "P0",
      "action": "Immediate action 1",
      "command": "specific command if applicable"
    }},
    {{
      "priority": "P1",
      "action": "Urgent action 2",
      "command": "specific command if applicable"
    }},
    {{
      "priority": "P2",
      "action": "Important action 3"
    }}
  ],
  "estimated_impact_time": "Estimate when this will cause severe problems (e.g., '6 hours', '2 days', 'already critical')"
}}

Focus on:
1. Practical, actionable insights
2. Security and compliance implications
3. Business impact (monitoring blind spots, data loss risk)
4. Specific commands when possible
5. Correlation between issues (e.g., disk full causing agent stops)

Respond ONLY with valid JSON."""

        system_msg = _build_system_prompt_for_health()
        LOG.debug("Requesting LLM analysis with model: %s", llm_model)
        analysis_text = _llm_chat_complete(llm_model, system_msg, user_prompt) or ""
        if not analysis_text:
            return None

        if "```json" in analysis_text:
            analysis_text = analysis_text.split("```json")[1].split("```")[0].strip()
        elif "```" in analysis_text:
            analysis_text = analysis_text.split("```")[1].split("```")[0].strip()

        analysis = json.loads(analysis_text)
        LOG.info("LLM analysis completed successfully using %s", llm_model)
        return analysis

    except json.JSONDecodeError as e:
        LOG.warning("Failed to parse LLM response as JSON: %s", e)
        LOG.debug("LLM response was: %s", analysis_text[:500] if analysis_text else "")
        return None
    except Exception as e:
        LOG.warning("LLM analysis failed: %s", e)
        return None


def load_alert_state() -> Dict:
    """Load alert state to track when alerts were last sent."""
    if not os.path.exists(ALERT_STATE_PATH):
        return {}
    
    try:
        with open(ALERT_STATE_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        LOG.warning(f"Failed to load alert state: {e}")
        return {}


def save_alert_state(state: Dict):
    """Save alert state to track when alerts were last sent."""
    try:
        os.makedirs(os.path.dirname(ALERT_STATE_PATH) or ".", exist_ok=True)
        with open(ALERT_STATE_PATH, 'w') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        LOG.warning(f"Failed to save alert state: {e}")


def should_send_alert(alert_key: str, alert_state: Dict) -> bool:
    """
    Check if an alert should be sent based on cooldown period.
    Returns True if alert hasn't been sent in the last 2 hours (or configured cooldown).
    """
    if alert_key not in alert_state:
        return True
    
    last_sent_str = alert_state[alert_key].get('last_sent')
    if not last_sent_str:
        return True
    
    try:
        last_sent = datetime.fromisoformat(last_sent_str.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        
        # Make both timezone-aware or both naive
        if last_sent.tzinfo is None:
            last_sent = last_sent.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        
        hours_since_last = (now - last_sent).total_seconds() / 3600
        
        if hours_since_last < ALERT_COOLDOWN_HOURS:
            LOG.info(f"Alert '{alert_key}' was sent {hours_since_last:.1f} hours ago. Cooldown: {ALERT_COOLDOWN_HOURS}h. Skipping.")
            return False
        
        LOG.info(f"Alert '{alert_key}' cooldown expired ({hours_since_last:.1f}h >= {ALERT_COOLDOWN_HOURS}h). Sending.")
        return True
    except Exception as e:
        LOG.warning(f"Error checking alert cooldown: {e}. Allowing send.")
        return True


def record_alert_sent(alert_key: str, alert_state: Dict, details: Dict = None):
    """Record that an alert was sent."""
    alert_state[alert_key] = {
        'last_sent': datetime.now(timezone.utc).isoformat(),
        'details': details or {}
    }
    save_alert_state(alert_state)


def get_recommendations_for_issue(issue: Dict) -> List[str]:
    cause = issue.get("cause") or issue.get("category") or ""
    recs = list(RECOMMENDATION_LIBRARY.get(cause, RECOMMENDATION_LIBRARY.get(issue.get("category", ""), [])))

    severity = issue.get("severity")
    node = issue.get("node") or "the affected node"
    if severity == "critical" and cause in ("heap_pressure", "disk_threshold"):
        recs.insert(0, f"Plan immediate intervention on {node}; critical threshold exceeded.")

    if cause == "query_latency" and issue.get("diagnosis"):
        details = issue.get("diagnosis")
        if isinstance(details, list):
            recs.append("Review suspected bottlenecks: " + "; ".join(details[:3]))
        else:
            recs.append(f"Investigate reported latency diagnosis: {details}")

    if cause == "index_rejections" and issue.get("value"):
        recs.append("Temporarily slow ingestion clients or add ingest nodes until rejections stop.")

    # Deduplicate while preserving order
    seen = set()
    unique_recs = []
    for r in recs:
        if not r:
            continue
        if r not in seen:
            seen.add(r)
            unique_recs.append(r)
    return unique_recs


def build_recommendations(issues: List[Dict], imminent: List[Dict], scenario: str, runbook_url: str = "") -> List[str]:
    recs: List[str] = []
    for issue in issues:
        if scenario and issue.get("scenario") not in (None, scenario):
            continue
        for rec in get_recommendations_for_issue(issue):
            if rec not in recs:
                recs.append(rec)

    for item in imminent or []:
        metric = item.get("metric")
        metric_scenario = "shutdown" if metric in ("heap", "disk") else "ingest"
        if scenario and metric_scenario != scenario:
            continue
        node = item.get("node")
        threshold = item.get("threshold")
        eta_h = item.get("eta_s", 0) / 3600.0 if item.get("eta_s") else None
        if eta_h is not None:
            recs.append(f"Prepare remediation for {node} {metric} reaching {threshold}% within {eta_h:.1f}h (expand capacity or shift workload).")

    if runbook_url:
        recs.append(f"Consult runbook for detailed steps: {runbook_url}")

    return recs[:10]


def _load_env_file(path: str = ".env"):
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and v and os.environ.get(k) is None:
                    os.environ[k] = v
    except Exception:
        LOG.debug("Failed loading .env")


def connect_es_from_env(timeout=30):
    host = os.getenv("ES_HOST")
    if not host or Elasticsearch is None:
        raise RuntimeError("Elasticsearch client unavailable or ES_HOST not set")
    api_key = os.getenv("ES_API_KEY", "").strip()
    if api_key:
        return Elasticsearch(hosts=[host], api_key=api_key,
                             verify_certs=False, request_timeout=timeout, ssl_show_warn=False)
    user = os.getenv("ES_USERNAME")
    pwd = os.getenv("ES_PASSWORD")
    if user and pwd:
        from urllib.parse import quote, urlparse
        parsed = urlparse(host)
        auth_host = f"{parsed.scheme}://{quote(user, safe='')}:{quote(pwd, safe='')}@{parsed.hostname}:{parsed.port or 9200}"
        return Elasticsearch(hosts=[auth_host], verify_certs=False, request_timeout=timeout, ssl_show_warn=False)
    return Elasticsearch(hosts=[host], verify_certs=False, request_timeout=timeout, ssl_show_warn=False)


def check_data_freshness(es, indexes: Dict[str, str]) -> List[Dict]:
    """
    Check data freshness across all configured indexes to detect stopped agents.
    Now checks ALL hosts individually, not just the most recent one.

    Args:
        es: Elasticsearch client
        indexes: Dict mapping index type to index pattern (e.g., {"process": ".ds-logs-endpoint.events.process-default-*"})

    Returns:
        List of issue dicts with category, cause, severity, scenario, note
    """
    issues = []
    now = datetime.now(timezone.utc)

    # Thresholds for data staleness
    STALE_WARNING_HOURS = 3
    STALE_CRITICAL_HOURS = 24
    AGENT_STOPPED_DAYS = 7

    # Operator-controlled suppression: comma-separated index type names to skip entirely
    # e.g. ES_FRESHNESS_DISABLED_INDEXES=discovery,network
    disabled_freshness_indexes = {
        s.strip().lower()
        for s in os.getenv("ES_FRESHNESS_DISABLED_INDEXES", "").split(",")
        if s.strip()
    }

    freshness_data = {}

    for index_type, index_pattern in indexes.items():
        if index_type.lower() in disabled_freshness_indexes:
            LOG.info("Skipping freshness check for '%s' (disabled via ES_FRESHNESS_DISABLED_INDEXES)", index_type)
            continue

        try:
            # ECS data streams map host.name as a keyword field directly (not host.name.keyword).
            # Using host.name works for both ECS keyword fields and dynamic-mapped text+keyword fields
            # because Elasticsearch falls back gracefully on terms aggs.
            # We try host.name first (ECS-standard); if it returns 0 buckets we also try host.hostname.
            host_field = "host.name"
            query = {
                "size": 0,
                "aggs": {
                    "hosts": {
                        "terms": {
                            "field": host_field,
                            "size": 100  # Adjust if you have more than 100 hosts
                        },
                        "aggs": {
                            "latest_event": {
                                "top_hits": {
                                    "size": 1,
                                    "sort": [{"@timestamp": {"order": "desc"}}],
                                    "_source": ["@timestamp", "host.name"]
                                }
                            }
                        }
                    }
                }
            }
            
            resp = es.search(index=index_pattern, body=query)

            host_buckets = resp.get("aggregations", {}).get("hosts", {}).get("buckets") or []

            if not host_buckets:
                # Before raising no_ingestion, verify the index actually exists and has docs.
                # An empty terms agg can also mean the host.name field is unmapped — in that
                # case there may still be indexed documents (false-positive suppression).
                try:
                    count_resp = es.count(index=index_pattern, body={"query": {"match_all": {}}})
                    doc_count = count_resp.get("count", 0)
                except Exception:
                    doc_count = 0

                if doc_count == 0:
                    # Index genuinely empty — real no_ingestion event
                    issues.append({
                        "category": "ingestion",
                        "cause": "no_ingestion",
                        "severity": "critical",
                        "scenario": "ingest",
                        "note": f"No data in {index_type} index ({index_pattern}). Agents may not be enrolled or sending data."
                    })
                    freshness_data[index_type] = {"status": "NO_DATA", "age_hours": None}
                else:
                    # Docs exist but host.name field may be unmapped — downgrade to warning
                    LOG.warning(
                        "Freshness agg for '%s' returned 0 host buckets but index has %d docs. "
                        "Check that 'host.name' is mapped as a keyword in %s.",
                        index_type, doc_count, index_pattern,
                    )
                    freshness_data[index_type] = {"status": "FIELD_UNMAPPED", "doc_count": doc_count}
                continue
            
            # Process each host
            freshness_data[index_type] = {"hosts": {}}
            
            for bucket in host_buckets:
                host_name = bucket["key"]
                latest_hit = bucket["latest_event"]["hits"]["hits"][0]
                timestamp_str = latest_hit["_source"]["@timestamp"]
                
                # Parse timestamp - handle nanosecond precision
                timestamp_str_clean = re.sub(r'\.(\d{6})\d*([+-])', r'.\1\2', timestamp_str.replace('Z', '+00:00'))
                last_event_time = datetime.fromisoformat(timestamp_str_clean)
                
                # Calculate age
                age = now - last_event_time
                age_hours = age.total_seconds() / 3600
                age_days = age.days
                
                # Store per-host data
                freshness_data[index_type]["hosts"][host_name] = {
                    "last_event": timestamp_str,
                    "age_hours": age_hours,
                    "age_days": age_days
                }
                
                # Determine severity and create issue for THIS host
                if age_days >= AGENT_STOPPED_DAYS:
                    issues.append({
                        "category": "agent",
                        "cause": "agent_stopped",
                        "severity": "critical",
                        "scenario": "ingest",
                        "node": host_name,
                        "value": age_days,
                        "note": f"No {index_type} events for {age_days}d {age.seconds//3600}h. Last: {timestamp_str} from {host_name}. Agent likely stopped."
                    })
                elif age_hours >= STALE_CRITICAL_HOURS:
                    issues.append({
                        "category": "data_freshness",
                        "cause": "data_stale",
                        "severity": "critical",
                        "scenario": "ingest",
                        "node": host_name,
                        "value": int(age_hours),
                        "note": f"{index_type} data is {int(age_hours)}h old (last: {timestamp_str} from {host_name}). Agent may be stopped."
                    })
                elif age_hours >= STALE_WARNING_HOURS:
                    issues.append({
                        "category": "data_freshness",
                        "cause": "data_stale",
                        "severity": "warning",
                        "scenario": "ingest",
                        "node": host_name,
                        "value": int(age_hours),
                        "note": f"{index_type} data is {int(age_hours)}h old (last: {timestamp_str} from {host_name}). Monitor agent health."
                    })
            
            # Log summary of hosts checked
            LOG.info(f"Checked {len(host_buckets)} hosts for {index_type} data freshness")
        
        except Exception as e:
            LOG.warning(f"Failed to check freshness for {index_type}: {e}")
            issues.append({
                "category": "data_freshness",
                "cause": "unreachable",
                "severity": "warning",
                "scenario": "ingest",
                "note": f"Failed to check freshness for {index_type}: {str(e)}"
            })
            freshness_data[index_type] = {"status": "ERROR", "error": str(e)}
    
    # Persist freshness data for trend analysis
    try:
        history = []
        if os.path.exists(FRESHNESS_PATH):
            with open(FRESHNESS_PATH, 'r') as f:
                history = json.load(f)
        
        history.append({
            "timestamp": now.isoformat(),
            "freshness": freshness_data
        })
        
        # Keep last 7 days of history
        cutoff = now - timedelta(days=7)
        history = [h for h in history if datetime.fromisoformat(h["timestamp"]) > cutoff]
        
        os.makedirs(os.path.dirname(FRESHNESS_PATH) or ".", exist_ok=True)
        with open(FRESHNESS_PATH, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        LOG.warning(f"Failed to persist freshness history: {e}")
    
    return issues


def get_stats(es) -> Dict:
    timings = {}
    health = None
    nodes = {}
    indices = {}
    try:
        t0 = time.time()
        health = es.cluster.health()
        timings['cluster_health'] = time.time() - t0
    except Exception as e:
        LOG.error("Cluster health query failed: %s", e)
        return {"error": "cluster_health_failed", "error_detail": str(e), "timings": timings}
    try:
        t0 = time.time()
        nodes = es.nodes.stats(metric=["jvm", "os", "fs", "process", "indices", "thread_pool"])  # type: ignore
        timings['nodes_stats'] = time.time() - t0
    except Exception as e:
        LOG.error("Nodes stats query failed: %s", e)
        nodes = {}
    try:
        t0 = time.time()
        indices = es.indices.stats(metric="store")
        timings['indices_stats'] = time.time() - t0
    except Exception:
        indices = {}
    return {"health": health, "nodes": nodes, "indices": indices, "ts": int(time.time()), "timings": timings}


def summarize_and_check(stats: Dict) -> List[Dict]:
    """Return list of detected issues with severity and metric values."""
    issues = []
    now = stats.get("ts", int(time.time()))
    timings = stats.get('timings', {}) or {}
    health = stats.get("health", {})
    # cluster-level checks
    if health and isinstance(health, dict):
        status = health.get("status")
        if status == "red":
            issues.append({"category": "cluster", "cause": "cluster_red", "severity": "critical", "scenario": "shutdown", "note": "Cluster health is RED"})
    nodes = stats.get("nodes", {}) or {}
    nodes_data = nodes.get("nodes", {}) if isinstance(nodes, dict) else {}
    for nid, n in nodes_data.items():
        node_name = n.get("name") or nid
        jvm = n.get("jvm", {})
        mem = jvm.get("mem", {})
        heap_pct = mem.get("heap_used_percent") if mem else None
        if heap_pct is not None and heap_pct >= 85:
            issues.append({"category": "jvm_heap", "node": node_name, "cause": "heap_pressure", "severity": "critical", "scenario": "shutdown", "value": heap_pct, "note": f"Heap used {heap_pct}%"})
        os_ = n.get("os", {})
        fs = n.get("fs", {})
        # compute disk used percent for the first fs total if present
        try:
            total = fs.get("total", {}).get("total_in_bytes")
            avail = fs.get("total", {}).get("available_in_bytes")
            if total and avail:
                used_pct = int(100 * (1 - (avail / total)))
                if used_pct >= 90:
                    issues.append({"category": "disk", "node": node_name, "cause": "disk_threshold", "severity": "critical", "scenario": "shutdown", "value": used_pct, "note": f"Disk used {used_pct}%"})
        except Exception:
            pass
        proc = n.get("process", {})
        cpu = proc.get("cpu", {})
        cpu_pct = cpu.get("percent") if cpu else None
        if cpu_pct is not None and cpu_pct >= 90:
            issues.append({"category": "cpu", "node": node_name, "cause": "high_cpu", "severity": "high", "scenario": "shutdown", "value": cpu_pct, "note": f"CPU {cpu_pct}%"})
        tp = n.get("thread_pool", {})
        idx = tp.get("index", {}) if tp else {}
        rejected = idx.get("rejected") if idx else None
        if rejected and rejected > 0:
            issues.append({"category": "ingest", "node": node_name, "cause": "index_rejections", "severity": "high", "scenario": "ingest", "value": rejected, "note": f"Index thread pool rejections={rejected}"})

    # detect slow ES query durations and attempt a diagnosis
    slow_threshold = float(os.getenv('ES_QUERY_SLOW_SEC', '2.0'))
    critical_threshold = float(os.getenv('ES_QUERY_CRITICAL_SEC', '10.0'))
    # examine timings returned by get_stats
    for call_name, dur in timings.items():
        if dur is None:
            continue
        if dur >= slow_threshold:
            sev = 'high' if dur < critical_threshold else 'critical'
            # basic diagnosis rules
            diagnosis = []
            # if any node has high cpu/heap/disk, point to resource pressure
            for nid, n in nodes_data.items():
                node_name = n.get('name') or nid
                jvm = n.get('jvm', {})
                mem = jvm.get('mem', {})
                heap_pct = mem.get('heap_used_percent') if mem else None
                proc = n.get('process', {})
                cpu = proc.get('cpu', {})
                cpu_pct = cpu.get('percent') if cpu else None
                fs = n.get('fs', {})
                try:
                    total = fs.get('total', {}).get('total_in_bytes')
                    avail = fs.get('total', {}).get('available_in_bytes')
                    used_pct = int(100 * (1 - (avail / total))) if total and avail else None
                except Exception:
                    used_pct = None
                if heap_pct and heap_pct >= 80:
                    diagnosis.append(f"{node_name}: high heap ({heap_pct}%)")
                if cpu_pct and cpu_pct >= 80:
                    diagnosis.append(f"{node_name}: high cpu ({cpu_pct}%)")
                if used_pct and used_pct >= 85:
                    diagnosis.append(f"{node_name}: high disk usage ({used_pct}%)")
                # thread pool rejections
                tp = n.get('thread_pool', {})
                idx = tp.get('index', {}) if tp else {}
                rej = idx.get('rejected') if idx else None
                if rej and rej > 0:
                    diagnosis.append(f"{node_name}: index thread pool rejections={rej}")

            # if there were errors earlier, suggest network/connectivity
            if stats.get('error'):
                diagnosis.append(f"network/connectivity error: {stats.get('error_detail')}")

            # if indices are large, suggest heavy indices/disk IO
            try:
                total_store = stats.get('indices', {}).get('_all', {}).get('total', {}).get('store', {}).get('size_in_bytes')
                if total_store and total_store > 0:
                    # convert to GB
                    gb = total_store / (1024 ** 3)
                    if gb >= 50:
                        diagnosis.append(f"large index store: {gb:.1f} GB total")
            except Exception:
                pass

            if not diagnosis:
                diagnosis = ["unknown - further investigation of nodes/indices required"]

            issues.append({
                'category': 'query_latency',
                'call': call_name,
                'duration_s': round(dur, 2),
                'severity': sev,
                'scenario': 'ingest',
                'note': f"{call_name} duration {dur:.2f}s",
                'diagnosis': diagnosis,
            })

    return issues


def load_history(path: str) -> Dict:
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
    except Exception:
        LOG.debug("Failed to load history")
    return {}


def save_history(path: str, hist: Dict):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(hist, fh)
    except Exception:
        LOG.debug("Failed to save history")


def estimate_time_to_threshold(history: Dict, node: str, metric: str, threshold: float) -> float:
    """Estimate seconds until threshold using simple linear trend on recent samples; return inf if not estimable."""
    series = history.get(node, {}).get(metric, [])
    if len(series) < 2:
        return float('inf')
    # series: list of [ts, value]
    xs = [s[0] for s in series]
    ys = [s[1] for s in series]
    # convert to seconds from first
    t0 = xs[0]
    xs_rel = [x - t0 for x in xs]
    # simple linear regression slope = cov(x,y)/var(x)
    n = len(xs_rel)
    mean_x = sum(xs_rel) / n
    mean_y = sum(ys) / n
    num = sum((xs_rel[i] - mean_x) * (ys[i] - mean_y) for i in range(n))
    den = sum((xs_rel[i] - mean_x) ** 2 for i in range(n))
    if den == 0:
        return float('inf')
    slope = num / den  # value per second
    if slope <= 0:
        return float('inf')
    current = ys[-1]
    secs = (threshold - current) / slope
    return secs if secs >= 0 else float('inf')


def _get_chat_service():
    """Build a Google Chat API service authenticated as the Chat App."""
    key_path = os.getenv("GOOGLE_CHAT_SA_KEY", "")
    if not key_path or not _HAS_GOOGLE_API:
        return None
    try:
        from pathlib import Path
        key_file = Path(key_path)
        if not key_file.is_file():
            return None
        creds = _sa.Credentials.from_service_account_file(
            str(key_file),
            scopes=["https://www.googleapis.com/auth/chat.bot"],
        )
        return _build_svc("chat", "v1", credentials=creds)
    except Exception as exc:
        LOG.debug("Failed to build Chat API service: %s", exc)
        return None


def _send_card_as_app(space_id: str, card: Dict, alert_id: str = "") -> Optional[Dict]:
    """Send a card message via Chat API as the registered Chat App.

    Returns the API response dict on success, None on failure.
    """
    svc = _get_chat_service()
    if svc is None:
        return None
    try:
        resp = svc.spaces().messages().create(
            parent=space_id,
            body={"cards": card.get("cards", [])},
        ).execute()
        thread_name = resp.get("thread", {}).get("name", "")
        if alert_id and thread_name:
            try:
                from alert_context import save_alert_context
            except ImportError:
                pass
        return resp
    except Exception as exc:
        LOG.warning("Chat API send failed: %s", exc)
        return None


def _strip_action_buttons_for_webhook(card: Dict, alert_id: str) -> Dict:
    """Replace interactive action buttons with link-mode buttons for webhook sends.

    Webhooks cannot handle onClick.action callbacks — only openLink works.
    """
    feedback_url = os.getenv("FEEDBACK_SERVER_URL", "")
    if not feedback_url and not alert_id:
        return card

    import copy
    card = copy.deepcopy(card)
    for c in card.get("cards", []):
        new_sections = []
        for section in c.get("sections", []):
            if section.get("header") == "Was this alert helpful?":
                if feedback_url and alert_id:
                    replacement = _build_feedback_link_buttons(alert_id, feedback_url)
                    if replacement:
                        new_sections.append(replacement)
                continue
            new_sections.append(section)
        c["sections"] = new_sections
    return card


def _build_feedback_link_buttons(alert_id: str, feedback_url: str) -> Optional[Dict]:
    """Build feedback buttons using openLink (safe for webhook sends)."""
    if not feedback_url or not alert_id:
        return None
    buttons = []
    for label, ftype in [("Helpful", "helpful"), ("Not Helpful", "not_helpful"), ("Incorrect", "incorrect")]:
        url = f"{feedback_url.rstrip('/')}/feedback/submit?alert_id={alert_id}&feedback_type={ftype}"
        buttons.append({"textButton": {"text": label, "onClick": {"openLink": {"url": url}}}})
    return {"header": "Was this alert helpful?", "widgets": [{"buttons": buttons}]}


def _build_feedback_buttons(alert_id: str) -> Optional[Dict]:
    """Build a card section with feedback buttons.

    Uses two modes depending on configuration:
    - App mode (GOOGLE_CHAT_SA_KEY set): onClick actions routed to the Chat App
    - Link mode (FEEDBACK_SERVER_URL set): buttons open URLs in the browser
    Returns None if neither is configured.
    """
    if not alert_id:
        return None

    has_app_mode = bool(os.getenv("GOOGLE_CHAT_SA_KEY"))
    feedback_url = os.getenv("FEEDBACK_SERVER_URL", "")

    if not has_app_mode and not feedback_url:
        return None

    def _btn_action(label: str, feedback_type: str) -> Dict:
        """Button that triggers a Chat App callback."""
        return {
            "textButton": {
                "text": label,
                "onClick": {
                    "action": {
                        "actionMethodName": "feedback_response",
                        "parameters": [
                            {"key": "alert_id", "value": alert_id},
                            {"key": "feedback_type", "value": feedback_type},
                        ],
                    }
                },
            }
        }

    def _btn_link(label: str, feedback_type: str) -> Dict:
        """Button that opens a feedback URL in the browser."""
        url = f"{feedback_url.rstrip('/')}/feedback/submit?alert_id={alert_id}&feedback_type={feedback_type}"
        return {
            "textButton": {
                "text": label,
                "onClick": {"openLink": {"url": url}},
            }
        }

    def _btn_custom() -> Optional[Dict]:
        """Button for custom instructions — dialog in app mode, link in link mode."""
        if has_app_mode:
            return {
                "textButton": {
                    "text": "Custom Instruction",
                    "onClick": {
                        "action": {
                            "actionMethodName": "open_custom_dialog",
                            "parameters": [
                                {"key": "alert_id", "value": alert_id},
                            ],
                        }
                    },
                }
            }
        form_url = os.getenv("FEEDBACK_FORM_URL", "")
        if not form_url:
            return None
        url = f"{form_url.rstrip('/')}/custom?alert_id={alert_id}"
        return {
            "textButton": {
                "text": "Custom Instruction",
                "onClick": {"openLink": {"url": url}},
            }
        }

    _btn = _btn_action if has_app_mode else _btn_link

    buttons = [
        _btn("Helpful", "helpful"),
        _btn("Not Helpful", "not_helpful"),
        _btn("Incorrect", "incorrect"),
        _btn_custom(),
    ]
    buttons = [b for b in buttons if b is not None]

    return {
        "header": "Was this alert helpful?",
        "widgets": [{"buttons": buttons}],
    }


def send_chat_card(webhook: str, space_name: str, title: str, body: str, issues: List[Dict],
                   recommendations: Optional[List[str]] = None, llm_analysis: Optional[Dict] = None,
                   alert_id: str = "") -> Dict:
    """Send enhanced health alert with optional LLM analysis and feedback buttons.

    Args:
        webhook: Google Chat webhook URL.
        space_name: Channel name (e.g., "SIEM-MAINTENANCE").
        title: Alert title.
        body: Alert body text.
        issues: List of issue dicts.
        recommendations: Legacy recommendations (used if no LLM analysis).
        llm_analysis: LLM-generated analysis dict.
        alert_id: Unique alert identifier for feedback correlation (optional).
    """
    if not webhook:
        LOG.warning("No webhook configured; skipping ES health alert")
        return {"sent": False, "reason": "no_webhook"}
    
    # Compose enhanced card with LLM analysis if available
    summary = body.splitlines()[0] if body else "Elasticsearch health alert"
    widgets = []
    
    # Add summary
    widgets.append({"textParagraph": {"text": f"<b>Summary</b>: {summary}"}})
    
    # Add LLM analysis sections if available
    if llm_analysis:
        # What it means
        if llm_analysis.get("what_it_means"):
            widgets.append({
                "textParagraph": {
                    "text": f"<b>What It Means</b>:<br>{llm_analysis['what_it_means']}"
                }
            })
        
        # What is at risk
        if llm_analysis.get("what_is_at_risk"):
            risks = "<br>".join(f"- {risk}" for risk in llm_analysis["what_is_at_risk"][:3])
            widgets.append({
                "textParagraph": {
                    "text": f"<b>What Is At Risk</b>:<br>{risks}"
                }
            })
        
        # Root cause
        if llm_analysis.get("root_cause"):
            widgets.append({
                "textParagraph": {
                    "text": f"<b>Root Cause</b>:<br>{llm_analysis['root_cause']}"
                }
            })
        
        # Impact timeline
        if llm_analysis.get("estimated_impact_time"):
            widgets.append({
                "textParagraph": {
                    "text": f"<b>Impact Timeline</b>: {llm_analysis['estimated_impact_time']}"
                }
            })
    
    # Add issues (max 5 to avoid overflow)
    if issues:
        issues_text = "<br>".join(
            f"• <b>{it.get('severity', 'unknown').upper()}</b> {it.get('node', '')}: {it.get('note', '')[:100]}"
            for it in issues[:5]
        )
        widgets.append({"textParagraph": {"text": f"<b>Issues Detected</b>:<br>{issues_text}"}})
    
    # Add LLM recommendations if available, otherwise use legacy recommendations
    if llm_analysis and llm_analysis.get("recommendations"):
        rec_text = ""
        for rec in llm_analysis["recommendations"][:5]:
            priority = rec.get("priority", "P2")
            action = rec.get("action", "")
            command = rec.get("command", "")
            
            if command:
                rec_text += f"<br><b>[{priority}]</b> {action}<br><code>{command}</code>"
            else:
                rec_text += f"<br><b>[{priority}]</b> {action}"
        
        widgets.append({"textParagraph": {"text": f"<b>Recommended Actions</b>:{rec_text}"}})
    elif recommendations:
        rec_lines = ''.join(f"<br>- {rec}" for rec in recommendations[:8])
        widgets.append({"textParagraph": {"text": f"<b>Recommended Actions</b>: {rec_lines}"}})

    logo_url = (os.getenv("GC_CARD_LOGO_URL") or "").strip()
    header: dict = {"title": title, "subtitle": space_name}
    if logo_url:
        header["imageUrl"] = logo_url

    sections = [{"widgets": widgets}]
    feedback_section = _build_feedback_buttons(alert_id)
    if feedback_section:
        sections.append(feedback_section)

    card = {"cards": [{"header": header, "sections": sections}]}

    # Try Chat API first (sends as the registered app — enables feedback buttons)
    space_id = os.getenv("GOOGLE_CHAT_SPACE_ID", "")
    if space_id and os.getenv("GOOGLE_CHAT_SA_KEY"):
        api_resp = _send_card_as_app(space_id, card, alert_id=alert_id)
        if api_resp:
            LOG.info("Alert sent via Chat API (app mode) to %s", space_name)
            return {"sent": True, "status_code": 200, "format": "card", "mode": "app"}
        LOG.debug("Chat API send failed, falling back to webhook")

    # Webhooks cannot handle interactive action buttons — strip them before sending
    card = _strip_action_buttons_for_webhook(card, alert_id)

    try:
        r = requests.post(webhook, json=card, timeout=10)
        if 200 <= r.status_code < 300:
            LOG.info(f"Enhanced alert sent successfully to {space_name}")
            return {"sent": True, "status_code": r.status_code, "format": "card"}
    except Exception as e:
        LOG.debug("Card send failed: %s", e)
    
    # Fallback to text format
    fallback_text = f"{title}\n\n{body}"
    
    if llm_analysis:
        if llm_analysis.get("what_it_means"):
            fallback_text += f"\n\nWHAT IT MEANS:\n{llm_analysis['what_it_means']}"
        
        if llm_analysis.get("what_is_at_risk"):
            fallback_text += "\n\nWHAT IS AT RISK:\n" + "\n".join(f"- {r}" for r in llm_analysis["what_is_at_risk"])
        
        if llm_analysis.get("root_cause"):
            fallback_text += f"\n\nROOT CAUSE:\n{llm_analysis['root_cause']}"
        
        if llm_analysis.get("recommendations"):
            fallback_text += "\n\nRECOMMENDED ACTIONS:\n"
            for rec in llm_analysis["recommendations"]:
                fallback_text += f"[{rec.get('priority', 'P2')}] {rec.get('action')}\n"
                if rec.get("command"):
                    fallback_text += f"    -> {rec.get('command')}\n"
    elif recommendations and "Recommended actions" not in body:
        fallback_text += "\n\nRecommended actions:\n" + "\n".join(f"- {rec}" for rec in recommendations)
    
    try:
        r2 = requests.post(webhook, json={"text": fallback_text}, timeout=10)

        if 200 <= r2.status_code < 300:
            return {"sent": True, "status_code": r2.status_code, "format": "text"}
        return {"sent": False, "status_code": r2.status_code, "text": r2.text}
    except Exception as e:
        return {"sent": False, "error": str(e)}


def generate_daily_maintenance_report(es) -> Dict:
    """Generate comprehensive daily SIEM maintenance report.
    
    Returns dict with all maintenance checks from the manual.
    """
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {}
    }
    
    # 1. Cluster Health Check
    try:
        health = es.cluster.health()
        report["checks"]["cluster_health"] = {
            "status": health.get("status"),
            "nodes": health.get("number_of_nodes"),
            "data_nodes": health.get("number_of_data_nodes"),
            "active_shards": health.get("active_shards"),
            "active_shards_percent": health.get("active_shards_percent_as_number"),
            "unassigned_shards": health.get("unassigned_shards"),
            "unassigned_primary_shards": health.get("initializing_shards", 0),
            "pending_tasks": health.get("number_of_pending_tasks"),
            "healthy": health.get("status") in ["green", "yellow"]
        }
    except Exception as e:
        report["checks"]["cluster_health"] = {"error": str(e), "healthy": False}
    
    # 2. Node Status and Resources
    try:
        nodes = es.nodes.stats(metric=["jvm", "os", "fs", "process"])
        nodes_info = es.cat.nodes(format="json", h="name,heap.percent,ram.percent,disk.used_percent,cpu,master,node.role")
        report["checks"]["nodes"] = []
        
        for node in nodes_info:
            node_data = {
                "name": node.get("name"),
                "heap_percent": node.get("heap.percent"),
                "ram_percent": node.get("ram.percent"),
                "disk_percent": node.get("disk.used_percent"),
                "cpu_percent": node.get("cpu"),
                "is_master": node.get("master") == "*",
                "role": node.get("node.role"),
                "healthy": True
            }
            
            # Flag unhealthy conditions
            try:
                if float(node.get("heap.percent", 0)) > 85:
                    node_data["healthy"] = False
                    node_data["issue"] = "High heap usage"
                elif float(node.get("disk.used_percent", 0)) > 85:
                    node_data["healthy"] = False
                    node_data["issue"] = "High disk usage"
                elif float(node.get("ram.percent", 0)) > 90:
                    node_data["healthy"] = False
                    node_data["issue"] = "High RAM usage"
            except (ValueError, TypeError):
                pass
            
            report["checks"]["nodes"].append(node_data)
    except Exception as e:
        report["checks"]["nodes"] = {"error": str(e)}
    
    # 3. Unassigned Shards Detail
    try:
        shards = es.cat.shards(format="json", h="index,shard,prirep,state,unassigned.reason,node")
        unassigned = [s for s in shards if s.get("state") == "UNASSIGNED"]
        report["checks"]["unassigned_shards"] = {
            "count": len(unassigned),
            "details": unassigned[:20],  # First 20 for brevity
            "has_unassigned_primaries": any(s.get("prirep") == "p" for s in unassigned)
        }
    except Exception as e:
        report["checks"]["unassigned_shards"] = {"error": str(e)}
    
    # 4. Disk Allocation per Node
    try:
        allocation = es.cat.allocation(format="json", v=True)
        report["checks"]["disk_allocation"] = []
        for alloc in allocation:
            report["checks"]["disk_allocation"].append({
                "node": alloc.get("node"),
                "shards": alloc.get("shards"),
                "disk_indices": alloc.get("disk.indices"),
                "disk_used": alloc.get("disk.used"),
                "disk_avail": alloc.get("disk.avail"),
                "disk_total": alloc.get("disk.total"),
                "disk_percent": alloc.get("disk.percent")
            })
    except Exception as e:
        report["checks"]["disk_allocation"] = {"error": str(e)}
    
    # 5. Pending Tasks
    try:
        pending = es.cluster.pending_tasks()
        report["checks"]["pending_tasks"] = {
            "count": len(pending.get("tasks", [])),
            "tasks": pending.get("tasks", [])[:10]  # First 10
        }
    except Exception as e:
        report["checks"]["pending_tasks"] = {"error": str(e)}
    
    # 6. Cluster Settings (allocation blocks, watermarks)
    try:
        settings = es.cluster.get_settings(include_defaults=True, flat_settings=True)
        persistent = settings.get("persistent", {})
        transient = settings.get("transient", {})
        defaults = settings.get("defaults", {})
        
        report["checks"]["cluster_settings"] = {
            "allocation_enable": persistent.get("cluster.routing.allocation.enable") or 
                                transient.get("cluster.routing.allocation.enable") or 
                                defaults.get("cluster.routing.allocation.enable", "all"),
            "watermark_low": persistent.get("cluster.routing.allocation.disk.watermark.low") or
                           defaults.get("cluster.routing.allocation.disk.watermark.low", "85%"),
            "watermark_high": persistent.get("cluster.routing.allocation.disk.watermark.high") or
                            defaults.get("cluster.routing.allocation.disk.watermark.high", "90%"),
            "watermark_flood": persistent.get("cluster.routing.allocation.disk.watermark.flood_stage") or
                             defaults.get("cluster.routing.allocation.disk.watermark.flood_stage", "95%")
        }
    except Exception as e:
        report["checks"]["cluster_settings"] = {"error": str(e)}
    
    # 7. MISP Events Check
    try:
        misp_indices = es.cat.indices(format="json", index="*misp*")
        report["checks"]["misp_events"] = {
            "count": len(misp_indices),
            "indices": [{"index": idx.get("index"), "docs": idx.get("docs.count"), "size": idx.get("store.size")} 
                       for idx in misp_indices]
        }
    except Exception as e:
        report["checks"]["misp_events"] = {"error": str(e), "count": 0}
    
    # 8. Index Health (large indices, old indices)
    try:
        all_indices = es.cat.indices(format="json", bytes="b", h="index,docs.count,store.size,creation.date")
        large_indices = []
        old_indices = []
        now = time.time() * 1000  # milliseconds
        thirty_days_ago = now - (30 * 24 * 60 * 60 * 1000)
        
        for idx in all_indices:
            try:
                size_bytes = int(idx.get("store.size", 0))
                if size_bytes > 10 * 1024 * 1024 * 1024:  # >10GB
                    large_indices.append({
                        "index": idx.get("index"),
                        "docs": idx.get("docs.count"),
                        "size_gb": round(size_bytes / (1024**3), 2)
                    })
                
                creation = float(idx.get("creation.date", now))
                if creation < thirty_days_ago:
                    old_indices.append({
                        "index": idx.get("index"),
                        "created": datetime.fromtimestamp(creation/1000, tz=timezone.utc).strftime("%Y-%m-%d"),
                        "size_gb": round(size_bytes / (1024**3), 2)
                    })
            except (ValueError, TypeError):
                continue
        
        report["checks"]["index_health"] = {
            "total_indices": len(all_indices),
            "large_indices_over_10gb": large_indices[:10],
            "old_indices_over_30days": old_indices[:10]
        }
    except Exception as e:
        report["checks"]["index_health"] = {"error": str(e)}
    
    # 9. Data Freshness (from existing function)
    indexes_to_check = {
        "process": os.getenv("ES_PROCESS_INDEX", ".ds-logs-endpoint.events.process-default-*"),
        "network": os.getenv("ES_NETWORK_INDEX", ".ds-logs-endpoint.events.network-default-*")
    }
    freshness_issues = check_data_freshness(es, indexes_to_check)
    report["checks"]["data_freshness"] = {
        "issues_count": len(freshness_issues),
        "issues": freshness_issues
    }
    
    return report


def format_daily_report_for_chat(report: Dict) -> Tuple[str, str, List[str]]:
    """Format daily maintenance report for Google Chat with a touch of humor.
    
    Returns (title, body, recommendations)
    """
    cat_tz = timezone(timedelta(hours=2))  # CAT is UTC+2
    now_cat = datetime.now(cat_tz)
    
    # Fun day-specific greetings
    day_greetings = {
        "Monday": "☕ Good Morning Sabine and Team - SIEM Daily Report (Powered by Monday Caffeine)",
        "Tuesday": "🌅 Good Morning Sabine and Team - SIEM Daily Report (Tuesday: Still Not Friday)",
        "Wednesday": "🐫 Good Morning Sabine and Team - SIEM Daily Report (Hump Day Edition)",
        "Thursday": "🎉 Good Morning Sabine and Team - SIEM Daily Report (Almost Friday!)",
        "Friday": "🎊 Good Morning Sabine and Team - SIEM Daily Report (TGIF Edition)",
        "Saturday": "🏖️ Good Morning Sabine and Team - SIEM Daily Report (Weekend Warrior Edition)",
        "Sunday": "😴 Good Morning Sabine and Team - SIEM Daily Report (Sunday Funday Status)"
    }
    
    day_name = now_cat.strftime('%A')
    title = day_greetings.get(day_name, "🌅 Good Morning Sabine and Team - SIEM Daily Report")
    
    body_lines = []
    body_lines.append(f"**Date**: {now_cat.strftime('%A, %B %d, %Y at %H:%M CAT')}")
    body_lines.append("_Your friendly neighborhood SIEM bot reporting for duty!_ 🤖")
    body_lines.append("")
    
    recommendations = []
    
    # 1. Cluster Health Summary
    cluster = report["checks"].get("cluster_health", {})
    if cluster.get("error"):
        body_lines.append("❌ **Cluster Health**: ERROR - " + cluster["error"])
        body_lines.append("   _Houston, we have a problem..._ 🚀")
        recommendations.append("URGENT: Elasticsearch cluster unreachable. Time to wake up the on-call dev!")
    elif cluster.get("status") == "red":
        body_lines.append(f"🔴 **Cluster Health**: RED ALERT! 🚨 - {cluster.get('unassigned_shards', 0)} unassigned shards")
        body_lines.append("   _Not the good kind of red (like pizza sauce). More like 'fire alarm' red._ 🔥")
        recommendations.append(f"CRITICAL: Run GET /_cluster/allocation/explain (it's like asking the cluster 'what's wrong buddy?')")
        recommendations.append("Check if any nodes are down or disk space is full (disk hoarders beware!)")
    elif cluster.get("status") == "yellow":
        body_lines.append(f"🟡 **Cluster Health**: YELLOW - {cluster.get('unassigned_shards', 0)} unassigned replicas")
        body_lines.append("   _Yellow means 'meh, could be better'. Like traffic lights, but for data._ 🚦")
        recommendations.append("Monitor cluster - yellow is acceptable but if it persists >24h, time to investigate!")
    else:
        body_lines.append(f"✅ **Cluster Health**: GREEN - All systems operational")
        body_lines.append("   _Living the dream! Everything is awesome! 🎵_ ✨")
    
    body_lines.append(f"   • Nodes: {cluster.get('nodes', 'N/A')} ({cluster.get('data_nodes', 'N/A')} data nodes)")
    body_lines.append(f"   • Active Shards: {cluster.get('active_shards', 'N/A')} ({cluster.get('active_shards_percent', 'N/A')}% active)")
    body_lines.append("")
    
    # 2. Node Resource Status
    nodes = report["checks"].get("nodes", [])
    if isinstance(nodes, list) and nodes:
        body_lines.append("**Node Resources** _(aka: How stressed are our servers?)_:")
        unhealthy_count = sum(1 for n in nodes if not n.get("healthy"))
        if unhealthy_count == 0:
            body_lines.append("   _Servers are zen. Namaste._ 🧘")
        elif unhealthy_count == len(nodes):
            body_lines.append("   _All servers need therapy. Group session recommended._ 😰")
        else:
            body_lines.append(f"   _{unhealthy_count} out of {len(nodes)} servers having a rough morning._ ☕")
        
        for node in nodes:
            icon = "✅" if node.get("healthy") else "⚠️"
            body_lines.append(f"{icon} {node['name']}: Heap {node.get('heap_percent', 'N/A')}% | "
                            f"Disk {node.get('disk_percent', 'N/A')}% | "
                            f"RAM {node.get('ram_percent', 'N/A')}% | "
                            f"CPU {node.get('cpu_percent', 'N/A')}%")
            
            if not node.get("healthy"):
                issue = node.get('issue', 'Resource pressure')
                if "disk" in issue.lower():
                    recommendations.append(f"Monitor {node['name']}: {issue} (Time for spring cleaning! 🧹)")
                elif "ram" in issue.lower():
                    recommendations.append(f"Monitor {node['name']}: {issue} (Feed it more RAM! 🐏)")
                elif "heap" in issue.lower():
                    recommendations.append(f"Monitor {node['name']}: {issue} (Heap heap hooray... not! 📚)")
                else:
                    recommendations.append(f"Monitor {node['name']}: {issue}")
        body_lines.append("")
    
    # 3. Unassigned Shards
    unassigned = report["checks"].get("unassigned_shards", {})
    if unassigned.get("count", 0) > 0:
        has_primaries = unassigned.get("has_unassigned_primaries", False)
        icon = "🔴" if has_primaries else "🟡"
        body_lines.append(f"{icon} **Unassigned Shards**: {unassigned['count']} "
                         f"({'INCLUDES PRIMARIES - CRITICAL' if has_primaries else 'replicas only'})")
        
        if has_primaries:
            body_lines.append("   _Primary shards are like house keys - you REALLY don't want to lose them!_ 🔑")
            recommendations.append("URGENT: Unassigned primary shards detected - data loss risk! (Not good, not good at all!)")
            recommendations.append("Run: GET /_cluster/allocation/explain (Ask nicely, it might tell you why)")
            recommendations.append("Check for closed indices: GET /_cat/indices?v | grep close (Maybe they're just sleeping?)")
        else:
            body_lines.append("   _Just replicas misbehaving. They're the backup singers anyway._ 🎤")
        
        if unassigned.get("details"):
            for shard in unassigned["details"][:5]:
                body_lines.append(f"   • {shard.get('index')} shard {shard.get('shard')} "
                                f"({shard.get('prirep')}) - {shard.get('unassigned.reason', 'unknown')}")
        body_lines.append("")
    else:
        body_lines.append("✅ **Unassigned Shards**: None")
        body_lines.append("   _All shards are exactly where they should be. Marie Kondo would be proud!_ ✨")
        body_lines.append("")
    
    # 4. Disk Allocation
    disk_alloc = report["checks"].get("disk_allocation", [])
    if isinstance(disk_alloc, list) and disk_alloc:
        body_lines.append("**Disk Usage Per Node** _(Digital hoarding status)_:")
        for alloc in disk_alloc:
            if alloc.get("node") and alloc.get("node") != "UNASSIGNED":
                try:
                    disk_pct = float(alloc.get("disk_percent", 0))
                    icon = "🔴" if disk_pct > 90 else "⚠️" if disk_pct > 85 else "✅"
                    body_lines.append(f"{icon} {alloc['node']}: {alloc.get('disk_percent', 'N/A')}% "
                                    f"({alloc.get('disk_used', 'N/A')} / {alloc.get('disk_total', 'N/A')})")
                    
                    if disk_pct > 95:
                        recommendations.append(f"🚨 URGENT: {alloc['node']} at {disk_pct}% - It's basically screaming for help! Run delete.sh NOW!")
                    elif disk_pct > 90:
                        recommendations.append(f"Disk pressure on {alloc['node']} at {disk_pct}% - Time for a digital diet! 🥗 (delete.sh or ILM)")
                    elif disk_pct > 85:
                        recommendations.append(f"Disk on {alloc['node']} at {disk_pct}% - Getting a bit chubby. Consider cleanup! 🧹")
                except (ValueError, TypeError):
                    pass
        body_lines.append("")
    
    # 5. MISP Events
    misp = report["checks"].get("misp_events", {})
    if misp.get("error"):
        body_lines.append("⚠️ **MISP Events**: Could not check - " + misp["error"])
        body_lines.append("   _MISP is playing hide and seek. And winning._ 🙈")
    elif misp.get("count", 0) == 0:
        body_lines.append("⚠️ **MISP Events**: No MISP indices found")
        body_lines.append("   _No threat intelligence? That's... actually kind of threatening._ 🤔")
        recommendations.append("Check MISP integration - we need those cyber threat gossip updates! 📰")
    else:
        body_lines.append(f"✅ **MISP Events**: {misp['count']} indices found")
        body_lines.append("   _Threat intel is flowing like coffee on Monday morning!_ ☕")
        for idx in misp.get("indices", [])[:3]:
            body_lines.append(f"   • {idx.get('index')}: {idx.get('docs', 'N/A')} docs ({idx.get('size', 'N/A')})")
    body_lines.append("")
    
    # 6. Large/Old Indices
    index_health = report["checks"].get("index_health", {})
    large = index_health.get("large_indices_over_10gb", [])
    old = index_health.get("old_indices_over_30days", [])
    
    if large:
        body_lines.append(f"📦 **Large Indices (>10GB)**: {len(large)} found")
        body_lines.append("   _These indices have been hitting the data buffet a bit too hard!_ 🍕")
        for idx in large[:5]:
            body_lines.append(f"   • {idx['index']}: {idx['size_gb']}GB ({idx.get('docs', 'N/A')} docs)")
        recommendations.append("Review large indices for ILM rollover or cleanup (Time to put them on a data diet! 🥗)")
        body_lines.append("")
    
    if len(old) > 10:
        body_lines.append(f"🗂️ **Old Indices (>30 days)**: {len(old)} found")
        body_lines.append(f"   _Ancient indices detected! These are older than last month's pizza in the office fridge!_ 🍕🧀")
        body_lines.append(f"   Consider cleanup: curl -XDELETE 'localhost:9200/logstash-YYYY.MM.*'")
        recommendations.append(f"Review and delete {len(old)} old indices to free space")
        body_lines.append("")
    
    # 7. Data Freshness (Agent Health)
    freshness = report["checks"].get("data_freshness", {})
    if freshness.get("issues_count", 0) > 0:
        body_lines.append(f"🔴 **Data Freshness Issues**: {freshness['issues_count']} detected")
        body_lines.append("   _Agents have ghosted us! They're not even leaving us on 'read'._ 👻")
        for issue in freshness.get("issues", [])[:3]:
            severity = issue.get("severity", "unknown").upper()
            body_lines.append(f"   {severity}: {issue.get('note', 'Unknown issue')}")
            
            if issue.get("cause") == "agent_stopped":
                host = issue.get("node", "unknown")
                recommendations.append(f"URGENT: Wake up the agent on {host}! (ssh {host} 'sudo systemctl start elastic-agent') ⏰")
        body_lines.append("")
    else:
        body_lines.append("✅ **Data Freshness**: All agents sending current data")
        body_lines.append("   _Fresh data! Fresher than the morning coffee! ☕✨_")
        body_lines.append("")
    
    # 8. Cluster Settings Check
    settings = report["checks"].get("cluster_settings", {})
    if settings.get("allocation_enable") != "all":
        body_lines.append(f"⚠️ **Cluster Settings**: Allocation is '{settings.get('allocation_enable')}' (not 'all')")
        body_lines.append("   _Allocation is disabled. It's like putting a 'Closed' sign on a 24/7 store!_ 🚫")
        recommendations.append("CRITICAL: Re-enable shard allocation ASAP! Your cluster is basically on strike! ✊")
        body_lines.append("")
    
    # Summary recommendations
    if not recommendations:
        body_lines.append("🎉 **Summary**: All systems healthy - no immediate action required")
        body_lines.append("_Everything's coming up Milhouse! Time to celebrate with a coffee break!_ ☕🎊")
        recommendations.append("Continue routine monitoring (but take it easy, you've earned it!)")
        recommendations.append("Review backup schedules and ILM policies (when you feel like it)")
        recommendations.append("Maybe treat yourself to a donut? 🍩 (You deserve it!)")
    else:
        body_lines.append(f"⚠️ **Action Items**: {len(recommendations)} recommendations below")
        if len(recommendations) > 10:
            body_lines.append("_Wow, that's a lot of action items. Better grab another coffee first!_ ☕😅")
        elif len(recommendations) > 5:
            body_lines.append("_Not too bad, but you've got some work to do. Roll up those sleeves!_ 💪")
        else:
            body_lines.append("_Just a few things to tackle. You got this!_ 👍")
    
    body = "\n".join(body_lines)
    return title, body, recommendations


def send_daily_report(dry_run=False):
    """Send daily morning maintenance report at 8:30 AM CAT."""
    _load_env_file()
    webhook = os.getenv('GC_ALERT_WEBHOOK')
    space = os.getenv('GC_ALERT_SPACE_NAME', 'SIEM-MAINTENANCE')
    
    if not webhook:
        LOG.warning("No webhook configured for daily report")
        return {"sent": False, "reason": "no_webhook"}
    
    try:
        es = connect_es_from_env()
    except Exception as e:
        LOG.error("ES connect failed for daily report: %s", e)
        if dry_run:
            LOG.info("DRY RUN: Would send ES unreachable alert")
            return {"sent": False, "reason": "es_unreachable"}
        
        # Send critical alert
        title = "SIEM Daily Report - Elasticsearch UNREACHABLE"
        body = f"Good Morning Sabine and Team,\n\nElasticsearch cluster could not be reached.\n\nError: {e}"
        recommendations = [
            "Check if Elasticsearch service is running: systemctl status elasticsearch",
            "Verify network connectivity to ES nodes",
            "Review Elasticsearch logs for errors"
        ]
        res = send_chat_card(webhook, space, title, body, [], recommendations)
        return res
    
    # Generate comprehensive report
    report = generate_daily_maintenance_report(es)
    title, body, recommendations = format_daily_report_for_chat(report)
    
    if dry_run:
        LOG.info("DRY RUN: Daily report")
        LOG.info("Title: %s", title)
        LOG.info("Body:\n%s", body)
        LOG.info("Recommendations: %s", recommendations)
        return {"sent": False, "dry_run": True}
    
    # Send to Google Chat
    res = send_chat_card(webhook, space, title, body, [], recommendations)
    LOG.info("Daily report send result: %s", res)
    
    # Save report to file for record keeping
    try:
        report_file = os.path.join("results", f"daily_report_{datetime.now().strftime('%Y%m%d')}.json")
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        LOG.info("Daily report saved to %s", report_file)
    except Exception as e:
        LOG.warning("Failed to save daily report to file: %s", e)
    
    return res


def main(dry_run=False):
    _load_env_file()
    webhook = os.getenv('GC_ALERT_WEBHOOK')
    space = os.getenv('GC_ALERT_SPACE_NAME', 'SIEM-MAINTENANCE')
    runbook_url = os.getenv('ES_HEALTH_RUNBOOK_URL', '')
    try:
        es = connect_es_from_env()
    except Exception as e:
        LOG.error("ES connect failed: %s", e)
        if not webhook:
            return
        body = f"Elasticsearch unreachable: {e}"
        recommendations = build_recommendations([
            {"cause": "unreachable", "severity": "critical", "node": "cluster"}
        ], [], 'shutdown', runbook_url)
        if dry_run:
            LOG.info("DRY RUN: would send: %s | recommendations=%s", body, recommendations)
            return
        res = send_chat_card(webhook, space, "Elasticsearch Health: unreachable", body, [], recommendations)
        LOG.info("Alert send result: %s", res)
        return

    stats = get_stats(es)
    if stats.get('error'):
        LOG.error("Stats error: %s", stats.get('error_detail'))
    issues = summarize_and_check(stats)
    
    # Enhanced data freshness check with intelligent thresholds
    # Only alert if multiple data sources are stale simultaneously (reduces false positives)
    indexes_to_check = {
        "process": os.getenv("ES_PROCESS_INDEX", ".ds-logs-endpoint.events.process-default-*"),
        "network": os.getenv("ES_NETWORK_INDEX", ".ds-logs-endpoint.events.network-default-*"),
        "discovery": os.getenv("ES_DISCOVERY_INDEX", "logs-endpoint.events.process-*")
    }
    freshness_issues = check_data_freshness(es, indexes_to_check)
    
    # Smart filtering: only alert if 2+ distinct hosts are stale or 1 source is critically stale (>=24h)
    # This avoids false positives where a single host appears stale across multiple index types
    critical_freshness_issues = []
    stale_hosts = set()
    for issue in freshness_issues:
        age_hours = issue.get('value', 0)
        if issue.get('cause') == 'agent_stopped':
            critical_freshness_issues.append(issue)
        elif issue.get('severity') == 'critical' and age_hours >= 24:
            critical_freshness_issues.append(issue)
        elif issue.get('cause') == 'data_stale':
            host = issue.get('node', 'unknown')
            stale_hosts.add(host)

    # If 2+ distinct hosts are stale, it's likely a real ingestion issue (not a transient blip)
    if len(stale_hosts) >= 2:
        critical_freshness_issues.extend([issue for issue in freshness_issues if issue.get('cause') == 'data_stale'])
    
    issues.extend(critical_freshness_issues)
    
    # Log freshness status for debugging
    if freshness_issues:
        LOG.info(f"Data freshness check found {len(freshness_issues)} issues, {len(critical_freshness_issues)} deemed critical")
        for issue in freshness_issues:
            age = issue.get('value', 'unknown')
            LOG.debug(f"Freshness issue: {issue.get('cause')} - {issue.get('note')} (age: {age}h)")
    else:
        LOG.debug("Data freshness check: all indexes current")

    # persist metrics for trend: per-node heap, disk
    hist = load_history(HISTORY_PATH)
    now = int(time.time())
    nodes = stats.get('nodes', {}).get('nodes', {}) if isinstance(stats.get('nodes'), dict) else {}
    for nid, n in (nodes.items() if isinstance(nodes, dict) else []):
        name = n.get('name') or nid
        jvm = n.get('jvm', {})
        heap = (jvm.get('mem') or {}).get('heap_used_percent')
        fs = (n.get('fs') or {}).get('total') or {}
        try:
            total = fs.get('total_in_bytes')
            avail = fs.get('available_in_bytes')
            disk_pct = int(100 * (1 - (avail / total))) if total and avail else None
        except Exception:
            disk_pct = None
        entry = hist.setdefault(name, {})
        if heap is not None:
            entry.setdefault('heap', []).append([now, heap])
            entry['heap'] = entry['heap'][-10:]
        if disk_pct is not None:
            entry.setdefault('disk', []).append([now, disk_pct])
            entry['disk'] = entry['disk'][-10:]

    save_history(HISTORY_PATH, hist)

    # compute ETA for dangerous metrics
    imminent = []
    for node, entry in hist.items():
        t_heap = estimate_time_to_threshold(hist, node, 'heap', 95)
        if t_heap != float('inf') and t_heap <= 7200:
            imminent.append({'node': node, 'metric': 'heap', 'eta_s': t_heap, 'threshold': 95})
        t_disk = estimate_time_to_threshold(hist, node, 'disk', 95)
        if t_disk != float('inf') and t_disk <= 7200:
            imminent.append({'node': node, 'metric': 'disk', 'eta_s': t_disk, 'threshold': 95})

    # Group issues by scenario (shutdown vs ingest) and send separate cards per category
    by_scenario = {}
    for it in issues:
        sc = it.get('scenario', 'ingest')
        by_scenario.setdefault(sc, []).append(it)

    # persist traces for imminent events (ETA <= 2 hours)
    TRACE_PATH = os.path.join('results', 'es_health_traces.json')
    traces = {}
    if os.path.exists(TRACE_PATH):
        try:
            with open(TRACE_PATH, 'r', encoding='utf-8') as tf:
                traces = json.load(tf)
        except Exception:
            traces = {}

    # Load alert state for cooldown tracking
    alert_state = load_alert_state()
    
    # Get LLM model from environment (ES Health specific model, defaults to gpt-4o-mini)
    llm_model = os.getenv("ES_HEALTH_LLM_MODEL") or os.getenv("LLM_MODEL", "gpt-4o-mini")
    llm_enabled = os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes")
    
    # Comma-separated list of scenarios to skip (e.g., "ingest,disk")
    disabled_scenarios = {
        s.strip().lower()
        for s in os.getenv("ES_HEALTH_DISABLED_SCENARIOS", "").split(",")
        if s.strip()
    }

    # send alerts per scenario
    for scenario, items in by_scenario.items():
        if scenario.lower() in disabled_scenarios:
            LOG.info(f"Skipping alert for scenario '{scenario}' (disabled via ES_HEALTH_DISABLED_SCENARIOS)")
            continue

        # Create alert key for cooldown tracking
        alert_key = f"scenario_{scenario}"

        # Check if we should send this alert (cooldown check)
        if not should_send_alert(alert_key, alert_state):
            LOG.info(f"Skipping alert for scenario '{scenario}' due to cooldown")
            continue
        
        lines = []
        lines.append(f"Scenario: {scenario} — {len(items)} issue(s)")
        for it in items:
            node = it.get('node', 'cluster')
            sev = it.get('severity')
            note = it.get('note')
            val = it.get('value')
            if val is not None:
                lines.append(f"{sev.upper()} - {node}: {note} (value={val})")
            else:
                lines.append(f"{sev.upper()} - {node}: {note}")

        # include imminent timelines for this scenario
        for im in imminent:
            # map imminent metric to scenario type: heap/disk -> shutdown, others -> ingest
            metric = im.get('metric')
            metric_scenario = 'shutdown' if metric in ('heap', 'disk') else 'ingest'
            if metric_scenario != scenario:
                continue
            eta_h = im['eta_s'] / 3600.0
            lines.append(f"Imminent: {im['node']} {im['metric']} will reach {im['threshold']}% in ~{eta_h:.2f} hours")
            # record trace
            traces.setdefault(im['node'], []).append({'metric': im['metric'], 'eta_s': im['eta_s'], 'threshold': im['threshold'], 'ts': now})

        body = "\n".join(lines)
        title = f"Elasticsearch Alert: {scenario.upper()}"
        
        # Generate LLM analysis if enabled
        llm_analysis = None
        if llm_enabled and items:
            LOG.info(f"Generating LLM analysis for {len(items)} issues in scenario '{scenario}'")
            
            # Extract actual cluster stats from the stats dict for LLM context
            health = stats.get('health', {}) or {}
            nodes_data = stats.get('nodes', {})
            nodes_dict = nodes_data.get('nodes', {}) if isinstance(nodes_data, dict) else {}
            
            # Calculate aggregate metrics from actual node data
            total_heap_used = 0
            total_disk_used = 0
            node_count = 0
            
            for nid, node in nodes_dict.items():
                node_count += 1
                jvm = node.get('jvm', {})
                heap_pct = jvm.get('mem', {}).get('heap_used_percent', 0)
                if heap_pct:
                    total_heap_used += heap_pct
                
                fs = node.get('fs', {})
                try:
                    total = fs.get('total', {}).get('total_in_bytes')
                    avail = fs.get('total', {}).get('available_in_bytes')
                    if total and avail:
                        disk_pct = int(100 * (1 - (avail / total)))
                        total_disk_used += disk_pct
                except Exception:
                    pass
            
            avg_heap = (total_heap_used / node_count) if node_count > 0 else 0
            avg_disk = (total_disk_used / node_count) if node_count > 0 else 0
            
            # Build proper cluster_stats dict with real data
            cluster_stats = {
                "cluster_status": health.get("status", "unknown"),
                "total_nodes": health.get("number_of_nodes", 0),
                "data_nodes": health.get("number_of_data_nodes", 0),
                "active_shards": health.get("active_shards", 0),
                "unassigned_shards": health.get("unassigned_shards", 0),
                "heap_used_percent": round(avg_heap, 1),
                "disk_used_percent": round(avg_disk, 1),
            }
            
            LOG.debug(f"LLM context: cluster_status={cluster_stats['cluster_status']}, nodes={cluster_stats['total_nodes']}, shards={cluster_stats['active_shards']}")
            
            llm_analysis = analyze_issues_with_llm(items, cluster_stats, llm_model)
            
            if llm_analysis:
                LOG.info("LLM analysis generated successfully")
            else:
                LOG.warning(
                    "AI/LLM unavailable — continuing with built-in recommendations only "
                    "(scheduler and alerts still run; fix LLM or set LLM_ENABLED=false)."
                )
        
        # Build legacy recommendations as fallback
        recommendations = build_recommendations(items, imminent, scenario, runbook_url)
        
        if dry_run:
            LOG.info("DRY RUN: would send alert for %s: %s\n%s", scenario, title, body)
            if llm_analysis:
                LOG.info("DRY RUN: LLM Analysis: %s", json.dumps(llm_analysis, indent=2))
            else:
                LOG.info("DRY RUN: Legacy Recommendations: %s", recommendations)
        else:
            # Generate alert_id for feedback correlation
            try:
                from alert_context import generate_alert_id, save_alert_context
                _alert_id = generate_alert_id()
            except Exception:
                _alert_id = ""

            res = send_chat_card(webhook, space, title, body, items, recommendations, llm_analysis, alert_id=_alert_id)
            LOG.info("ES health alert send result for %s: %s", scenario, res)

            # Record that alert was sent
            if res.get('sent'):
                record_alert_sent(alert_key, alert_state, {
                    'scenario': scenario,
                    'issue_count': len(items),
                    'title': title,
                    'llm_analysis_used': llm_analysis is not None
                })
                if _alert_id:
                    try:
                        save_alert_context(
                            alert_id=_alert_id,
                            scenario=scenario,
                            issues=items,
                            recommendations=recommendations,
                            llm_analysis=llm_analysis,
                            card_title=title,
                        )
                    except Exception as _ctx_err:
                        LOG.debug("Failed to save alert context: %s", _ctx_err)

    # save traces
    try:
        with open(TRACE_PATH, 'w', encoding='utf-8') as tf:
            json.dump(traces, tf)
    except Exception:
        LOG.debug("Failed to save traces")

    if not issues and not imminent:
        LOG.info("No critical conditions detected")
    else:
        LOG.info("Detected %d issue(s) and %d imminent threshold(s)", len(issues), len(imminent))


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--dry-run', action='store_true')
    args = p.parse_args()
    main(dry_run=args.dry_run)
