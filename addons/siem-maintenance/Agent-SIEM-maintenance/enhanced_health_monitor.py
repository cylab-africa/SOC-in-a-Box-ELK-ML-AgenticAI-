#!/usr/bin/env python3
"""
Enhanced Elasticsearch Health and Alert Analysis System

This script provides:
1. Real-time health monitoring of Elasticsearch cluster and data ingestion
2. LLM-powered analysis of health issues and recommendations
3. Intelligent alert generation with context and actionable insights
4. Integration with Google Chat for immediate notifications

Usage:
    python enhanced_health_monitor.py [--analyze-alerts] [--dry-run] [--llm-model MODEL]
"""

import os
import json
import logging
import argparse
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional
import requests


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting so text renders cleanly in Google Chat."""
    text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
    text = re.sub(r'\*\*(.+?)\*\*', r'\1', text)
    text = re.sub(r'__(.+?)__', r'\1', text)
    text = re.sub(r'\*(.+?)\*', r'\1', text)
    text = re.sub(r'_(.+?)_', r'\1', text)
    text = re.sub(r'`([^`]+)`', r'\1', text)
    text = re.sub(r'```[\s\S]*?```', '', text)
    return text


def _load_env_files() -> None:
    here = Path(__file__).resolve().parent
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    load_dotenv(here.parent / ".env", override=False)
    load_dotenv(here / ".env", override=True)


_load_env_files()

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("enhanced_health_monitor")


def _llm_output_is_failure(text: str) -> bool:
    """True if ``call_llm_api`` returned an error placeholder instead of model text."""
    if not (text and text.strip()):
        return False
    t = text.strip()
    return t.startswith("LLM analysis failed") or t.startswith("LLM analysis unavailable")


def _ollama_tags(base_url: str, timeout: float = 5.0) -> Optional[set]:
    """List installed Ollama tags. Returns None on connectivity failure (vs empty set = up but no models)."""
    try:
        r = requests.get(f"{base_url.rstrip('/')}/api/tags",
                         headers={"User-Agent": "siem-maintenance"}, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json() or {}
        names = set()
        for m in (data.get("models") or []):
            n = (m.get("name") or "").strip()
            if n:
                names.add(n)
        return names
    except requests.RequestException:
        return None


def _ollama_model_present(tags: Optional[set], want: str) -> bool:
    if not tags or not want:
        return False
    w = want.strip()
    for n in tags:
        if n == w or n.startswith(w + ":") or w in n:
            return True
    return False


def call_llm_api(prompt: str, model: str = "gpt-4", max_tokens: int = 4000) -> str:
    """Call OpenAI or Ollama. On failure returns 'LLM analysis failed: <classified reason>'.

    Reason strings are stable enough for operators to grep:
      - 'OpenAI API key not configured'
      - 'OpenAI API error <code>'
      - 'Ollama not reachable at <url> (connection)'
      - 'Ollama model <name> not pulled — run: ollama pull <name>'
      - 'Ollama timed out after <s>s (model cold-load?)'
      - 'Ollama returned empty response (prompt may exceed num_ctx)'
      - 'Ollama API error <code>: <body excerpt>'
    """
    if model.startswith("gpt-"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            return "LLM analysis failed: OpenAI API key not configured"
        try:
            from llm_common import _openai_uses_new_params
            new_style = _openai_uses_new_params(model)
            payload: dict = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
            }
            if new_style:
                payload["max_completion_tokens"] = max_tokens
            else:
                payload["max_tokens"] = max_tokens
                payload["temperature"] = 0.3
            openai_timeout = int(os.getenv("OPENAI_TIMEOUT_SECONDS", "300"))
            r = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json=payload,
                timeout=openai_timeout,
            )
        except requests.Timeout:
            return "LLM analysis failed: OpenAI request timed out"
        except requests.RequestException as e:
            return f"LLM analysis failed: OpenAI network error ({e.__class__.__name__})"
        if r.status_code != 200:
            logger.error("OpenAI API error: %s - %s", r.status_code, r.text[:300])
            return f"LLM analysis failed: OpenAI API error {r.status_code}"
        try:
            text = (r.json()["choices"][0]["message"]["content"] or "").strip()
        except (KeyError, IndexError, ValueError):
            return "LLM analysis failed: OpenAI response malformed"
        if not text:
            finish = (r.json().get("choices") or [{}])[0].get("finish_reason", "unknown")
            return f"LLM analysis failed: OpenAI returned empty content (finish_reason={finish}; raise max_completion_tokens or OPENAI_TIMEOUT_SECONDS)"
        return text

    base = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    timeout_s = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "180"))
    num_ctx = int(os.getenv("OLLAMA_NUM_CTX", "8192"))

    tags = _ollama_tags(base)
    if tags is None:
        return f"LLM analysis failed: Ollama not reachable at {base} (connection)"
    if not _ollama_model_present(tags, model):
        installed = ", ".join(sorted(tags)) or "(no models installed)"
        return (
            f"LLM analysis failed: Ollama model '{model}' not pulled — "
            f"run: ollama pull {model}. Installed: {installed}"
        )

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "num_predict": max_tokens,
            "num_ctx": num_ctx,
        },
    }
    last_err = ""
    for attempt in (1, 2):
        try:
            r = requests.post(f"{base}/api/generate", json=payload, timeout=timeout_s)
        except requests.Timeout:
            last_err = f"Ollama timed out after {timeout_s}s (model cold-load?)"
            logger.warning("%s (attempt %d)", last_err, attempt)
            continue
        except requests.RequestException as e:
            last_err = f"Ollama network error ({e.__class__.__name__})"
            logger.warning("%s (attempt %d)", last_err, attempt)
            continue
        if r.status_code == 404:
            return (f"LLM analysis failed: Ollama model '{model}' not found by server — "
                    f"run: ollama pull {model}")
        if r.status_code != 200:
            logger.error("Ollama API error: %s - %s", r.status_code, r.text[:300])
            return f"LLM analysis failed: Ollama API error {r.status_code}: {r.text[:200]}"
        try:
            text = ((r.json() or {}).get("response") or "").strip()
        except ValueError:
            return "LLM analysis failed: Ollama response not JSON"
        if not text:
            return ("LLM analysis failed: Ollama returned empty response "
                    "(prompt may exceed num_ctx; raise OLLAMA_NUM_CTX or trim the prompt)")
        return text
    return f"LLM analysis failed: {last_err}"

def analyze_health_with_llm(health_data: dict, model: str = "gpt-4") -> str:
    """Use LLM to analyze health data and provide insights based on factual observations."""
    
    factual_obs = health_data.get("factual_observations", [])
    cluster_health = health_data.get("cluster_health", {})
    agent_status = health_data.get("agent_status", {})
    shard_analysis = health_data.get("shard_analysis", {})
    node_status = health_data.get("node_status", {})

    agent_summary = {}
    for k, v in (agent_status or {}).items():
        if isinstance(v, dict):
            agent_summary[k] = {"active_agents": v.get("active_agents", v.get("error", 0))}
    shard_summary = {k: shard_analysis.get(k) for k in
                     ("total_shards", "primary_shards", "replica_shards",
                      "unassigned_shards", "relocating_shards", "initializing_shards")
                     if isinstance(shard_analysis, dict)}
    nd = (node_status or {}).get("node_details") or []
    nodes_compact = [
        {"name": n.get("name"), "heap_percent": n.get("heap_used_percent"),
         "roles": [r for r in (n.get("roles") or []) if r in ("master", "data", "ingest")]}
        for n in nd[:8]
    ]

    prompt = f"""
You are a senior SIEM/Elasticsearch operations analyst. Based ONLY on the factual observations below, provide specific recommendations and analysis. Do NOT make assumptions or estimates.

FACTUAL OBSERVATIONS FROM SIEM:
{chr(10).join(f"- {obs}" for obs in factual_obs) or "- (no factual observations recorded)"}

CLUSTER STATUS:
- Status: {cluster_health.get('status', 'unknown')}
- Nodes: {cluster_health.get('number_of_nodes', 'unknown')} total, {cluster_health.get('number_of_data_nodes', 'unknown')} data nodes
- Shards: {cluster_health.get('active_shards', 'unknown')} active, {cluster_health.get('unassigned_shards', 0)} unassigned
- Pending tasks: {cluster_health.get('number_of_pending_tasks', 0)}

AGENT STATUS SUMMARY:
{json.dumps(agent_summary, indent=2)}

SHARD ANALYSIS:
{json.dumps(shard_summary, indent=2)}

NODE DETAILS (top 8 by listing order):
{json.dumps(nodes_compact, indent=2)}

Provide analysis in these sections. Use PLAIN TEXT only — no markdown, no asterisks, no hashtags, no bold/italic formatting. Use UPPERCASE for section headers and dashes for bullet points.

IMMEDIATE ACTIONS REQUIRED (Next 30 minutes)
- List specific actions needed RIGHT NOW based on observed facts
- Include exact node names, agent IDs, shard counts where applicable
- Prioritize by severity of impact on security monitoring

AGENT INVESTIGATION FINDINGS
- Which agents are NOT reporting (specific agent IDs if known)
- Which hosts have missing coverage
- Data ingestion gaps identified by timestamp analysis

INFRASTRUCTURE ISSUES DETECTED
- Specific shard allocation problems with exact counts
- Node performance issues with actual metrics
- Resource constraints with measured values

SPECIFIC RECOMMENDATIONS
- Exact commands to run or configs to check
- Specific thresholds that are exceeded
- Concrete next steps with measurable outcomes

ROOT CAUSE ANALYSIS
- Based ONLY on the observed data patterns
- Timeline of when issues likely started
- Correlation between different metrics observed

Focus on FACTS, not estimates. If data is missing, state that explicitly rather than guessing.
IMPORTANT: Do NOT use any markdown formatting (no **, no ## , no ``` , no _italic_). Write plain text only.
"""
    
    # Reasoning models (gpt-5-*, o1-*, o3-*) consume hidden reasoning tokens before
    # producing visible output. 8000 provides enough budget for both.
    return call_llm_api(prompt, model, max_tokens=8000)

def get_comprehensive_health_status() -> dict:
    """Get comprehensive health status with detailed SIEM investigation."""
    health_status = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "cluster_health": {},
        "data_freshness": {},
        "agent_status": {},
        "shard_analysis": {},
        "node_status": {},
        "ingestion_rates": {},
        "alerts": [],
        "factual_observations": [],
        "specific_recommendations": []
    }
    
    try:
        # Import and run the ES health monitor
        import es_health_monitor
        
        # Get ES connection
        es = es_health_monitor.connect_es_from_env()
        if not es:
            health_status["alerts"].append({
                "severity": "critical",
                "category": "connectivity",
                "message": "Cannot connect to Elasticsearch cluster - SIEM unavailable"
            })
            return health_status
        
        # Get detailed cluster information
        logger.info("Investigating cluster health and node status...")
        cluster_health = es.cluster.health()
        cluster_stats = es.cluster.stats()
        nodes_info = es.nodes.info()
        try:
            nodes_stats = es.nodes.stats(metric=["jvm", "os", "fs", "process"])
        except Exception as e:
            logger.warning("nodes.stats timed out, retrying with minimal metrics: %s", e)
            try:
                nodes_stats = es.nodes.stats(metric=["jvm", "fs"])
            except Exception:
                nodes_stats = {}
        
        health_status["cluster_health"] = {
            "status": cluster_health.get("status"),
            "number_of_nodes": cluster_health.get("number_of_nodes"),
            "number_of_data_nodes": cluster_health.get("number_of_data_nodes"),
            "active_primary_shards": cluster_health.get("active_primary_shards"),
            "active_shards": cluster_health.get("active_shards"),
            "relocating_shards": cluster_health.get("relocating_shards"),
            "initializing_shards": cluster_health.get("initializing_shards"),
            "unassigned_shards": cluster_health.get("unassigned_shards"),
            "delayed_unassigned_shards": cluster_health.get("delayed_unassigned_shards"),
            "number_of_pending_tasks": cluster_health.get("number_of_pending_tasks"),
            "task_max_waiting_in_queue_millis": cluster_health.get("task_max_waiting_in_queue_millis")
        }
        
        # Detailed shard analysis
        logger.info("Analyzing shard distribution and health...")
        try:
            shards = es.cat.shards(format="json", h="index,shard,prirep,state,docs,store,node")
            health_status["shard_analysis"] = {
                "total_shards": len(shards),
                "primary_shards": len([s for s in shards if s.get("prirep") == "p"]),
                "replica_shards": len([s for s in shards if s.get("prirep") == "r"]),
                "unassigned_shards": len([s for s in shards if s.get("state") == "UNASSIGNED"]),
                "relocating_shards": len([s for s in shards if s.get("state") == "RELOCATING"]),
                "initializing_shards": len([s for s in shards if s.get("state") == "INITIALIZING"]),
                "shard_details": shards[:20]  # First 20 for analysis
            }
        except Exception as e:
            logger.warning(f"Failed to get shard details: {e}")
            health_status["shard_analysis"] = {"error": str(e)}
        
        # Node status analysis
        logger.info("Checking individual node performance...")
        node_details = []
        for node_id, node_info in nodes_info.get("nodes", {}).items():
            node_stat = nodes_stats.get("nodes", {}).get(node_id, {})
            node_detail = {
                "node_id": node_id,
                "name": node_info.get("name"),
                "roles": node_info.get("roles", []),
                "ip": node_info.get("ip"),
                "heap_used_percent": node_stat.get("jvm", {}).get("mem", {}).get("heap_used_percent", 0),
                "disk_usage": node_stat.get("fs", {}).get("total", {}),
                "load_average": node_stat.get("os", {}).get("cpu", {}).get("load_average"),
                "uptime": node_stat.get("jvm", {}).get("uptime_in_millis", 0)
            }
            node_details.append(node_detail)
        
        health_status["node_status"] = {
            "total_nodes": len(node_details),
            "data_nodes": len([n for n in node_details if "data" in n.get("roles", [])]),
            "master_nodes": len([n for n in node_details if "master" in n.get("roles", [])]),
            "node_details": node_details
        }
        
        # Agent status investigation - check for active agents by looking at recent data
        logger.info("Investigating agent status through data patterns...")
        indexes_to_check = {
            "process": os.getenv("ES_PROCESS_INDEX", ".ds-logs-endpoint.events.process-default-*"),
            "network": os.getenv("ES_NETWORK_INDEX", ".ds-logs-endpoint.events.network-default-*"),
            "discovery": os.getenv("ES_DISCOVERY_INDEX", "logs-endpoint.events.process-*")
        }
        
        agent_analysis = {}
        for data_type, index_pattern in indexes_to_check.items():
            try:
                # Get unique agents reporting in last 2 hours
                query = {
                    "size": 0,
                    "query": {
                        "range": {
                            "@timestamp": {
                                "gte": "now-2h"
                            }
                        }
                    },
                    "aggs": {
                        "agents": {
                            "terms": {
                                # ECS data streams map agent.id as keyword directly (no .keyword sub-field)
                                "field": "agent.id",
                                "size": 1000
                            },
                            "aggs": {
                                "latest": {
                                    "max": {
                                        "field": "@timestamp"
                                    }
                                },
                                "hosts": {
                                    "terms": {
                                        "field": "host.name.keyword",
                                        "size": 10
                                    }
                                }
                            }
                        }
                    }
                }
                
                result = es.search(index=index_pattern, body=query)
                active_agents = result.get("aggregations", {}).get("agents", {}).get("buckets", [])
                
                agent_analysis[data_type] = {
                    "active_agents": len(active_agents),
                    "agent_details": [
                        {
                            "agent_id": agent["key"],
                            "event_count": agent["doc_count"],
                            "last_seen": agent["latest"]["value_as_string"],
                            "hosts": [h["key"] for h in agent.get("hosts", {}).get("buckets", [])]
                        }
                        for agent in active_agents[:10]  # Top 10 most active
                    ]
                }
                
            except Exception as e:
                logger.warning(f"Failed to analyze {data_type} agents: {e}")
                agent_analysis[data_type] = {"error": str(e)}
        
        health_status["agent_status"] = agent_analysis
        
        # Data freshness with specific timestamps
        freshness_issues = es_health_monitor.check_data_freshness(es, indexes_to_check)
        health_status["data_freshness"] = {
            "issues": freshness_issues,
            "status": "healthy" if not freshness_issues else "degraded",
            "last_check": datetime.utcnow().isoformat() + "Z"
        }
        
        # Generate factual observations
        observations = []
        
        # Cluster observations
        if cluster_health.get("status") != "green":
            observations.append(f"Cluster status is {cluster_health.get('status')} (not green)")
        
        if health_status["cluster_health"].get("unassigned_shards", 0) > 0:
            observations.append(f"Found {health_status['cluster_health']['unassigned_shards']} unassigned shards")
        
        # Node observations
        high_heap_nodes = [n for n in node_details if n.get("heap_used_percent", 0) > 85]
        if high_heap_nodes:
            observations.append(f"Found {len(high_heap_nodes)} nodes with >85% heap usage: {[n['name'] for n in high_heap_nodes]}")
        
        # Agent observations
        for data_type, analysis in agent_analysis.items():
            if "error" not in analysis:
                agent_count = analysis.get("active_agents", 0)
                observations.append(f"Found {agent_count} active agents reporting {data_type} data in last 2 hours")
                if agent_count == 0:
                    observations.append(f"NO AGENTS reporting {data_type} data - potential ingestion failure")
        
        health_status["factual_observations"] = observations
        
        # Analyze all issues
        all_issues = es_health_monitor.summarize_and_check(cluster_stats)
        all_issues.extend(freshness_issues)
        health_status["alerts"] = all_issues
        
        # Calculate severity counts
        severity_counts = {"critical": 0, "warning": 0, "info": 0}
        for issue in all_issues:
            severity = issue.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        health_status["summary"] = {
            "total_issues": len(all_issues),
            "severity_breakdown": severity_counts,
            "overall_status": "critical" if severity_counts["critical"] > 0 else 
                            "warning" if severity_counts["warning"] > 0 else "healthy"
        }

        try:
            from siem_daily_report import enrich_health_for_daily_report

            enrich_health_for_daily_report(es, health_status, nodes_info, cluster_stats)
        except Exception as enrich_ex:
            logger.warning("Daily report enrichment skipped: %s", enrich_ex)

    except Exception as e:
        logger.exception(f"Failed to get comprehensive health status: {e}")
        health_status["alerts"].append({
            "severity": "critical",
            "category": "system_error",
            "message": f"Health monitoring system error: {str(e)}"
        })
    
    return health_status

def send_enhanced_alert(
    health_data: dict,
    analysis: str,
    dry_run: bool = False,
    *,
    ai_unavailable_note: bool = False,
    llm_error_detail: str = "",
) -> bool:
    """Send structured Daily SIEM Report to Google Chat plus optional ES JSON excerpt."""
    from siem_daily_report import (
        build_es_snapshot_text,
        chat_chunk_text,
        daily_report_titles,
        fetch_recent_es_log_excerpt,
        format_daily_siem_report,
        post_chat_text_message,
    )

    webhook_url = os.getenv("GC_ALERT_WEBHOOK")
    if not webhook_url:
        logger.warning("GC_ALERT_WEBHOOK not configured; cannot send alerts")
        return False

    report_text = format_daily_siem_report(
        health_data,
        analysis,
        ai_unavailable_note=ai_unavailable_note,
        raw_llm_failure=llm_error_detail or "",
    )
    title, subtitle = daily_report_titles()

    sections: List[dict] = []
    for chunk in chat_chunk_text(report_text):
        sections.append({"widgets": [{"textParagraph": {"text": chunk}}]})

    kibana = (os.getenv("KIBANA_HOST") or "").strip() or os.getenv("ES_HOST", "https://localhost:9200").replace(
        ":9200", ":5601"
    )
    es_h = os.getenv("ES_HOST", "https://localhost:9200").rstrip("/")

    sections.append({
        "header": "Quick links",
        "widgets": [{
            "buttons": [
                {
                    "textButton": {
                        "text": "Kibana Security",
                        "onClick": {"openLink": {"url": f"{kibana.rstrip('/')}/app/security/overview"}},
                    }
                },
                {
                    "textButton": {
                        "text": "Cluster health",
                        "onClick": {"openLink": {"url": f"{es_h}/_cluster/health?pretty"}},
                    }
                },
            ]
        }],
    })

    # Generate alert_id and append feedback + custom-instruction buttons
    _alert_id = ""
    try:
        from alert_context import generate_alert_id, save_alert_context
        import es_health_monitor as _ehm
        _alert_id = generate_alert_id()
        fb_section = _ehm._build_feedback_buttons(_alert_id)
        if fb_section:
            sections.append(fb_section)
    except Exception as _fb_err:
        logger.debug("Could not build feedback buttons: %s", _fb_err)

    logo_url = (os.getenv("GC_CARD_LOGO_URL") or "").strip()
    header: dict = {"title": title, "subtitle": subtitle}
    if logo_url:
        header["imageUrl"] = logo_url

    card = {
        "cards": [{
            "header": header,
            "sections": sections,
        }]
    }

    if dry_run:
        logger.info("DRY RUN: Would send Daily SIEM Report card + ES snapshot")
        logger.info(json.dumps(card, indent=2)[:12000])
        return True

    try:
        # Prefer Chat API app-mode (enables interactive buttons); fall back to webhook
        space_id = os.getenv("GOOGLE_CHAT_SPACE_ID", "")
        sent_via_app = False
        if space_id and os.getenv("GOOGLE_CHAT_SA_KEY"):
            try:
                import es_health_monitor as _ehm
                api_resp = _ehm._send_card_as_app(space_id, card, alert_id=_alert_id)
                if api_resp:
                    sent_via_app = True
                    logger.info("Daily SIEM Report card sent via Chat API (app mode)")
            except Exception as _app_err:
                logger.debug("App-mode send failed, using webhook: %s", _app_err)

        if not sent_via_app:
            # Webhooks cannot handle interactive action buttons — strip them
            try:
                import es_health_monitor as _ehm
                card = _ehm._strip_action_buttons_for_webhook(card, _alert_id)
            except Exception:
                pass
            response = requests.post(webhook_url, json=card, timeout=90)
            if response.status_code != 200:
                logger.error("Failed to send Chat card: %s - %s", response.status_code, response.text[:500])
                return False
            logger.info("Daily SIEM Report card sent to Google Chat")

        if _alert_id:
            try:
                save_alert_context(
                    alert_id=_alert_id,
                    scenario="daily_report",
                    issues=health_data.get("alerts", []) if isinstance(health_data, dict) else [],
                    recommendations=None,
                    llm_analysis={"what_it_means": analysis[:2000]} if analysis else None,
                    card_title=title,
                )
            except Exception as _ctx_err:
                logger.debug("Could not save alert context: %s", _ctx_err)

        attach_logs = os.getenv("DAILY_REPORT_ATTACH_ES_LOGS", "false").lower() in ("1", "true", "yes", "on")
        attach_json = os.getenv("DAILY_REPORT_ATTACH_ES_JSON", "false").lower() in ("1", "true", "yes", "on")
        if attach_logs:
            try:
                import es_health_monitor as _ehm
                es_client = _ehm.connect_es_from_env()
            except Exception as e:
                logger.warning("Could not open ES client for log excerpt: %s", e)
                es_client = None
            if es_client is not None:
                try:
                    excerpt = fetch_recent_es_log_excerpt(es_client)
                except Exception as e:
                    logger.warning("Log excerpt fetch failed: %s", e)
                    excerpt = f"(log excerpt unavailable: {e})"
                post_chat_text_message(
                    webhook_url,
                    "Elastic log excerpt (last 24h, WARN/ERROR + cluster diagnostics):\n" + excerpt,
                    fenced=True,
                )
        if attach_json:
            snap = build_es_snapshot_text(health_data)
            post_chat_text_message(
                webhook_url,
                f"Elasticsearch snapshot (JSON excerpt for operators):\n{snap}",
                fenced=False,
            )
        return True
    except Exception as e:
        logger.exception("Failed to send Daily SIEM Report: %s", e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Enhanced Elasticsearch Health Monitor with LLM Analysis")
    parser.add_argument("--analyze-alerts", action="store_true", help="Analyze existing alerts and send enhanced notification")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing them")
    parser.add_argument("--llm-model", default="gpt-4", help="LLM model to use for analysis (gpt-4, gpt-3.5-turbo, llama2, etc.)")
    parser.add_argument("--send-alert-threshold", choices=["critical", "warning", "any"], default="warning", 
                        help="Minimum severity to trigger alert sending")
    parser.add_argument("--no-chat", action="store_true",
                        help="Do not post to Google Chat (still gather health; run LLM only if LLM_ENABLED)")
    args = parser.parse_args()
    
    logger.info("Starting enhanced Elasticsearch health monitoring")

    llm_enabled = os.getenv("LLM_ENABLED", "true").lower() in ("true", "1", "yes", "on")

    # Get comprehensive health status
    health_data = get_comprehensive_health_status()
    
    # Determine if we should send an alert
    should_alert = False
    overall_status = health_data.get("summary", {}).get("overall_status", "healthy")
    
    if args.send_alert_threshold == "any" and health_data.get("alerts"):
        should_alert = True
    elif args.send_alert_threshold == "warning" and overall_status in ["warning", "critical"]:
        should_alert = True
    elif args.send_alert_threshold == "critical" and overall_status == "critical":
        should_alert = True
    
    # Generate LLM analysis if there are issues or if explicitly requested
    analysis = ""
    ai_unavailable_note = False
    raw_llm = ""
    if (should_alert or args.analyze_alerts) and llm_enabled:
        logger.info(f"Generating LLM analysis using model: {args.llm_model}")
        raw_llm = analyze_health_with_llm(health_data, args.llm_model)
        if _llm_output_is_failure(raw_llm):
            logger.warning(
                "AI/LLM request failed or is misconfigured — continuing with metrics-only default "
                "(no AI narrative for this run). Check OpenAI key, OLLAMA_URL, or install/pull the model."
            )
            analysis = ""
            ai_unavailable_note = True
        else:
            analysis = _strip_markdown(raw_llm)

        if not args.dry_run:
            # Save analysis for future reference
            analysis_file = f"results/health_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs("results", exist_ok=True)
            with open(analysis_file, "w") as f:
                json.dump({
                    "timestamp": health_data["timestamp"],
                    "health_data": health_data,
                    "llm_analysis": analysis,
                    "llm_failed": ai_unavailable_note,
                    "llm_error_detail": raw_llm if ai_unavailable_note else None,
                    "model_used": args.llm_model
                }, f, indent=2)
            logger.info(f"Analysis saved to {analysis_file}")
    elif (should_alert or args.analyze_alerts) and not llm_enabled:
        logger.info("LLM_ENABLED is off — skipping LLM analysis (health snapshot still saved)")
        if not args.dry_run:
            analysis_file = f"results/health_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            os.makedirs("results", exist_ok=True)
            with open(analysis_file, "w") as f:
                json.dump(
                    {
                        "timestamp": health_data["timestamp"],
                        "health_data": health_data,
                        "llm_analysis": "",
                        "model_used": None,
                        "llm_disabled": True,
                    },
                    f,
                    indent=2,
                )
            logger.info("Health snapshot saved to %s (no LLM)", analysis_file)

    # Send alert if needed
    if (should_alert or args.analyze_alerts) and not args.no_chat:
        logger.info(f"Sending enhanced alert (threshold: {args.send_alert_threshold}, status: {overall_status})")
        send_enhanced_alert(
            health_data,
            analysis,
            args.dry_run,
            ai_unavailable_note=ai_unavailable_note,
            llm_error_detail=raw_llm if ai_unavailable_note else "",
        )
    elif args.no_chat and (should_alert or args.analyze_alerts):
        logger.info("Skipping Google Chat (--no-chat)")
    else:
        logger.info(f"No alert needed (status: {overall_status}, threshold: {args.send_alert_threshold})")
    
    # Print summary
    total_issues = health_data.get("summary", {}).get("total_issues", 0)
    if total_issues > 0:
        logger.warning(f"Health check completed: {total_issues} issues found (status: {overall_status})")
        return 1 if overall_status == "critical" else 0
    else:
        logger.info("Health check completed: All systems healthy")
        return 0

if __name__ == "__main__":
    exit(main())