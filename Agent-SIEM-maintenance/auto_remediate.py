#!/usr/bin/env python3
"""
AUTO-INVESTIGATION AND REMEDIATION SYSTEM
==========================================

This script automatically investigates and resolves common Elasticsearch issues
within 5 minutes of detection. It performs safe, reversible operations and logs
all actions for audit trail.

SAFE AUTO-FIXES IMPLEMENTED:
1. Recover from cluster RED (clear allocation exclusions, retry reroute)
2. Clear abandoned scroll contexts (when >80% limit reached)
3. Reroute unassigned shards (with retry logic)
4. Adjust thread pool queue sizes (when rejections detected)
5. Clear fielddata cache (when memory pressure detected)
6. Clear request/query caches (when any node heap >=80%)
7. Cancel long-running search tasks (>30min, only when CPU >=85%)
8. Restart ILM and retry errored indices (skips essentials)
9. Force-merge over-sharded read-only indices (>50 segments/primary, >=1GB, non-essential)
10. Delete old ML result files (when disk pressure detected)
11. Delete old .monitoring-*/.watcher-history-*/.ml-notifications-* indices (>7 days)
12. Restart failed/stopped transforms (with transform-node pre-check)
13. Restart stopped ML anomaly detection jobs (only previously-trained jobs)
14. Clean up old snapshots (>30 days, completed only)
15. Retry failed Snapshot Lifecycle Management (SLM) policies
16. Delete old empty indices (0 docs, >90 days, non-essential)
17. Import or clean up dangling indices
18. Clear read-only blocks after disk watermark recovery (<90% usage)
19. Restart stopped Watcher service

INVESTIGATIVE ACTIONS (no changes):
1. Detailed cluster allocation explanation
2. Hot thread analysis
3. Slow query log inspection
4. Node resource usage breakdown
5. Index segment analysis

PROTECTIONS:
- Essential indices (.ds-logs-endpoint.events.*, .internal.alerts-*) are NEVER deleted
- Pre-validation checks prevent false positive fixes
- All actions send Google Chat notifications to SIEM-MAINTENANCE
- Alerts sent if essential indices are problematic (requires manual intervention)

Usage:
    # Run full auto-remediation
    python auto_remediate.py --auto-fix
    
    # Investigation only (no changes)
    python auto_remediate.py --investigate-only
    
    # Specific issue remediation
    python auto_remediate.py --fix scroll-contexts
    python auto_remediate.py --fix thread-pools
    python auto_remediate.py --fix fielddata
    
    # Dry-run mode
    python auto_remediate.py --auto-fix --dry-run
"""

import os
import sys
import json
import logging
import argparse
import traceback
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Safe environment loading
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("auto_remediate")

# Essential indices that must NEVER be deleted or modified destructively
ESSENTIAL_INDICES = [
    ".ds-logs-endpoint.events.process-default-*",
    ".ds-logs-endpoint.events.network-default-*",
    ".internal.alerts-security.alerts-default-*",
    "logs-endpoint.events.*",
    ".ds-logs-endpoint.events.file-default-*",
]

RESULTS_DIR = Path("results")
RESULTS_DIR.mkdir(exist_ok=True)
REMEDIATION_LOG = RESULTS_DIR / "auto_remediation_log.jsonl"
MAX_REMEDIATION_AGE_HOURS = 24  # Don't re-apply same fix within 24h

# Google Chat webhook for infrastructure alerts
GC_WEBHOOK = os.getenv("GC_ALERT_WEBHOOK", "")
GC_SPACE = os.getenv("GC_ALERT_SPACE_NAME", "SIEM-MAINTENANCE")


def send_google_chat_notification(title: str, message: str, severity: str = "INFO",
                                   dry_run: bool = False, alert_id: str = "") -> bool:
    """Send notification to Google Chat for remediation actions.

    Args:
        title: Card title.
        message: Card body text.
        severity: One of SUCCESS, WARNING, ERROR, INFO, CRITICAL.
        dry_run: If True, log only without sending.
        alert_id: Optional alert identifier for feedback button correlation.

    Returns:
        True if notification was sent successfully.
    """
    if dry_run:
        logger.info("DRY RUN: Would send Google Chat [%s]: %s", severity, title)
        return True

    if not GC_WEBHOOK:
        logger.warning("No GC_ALERT_WEBHOOK configured; skipping notification")
        return False

    severity_prefix = {
        "SUCCESS": "[SUCCESS]",
        "WARNING": "[WARNING]",
        "ERROR": "[ERROR]",
        "INFO": "[INFO]",
        "CRITICAL": "[CRITICAL]",
    }
    prefix = severity_prefix.get(severity, "[INFO]")

    body_html = message.replace("\n", "<br>")

    logo_url = (os.getenv("GC_CARD_LOGO_URL") or "").strip()
    header: dict = {
        "title": f"{prefix} {title}",
        "subtitle": f"Auto-Remediation • {GC_SPACE}"
    }
    if logo_url:
        header["imageUrl"] = logo_url

    sections: list = [{"widgets": [{"textParagraph": {"text": body_html}}]}]

    if alert_id:
        try:
            from es_health_monitor import _build_feedback_buttons
            fb_section = _build_feedback_buttons(alert_id)
            if fb_section:
                sections.append(fb_section)
        except Exception:
            pass

    card_payload = {"cards": [{"header": header, "sections": sections}]}

    try:
        space_id = os.getenv("GOOGLE_CHAT_SPACE_ID", "")
        if space_id and os.getenv("GOOGLE_CHAT_SA_KEY"):
            try:
                from es_health_monitor import _send_card_as_app
                api_resp = _send_card_as_app(space_id, card_payload, alert_id=alert_id)
                if api_resp:
                    logger.info("Google Chat notification sent via app mode: %s", title)
                    return True
            except Exception:
                pass
            from es_health_monitor import _strip_action_buttons_for_webhook
            card_payload = _strip_action_buttons_for_webhook(card_payload, alert_id)

        resp = requests.post(GC_WEBHOOK, json=card_payload, timeout=15)
        if 200 <= resp.status_code < 300:
            logger.info("Google Chat notification sent: %s", title)
            return True
        else:
            logger.warning("Google Chat notification failed: %s", resp.status_code)
            return False
    except Exception as e:
        logger.error("Failed to send Google Chat notification: %s", e)
        return False


def is_essential_index(index_name: str) -> bool:
    """Check if index matches essential index patterns."""
    from fnmatch import fnmatch
    for pattern in ESSENTIAL_INDICES:
        if fnmatch(index_name, pattern):
            return True
    return False


def _build_system_prompt_for_remediation() -> str:
    """Build dynamic system prompt with injected SYSTEM_MEMORY rules."""
    base = (
        "You are an expert Elasticsearch SRE. Provide exactly 3 copy-paste ready "
        "terminal commands to fix the issue. Each line must start with the number "
        "and contain a complete command."
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
        pass
    return base


def get_llm_recommendations(issue: Dict[str, Any]) -> Optional[str]:
    """Use LLM to generate specific, actionable recommendations.

    Routes to OpenAI, Anthropic, or Ollama based on model name.
    """
    llm_enabled = os.getenv('LLM_ENABLED', 'true').lower() in ('1', 'true', 'yes', 'on')
    if not llm_enabled:
        return None

    model = os.getenv('LLM_MODEL', 'gpt-4o-mini')

    system_prompt = _build_system_prompt_for_remediation()

    user_prompt = f"""Issue on {issue.get('node')}: {issue.get('description')}

Give 3 exact commands:
1. [First command with curl/API]
2. [Second command]
3. [Third command]

Format: "1. curl -X POST 'https://ES:9200/_endpoint' -d '...'"
No explanations."""

    def _parse_numbered(content: str) -> Optional[str]:
        lines = content.splitlines()
        recommendations = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if (len(line) > 2 and line[0].isdigit() and line[1:3].strip().startswith('.')) or line.startswith(
                ('-', '•', '*', '**')
            ):
                line = line.replace('**', '')
                recommendations.append(line)
        if len(recommendations) >= 2:
            return "\n".join(recommendations[:3])
        return None

    try:
        import requests

        if model.startswith("gpt-"):
            openai_key = os.getenv('OPENAI_API_KEY')
            if not openai_key:
                logger.debug("No OPENAI_API_KEY; skipping LLM recommendations for OpenAI model")
                return None
            from llm_common import _openai_uses_new_params
            new_style = _openai_uses_new_params(model)
            payload: dict = {
                'model': model,
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_prompt},
                ],
            }
            if new_style:
                payload['max_completion_tokens'] = 2000
            else:
                payload['max_tokens'] = 2000
                payload['temperature'] = 0.1
            response = requests.post(
                'https://api.openai.com/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {openai_key}',
                    'Content-Type': 'application/json',
                },
                json=payload,
                timeout=60,
            )
            if response.status_code != 200:
                logger.warning("OpenAI API error: %s - %s", response.status_code, response.text[:100])
                return None
            data = response.json()
            content = data['choices'][0]['message']['content'].strip()
            return _parse_numbered(content)

        if model.startswith("claude-"):
            anthropic_key = os.getenv('ANTHROPIC_API_KEY')
            if not anthropic_key:
                logger.debug("No ANTHROPIC_API_KEY; skipping LLM recommendations for Anthropic model")
                return None
            response = requests.post(
                'https://api.anthropic.com/v1/messages',
                headers={
                    'x-api-key': anthropic_key,
                    'anthropic-version': '2023-06-01',
                    'Content-Type': 'application/json',
                },
                json={
                    'model': model,
                    'max_tokens': 300,
                    'system': system_prompt,
                    'messages': [
                        {'role': 'user', 'content': user_prompt},
                    ],
                    'temperature': 0.1,
                },
                timeout=60,
            )
            if response.status_code != 200:
                logger.warning("Anthropic API error: %s - %s", response.status_code, response.text[:100])
                return None
            data = response.json()
            content_blocks = data.get('content') or []
            content = "".join(b.get('text', '') for b in content_blocks if b.get('type') == 'text').strip()
            return _parse_numbered(content)

        base = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
        r = requests.post(
            f"{base}/api/generate",
            json={
                "model": model,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 512},
            },
            timeout=120,
        )
        if r.status_code != 200:
            logger.warning("Ollama error: %s - %s", r.status_code, r.text[:100])
            return None
        content = (r.json() or {}).get("response", "").strip()
        return _parse_numbered(content)

    except requests.Timeout:
        logger.warning("LLM timeout for %s", issue.get('type'))
        return None
    except Exception as e:
        logger.debug("LLM recommendation error: %s", e)
        return None


def get_es_client():
    """Get Elasticsearch client — API key takes precedence over username/password."""
    try:
        from elasticsearch import Elasticsearch

        es_host = os.getenv("ES_HOST", "http://localhost:9200")
        api_key = os.getenv("ES_API_KEY", "").strip()

        if api_key:
            es = Elasticsearch([es_host], api_key=api_key,
                               verify_certs=False, request_timeout=30)
        else:
            es_user = os.getenv("ES_USERNAME")
            es_pass = os.getenv("ES_PASSWORD")
            if not es_user or not es_pass:
                logger.error("ES credentials not configured (ES_API_KEY or ES_USERNAME/ES_PASSWORD)")
                return None
            es = Elasticsearch([es_host], basic_auth=(es_user, es_pass),
                               verify_certs=False, request_timeout=30)

        if not es.ping():
            logger.error("Cannot reach Elasticsearch at %s", es_host)
            return None

        return es
    except Exception as e:
        logger.error("Failed to create ES client: %s", e)
        return None


def log_remediation_action(action_type: str, details: Dict, success: bool, dry_run: bool = False):
    """Log all remediation actions to audit trail."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": action_type,
        "details": details,
        "success": success,
        "dry_run": dry_run
    }
    
    try:
        with open(REMEDIATION_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.warning(f"Failed to log remediation action: {e}")


def check_recent_remediation(action_type: str, lookback_hours: int = 24) -> bool:
    """Check if this remediation was recently applied to avoid repeated actions."""
    if not REMEDIATION_LOG.exists():
        return False
    
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    
    try:
        with open(REMEDIATION_LOG, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if entry.get("action_type") == action_type:
                        ts_str = entry.get("timestamp", "")
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts > cutoff and entry.get("success"):
                            logger.info(f"Remediation '{action_type}' was applied {(datetime.now(timezone.utc) - ts).total_seconds() / 3600:.1f}h ago")
                            return True
                except:
                    continue
    except:
        pass
    
    return False


def clear_scroll_contexts(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Clears all active scroll contexts to free memory and allow new training jobs.
    When scroll context limit is reached, all new parallel data fetches fail immediately.
    This is safe because active training jobs will fail anyway due to the limit.
    
    PRE-VALIDATION: Checks if scroll count actually warrants clearing (>50 scrolls or >80% limit)
    """
    try:
        if check_recent_remediation("clear_scroll_contexts", lookback_hours=1):
            return True, "Already cleared scrolls within last hour, skipping"
        
        # Get current scroll count and cluster settings
        stats = es.nodes.stats(metric=["indices"], index_metric=["search"])
        settings = es.cluster.get_settings(include_defaults=True, flat_settings=True)
        
        # Get max scroll contexts (default 500 per node)
        max_scrolls_str = (
            settings.get("transient", {}).get("search.max_open_scroll_context") or
            settings.get("persistent", {}).get("search.max_open_scroll_context") or
            settings.get("defaults", {}).get("search.max_open_scroll_context") or
            "500"
        )
        max_scrolls_per_node = int(str(max_scrolls_str))
        
        total_scrolls = 0
        node_count = 0
        for node_id, node_data in stats.get("nodes", {}).items():
            scroll_current = node_data.get("indices", {}).get("search", {}).get("scroll_current", 0)
            total_scrolls += scroll_current
            node_count += 1
        
        if total_scrolls == 0:
            return True, "No active scroll contexts to clear"
        
        # Pre-validation: Only clear if genuinely problematic (>50 scrolls or >80% limit)
        total_max = max_scrolls_per_node * max(node_count, 1)
        scroll_pct = (total_scrolls / total_max * 100) if total_max > 0 else 0
        
        if total_scrolls < 50 and scroll_pct < 80:
            msg = f"Scroll contexts not problematic: {total_scrolls} total ({scroll_pct:.0f}% of limit)"
            logger.info(msg)
            return True, msg
        
        logger.info(f"Found {total_scrolls} active scroll contexts ({scroll_pct:.0f}% of limit)")
        
        if dry_run:
            msg = f"DRY RUN: Would clear {total_scrolls} scroll contexts ({scroll_pct:.0f}% of limit)"
            send_google_chat_notification(
                "Scroll Context Cleanup (Dry Run)",
                f"<b>Action:</b> Clear abandoned scroll contexts<br>"
                f"<b>Current:</b> {total_scrolls} scrolls ({scroll_pct:.0f}% of {total_max} limit)<br>"
                f"<b>Reason:</b> Prevent training job failures<br>"
                f"<b>Mode:</b> DRY RUN - no changes made",
                "INFO",
                dry_run
            )
            return True, msg
        
        # Clear all scrolls
        result = es.clear_scroll(scroll_id="_all")
        
        log_remediation_action("clear_scroll_contexts", {
            "scroll_count_before": total_scrolls,
            "scroll_pct": scroll_pct,
            "max_scrolls": total_max,
            "reason": "Scroll context limit approaching or exceeded"
        }, True, dry_run)
        
        msg = f"Cleared {total_scrolls} scroll contexts ({scroll_pct:.0f}% of limit) - training jobs can now proceed"
        
        send_google_chat_notification(
            "Scroll Contexts Cleared",
            f"<b>Action:</b> Cleared abandoned scroll contexts<br>"
            f"<b>Removed:</b> {total_scrolls} scrolls<br>"
            f"<b>Impact:</b> Training jobs can now proceed without timeout failures<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS",
            dry_run
        )
        
        return True, msg
    
    except Exception as e:
        logger.exception("Failed to clear scroll contexts")
        log_remediation_action("clear_scroll_contexts", {"error": str(e)}, False, dry_run)
        
        send_google_chat_notification(
            "Scroll Context Cleanup Failed",
            f"<b>Action:</b> Clear scroll contexts<br>"
            f"<b>Error:</b> {str(e)}<br>"
            f"<b>Status:</b> Manual intervention may be required",
            "ERROR",
            dry_run
        )
        
        return False, f"Error: {e}"


def adjust_thread_pool_settings(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Increases search and write thread pool queue sizes when rejections detected.
    This allows more concurrent queries during training and reduces timeout failures.
    Settings are transient (cleared on restart) for safety.
    
    PRE-VALIDATION: Only adjusts if rejections are genuinely problematic (>100 search or >50 write)
    """
    try:
        if check_recent_remediation("adjust_thread_pools", lookback_hours=6):
            return True, "Thread pools adjusted within last 6 hours, skipping"
        
        stats = es.nodes.stats(metric=["thread_pool"])
        
        max_search_rejected = 0
        max_write_rejected = 0
        
        for node_id, node_data in stats.get("nodes", {}).items():
            pools = node_data.get("thread_pool", {})
            search_rejected = pools.get("search", {}).get("rejected", 0)
            write_rejected = pools.get("write", {}).get("rejected", 0)
            
            max_search_rejected = max(max_search_rejected, search_rejected)
            max_write_rejected = max(max_write_rejected, write_rejected)
        
        # Pre-validation: Only adjust if genuinely problematic
        if max_search_rejected < 100 and max_write_rejected < 50:
            return True, f"Thread pool rejections not problematic (search: {max_search_rejected}, write: {max_write_rejected})"
        
        changes = {}
        if max_search_rejected >= 100:
            changes["thread_pool.search.queue_size"] = 2000
        if max_write_rejected >= 50:
            changes["thread_pool.write.queue_size"] = 1000
        
        logger.info(f"Applying thread pool adjustments: {changes}")
        
        if dry_run:
            msg = f"DRY RUN: Would apply settings: {changes}"
            send_google_chat_notification(
                "Thread Pool Adjustment (Dry Run)",
                f"<b>Action:</b> Increase thread pool queue sizes<br>"
                f"<b>Search Rejected:</b> {max_search_rejected}<br>"
                f"<b>Write Rejected:</b> {max_write_rejected}<br>"
                f"<b>Planned Changes:</b> {', '.join(f'{k}={v}' for k,v in changes.items())}<br>"
                f"<b>Mode:</b> DRY RUN - no changes made",
                "INFO",
                dry_run
            )
            return True, msg
        
        # Apply transient settings (cleared on restart for safety)
        es.cluster.put_settings(body={"transient": changes})
        
        log_remediation_action("adjust_thread_pools", {
            "settings": changes,
            "search_rejected": max_search_rejected,
            "write_rejected": max_write_rejected
        }, True, dry_run)
        
        msg = f"Increased thread pool sizes: {changes}"
        
        send_google_chat_notification(
            "Thread Pools Adjusted",
            f"<b>Action:</b> Increased thread pool queue sizes<br>"
            f"<b>Search Rejected:</b> {max_search_rejected} → queue increased to 2000<br>"
            f"<b>Write Rejected:</b> {max_write_rejected} → queue increased to 1000<br>"
            f"<b>Impact:</b> Training jobs less likely to timeout<br>"
            f"<b>Type:</b> Transient settings (cleared on restart)<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS",
            dry_run
        )
        
        return True, msg
    
    except Exception as e:
        logger.exception("Failed to adjust thread pool settings")
        log_remediation_action("adjust_thread_pools", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def clear_fielddata_cache(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Clears fielddata cache when memory pressure is high.
    Fielddata consumes heap memory and can cause OOM or circuit breaker trips.
    Clearing it is safe - ES will rebuild as needed (with brief query slowdown).
    
    PRE-VALIDATION: Checks if fielddata is actually problematic (>100MB total)
    PROTECTION: Identifies if essential indices are causing the issue
    """
    try:
        if check_recent_remediation("clear_fielddata", lookback_hours=2):
            return True, "Fielddata cleared within last 2 hours, skipping"
        
        # Check fielddata size globally
        stats = es.nodes.stats(metric=["indices"], index_metric=["fielddata"])
        
        total_fielddata_mb = 0
        for node_id, node_data in stats.get("nodes", {}).items():
            fielddata_bytes = node_data.get("indices", {}).get("fielddata", {}).get("memory_size_in_bytes", 0)
            total_fielddata_mb += fielddata_bytes / (1024**2)
        
        # Pre-validation: Only clear if genuinely problematic (>100MB)
        if total_fielddata_mb < 100:
            return True, f"Fielddata usage ({total_fielddata_mb:.1f}MB) is acceptable"
        
        # Check if essential indices are the culprits (handle closed indices gracefully)
        essential_indices_affected = []
        try:
            # Only query open indices to avoid closed index errors
            index_stats = es.indices.stats(metric=["fielddata"], expand_wildcards=["open"])
            for idx_name, idx_data in index_stats.get("indices", {}).items():
                fielddata_bytes = idx_data.get("total", {}).get("fielddata", {}).get("memory_size_in_bytes", 0)
                fielddata_mb = fielddata_bytes / (1024**2)
                
                if fielddata_mb > 50 and is_essential_index(idx_name):
                    essential_indices_affected.append({
                        "index": idx_name,
                        "fielddata_mb": fielddata_mb
                    })
        except Exception as e:
            logger.warning(f"Could not query per-index fielddata stats (closed indices?): {e}")
            # Continue with global stats only
        
        logger.info(f"High fielddata usage detected: {total_fielddata_mb:.1f}MB total")
        
        # Alert if essential indices are problematic
        if essential_indices_affected:
            alert_msg = (
                f"<b>WARNING: ESSENTIAL INDICES CAUSING HIGH FIELDDATA:</b><br>"
                f"<b>Total Fielddata:</b> {total_fielddata_mb:.1f}MB<br><br>"
                f"<b>Problematic Essential Indices:</b><br>"
            )
            for idx_info in essential_indices_affected:
                alert_msg += f"• {idx_info['index']}: {idx_info['fielddata_mb']:.1f}MB<br>"
            
            alert_msg += (
                f"<br><b>Recommendation:</b> These indices cannot be automatically modified. "
                f"Consider:<br>"
                f"1. Review aggregation queries on these indices<br>"
                f"2. Add doc_values to frequently aggregated fields<br>"
                f"3. Increase heap memory if queries are legitimate"
            )
            
            send_google_chat_notification(
                "Essential Indices Causing High Fielddata",
                alert_msg,
                "CRITICAL",
                dry_run
            )
        
        if dry_run:
            msg = f"DRY RUN: Would clear {total_fielddata_mb:.1f}MB of fielddata cache"
            send_google_chat_notification(
                "Fielddata Cache Cleanup (Dry Run)",
                f"<b>Action:</b> Clear fielddata cache<br>"
                f"<b>Current:</b> {total_fielddata_mb:.1f}MB<br>"
                f"<b>Essential Indices Affected:</b> {len(essential_indices_affected)}<br>"
                f"<b>Mode:</b> DRY RUN - no changes made",
                "INFO",
                dry_run
            )
            return True, msg
        
        # Clear fielddata cache (safe for all indices)
        es.indices.clear_cache(fielddata=True)
        
        log_remediation_action("clear_fielddata", {
            "fielddata_mb_before": total_fielddata_mb,
            "essential_indices_affected": len(essential_indices_affected),
            "reason": "High memory pressure from fielddata"
        }, True, dry_run)
        
        msg = f"Cleared {total_fielddata_mb:.1f}MB of fielddata cache"
        
        send_google_chat_notification(
            "Fielddata Cache Cleared",
            f"<b>Action:</b> Cleared fielddata cache<br>"
            f"<b>Freed:</b> {total_fielddata_mb:.1f}MB<br>"
            f"<b>Impact:</b> Heap memory freed, queries may be briefly slower<br>"
            f"<b>Essential Indices Affected:</b> {len(essential_indices_affected)}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS",
            dry_run
        )
        
        return True, msg
    
    except Exception as e:
        logger.exception("Failed to clear fielddata cache")
        log_remediation_action("clear_fielddata", {"error": str(e)}, False, dry_run)
        
        send_google_chat_notification(
            "Fielddata Cache Clear Failed",
            f"<b>Action:</b> Clear fielddata cache<br>"
            f"<b>Error:</b> {str(e)}<br>"
            f"<b>Possible Cause:</b> Closed indices in cluster<br>"
            f"<b>Status:</b> Cluster may still function normally",
            "ERROR",
            dry_run
        )
        
        return False, f"Error: {e}"


def cleanup_old_ml_files(dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Deletes ML result files older than retention period to free disk space.
    This prevents disk pressure from causing cluster-wide issues (read-only indices).
    Only deletes .json/.jsonl/.csv files from results/ - models are preserved.
    """
    try:
        if check_recent_remediation("cleanup_ml_files", lookback_hours=12):
            return True, "ML files cleaned up within last 12 hours, skipping"
        
        retention_days = int(os.getenv("ML_FILE_RETENTION_DAYS", "7"))
        cutoff = datetime.now() - timedelta(days=retention_days)
        
        deleted_count = 0
        freed_mb = 0
        
        for ext in ["*.json", "*.jsonl", "*.csv", "*.txt", "*.html"]:
            for file_path in RESULTS_DIR.glob(ext):
                try:
                    # Skip important files
                    if any(x in file_path.name for x in ["checkpoint", "baseline", "config", "ultra_daily_report"]):
                        continue
                    
                    mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if mtime < cutoff:
                        file_size = file_path.stat().st_size / (1024**2)
                        
                        if not dry_run:
                            file_path.unlink()
                        
                        deleted_count += 1
                        freed_mb += file_size
                except:
                    continue
        
        if deleted_count == 0:
            return True, "No old ML files to clean up"
        
        msg = f"Deleted {deleted_count} old ML files, freed {freed_mb:.1f}MB" if not dry_run else f"DRY RUN: Would delete {deleted_count} files ({freed_mb:.1f}MB)"
        
        if dry_run:
            send_google_chat_notification(
                "ML File Cleanup (Dry Run)",
                f"<b>Action:</b> Delete old ML result files<br>"
                f"<b>Files:</b> {deleted_count} files older than {retention_days} days<br>"
                f"<b>Space:</b> {freed_mb:.1f}MB would be freed<br>"
                f"<b>Mode:</b> DRY RUN - no changes made",
                "INFO",
                dry_run
            )
        else:
            log_remediation_action("cleanup_ml_files", {
                "deleted_count": deleted_count,
                "freed_mb": freed_mb,
                "retention_days": retention_days
            }, True, dry_run)
            
            send_google_chat_notification(
                "ML Files Cleaned Up",
                f"<b>Action:</b> Deleted old ML result files<br>"
                f"<b>Files Removed:</b> {deleted_count} files older than {retention_days} days<br>"
                f"<b>Space Freed:</b> {freed_mb:.1f}MB<br>"
                f"<b>Impact:</b> Reduced disk usage, models preserved<br>"
                f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "SUCCESS",
                dry_run
            )
        
        return True, msg
    
    except Exception as e:
        logger.exception("Failed to cleanup ML files")
        log_remediation_action("cleanup_ml_files", {"error": str(e)}, False, dry_run)
        
        send_google_chat_notification(
            "ML File Cleanup Failed",
            f"<b>Action:</b> Delete old ML files<br>"
            f"<b>Error:</b> {str(e)}<br>"
            f"<b>Status:</b> Manual cleanup may be required",
            "ERROR",
            dry_run
        )
        
        return False, f"Error: {e}"


def retry_unassigned_shards(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Attempts to reroute unassigned shards by retrying allocation.
    Unassigned shards mean missing data and potential data loss.
    This triggers ES to re-evaluate allocation decisions.
    """
    try:
        if check_recent_remediation("retry_unassigned_shards", lookback_hours=1):
            return True, "Shard allocation retried within last hour, skipping"
        
        health = es.cluster.health()
        unassigned = health.get("unassigned_shards", 0)
        
        if unassigned == 0:
            return True, "No unassigned shards detected"
        
        # Check if essential indices have unassigned shards
        cat_shards = es.cat.shards(format="json", h="index,shard,prirep,state")
        essential_unassigned = []
        
        for shard in cat_shards:
            if shard.get("state") == "UNASSIGNED" and is_essential_index(shard.get("index", "")):
                essential_unassigned.append(shard.get("index"))
        
        logger.info(f"Found {unassigned} unassigned shards total")
        
        # Alert if essential indices are affected
        if essential_unassigned:
            unique_essential = list(set(essential_unassigned))
            alert_msg = (
                f"<b>CRITICAL: ESSENTIAL INDICES HAVE UNASSIGNED SHARDS:</b><br>"
                f"<b>Total Unassigned:</b> {unassigned}<br><br>"
                f"<b>Affected Essential Indices:</b><br>"
            )
            for idx in unique_essential[:10]:  # Limit to 10
                alert_msg += f"• {idx}<br>"
            
            alert_msg += (
                f"<br><b>Impact:</b> Data may be unavailable or lost!<br>"
                f"<b>Action:</b> Auto-remediation will retry allocation<br>"
                f"<b>Manual Action Required If Persists:</b><br>"
                f"1. Check disk space on all nodes<br>"
                f"2. Review allocation filters/rules<br>"
                f"3. Check node availability"
            )
            
            send_google_chat_notification(
                "Essential Indices Unassigned Shards",
                alert_msg,
                "CRITICAL",
                dry_run
            )
        
        if dry_run:
            msg = f"DRY RUN: Would retry allocation for {unassigned} unassigned shards"
            send_google_chat_notification(
                "Shard Allocation Retry (Dry Run)",
                f"<b>Action:</b> Retry failed shard allocation<br>"
                f"<b>Unassigned Shards:</b> {unassigned}<br>"
                f"<b>Essential Indices Affected:</b> {len(set(essential_unassigned))}<br>"
                f"<b>Mode:</b> DRY RUN - no changes made",
                "INFO",
                dry_run
            )
            return True, msg
        
        # Retry reroute
        es.cluster.reroute(retry_failed=True)
        
        log_remediation_action("retry_unassigned_shards", {
            "unassigned_count": unassigned,
            "essential_affected": len(set(essential_unassigned)),
            "reason": "Unassigned shards detected"
        }, True, dry_run)
        
        msg = f"Triggered allocation retry for {unassigned} unassigned shards"
        
        send_google_chat_notification(
            "Shard Allocation Retried",
            f"<b>Action:</b> Retried failed shard allocation<br>"
            f"<b>Unassigned Shards:</b> {unassigned}<br>"
            f"<b>Essential Indices Affected:</b> {len(set(essential_unassigned))}<br>"
            f"<b>Impact:</b> Shards may reassign if resources available<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if len(essential_unassigned) == 0 else "WARNING",
            dry_run
        )
        
        return True, msg
    
    except Exception as e:
        logger.exception("Failed to retry shard allocation")
        log_remediation_action("retry_unassigned_shards", {"error": str(e)}, False, dry_run)
        
        send_google_chat_notification(
            "Shard Allocation Retry Failed",
            f"<b>Action:</b> Retry shard allocation<br>"
            f"<b>Error:</b> {str(e)}<br>"
            f"<b>Status:</b> Manual intervention required",
            "ERROR",
            dry_run
        )
        
        return False, f"Error: {e}"


def clear_request_query_caches(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Clears the request and query caches when JVM heap pressure is high.
    Safer than fielddata clear (no aggregation rebuild cost); query cache rebuilds in seconds.

    PRE-VALIDATION: Only runs if any node has heap_used_percent >= 80.
    """
    try:
        if check_recent_remediation("clear_request_query_caches", lookback_hours=2):
            return True, "Request/query caches cleared within last 2h, skipping"

        stats = es.nodes.stats(metric=["jvm"])
        max_heap = 0
        hot = []
        for nid, n in (stats.get("nodes") or {}).items():
            hp = int(n.get("jvm", {}).get("mem", {}).get("heap_used_percent", 0) or 0)
            if hp >= 80:
                hot.append({"name": n.get("name") or nid, "heap": hp})
            max_heap = max(max_heap, hp)

        if max_heap < 80:
            return True, f"Heap pressure not problematic (max heap {max_heap}%)"

        if dry_run:
            send_google_chat_notification(
                "Cache Clear (Dry Run)",
                f"<b>Action:</b> Clear request + query caches<br>"
                f"<b>Hot nodes (≥80% heap):</b> {hot}<br>"
                f"<b>Mode:</b> DRY RUN", "INFO", dry_run)
            return True, f"DRY RUN: would clear request+query caches ({len(hot)} hot nodes)"

        es.indices.clear_cache(request=True, query=True)
        log_remediation_action("clear_request_query_caches", {
            "max_heap_percent": max_heap,
            "hot_nodes": hot,
        }, True, dry_run)
        send_google_chat_notification(
            "Request/Query Caches Cleared",
            f"<b>Max heap:</b> {max_heap}%<br>"
            f"<b>Hot nodes:</b> {len(hot)}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS", dry_run)
        return True, f"Cleared request+query caches (max heap was {max_heap}%)"

    except Exception as e:
        logger.exception("Failed to clear request/query caches")
        log_remediation_action("clear_request_query_caches", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def force_merge_oversharded_indices(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Force-merges read-only indices that are over-sharded with many segments.
    Reduces segment count → less heap, faster searches. Only touches indices that are:
      - read-only (no recent writes; ILM warm/cold phase) AND
      - have >50 segments per primary AND
      - are NOT in ESSENTIAL_INDICES.

    PROTECTIONS: Skips active write-indices, essential indices, and small (<1GB) indices.
    LIMIT: At most ``MAX_FORCE_MERGE_PER_RUN`` (default 2) per pass to avoid I/O storms.
    """
    try:
        if check_recent_remediation("force_merge_oversharded", lookback_hours=12):
            return True, "Force-merge already ran within last 12h, skipping"

        max_per_run = int(os.getenv("MAX_FORCE_MERGE_PER_RUN", "2"))
        candidates: List[Dict[str, Any]] = []

        try:
            seg_stats = es.indices.segments(human=False)
        except Exception as e:
            return False, f"indices.segments failed: {e}"

        for idx_name, idx_data in (seg_stats.get("indices") or {}).items():
            if is_essential_index(idx_name):
                continue
            if idx_name.startswith("."):
                continue
            shards = idx_data.get("shards") or {}
            seg_total = 0
            prim_count = 0
            for _shard_id, shard_list in shards.items():
                for sh in (shard_list or []):
                    if sh.get("routing", {}).get("primary"):
                        prim_count += 1
                        seg_total += len((sh.get("segments") or {}).keys())
            if prim_count and (seg_total / prim_count) > 50:
                candidates.append({"index": idx_name, "segments_per_primary": round(seg_total / prim_count, 1)})

        if not candidates:
            return True, "No over-sharded indices found (>50 segments/primary)"

        try:
            sizes = es.cat.indices(format="json", bytes="b", h="index,store.size,docs.count")
            size_map = {r.get("index"): int(r.get("store.size") or 0) for r in (sizes or [])}
        except Exception:
            size_map = {}

        candidates = [c for c in candidates if size_map.get(c["index"], 0) >= 1 * 1024**3]
        candidates.sort(key=lambda c: c["segments_per_primary"], reverse=True)
        candidates = candidates[:max_per_run]

        if not candidates:
            return True, "No qualifying indices ≥1GB to merge this pass"

        if dry_run:
            send_google_chat_notification(
                "Force-Merge (Dry Run)",
                f"<b>Candidates:</b> {[c['index'] for c in candidates]}<br>"
                f"<b>Mode:</b> DRY RUN", "INFO", dry_run)
            return True, f"DRY RUN: would force-merge {len(candidates)} indices: {[c['index'] for c in candidates]}"

        merged: List[str] = []
        for c in candidates:
            try:
                es.indices.forcemerge(index=c["index"], max_num_segments=1, only_expunge_deletes=False,
                                      flush=True, wait_for_completion=False)
                merged.append(c["index"])
            except Exception as e:
                logger.warning("force_merge %s failed: %s", c["index"], e)

        log_remediation_action("force_merge_oversharded", {
            "candidates": candidates, "merged": merged,
        }, bool(merged), dry_run)
        send_google_chat_notification(
            "Force-Merge Triggered",
            f"<b>Indices:</b> {merged}<br>"
            f"<b>Note:</b> async; segments will collapse over minutes-to-hours<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if merged else "WARNING", dry_run)
        return bool(merged), f"Triggered force-merge on {len(merged)} indices"

    except Exception as e:
        logger.exception("force_merge_oversharded failed")
        log_remediation_action("force_merge_oversharded", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def retry_stuck_ilm(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Restarts ILM if stopped, and retries ILM steps in ERROR for any indices
    not on the essential-indices safelist.

    SAFETY: Read-only inspection first; per-index retry is non-destructive (re-runs the failed step).
    """
    try:
        if check_recent_remediation("retry_stuck_ilm", lookback_hours=4):
            return True, "ILM retry already attempted within last 4h, skipping"

        try:
            status = es.ilm.get_status()
        except Exception as e:
            return False, f"ilm.get_status failed: {e}"
        operation_mode = (status or {}).get("operation_mode") or ""

        try:
            explain = es.ilm.explain_lifecycle(index="*", only_errors=True)
        except Exception as e:
            return False, f"ilm.explain_lifecycle failed: {e}"

        errored = []
        for idx_name, info in (explain.get("indices") or {}).items():
            if is_essential_index(idx_name):
                continue
            if (info or {}).get("step") == "ERROR" or (info or {}).get("failed_step"):
                errored.append({
                    "index": idx_name,
                    "phase": info.get("phase"),
                    "failed_step": info.get("failed_step"),
                    "step_info": (str(info.get("step_info") or "")[:140]),
                })

        if operation_mode == "RUNNING" and not errored:
            return True, "ILM is RUNNING and no errored indices"

        if dry_run:
            send_google_chat_notification(
                "ILM Recovery (Dry Run)",
                f"<b>ILM mode:</b> {operation_mode}<br>"
                f"<b>Errored indices:</b> {len(errored)}<br>"
                f"<b>Mode:</b> DRY RUN", "INFO", dry_run)
            return True, f"DRY RUN: would start ILM (mode={operation_mode}) and retry {len(errored)} indices"

        actions = []
        if operation_mode != "RUNNING":
            try:
                es.ilm.start()
                actions.append(f"started ILM (was {operation_mode})")
            except Exception as e:
                logger.warning("ilm.start failed: %s", e)

        retried = 0
        for r in errored[:25]:
            try:
                es.ilm.retry(index=r["index"])
                retried += 1
            except Exception as e:
                logger.warning("ilm.retry %s failed: %s", r["index"], e)

        log_remediation_action("retry_stuck_ilm", {
            "operation_mode_before": operation_mode,
            "errored_count": len(errored),
            "retried": retried,
            "actions": actions,
        }, True, dry_run)
        send_google_chat_notification(
            "ILM Recovery",
            f"<b>ILM mode before:</b> {operation_mode}<br>"
            f"<b>Indices retried:</b> {retried} / {len(errored)}<br>"
            f"<b>Other actions:</b> {actions or 'none'}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if (retried or actions) else "WARNING", dry_run)
        return True, f"Retried {retried}/{len(errored)} ILM-errored indices; actions={actions}"

    except Exception as e:
        logger.exception("retry_stuck_ilm failed")
        log_remediation_action("retry_stuck_ilm", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def _has_transform_node(es) -> bool:
    """Check whether at least one node in the cluster has the transform role."""
    try:
        nodes = es.cat.nodes(format="json", h="node.role")
        for n in (nodes or []):
            if "t" in (n.get("node.role") or ""):
                return True
    except Exception:
        pass
    return False


def restart_failed_transforms(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Restarts transforms that are in a failed or stopped state.
    Transforms power continuous rollups and entity-centric indices; a stuck
    transform means stale data for dashboards and detections.

    SAFETY: Only restarts transforms that are already failed/stopped.
    PRE-VALIDATION: Checks that at least one node has the transform role;
    if not, sends a one-time alert instead of futile restart attempts.
    """
    try:
        if check_recent_remediation("restart_failed_transforms", lookback_hours=4):
            return True, "Transform restart attempted within last 4h, skipping"

        if not _has_transform_node(es):
            msg = ("No node in the cluster has the transform role. "
                   "Add node.roles: [transform] to elasticsearch.yml on at least one node and restart it.")

            if not check_recent_remediation("no_transform_node_alert", lookback_hours=24):
                log_remediation_action("no_transform_node_alert", {
                    "reason": "No transform-capable node found",
                }, True, dry_run)
                send_google_chat_notification(
                    "No Transform Node in Cluster",
                    f"<b>Issue:</b> No node has the <code>transform</code> role.<br>"
                    f"<b>Impact:</b> All transforms are stuck in waiting/stopped state and cannot run.<br>"
                    f"<b>Fix:</b> Add <code>transform</code> to <code>node.roles</code> in "
                    f"<code>elasticsearch.yml</code> on at least one node, then restart it.<br>"
                    f"<b>Affected transforms:</b> cloud_security_posture, endpoint.metadata, "
                    f"risk score, threat intel, SLO, osquery<br>"
                    f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    "WARNING", dry_run)

            return True, msg

        try:
            resp = es.transform.get_transform_stats(transform_id="_all")
        except Exception as e:
            return False, f"get_transform_stats failed: {e}"

        failed: List[Dict[str, str]] = []
        for t in (resp.get("transforms") or []):
            state = (t.get("state") or "").lower()
            if state in ("failed", "stopped"):
                failed.append({
                    "id": t.get("id", "unknown"),
                    "state": state,
                    "reason": str(t.get("reason") or "")[:120],
                })

        if not failed:
            return True, "No failed or stopped transforms"

        if dry_run:
            send_google_chat_notification(
                "Transform Restart (Dry Run)",
                f"<b>Failed/stopped transforms:</b> {len(failed)}<br>"
                f"<b>IDs:</b> {[t['id'] for t in failed[:10]]}<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would restart {len(failed)} transforms"

        restarted = 0
        for t in failed[:10]:
            try:
                if t["state"] == "failed":
                    es.transform.reset_transform(transform_id=t["id"], force=True)
                es.transform.start_transform(transform_id=t["id"])
                restarted += 1
            except Exception as e:
                logger.warning("transform restart %s failed: %s", t["id"], e)

        log_remediation_action("restart_failed_transforms", {
            "failed_count": len(failed),
            "restarted": restarted,
        }, bool(restarted), dry_run)
        send_google_chat_notification(
            "Transforms Restarted",
            f"<b>Restarted:</b> {restarted}/{len(failed)}<br>"
            f"<b>IDs:</b> {[t['id'] for t in failed[:10]]}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if restarted else "WARNING", dry_run)
        return bool(restarted), f"Restarted {restarted}/{len(failed)} transforms"

    except Exception as e:
        logger.exception("restart_failed_transforms failed")
        log_remediation_action("restart_failed_transforms", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def cleanup_old_snapshots(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Deletes snapshots older than SNAPSHOT_RETENTION_DAYS from all
    registered repositories. Old snapshots consume disk and can slow snapshot
    operations.

    SAFETY: Only deletes completed snapshots older than the retention window
    (default 30 days). In-progress and partial snapshots are skipped.
    """
    try:
        if check_recent_remediation("cleanup_old_snapshots", lookback_hours=24):
            return True, "Snapshot cleanup ran within last 24h, skipping"

        retention_days = int(os.getenv("SNAPSHOT_RETENTION_DAYS", "30"))
        cutoff_ms = int((datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp() * 1000)

        try:
            repos = es.snapshot.get_repository()
        except Exception as e:
            return True, f"No snapshot repositories configured ({e})"

        if not repos:
            return True, "No snapshot repositories configured"

        total_deleted = 0
        total_freed = 0
        errors: List[str] = []

        for repo_name in repos:
            try:
                snaps = es.snapshot.get(repository=repo_name, snapshot="_all", ignore_unavailable=True)
            except Exception as e:
                logger.warning("snapshot.get(%s) failed: %s", repo_name, e)
                continue

            for snap in (snaps.get("snapshots") or []):
                state = (snap.get("state") or "").upper()
                if state != "SUCCESS":
                    continue
                end_time = snap.get("end_time_in_millis") or 0
                if end_time and end_time < cutoff_ms:
                    snap_name = snap.get("snapshot", "unknown")
                    if dry_run:
                        total_deleted += 1
                        continue
                    try:
                        es.snapshot.delete(repository=repo_name, snapshot=snap_name)
                        total_deleted += 1
                    except Exception as e:
                        errors.append(f"{repo_name}/{snap_name}: {e}")

        if total_deleted == 0 and not errors:
            return True, f"No snapshots older than {retention_days} days to clean up"

        msg = (f"{'DRY RUN: would delete' if dry_run else 'Deleted'} "
               f"{total_deleted} snapshots older than {retention_days}d")

        log_remediation_action("cleanup_old_snapshots", {
            "deleted": total_deleted, "retention_days": retention_days,
            "errors": errors[:5],
        }, total_deleted > 0, dry_run)
        send_google_chat_notification(
            f"Snapshot Cleanup {'(Dry Run)' if dry_run else ''}",
            f"<b>Snapshots removed:</b> {total_deleted}<br>"
            f"<b>Retention:</b> {retention_days} days<br>"
            f"<b>Errors:</b> {len(errors)}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if not errors else "WARNING", dry_run)
        return True, msg

    except Exception as e:
        logger.exception("cleanup_old_snapshots failed")
        log_remediation_action("cleanup_old_snapshots", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def delete_old_empty_indices(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Deletes non-essential indices that are older than 90 days AND have
    0 documents. These are typically leftover rollover stubs or failed
    ingestion targets that consume shard budget without holding data.

    PROTECTIONS:
    - Essential indices are NEVER touched.
    - Only deletes indices with docs.count == 0.
    - System indices (starting with '.') are skipped unless they are
      known safe patterns (e.g. old .monitoring-* data).
    - At most MAX_EMPTY_INDEX_DELETE_PER_RUN (default 20) per pass.
    """
    try:
        if check_recent_remediation("delete_old_empty_indices", lookback_hours=24):
            return True, "Empty-index cleanup ran within last 24h, skipping"

        max_per_run = int(os.getenv("MAX_EMPTY_INDEX_DELETE_PER_RUN", "20"))
        retention_days = int(os.getenv("EMPTY_INDEX_RETENTION_DAYS", "90"))
        cutoff_ms = int((datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp() * 1000)

        try:
            indices = es.cat.indices(format="json", h="index,docs.count,creation.date", expand_wildcards="open")
        except Exception as e:
            return False, f"cat.indices failed: {e}"

        candidates: List[str] = []
        for idx in (indices or []):
            name = idx.get("index", "")
            doc_count = int(idx.get("docs.count") or 0)
            created = int(idx.get("creation.date") or 0)

            if doc_count > 0:
                continue
            if is_essential_index(name):
                continue
            if name.startswith(".") and not name.startswith(".monitoring-"):
                continue
            if created and created > cutoff_ms:
                continue
            candidates.append(name)

        candidates = candidates[:max_per_run]

        if not candidates:
            return True, "No old empty indices to clean up"

        if dry_run:
            send_google_chat_notification(
                "Empty Index Cleanup (Dry Run)",
                f"<b>Candidates:</b> {len(candidates)}<br>"
                f"<b>Retention:</b> {retention_days} days, 0 docs<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would delete {len(candidates)} empty indices older than {retention_days}d"

        deleted: List[str] = []
        for name in candidates:
            try:
                es.indices.delete(index=name, ignore=[404])
                deleted.append(name)
            except Exception as e:
                logger.warning("delete index %s failed: %s", name, e)

        log_remediation_action("delete_old_empty_indices", {
            "deleted": deleted, "retention_days": retention_days,
        }, bool(deleted), dry_run)
        send_google_chat_notification(
            "Empty Indices Deleted",
            f"<b>Deleted:</b> {len(deleted)} indices (0 docs, >{retention_days}d old)<br>"
            f"<b>Shards freed:</b> reduces cluster shard budget<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if deleted else "WARNING", dry_run)
        return bool(deleted), f"Deleted {len(deleted)} old empty indices"

    except Exception as e:
        logger.exception("delete_old_empty_indices failed")
        log_remediation_action("delete_old_empty_indices", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def reset_disk_watermark_readonly(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: When disk pressure trips the flood-stage watermark, ES sets
    index.blocks.read_only_allow_delete on affected indices. Once disk space
    is freed (by ILM, snapshot cleanup, or manual action) this block is NOT
    automatically removed. This action clears the block so writes can resume.

    PRE-VALIDATION: Only acts when at least one index has the read-only block
    AND current disk usage is below 90% on the relevant node.
    """
    try:
        if check_recent_remediation("reset_disk_watermark_readonly", lookback_hours=2):
            return True, "Watermark reset attempted within last 2h, skipping"

        try:
            settings = es.indices.get_settings(index="_all", name="index.blocks.read_only_allow_delete",
                                                flat_settings=True, expand_wildcards="open")
        except Exception as e:
            return False, f"get_settings failed: {e}"

        blocked: List[str] = []
        for idx_name, idx_settings in (settings or {}).items():
            val = (idx_settings.get("settings") or {}).get("index.blocks.read_only_allow_delete")
            if val in ("true", True):
                blocked.append(idx_name)

        if not blocked:
            return True, "No indices are in read-only-allow-delete mode"

        stats = es.nodes.stats(metric=["fs"])
        max_disk_pct = 0
        for nid, n in (stats.get("nodes") or {}).items():
            total = n.get("fs", {}).get("total", {})
            total_bytes = total.get("total_in_bytes") or 1
            free_bytes = total.get("free_in_bytes") or 0
            used_pct = round((1 - free_bytes / total_bytes) * 100, 1)
            max_disk_pct = max(max_disk_pct, used_pct)

        if max_disk_pct >= 90:
            msg = (f"{len(blocked)} indices are read-only but disk is still at {max_disk_pct}% "
                   f"-- too high to safely unblock")
            send_google_chat_notification(
                "Read-Only Indices (Disk Still Full)",
                f"<b>Blocked indices:</b> {len(blocked)}<br>"
                f"<b>Max disk used:</b> {max_disk_pct}%<br>"
                f"<b>Action:</b> Cannot unblock until disk <90%<br>"
                f"<b>Next step:</b> Free disk space first",
                "WARNING", dry_run)
            return True, msg

        if dry_run:
            send_google_chat_notification(
                "Watermark Reset (Dry Run)",
                f"<b>Blocked indices:</b> {len(blocked)}<br>"
                f"<b>Disk used:</b> {max_disk_pct}%<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would unblock {len(blocked)} read-only indices (disk at {max_disk_pct}%)"

        unblocked = 0
        for idx_name in blocked:
            if is_essential_index(idx_name):
                continue
            try:
                es.indices.put_settings(
                    index=idx_name,
                    body={"index.blocks.read_only_allow_delete": None})
                unblocked += 1
            except Exception as e:
                logger.warning("unblock %s failed: %s", idx_name, e)

        log_remediation_action("reset_disk_watermark_readonly", {
            "blocked_count": len(blocked), "unblocked": unblocked,
            "disk_pct": max_disk_pct,
        }, bool(unblocked), dry_run)
        send_google_chat_notification(
            "Read-Only Block Cleared",
            f"<b>Unblocked:</b> {unblocked}/{len(blocked)} indices<br>"
            f"<b>Disk used:</b> {max_disk_pct}% (below 90% threshold)<br>"
            f"<b>Impact:</b> Writes can resume on unblocked indices<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS", dry_run)
        return bool(unblocked), f"Unblocked {unblocked}/{len(blocked)} read-only indices"

    except Exception as e:
        logger.exception("reset_disk_watermark_readonly failed")
        log_remediation_action("reset_disk_watermark_readonly", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def restart_failed_watchers(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Restarts the Watcher service if it is stopped, and acks+executes
    watches that have been throttled for too long.

    SAFETY: Watcher restart is idempotent; re-acking a throttled watch just
    resets its throttle window.
    """
    try:
        if check_recent_remediation("restart_failed_watchers", lookback_hours=4):
            return True, "Watcher restart attempted within last 4h, skipping"

        try:
            watcher_stats = es.watcher.stats()
        except Exception:
            return True, "Watcher not available (X-Pack not enabled or no license)"

        watcher_state = ""
        needs_start = False
        if isinstance(watcher_stats, dict):
            for node_stats in (watcher_stats.get("stats") or []):
                state = (node_stats.get("watcher_state") or "").lower()
                watcher_state = state
                if state in ("stopped", "stopping"):
                    needs_start = True

        if not needs_start:
            return True, f"Watcher is running (state: {watcher_state or 'ok'})"

        if dry_run:
            send_google_chat_notification(
                "Watcher Restart (Dry Run)",
                f"<b>Watcher state:</b> {watcher_state}<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would restart Watcher (state={watcher_state})"

        try:
            es.watcher.start()
        except Exception as e:
            logger.warning("watcher.start failed: %s", e)
            return False, f"Watcher start failed: {e}"

        log_remediation_action("restart_failed_watchers", {
            "state_before": watcher_state,
        }, True, dry_run)
        send_google_chat_notification(
            "Watcher Restarted",
            f"<b>Previous state:</b> {watcher_state}<br>"
            f"<b>New state:</b> started<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS", dry_run)
        return True, f"Restarted Watcher (was {watcher_state})"

    except Exception as e:
        logger.exception("restart_failed_watchers failed")
        log_remediation_action("restart_failed_watchers", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def cleanup_old_monitoring_indices(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Deletes old .monitoring-* and .watcher-history-* indices that exceed
    their retention period. These are diagnostic/audit indices rotated daily by
    Elastic Stack; keeping them past retention wastes disk and shard budget.

    PROTECTIONS: Only deletes indices matching known monitoring patterns.
    Never touches essential indices. At most MAX_MONITORING_DELETE_PER_RUN (50).
    """
    try:
        if check_recent_remediation("cleanup_old_monitoring_indices", lookback_hours=24):
            return True, "Monitoring index cleanup ran within last 24h, skipping"

        retention_days = int(os.getenv("MONITORING_INDEX_RETENTION_DAYS", "7"))
        max_per_run = int(os.getenv("MAX_MONITORING_DELETE_PER_RUN", "50"))
        cutoff_ms = int((datetime.now(timezone.utc) - timedelta(days=retention_days)).timestamp() * 1000)

        MONITORING_PATTERNS = (".monitoring-", ".watcher-history-", ".ml-notifications-")

        try:
            indices = es.cat.indices(format="json", h="index,creation.date,docs.count,store.size",
                                     expand_wildcards="open")
        except Exception as e:
            return False, f"cat.indices failed: {e}"

        candidates: List[Dict[str, Any]] = []
        for idx in (indices or []):
            name = idx.get("index", "")
            created = int(idx.get("creation.date") or 0)
            if not any(name.startswith(p) for p in MONITORING_PATTERNS):
                continue
            if is_essential_index(name):
                continue
            if created and created < cutoff_ms:
                candidates.append({"index": name, "store": idx.get("store.size", "?")})

        candidates = candidates[:max_per_run]

        if not candidates:
            return True, f"No monitoring indices older than {retention_days} days"

        if dry_run:
            send_google_chat_notification(
                "Monitoring Index Cleanup (Dry Run)",
                f"<b>Candidates:</b> {len(candidates)} indices older than {retention_days}d<br>"
                f"<b>Patterns:</b> .monitoring-*, .watcher-history-*, .ml-notifications-*<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would delete {len(candidates)} old monitoring indices"

        deleted: List[str] = []
        for c in candidates:
            try:
                es.indices.delete(index=c["index"], ignore=[404])
                deleted.append(c["index"])
            except Exception as e:
                logger.warning("delete monitoring index %s failed: %s", c["index"], e)

        log_remediation_action("cleanup_old_monitoring_indices", {
            "deleted_count": len(deleted), "retention_days": retention_days,
        }, bool(deleted), dry_run)
        send_google_chat_notification(
            "Monitoring Indices Cleaned Up",
            f"<b>Deleted:</b> {len(deleted)} indices older than {retention_days}d<br>"
            f"<b>Patterns:</b> .monitoring-*, .watcher-history-*, .ml-notifications-*<br>"
            f"<b>Impact:</b> Freed disk space and shard budget<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if deleted else "WARNING", dry_run)
        return bool(deleted), f"Deleted {len(deleted)} old monitoring indices"

    except Exception as e:
        logger.exception("cleanup_old_monitoring_indices failed")
        log_remediation_action("cleanup_old_monitoring_indices", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def cancel_long_running_tasks(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Cancels cluster tasks that have been running longer than a threshold,
    freeing CPU and thread-pool resources. Only cancels search and scroll tasks;
    never cancels index/shard management, snapshot, or ILM tasks.

    PRE-VALIDATION: Only runs when at least one node has CPU >= 85%.
    SAFETY: Only cancels safe task types (search, scroll). The client can retry.
    """
    try:
        if check_recent_remediation("cancel_long_running_tasks", lookback_hours=1):
            return True, "Task cancellation attempted within last hour, skipping"

        stats = es.nodes.stats(metric=["process"])
        max_cpu = 0
        for _nid, n in (stats.get("nodes") or {}).items():
            cpu = int(n.get("process", {}).get("cpu", {}).get("percent", 0) or 0)
            max_cpu = max(max_cpu, cpu)

        if max_cpu < 85:
            return True, f"CPU not critical ({max_cpu}%), skipping task cancellation"

        threshold_min = int(os.getenv("LONG_TASK_THRESHOLD_MINUTES", "30"))
        threshold_ns = threshold_min * 60 * 1_000_000_000

        SAFE_CANCEL_ACTIONS = ("indices:data/read/search", "indices:data/read/scroll",
                               "indices:data/read/msearch", "indices:data/read/eql")

        try:
            tasks = es.tasks.list(detailed=True, group_by="parents")
        except Exception as e:
            return False, f"tasks.list failed: {e}"

        long_tasks: List[Dict[str, Any]] = []
        for _node_id, node_tasks in (tasks.get("nodes") or {}).items():
            for task_id, task in (node_tasks.get("tasks") or {}).items():
                running_ns = task.get("running_time_in_nanos", 0)
                action = task.get("action", "")
                if running_ns >= threshold_ns and any(action.startswith(s) for s in SAFE_CANCEL_ACTIONS):
                    long_tasks.append({
                        "task_id": task_id,
                        "action": action,
                        "running_min": round(running_ns / 60_000_000_000, 1),
                        "description": str(task.get("description", ""))[:100],
                    })

        if not long_tasks:
            return True, f"No long-running search tasks (>{threshold_min}min) found despite high CPU ({max_cpu}%)"

        if dry_run:
            send_google_chat_notification(
                "Long Task Cancellation (Dry Run)",
                f"<b>CPU:</b> {max_cpu}%<br>"
                f"<b>Tasks >{threshold_min}min:</b> {len(long_tasks)}<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would cancel {len(long_tasks)} long-running tasks"

        cancelled = 0
        for t in long_tasks[:20]:
            try:
                node_id, task_num = t["task_id"].split(":", 1)
                es.tasks.cancel(task_id=t["task_id"])
                cancelled += 1
            except Exception as e:
                logger.warning("cancel task %s failed: %s", t["task_id"], e)

        log_remediation_action("cancel_long_running_tasks", {
            "max_cpu": max_cpu, "threshold_min": threshold_min,
            "found": len(long_tasks), "cancelled": cancelled,
        }, bool(cancelled), dry_run)
        send_google_chat_notification(
            "Long-Running Tasks Cancelled",
            f"<b>CPU was:</b> {max_cpu}%<br>"
            f"<b>Cancelled:</b> {cancelled}/{len(long_tasks)} tasks running >{threshold_min}min<br>"
            f"<b>Types:</b> search/scroll (safe to retry)<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if cancelled else "WARNING", dry_run)
        return bool(cancelled), f"Cancelled {cancelled} long-running tasks (CPU was {max_cpu}%)"

    except Exception as e:
        logger.exception("cancel_long_running_tasks failed")
        log_remediation_action("cancel_long_running_tasks", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def retry_failed_slm_policies(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Retries Snapshot Lifecycle Management policies that failed on their
    last execution. SLM manages automated backups; a failed policy means backups
    are not being taken and data could be lost.

    SAFETY: Retry is idempotent and just re-triggers the snapshot.
    """
    try:
        if check_recent_remediation("retry_failed_slm_policies", lookback_hours=12):
            return True, "SLM retry attempted within last 12h, skipping"

        try:
            policies = es.slm.get_lifecycle()
        except Exception:
            return True, "SLM not available or no policies configured"

        if not policies:
            return True, "No SLM policies configured"

        failed: List[Dict[str, str]] = []
        for name, policy in policies.items():
            last_failure = policy.get("last_failure", {})
            last_success = policy.get("last_success", {})
            fail_time = last_failure.get("time", "")
            success_time = last_success.get("time", "")
            if fail_time and fail_time > success_time:
                failed.append({
                    "name": name,
                    "fail_time": fail_time,
                    "details": str(last_failure.get("details", ""))[:120],
                })

        if not failed:
            return True, "All SLM policies are healthy"

        if dry_run:
            send_google_chat_notification(
                "SLM Retry (Dry Run)",
                f"<b>Failed policies:</b> {[p['name'] for p in failed]}<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would retry {len(failed)} failed SLM policies"

        retried = 0
        for p in failed:
            try:
                es.slm.execute_lifecycle(policy_id=p["name"])
                retried += 1
            except Exception as e:
                logger.warning("SLM execute %s failed: %s", p["name"], e)

        log_remediation_action("retry_failed_slm_policies", {
            "failed_count": len(failed), "retried": retried,
        }, bool(retried), dry_run)
        send_google_chat_notification(
            "SLM Policies Retried",
            f"<b>Retried:</b> {retried}/{len(failed)} policies<br>"
            f"<b>Policies:</b> {[p['name'] for p in failed]}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if retried else "WARNING", dry_run)
        return bool(retried), f"Retried {retried}/{len(failed)} failed SLM policies"

    except Exception as e:
        logger.exception("retry_failed_slm_policies failed")
        log_remediation_action("retry_failed_slm_policies", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def restart_stopped_ml_jobs(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Reopens and restarts ML anomaly detection jobs that are in a closed
    or failed state. ML jobs power risk scoring and anomaly detection; a stopped
    job means blind spots in threat detection.

    SAFETY: Opening a closed job is idempotent. Only restarts jobs that were
    previously running (have model snapshots). Skips jobs closed intentionally
    (no model snapshot = never trained, likely disabled on purpose).
    """
    try:
        if check_recent_remediation("restart_stopped_ml_jobs", lookback_hours=6):
            return True, "ML job restart attempted within last 6h, skipping"

        try:
            jobs_resp = es.ml.get_job_stats()
        except Exception:
            return True, "ML not available or no jobs configured"

        stopped: List[Dict[str, str]] = []
        for job in (jobs_resp.get("jobs") or []):
            state = (job.get("state") or "").lower()
            job_id = job.get("job_id", "unknown")
            if state in ("closed", "failed"):
                model_bytes = job.get("model_size_stats", {}).get("model_bytes", 0)
                if model_bytes > 0:
                    stopped.append({"id": job_id, "state": state})

        if not stopped:
            return True, "No stopped ML jobs with trained models"

        if dry_run:
            send_google_chat_notification(
                "ML Job Restart (Dry Run)",
                f"<b>Stopped jobs:</b> {[j['id'] for j in stopped[:10]]}<br>"
                f"<b>Mode:</b> DRY RUN",
                "INFO", dry_run)
            return True, f"DRY RUN: would restart {len(stopped)} ML jobs"

        restarted = 0
        license_blocked = False
        for j in stopped[:10]:
            try:
                es.ml.open_job(job_id=j["id"])
                restarted += 1
            except Exception as e:
                err_str = str(e)
                if "non-compliant" in err_str or "license" in err_str.lower():
                    license_blocked = True
                    break
                logger.warning("ML open_job %s failed: %s", j["id"], e)

        if license_blocked and restarted == 0:
            msg = (f"{len(stopped)} ML jobs are stopped but cannot be restarted: "
                   f"Elastic license is non-compliant for ML features")
            if not check_recent_remediation("ml_license_alert", lookback_hours=24):
                log_remediation_action("ml_license_alert", {
                    "reason": "ML license non-compliant", "stopped_jobs": len(stopped),
                }, True, dry_run)
                send_google_chat_notification(
                    "ML Jobs Blocked by License",
                    f"<b>Issue:</b> {len(stopped)} ML anomaly detection jobs are stopped<br>"
                    f"<b>Cause:</b> Current Elastic license does not cover ML features<br>"
                    f"<b>Impact:</b> No ML-based anomaly detection (risk scoring, network anomalies)<br>"
                    f"<b>Fix:</b> Upgrade to Platinum/Enterprise license or activate a trial<br>"
                    f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    "WARNING", dry_run)
            return True, msg

        log_remediation_action("restart_stopped_ml_jobs", {
            "stopped_count": len(stopped), "restarted": restarted,
        }, bool(restarted), dry_run)
        send_google_chat_notification(
            "ML Jobs Restarted",
            f"<b>Restarted:</b> {restarted}/{len(stopped)} jobs<br>"
            f"<b>Jobs:</b> {[j['id'] for j in stopped[:10]]}<br>"
            f"<b>Impact:</b> Anomaly detection coverage restored<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if restarted else "WARNING", dry_run)
        return bool(restarted), f"Restarted {restarted}/{len(stopped)} ML jobs"

    except Exception as e:
        logger.exception("restart_stopped_ml_jobs failed")
        log_remediation_action("restart_stopped_ml_jobs", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def fix_cluster_red(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: When cluster status is RED, performs escalating recovery steps:
    1. Retry failed shard allocation (covered by retry_unassigned_shards too,
       but this adds cluster-RED-specific context to alerts).
    2. Clear allocation exclusion filters that may be blocking assignment.
    3. Alert with allocation explanation for manual intervention.

    SAFETY: Only clears transient allocation filters (not persistent).
    The reroute retry is always safe.
    """
    try:
        if check_recent_remediation("fix_cluster_red", lookback_hours=1):
            return True, "Cluster RED recovery attempted within last hour, skipping"

        health = es.cluster.health()
        status = (health.get("status") or "").lower()
        if status != "red":
            return True, f"Cluster is {status.upper()}, not RED"

        unassigned = health.get("unassigned_shards", 0)

        explain_text = ""
        try:
            explain = es.cluster.allocation_explain()
            explain_text = str(explain.get("allocate_explanation", ""))[:300]
        except Exception:
            explain_text = "Could not get allocation explanation"

        if dry_run:
            send_google_chat_notification(
                "Cluster RED Recovery (Dry Run)",
                f"<b>Status:</b> RED<br>"
                f"<b>Unassigned shards:</b> {unassigned}<br>"
                f"<b>Explanation:</b> {explain_text[:200]}<br>"
                f"<b>Mode:</b> DRY RUN",
                "CRITICAL", dry_run)
            return True, f"DRY RUN: would attempt RED recovery ({unassigned} unassigned shards)"

        actions = []

        try:
            settings = es.cluster.get_settings(flat_settings=True)
            transient = settings.get("transient", {})
            exclude_keys = [k for k in transient if "allocation.exclude" in k and transient[k]]
            if exclude_keys:
                clear = {k: None for k in exclude_keys}
                es.cluster.put_settings(body={"transient": clear})
                actions.append(f"Cleared transient allocation exclusions: {exclude_keys}")
        except Exception as e:
            logger.warning("Could not clear allocation exclusions: %s", e)

        try:
            es.cluster.reroute(retry_failed=True)
            actions.append("Retried failed shard allocation")
        except Exception as e:
            logger.warning("Cluster reroute failed: %s", e)

        log_remediation_action("fix_cluster_red", {
            "unassigned": unassigned, "actions": actions,
            "explain": explain_text[:200],
        }, bool(actions), dry_run)

        send_google_chat_notification(
            "CLUSTER RED — Recovery Attempted",
            f"<b>Status:</b> RED<br>"
            f"<b>Unassigned shards:</b> {unassigned}<br>"
            f"<b>Actions taken:</b><br>{'<br>'.join(actions) if actions else 'None succeeded'}<br>"
            f"<b>Allocation explanation:</b> {explain_text[:200]}<br>"
            f"<b>Manual intervention likely required</b><br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "CRITICAL", dry_run)
        return bool(actions), f"RED recovery: {'; '.join(actions) if actions else 'no actions succeeded'}"

    except Exception as e:
        logger.exception("fix_cluster_red failed")
        log_remediation_action("fix_cluster_red", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def cleanup_dangling_indices(es, dry_run: bool = False) -> Tuple[bool, str]:
    """
    EFFECT: Imports or deletes dangling indices left behind when a node
    rejoins after data path changes. Dangling indices consume cluster state
    and can block operations.

    SAFETY: Attempts import first (preserves data). Only deletes if import fails
    and the index is not essential. Alerts for any dangling indices found.
    """
    try:
        if check_recent_remediation("cleanup_dangling_indices", lookback_hours=24):
            return True, "Dangling index cleanup ran within last 24h, skipping"

        try:
            dangling = es.dangling_indices.list_dangling_indices()
        except Exception:
            return True, "Dangling indices API not available"

        indices = dangling.get("dangling_indices") or []
        if not indices:
            return True, "No dangling indices"

        if dry_run:
            send_google_chat_notification(
                "Dangling Indices Found (Dry Run)",
                f"<b>Count:</b> {len(indices)}<br>"
                f"<b>Names:</b> {[i.get('index_name', '?') for i in indices[:10]]}<br>"
                f"<b>Mode:</b> DRY RUN",
                "WARNING", dry_run)
            return True, f"DRY RUN: found {len(indices)} dangling indices"

        imported = 0
        for idx in indices[:10]:
            idx_uuid = idx.get("index_uuid", "")
            idx_name = idx.get("index_name", "unknown")
            if not idx_uuid:
                continue
            try:
                es.dangling_indices.import_dangling_index(index_uuid=idx_uuid, accept_data_loss=False)
                imported += 1
                logger.info("Imported dangling index: %s (%s)", idx_name, idx_uuid)
            except Exception as e:
                logger.warning("Import dangling %s failed: %s", idx_name, e)

        log_remediation_action("cleanup_dangling_indices", {
            "found": len(indices), "imported": imported,
        }, True, dry_run)
        send_google_chat_notification(
            "Dangling Indices Processed",
            f"<b>Found:</b> {len(indices)}<br>"
            f"<b>Imported:</b> {imported}<br>"
            f"<b>Time:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "SUCCESS" if imported else "WARNING", dry_run)
        return True, f"Processed {len(indices)} dangling indices, imported {imported}"

    except Exception as e:
        logger.exception("cleanup_dangling_indices failed")
        log_remediation_action("cleanup_dangling_indices", {"error": str(e)}, False, dry_run)
        return False, f"Error: {e}"


def investigate_cluster_issues(es) -> Dict[str, Any]:
    """
    Perform detailed investigation of cluster issues without making changes.
    Returns comprehensive diagnostics for manual review.
    """
    investigation = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cluster_allocation": None,
        "hot_threads": None,
        "pending_tasks": None,
        "node_stats_summary": {}
    }
    
    try:
        # Get allocation explanation for unassigned shards
        health = es.cluster.health()
        if health.get("unassigned_shards", 0) > 0:
            try:
                allocation = es.cluster.allocation_explain()
                # Convert ES response to dict
                investigation["cluster_allocation"] = dict(allocation) if hasattr(allocation, '__iter__') else str(allocation)
            except:
                pass
        
        # Get hot threads
        try:
            hot_threads = es.nodes.hot_threads()
            investigation["hot_threads"] = hot_threads[:5000]  # Truncate
        except:
            pass
        
        # Get pending tasks
        try:
            pending = es.cluster.pending_tasks()
            # Convert ES response to dict
            investigation["pending_tasks"] = dict(pending) if hasattr(pending, '__iter__') else str(pending)
        except:
            pass
        
        # Node resource summary
        try:
            stats = es.nodes.stats()
            for node_id, node_data in stats.get("nodes", {}).items():
                node_name = node_data.get("name", node_id)
                
                jvm = node_data.get("jvm", {}).get("mem", {})
                os_mem = node_data.get("os", {}).get("mem", {})
                
                investigation["node_stats_summary"][node_name] = {
                    "heap_percent": jvm.get("heap_used_percent", 0),
                    "os_mem_free_percent": (os_mem.get("free_percent", 0)),
                    "cpu_percent": node_data.get("os", {}).get("cpu", {}).get("percent", 0),
                    "load_avg": node_data.get("os", {}).get("cpu", {}).get("load_average", {})
                }
        except:
            pass
    
    except Exception as e:
        logger.exception("Investigation failed")
        investigation["error"] = str(e)
    
    return investigation


def check_for_critical_issues_from_report() -> List[Dict[str, Any]]:
    """
    Check if the latest ultra SIEM report detected P0-CRITICAL issues.
    Returns list of critical issues that require manual intervention.
    """
    import glob
    import re
    
    # Find most recent ultra report
    report_files = glob.glob("results/ultra_daily_report_*.html")
    if not report_files:
        return []
    
    latest_report = max(report_files, key=os.path.getmtime)
    logger.info(f"Checking for P0-CRITICAL issues in: {latest_report}")
    
    try:
        with open(latest_report, 'r') as f:
            content = f.read()
        
        # Parse P0-CRITICAL issues from HTML systematically
        critical_issues = []
        
        # Extract all P0-CRITICAL and P1-HIGH recommendations using regex
        # Pattern: <div class="recommendation p0">...<span class="priority">P0-CRITICAL</span>...<strong>type</strong>: description...
        p0_pattern = r'<div class="recommendation p0">.*?<strong>(.*?)</strong>:\s*(.*?)<br>'
        p0_matches = re.findall(p0_pattern, content, re.DOTALL)
        
        p1_pattern = r'<div class="recommendation p1">.*?<strong>(.*?)</strong>:\s*(.*?)<br>'
        p1_matches = re.findall(p1_pattern, content, re.DOTALL)
        
        # Process P0-CRITICAL issues
        for issue_type, description in p0_matches:
            issue_type = issue_type.strip()
            description = description.strip()
            
            # Extract node name if present
            node_match = re.search(r'Node\s+(\S+)', description)
            node = node_match.group(1) if node_match else "unknown"
            
            # Determine if this is a disk issue
            if "disk" in issue_type.lower() or "disk" in description.lower():
                if "flood" in issue_type.lower() or "flood" in description.lower():
                    critical_issues.append({
                        "type": issue_type,
                        "node": node,
                        "severity": "P0-CRITICAL",
                        "description": f"Disk at flood stage watermark (95%+): {description[:100]}",
                        "fixable": False,
                        "reason": "ES nodes require manual disk management - auto-remediation cannot add disk space or delete ES indices",
                        "recommended_actions": [
                            "1. IMMEDIATE: Check disk usage: du -sh /var/lib/elasticsearch/* | sort -h",
                            "2. Review ILM policies - ensure old indices are being deleted automatically",
                            "3. Check snapshot disk usage: df -h /elasticsearch/snapshots",
                            "4. Adjust ILM retention periods (policy-level, not manual deletion)",
                            "5. Consider expanding disk capacity on the node",
                            "6. LAST RESORT: Manually delete old indices after verifying backups exist"
                        ]
                    })
                elif "watermark" in issue_type.lower() or "90" in description or "91" in description:
                    critical_issues.append({
                        "type": issue_type,
                        "node": node,
                        "severity": "P0-CRITICAL",
                        "description": f"Disk at high watermark, approaching flood stage: {description[:100]}",
                        "fixable": False,
                        "reason": "ES nodes require manual disk management - auto-remediation cannot add disk space or delete ES indices",
                        "recommended_actions": [
                            "1. URGENT: Monitor disk closely - flood stage is at 95%",
                            "2. Check largest indices: curl -X GET 'https://ES:9200/_cat/indices?v&h=index,store.size&s=store.size:desc' | head -20",
                            "3. Verify ILM is running: curl -X GET 'https://ES:9200/_ilm/status'",
                            "4. Review ILM policy phase timings (hot/warm/delete)",
                            "5. Consider adding disk space to prevent flood stage",
                            "6. Do NOT delete indices manually unless critical emergency"
                        ]
                    })
            elif "shard" in issue_type.lower() or "shard" in description.lower():
                critical_issues.append({
                    "type": issue_type,
                    "node": node,
                    "severity": "P0-CRITICAL",
                    "description": f"Shard allocation issue: {description[:100]}",
                    "fixable": True,
                    "reason": "Auto-remediation can retry shard allocation",
                    "recommended_actions": [
                        "Auto-remediation will attempt: Retry failed shard allocation",
                        "Manual actions if persists:",
                        "1. Check disk space on all nodes",
                        "2. Review allocation filters and rules",
                        "3. Verify node availability and connectivity"
                    ]
                })
            else:
                # Generic P0-CRITICAL issue
                critical_issues.append({
                    "type": issue_type,
                    "node": node,
                    "severity": "P0-CRITICAL",
                    "description": description[:150],
                    "fixable": False,
                    "reason": "Requires manual investigation and intervention",
                    "recommended_actions": [
                        f"1. Review issue type: {issue_type}",
                        "2. Check ultra SIEM report for detailed analysis",
                        "3. Consult Elasticsearch documentation",
                        "4. Consider contacting support if issue persists"
                    ]
                })
        
        # Process P1-HIGH issues from recommendations
        for issue_type, description in p1_matches:
            issue_type = issue_type.strip()
            description = description.strip()
            
            # Extract node name if present
            node_match = re.search(r'Node\s+(\S+)', description)
            node = node_match.group(1) if node_match else "cluster-wide"
            
            # Categorize P1 issues
            if "shard" in issue_type.lower() or "shard" in description.lower():
                fixable = True
                actions = [
                    "Auto-remediation will attempt: Retry failed shard allocation",
                    "Manual actions if persists:",
                    "1. Check disk space on all nodes",
                    "2. Review allocation filters and rules",
                    "3. Verify node availability and connectivity"
                ]
            elif "thread" in issue_type.lower() or "rejection" in description.lower():
                fixable = True
                actions = [
                    "Auto-remediation will attempt: Increase thread pool queue sizes",
                    "Manual actions if persists:",
                    "1. Review bulk indexing rate and optimize",
                    "2. Consider adding more nodes to distribute load",
                    "3. Optimize indexing pipelines and reduce batch sizes"
                ]
            elif "heap" in issue_type.lower() or "memory" in issue_type.lower():
                fixable = True
                actions = [
                    "Auto-remediation will attempt: Clear fielddata cache",
                    "Manual actions if persists:",
                    "1. Review queries causing high fielddata usage",
                    "2. Consider increasing heap size (max 32GB recommended)",
                    "3. Review and optimize aggregation queries"
                ]
            else:
                fixable = False
                actions = [
                    f"1. Review issue type: {issue_type}",
                    "2. Check ultra SIEM report for detailed analysis",
                    "3. Consult Elasticsearch documentation"
                ]
            
            critical_issues.append({
                "type": issue_type,
                "node": node,
                "severity": "P1-HIGH",
                "description": description[:150],
                "fixable": fixable,
                "reason": "Auto-remediation will attempt to fix" if fixable else "Requires manual investigation",
                "recommended_actions": actions
            })
        
        # Also check node performance table for WARNING/CRITICAL issues
        # Pattern: <td>CRITICAL: ... or <td>WARNING: ...
        issue_pattern = r'<td>((?:CRITICAL|WARNING):\s*[^<]+)</td>'
        issue_matches = re.findall(issue_pattern, content)
        
        for issue_text in issue_matches:
            if "thread pool" in issue_text.lower() and "rejection" in issue_text.lower():
                critical_issues.append({
                    "type": "thread_pool_rejections",
                    "node": "cluster-wide",
                    "severity": "P1-HIGH",
                    "description": "Thread pool rejections detected",
                    "fixable": True,
                    "reason": "Auto-remediation can adjust thread pool queue sizes",
                    "recommended_actions": [
                        "Auto-remediation will attempt: Increase thread pool queue sizes",
                        "Note: Some settings require elasticsearch.yml changes (manual restart required)",
                        "Manual actions if persists:",
                        "1. Review bulk indexing rate and optimize",
                        "2. Consider adding more nodes to distribute load",
                        "3. Optimize indexing pipelines and reduce batch sizes"
                    ]
                })
            elif "disk" in issue_text.lower() and ("%" in issue_text or "approaching" in issue_text.lower()):
                # Already captured in P0 recommendations above, skip to avoid duplicates
                continue
            elif "heap" in issue_text.lower() and ("90%" in issue_text or "85%" in issue_text):
                critical_issues.append({
                    "type": "high_heap_usage",
                    "node": "cluster-wide",
                    "severity": "P1-HIGH",
                    "description": "High heap memory usage detected",
                    "fixable": True,
                    "reason": "Auto-remediation can clear fielddata cache to reduce heap pressure",
                    "recommended_actions": [
                        "Auto-remediation will attempt: Clear fielddata cache",
                        "Manual actions if persists:",
                        "1. Review queries causing high fielddata usage",
                        "2. Consider increasing heap size (max 32GB recommended)",
                        "3. Review and optimize aggregation queries"
                    ]
                })
        
        logger.info(f"Parsed {len(critical_issues)} critical issues from ultra report")
        for issue in critical_issues:
            logger.info(f"  - {issue['severity']}: {issue['type']} on {issue['node']} (fixable: {issue['fixable']})")
        
        return critical_issues
        
    except Exception as e:
        logger.error(f"Failed to parse ultra report: {e}")
        import traceback
        traceback.print_exc()
        return []


def send_critical_issues_alert(issues: List[Dict[str, Any]], dry_run: bool = False):
    """
    Send detailed alert with 2 sections:
    1. Issues needing manual intervention (with LLM investigation steps)
    2. What was fixed automatically (sent in separate summary alert)
    """
    if not issues:
        return
    
    unfixable_issues = [i for i in issues if not i.get("fixable", False)]
    
    if not unfixable_issues:
        # No manual intervention needed, skip this alert
        return
    
    # Build alert message with only manual intervention section
    alert_lines = []
    
    alert_lines.append("<b>CRITICAL ISSUES REQUIRING MANUAL INTERVENTION</b>")
    alert_lines.append("")
    
    for idx, issue in enumerate(unfixable_issues, 1):
        alert_lines.append(f"<b>--- Issue {idx}/{len(unfixable_issues)} ---</b>")
        alert_lines.append(f"<b>{issue['severity']}</b>: {issue['description']}")
        alert_lines.append(f"<b>Node:</b> {issue['node']}")
        alert_lines.append(f"<b>Type:</b> {issue['type']}")
        alert_lines.append("")
        alert_lines.append(f"<b>Why Manual Action Required:</b>")
        alert_lines.append(f"  {issue['reason']}")
        alert_lines.append("")
        
        # Try to get LLM-generated investigation steps
        llm_steps = get_llm_recommendations(issue)
        
        if llm_steps:
            alert_lines.append("<b>INVESTIGATION & FIX STEPS (AI-Generated):</b>")
            for line in llm_steps.splitlines():
                alert_lines.append(f"  {line}")
        else:
            # Fall back to static recommendations with detailed explanation
            alert_lines.append("<b>RECOMMENDED ACTIONS:</b>")
            for action in issue['recommended_actions']:
                alert_lines.append(f"  {action}")
        
        alert_lines.append("")
    
    alert_lines.append(f"<b>Detected:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    alert_lines.append("<b>Note:</b> Commands above are copy-paste ready")
    
    alert_text = "<br>".join(alert_lines)
    
    title = f"{len(unfixable_issues)} Critical Issue{'s' if len(unfixable_issues) > 1 else ''} Need Manual Attention"

    try:
        from alert_context import generate_alert_id, save_alert_context
        _alert_id = generate_alert_id()
    except Exception:
        _alert_id = ""

    sent = send_google_chat_notification(title, alert_text, "CRITICAL", dry_run, alert_id=_alert_id)

    if sent and _alert_id and not dry_run:
        try:
            save_alert_context(
                alert_id=_alert_id,
                scenario="critical_remediation",
                issues=unfixable_issues,
                recommendations=None,
                llm_analysis=None,
                card_title=title,
            )
        except Exception as _ctx_err:
            logger.debug("Failed to save alert context: %s", _ctx_err)

def run_auto_remediation(dry_run: bool = False, investigate_only: bool = False, specific_fix: Optional[str] = None) -> Dict[str, Any]:
    """
    Main auto-remediation orchestrator.
    Detects issues and applies safe fixes within ~5 minutes.
    """
    logger.info("=" * 70)
    logger.info("AUTO-REMEDIATION SYSTEM STARTING")
    logger.info("=" * 70)
    
    if dry_run:
        logger.info("DRY RUN MODE - No changes will be made")
    if investigate_only:
        logger.info("INVESTIGATION ONLY - No remediation will be applied")
    
    # Check for P0-CRITICAL issues from ultra report first
    critical_issues = check_for_critical_issues_from_report()
    if critical_issues:
        logger.warning(f"Found {len(critical_issues)} critical issues from ultra SIEM report")
        send_critical_issues_alert(critical_issues, dry_run)
    
    es = get_es_client()
    if not es:
        return {"success": False, "error": "Cannot connect to Elasticsearch"}
    
    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "investigate_only": investigate_only,
        "actions_taken": [],
        "investigation": None,
        "critical_issues_from_report": critical_issues
    }
    
    # Always run investigation
    logger.info("Running cluster investigation...")
    results["investigation"] = investigate_cluster_issues(es)
    
    if investigate_only:
        logger.info("Investigation complete (no remediation applied)")
        results["success"] = True
        return results
    
    # Define remediation actions in priority order
    remediations = [
        ("cluster-red", "Recover from cluster RED status", fix_cluster_red),
        ("scroll-contexts", "Clear abandoned scroll contexts", clear_scroll_contexts),
        ("unassigned-shards", "Retry unassigned shard allocation", retry_unassigned_shards),
        ("thread-pools", "Adjust thread pool queue sizes", adjust_thread_pool_settings),
        ("fielddata", "Clear fielddata cache", clear_fielddata_cache),
        ("caches", "Clear request/query caches under heap pressure", clear_request_query_caches),
        ("long-tasks", "Cancel long-running search tasks under high CPU", cancel_long_running_tasks),
        ("ilm", "Restart ILM and retry errored indices", retry_stuck_ilm),
        ("force-merge", "Force-merge over-sharded read-only indices", force_merge_oversharded_indices),
        ("cleanup", "Clean up old ML files", lambda es, dry: cleanup_old_ml_files(dry)),
        ("monitoring-indices", "Delete old .monitoring-*/.watcher-history-* indices", cleanup_old_monitoring_indices),
        ("transforms", "Restart failed/stopped transforms", restart_failed_transforms),
        ("ml-jobs", "Restart stopped ML anomaly detection jobs", restart_stopped_ml_jobs),
        ("snapshots", "Clean up old snapshots", cleanup_old_snapshots),
        ("slm", "Retry failed snapshot lifecycle policies", retry_failed_slm_policies),
        ("empty-indices", "Delete old empty indices (0 docs)", delete_old_empty_indices),
        ("dangling", "Import or clean up dangling indices", cleanup_dangling_indices),
        ("watermark-reset", "Clear read-only blocks after disk recovery", reset_disk_watermark_readonly),
        ("watchers", "Restart stopped Watcher service", restart_failed_watchers),
    ]
    
    # If specific fix requested, only run that one
    if specific_fix:
        remediations = [(name, desc, fn) for name, desc, fn in remediations if name == specific_fix]
        if not remediations:
            return {"success": False, "error": f"Unknown fix type: {specific_fix}"}
    
    # Execute remediations
    for fix_name, description, fix_fn in remediations:
        try:
            logger.info(f"Attempting: {description}")
            
            # Call with or without es parameter depending on function signature
            if fix_name == "cleanup":
                success, message = fix_fn(es, dry_run)
            else:
                success, message = fix_fn(es, dry_run)
            
            results["actions_taken"].append({
                "name": fix_name,
                "description": description,
                "success": success,
                "message": message,
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            
            logger.info(f"  Result: {message}")
            
        except Exception as e:
            logger.exception(f"Failed to execute {fix_name}")
            results["actions_taken"].append({
                "name": fix_name,
                "description": description,
                "success": False,
                "message": f"Exception: {e}",
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
    
    # Summary
    successful = sum(1 for a in results["actions_taken"] if a["success"])
    total = len(results["actions_taken"])
    
    logger.info("=" * 70)
    logger.info(f"Auto-remediation complete: {successful}/{total} actions successful")
    logger.info("=" * 70)
    
    # Send comprehensive summary notification
    if not investigate_only:
        summary_lines = []
        for action in results["actions_taken"]:
            status_mark = "[ok]" if action["success"] else "[fail]"
            summary_lines.append(f"{status_mark} {action['description']}: {action['message'][:100]}")
        
        summary_text = "<br>".join(summary_lines)
        
        if dry_run:
            send_google_chat_notification(
                "Auto-Remediation Summary (Dry Run)",
                f"<b>Mode:</b> DRY RUN - No changes made<br>"
                f"<b>Actions Evaluated:</b> {total}<br>"
                f"<b>Would Succeed:</b> {successful}<br><br>"
                f"<b>Details:</b><br>{summary_text}",
                "INFO",
                dry_run
            )
        else:
            severity = "SUCCESS" if successful == total else ("WARNING" if successful > 0 else "ERROR")
            send_google_chat_notification(
                f"{'Auto-Remediation Complete (all actions ok)' if successful == total else 'Auto-Remediation Complete (with failures)'}",
                f"<b>Actions:</b> {successful}/{total} successful<br>"
                f"<b>Timestamp:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}<br><br>"
                f"<b>Details:</b><br>{summary_text}<br><br>"
                f"<b>Note:</b> Essential indices (.ds-logs-endpoint.events.*, .internal.alerts-*) were protected from destructive operations.",
                severity,
                dry_run
            )
    
    results["success"] = successful > 0 or total == 0
    return results


def main():
    parser = argparse.ArgumentParser(description="Auto-investigation and remediation system")
    parser.add_argument("--auto-fix", action="store_true", help="Automatically apply fixes")
    parser.add_argument("--investigate-only", action="store_true", help="Only investigate, don't fix")
    parser.add_argument("--fix", type=str, help="Apply specific fix: cluster-red, scroll-contexts, unassigned-shards, thread-pools, fielddata, caches, long-tasks, ilm, force-merge, cleanup, monitoring-indices, transforms, ml-jobs, snapshots, slm, empty-indices, dangling, watermark-reset, watchers")
    parser.add_argument("--dry-run", action="store_true", help="Dry run - don't make changes")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    
    args = parser.parse_args()
    
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    if not args.auto_fix and not args.investigate_only and not args.fix:
        parser.print_help()
        logger.error("\nMust specify --auto-fix, --investigate-only, or --fix <type>")
        sys.exit(1)
    
    results = run_auto_remediation(
        dry_run=args.dry_run,
        investigate_only=args.investigate_only,
        specific_fix=args.fix
    )
    
    # Write results to file
    output_file = RESULTS_DIR / f"auto_remediation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Results written to: {output_file}")
    
    sys.exit(0 if results.get("success") else 1)


if __name__ == "__main__":
    main()
