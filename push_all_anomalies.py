"""
Alert filtering, dedup, enrichment, and push for the anomaly pipeline.

Agent 4 owns filtering sections:
  - filter_* functions, dedup_* functions, is_benign / should_push helpers
  - compute_effective_threshold, _build_trace

Agent 6 owns enrichment, bulk-index, and health-metric sections:
  - map_mitre_fields, enrich_anomaly, enrich_batch
  - add_context_placeholders, enrich_with_context
  - push_anomaly, bulk_index_anomalies, index_correlation_chain
  - push_to_buffer, flush_push_buffer
  - health_write, health_read, metrics_build

ATT&CK techniques referenced:
  T1059 (Command and Scripting Interpreter)
  T1046 (Network Service Scanning)
  T1548 (Abuse Elevation Control Mechanism)
  T1105 (Ingress Tool Transfer)
"""

from __future__ import annotations

import argparse
import glob
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from benign_lists import AllowlistManager
from config import AdaptiveThreshold
from es_tls import diagnose_connection_failure, es_tls_kwargs

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEDUP_WINDOW_HOURS: int = 4
SCORE_ESCALATION_DELTA: float = 0.20  # 20% higher score forces re-push
THRESHOLD_AUDIT_LOG: Path = Path("results/threshold_audit.json")

# ---------------------------------------------------------------------------
# Source-index enrichment: cross-reference raw event logs for context
# ---------------------------------------------------------------------------

# File-event source shared by every data type. File context matters for
# all process-centric jobs because the user-facing dashboard renders a
# `file.name` column that is currently 100% empty.
_FILE_SOURCE_TIGHT: dict[str, Any] = {
    "indices": [".ds-logs-endpoint.events.file-default-*"],
    "provides": ["file.name", "file.path", "file.extension"],
    "match_fields": ["host.name", "process.name"],
}
_FILE_SOURCE_HOST: dict[str, Any] = {
    "indices": [".ds-logs-endpoint.events.file-default-*"],
    "provides": ["file.name", "file.path", "file.extension"],
    "match_fields": ["host.name"],
}

_ENRICHMENT_SOURCE_MAP: dict[str, list[dict[str, Any]]] = {
    "process": [
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["user.name", "process.executable", "process.command_line", "host.ip"],
         "match_fields": ["host.name", "process.name"]},
        # Process-level network events (tight: same process made the connection)
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port",
                      "destination.geo", "destination.as"],
         "match_fields": ["host.name", "process.name"]},
        # Host-level network fallback (broad: any network activity on same host/time)
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port",
                      "destination.geo", "destination.as"],
         "match_fields": ["host.name"]},
        # File activity by the same process, then fall back to host-only
        _FILE_SOURCE_TIGHT,
        _FILE_SOURCE_HOST,
        # Auth fallback for user context
        {"indices": [".ds-logs-system.auth-default-*"],
         "provides": ["user.name"],
         "match_fields": ["host.name"]},
    ],
    "network": [
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["host.name", "user.name", "process.name", "source.ip",
                      "destination.ip", "source.port", "destination.port",
                      "destination.geo", "destination.as", "source.geo"],
         "match_fields": ["host.name"]},
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["user.name", "process.name", "process.executable", "process.command_line"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_HOST,
    ],
    "auth": [
        {"indices": [".ds-logs-system.auth-default-*"],
         "provides": ["user.name", "process.name", "source.ip"],
         "match_fields": ["host.name"]},
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["destination.ip", "source.ip", "source.port", "destination.port"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_HOST,
    ],
    "discovery": [
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["user.name", "process.name", "process.executable", "process.command_line"],
         "match_fields": ["host.name"]},
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port",
                      "destination.geo", "destination.as"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_TIGHT,
        _FILE_SOURCE_HOST,
    ],
    "user": [
        {"indices": [".ds-logs-system.auth-default-*"],
         "provides": ["user.name", "host.name", "process.name", "source.ip"],
         "match_fields": ["host.name", "user.name"]},
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["process.name", "process.executable", "process.command_line"],
         "match_fields": ["host.name", "user.name"]},
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_HOST,
    ],
    "metadata": [
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["user.name", "process.executable", "process.command_line", "host.ip"],
         "match_fields": ["host.name", "process.name"]},
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_HOST,
    ],
    "host": [
        {"indices": [".ds-logs-endpoint.events.process-default-*"],
         "provides": ["user.name", "process.name", "process.executable"],
         "match_fields": ["host.name"]},
        {"indices": [".ds-logs-endpoint.events.network-default-*"],
         "provides": ["source.ip", "destination.ip", "source.port", "destination.port"],
         "match_fields": ["host.name"]},
        _FILE_SOURCE_HOST,
    ],
}

# Host-only fallback for the endpoint's own IP. host.ip is a property of
# the host, so matching on host.name alone is always correct -- unlike
# source.ip / destination.ip, which must stay tied to the specific
# process or connection (a host-only match for those would manufacture
# false correlation). Process events are emitted constantly on every
# host, so this guarantees the endpoint IP is present on every alert and
# analysts can always pivot by host. Appended to every data type's source
# list in enrich_from_source_indices.
_HOST_IP_SOURCE: dict[str, Any] = {
    "indices": [".ds-logs-endpoint.events.process-default-*"],
    "provides": ["host.ip"],
    "match_fields": ["host.name"],
}

_PLACEHOLDER_VALUES: set[str] = {
    "unknown-user", "unknown-process", "unknown", "none", "", "n/a",
}

# Cache of dotted-path prefixes that are incompatible with a target index's
# mapping (e.g. index maps `source` as `keyword` so sending `source.ip` as a
# dotted-nested value breaks the bulk request).  Populated lazily per-index
# by `_get_blocked_dotted_fields()`.
_BLOCKED_DOTTED_FIELDS_CACHE: dict[str, set[str]] = {}

# Dotted-path parents we emit during enrichment and therefore must check.
# If any of these is mapped as `keyword` on a given index, we strip them.
_ENRICHMENT_DOTTED_PARENTS: tuple[str, ...] = (
    "source",
    "destination",
    "destination.geo",
    "destination.as",
    "source.geo",
    "file",
)


def _get_blocked_dotted_fields(es: Any, index_name: str) -> set[str]:
    """Return the set of dotted-parent prefixes that cannot safely accept
    nested writes on `index_name`.

    A parent is blocked when ANY of the following hold:
      * It is explicitly mapped as a scalar type (keyword/text/ip/...).
      * It is NOT explicitly mapped but a catch-all dynamic template
        (`match: "*"` with a scalar target type) will force new paths to a
        scalar -- writing a nested object under such a parent will be
        rejected by ES with `document_parsing_exception`.

    Cached per index for the process lifetime.
    """
    cached = _BLOCKED_DOTTED_FIELDS_CACHE.get(index_name)
    if cached is not None:
        return cached
    blocked: set[str] = set()
    try:
        mapping = es.indices.get_mapping(index=index_name)
        for _idx, mm in (mapping or {}).items():
            mappings = mm.get("mappings") or {}
            props = mappings.get("properties") or {}
            # Detect catch-all dynamic template that maps unknown fields
            # to a scalar type.  Presence of such a template means any
            # parent NOT explicitly declared as an object will be turned
            # into that scalar on first sight, breaking nested writes.
            dynamic_templates = mappings.get("dynamic_templates") or []
            _scalar = {"keyword", "text", "ip", "long", "integer", "short",
                       "byte", "float", "double", "boolean", "date"}
            has_catchall_scalar = False
            for tmpl in dynamic_templates:
                for _tname, body in (tmpl or {}).items():
                    match = body.get("match") or body.get("path_match") or ""
                    target_type = (body.get("mapping") or {}).get("type")
                    if match == "*" and target_type in _scalar:
                        has_catchall_scalar = True
                        break
                if has_catchall_scalar:
                    break
            # Walk the candidate parents.
            for parent in _ENRICHMENT_DOTTED_PARENTS:
                parts = parent.split(".")
                node: Any = props
                declared_scalar = False
                fully_declared_object = True
                for p in parts:
                    if not isinstance(node, dict) or p not in node:
                        fully_declared_object = False
                        break
                    child = node[p]
                    if "properties" in child:
                        node = child["properties"]
                        continue
                    # Leaf with concrete type -> scalar.
                    if child.get("type") in _scalar:
                        declared_scalar = True
                    fully_declared_object = False
                    break
                if declared_scalar:
                    blocked.add(parent)
                elif not fully_declared_object and has_catchall_scalar:
                    # Parent not explicitly declared as an object AND a
                    # catch-all scalar dynamic template exists -> unsafe.
                    blocked.add(parent)
    except Exception as exc:
        logger.debug("_get_blocked_dotted_fields(%s) failed: %s", index_name, exc)
    _BLOCKED_DOTTED_FIELDS_CACHE[index_name] = blocked
    return blocked


def _doc_get(doc: dict[str, Any], dotted_key: str) -> Any:
    """Read a field from a doc supporting both flat dotted keys and nested dicts."""
    # Flat key first (our doc format)
    val = doc.get(dotted_key)
    if val is not None:
        return val
    # Try nested dict path
    parts = dotted_key.split(".")
    cur: Any = doc
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _doc_field_missing(doc: dict[str, Any], field: str) -> bool:
    """Return True if the field is absent or a placeholder."""
    val = _doc_get(doc, field)
    if val is None:
        return True
    return str(val).strip().lower() in _PLACEHOLDER_VALUES


def _data_type_from_job(job_id: str) -> str:
    """Derive data-type category from a job_id string."""
    j = (job_id or "").lower()
    if "auth" in j:
        return "auth"
    if "user" in j or "sudo" in j or "compiler" in j:
        return "user"
    if "network" in j or "destination" in j or "port_activity" in j:
        return "network"
    if "discovery" in j or "information" in j:
        return "discovery"
    if "metadata" in j:
        return "metadata"
    if "host_activity" in j or "host_user" in j:
        return "host"
    return "process"


def enrich_from_source_indices(
    es: Any,
    docs: list[dict[str, Any]],
    lookback_minutes: int = 30,
) -> int:
    """Fill missing alert fields by querying raw event indices.

    Cross-references process, network, and auth logs to add:
    process.executable, process.command_line, source/destination IPs,
    ports, geo, user.name, host.ip — the fields needed for accurate
    FP classification.

    Returns total number of fields enriched.
    """
    if es is None or not docs:
        return 0

    total_enriched = 0

    # Group by data type
    by_dtype: dict[str, list[int]] = {}
    for i, doc in enumerate(docs):
        dtype = _data_type_from_job(doc.get("job_id", ""))
        by_dtype.setdefault(dtype, []).append(i)

    for dtype, indices in by_dtype.items():
        # Always run the host-only host.ip fallback last so the endpoint
        # IP is filled even when no process/network event matched the
        # tighter (host + process.name) sources above.
        source_list = _ENRICHMENT_SOURCE_MAP.get(dtype, []) + [_HOST_IP_SOURCE]
        for cfg in source_list:
            # Only query for docs that still have missing fields
            batch: list[tuple[int, dict[str, Any]]] = []
            for di in indices:
                needs = any(_doc_field_missing(docs[di], f) for f in cfg["provides"])
                if not needs:
                    continue
                query = _build_source_query(docs[di], cfg, lookback_minutes)
                if query is None:
                    continue
                batch.append((di, query))

            if not batch:
                continue

            # ES msearch in chunks of 20
            for chunk_start in range(0, len(batch), 20):
                chunk = batch[chunk_start:chunk_start + 20]
                msearch_body: list[dict[str, Any]] = []
                for _, q in chunk:
                    msearch_body.append({"index": cfg["indices"]})
                    msearch_body.append(q)
                try:
                    resp = es.msearch(body=msearch_body)
                    responses = resp.get("responses", [])
                except Exception as exc:
                    logger.debug("Source enrichment msearch failed: %s", exc)
                    continue

                for resp_idx, (doc_idx, _) in enumerate(chunk):
                    if resp_idx >= len(responses):
                        break
                    hits = (responses[resp_idx].get("hits") or {}).get("hits", [])
                    if not hits:
                        continue
                    hit = hits[0].get("_source", {})
                    total_enriched += _apply_source_enrichment(docs[doc_idx], hit, cfg["provides"])

    if total_enriched > 0:
        logger.info("Source enrichment: filled %d fields across docs", total_enriched)
    return total_enriched


def _build_source_query(
    doc: dict[str, Any], cfg: dict[str, Any], lookback_minutes: int
) -> dict[str, Any] | None:
    """Build an ES query to find correlated raw events for source enrichment."""
    host_name = _doc_get(doc, "host.name") or ""
    host_valid = host_name and str(host_name).strip().lower() not in _PLACEHOLDER_VALUES

    if not host_valid:
        return None

    # Time window around anomaly timestamp (30 min default)
    ts_raw = doc.get("timestamp", "")
    try:
        if isinstance(ts_raw, (int, float)):
            ts_dt = datetime.fromtimestamp(ts_raw / 1000 if ts_raw > 1e10 else ts_raw, tz=timezone.utc)
        else:
            ts_dt = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
    except Exception:
        ts_dt = datetime.now(timezone.utc)

    delta = timedelta(minutes=lookback_minutes)
    ts_from = (ts_dt - delta).isoformat()
    ts_to = (ts_dt + delta).isoformat()

    must: list[dict[str, Any]] = [
        {"range": {"@timestamp": {"gte": ts_from, "lte": ts_to}}},
        {"term": {"host.name": str(host_name).strip()}},
    ]

    # Tighter match with process.name if available
    proc = _doc_get(doc, "process.name") or doc.get("process_name", "")
    if proc and str(proc).strip().lower() not in _PLACEHOLDER_VALUES:
        if "process.name" in cfg.get("match_fields", []):
            must.append({"term": {"process.name": str(proc).strip()}})

    # User match for user-type anomalies
    user = _doc_get(doc, "user.name") or ""
    if user and str(user).strip().lower() not in _PLACEHOLDER_VALUES:
        if "user.name" in cfg.get("match_fields", []):
            must.append({"term": {"user.name": str(user).strip()}})

    return {
        "size": 1,
        "sort": [{"@timestamp": "desc"}],
        "_source": [
            "host.name", "host.ip", "user.name",
            "process.name", "process.executable", "process.command_line",
            "source.ip", "source.port",
            "destination.ip", "destination.port",
            "destination.geo", "destination.as", "source.geo",
            "file.name", "file.path", "file.extension",
        ],
        "query": {"bool": {"must": must}},
    }


def _apply_source_enrichment(
    doc: dict[str, Any], hit: dict[str, Any], provides: list[str]
) -> int:
    """Merge fields from a raw-event hit into the anomaly doc.

    Only writes fields that are currently missing. Uses flat dotted keys
    to match the new system's doc format.

    Cross-host contamination guard: if doc has host.name and the hit comes
    from a different host, skip entirely. Comparison is case-insensitive
    and trimmed so capitalisation differences do not block valid hits.
    """
    doc_host_raw = _doc_get(doc, "host.name")
    doc_host = str(doc_host_raw or "").strip().lower()
    hit_host_raw = (hit.get("host") or {}).get("name")
    # Hit host can be a list in ECS normalization; handle that.
    if isinstance(hit_host_raw, list):
        hit_host_list = [str(x).strip().lower() for x in hit_host_raw if x]
        hit_host = hit_host_list[0] if hit_host_list else ""
        hit_host_matches = doc_host in hit_host_list if doc_host else True
    else:
        hit_host = str(hit_host_raw or "").strip().lower()
        hit_host_matches = (not doc_host) or (not hit_host) or doc_host == hit_host

    if doc_host and hit_host and not hit_host_matches:
        return 0

    enriched = 0
    # Map of flat doc keys to hit-source extraction paths
    hit.get("file") or {}
    # Try nested then flat dotted key fallback. Some ES indices return
    # fields only as flat dotted keys (no nested reconstruction).
    def _pick(nested_parent: str, nested_child: str):
        parent = hit.get(nested_parent) or {}
        if isinstance(parent, dict):
            v = parent.get(nested_child)
            if v is not None:
                return v
        flat = hit.get(f"{nested_parent}.{nested_child}")
        if isinstance(flat, list) and flat:
            return flat[0]
        return flat

    field_map: dict[str, Any] = {
        "user.name": _pick("user", "name"),
        "process.executable": _pick("process", "executable"),
        "process.command_line": _pick("process", "command_line"),
        "process.name": _pick("process", "name"),
        "source.ip": _pick("source", "ip"),
        "source.port": _pick("source", "port"),
        "destination.ip": _pick("destination", "ip"),
        "destination.port": _pick("destination", "port"),
        "host.ip": _pick("host", "ip"),
        # File context - previously missing entirely; surfaces file.name
        # in Kibana's alert table and `kibana.alert.reason`.
        "file.name": _pick("file", "name"),
        "file.path": _pick("file", "path"),
        "file.extension": _pick("file", "extension"),
    }

    for field_key, val in field_map.items():
        if field_key not in provides and not field_key.startswith("host.ip"):
            continue
        if val is None:
            continue
        val_str = str(val).strip()
        if not val_str or val_str.lower() in _PLACEHOLDER_VALUES:
            continue
        if _doc_field_missing(doc, field_key):
            doc[field_key] = val
            enriched += 1

    # Geo/AS enrichment for destination
    if "destination.geo" in provides and not doc.get("destination.geo"):
        geo = (hit.get("destination") or {}).get("geo")
        if geo and isinstance(geo, dict):
            doc["destination.geo"] = geo
            enriched += 1
    if "destination.as" in provides and not doc.get("destination.as"):
        as_info = (hit.get("destination") or {}).get("as")
        if as_info and isinstance(as_info, dict):
            doc["destination.as"] = as_info
            enriched += 1
    if "source.geo" in provides and not doc.get("source.geo"):
        geo = (hit.get("source") or {}).get("geo")
        if geo and isinstance(geo, dict):
            doc["source.geo"] = geo
            enriched += 1

    return enriched


# ---------------------------------------------------------------------------
# False-positive classification — ported from production SIEM
# ---------------------------------------------------------------------------

# Known-automation command-line patterns. Used by the shell-on-infra rule
# so that ONLY recognisable system automation (cron wrappers, Debian sar,
# apt.systemd, unattended-upgrade, microk8s / VBox helpers, container
# init, trivial `sleep N`, admin net discovery via `sh -c ip neigh ...`,
# app startup scripts) is suppressed. Anything else - including a plain
# `bash --regular-use` or any previously-unseen cmdline - falls through
# to manual triage.
_AUTOMATION_CMD_RE = re.compile(
    r"(?i)"
    r"/etc/cron\."
    r"|\brun-parts\b"
    r"|\bdebian-sa1\b"
    r"|apt\.systemd\.daily"
    r"|/usr/lib/update-notifier/"
    r"|/usr/lib/virtualbox/"
    r"|/usr/lib/apt/"
    r"|/usr/libexec/docker/"
    r"|/snap/microk8s/"
    r"|/var/snap/microk8s/"
    r"|^runc\s+init\b"
    r"|\bsleep\s+\d+\s*$"
    r"|\bip\s+(?:neigh|route|addr|link)\b"
    r"|\bstartup\.sh\b"
    r"|\bcommand\s+-v\s"
    r"|docker-init\s+--version"
    r"|falconctl\s+-g"
)

# Suspicious command-line patterns that OVERRIDE FP classification (never filter)
_SUSPICIOUS_CMD_RE = re.compile(
    r"(?i)"
    r"(?:base64\s+-d|base64\s+--decode)"
    r"|(?:curl|wget)\s+[^\s]+\s*\|\s*(?:bash|sh|python)"
    r"|/dev/tcp/"
    r"|nc\s+-[elp]"
    r"|mkfifo\s+/tmp/"
    r"|python[23]?\s+-c\s+.*socket"
    r"|meterpreter|mimikatz|lazagne|bloodhound"
    r"|chmod\s+[47]777\s+/"
    r"|rm\s+-rf\s+/"
    r"|iptables\s+-F"
    r"|history\s+-c"
    r"|xmrig|stratum\+tcp"
    r"|/etc/shadow"
)

# Admin/discovery CLIs that legitimate infrastructure tooling (monitoring,
# backup, session management) invokes constantly. These surface as the
# top noisy processes in the live `ML Anomaly High Score` dashboard but
# are only benign in context - we only suppress them when the job class
# is explicitly discovery and the host is known infrastructure.
_ADMIN_DISCOVERY_CLIS: set[str] = {
    "ip", "ps", "grep", "stat", "cp", "date", "cat", "timeout",
    "byobu-status", "uname", "df", "ss", "du", "uptime", "whoami",
    "id", "hostname", "lsb_release", "head", "tail", "awk", "sort",
    "wc", "cut", "basename", "dirname", "tr", "readlink",
}

# Job IDs whose purpose is rare-process / discovery detection. When one
# of these jobs fires on a benign discovery CLI, downgrade to FP
# without letting the NEVER_ALLOWLIST path fire (which would still
# suppress genuinely suspicious LOLBin use).
_DISCOVERY_JOB_PREFIXES: tuple[str, ...] = (
    "v3_linux_network_configuration_discovery",
    "v3_linux_network_connection_discovery",
    "v3_linux_system_information_discovery",
    "v3_linux_system_process_discovery",
    "v3_linux_system_user_discovery",
    "v3_rare_process_by_host_linux",
    "v3_linux_anomalous_process_all_hosts",
    "v3_linux_rare_metadata_process",
    "v3_linux_rare_metadata_user",
)

# Dedicated JSONL trace for every FP decision. Analysts use this to
# verify that the classifier is suppressing only the patterns we
# intended to suppress. Intentionally separate from the allowlist log.
FP_TRACE_LOG: Path = Path("results/fp_classification_trace.jsonl")


def _is_discovery_job(job_id: str) -> bool:
    """Return True if this job belongs to the discovery / rare-process class."""
    j = (job_id or "").lower()
    return any(j.startswith(p) for p in _DISCOVERY_JOB_PREFIXES)


def _log_fp_decision(doc: dict[str, Any], is_fp: bool, reason: str) -> None:
    """Append a structured FP decision record for analyst audit."""
    try:
        FP_TRACE_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "anomaly_id": doc.get("anomaly_id"),
            "job_id": doc.get("job_id"),
            "host.name": _doc_get(doc, "host.name"),
            "user.name": _doc_get(doc, "user.name"),
            "process.name": _doc_get(doc, "process.name"),
            "process.command_line": _doc_get(doc, "process.command_line"),
            "source.ip": _doc_get(doc, "source.ip"),
            "destination.ip": _doc_get(doc, "destination.ip"),
            "ml_score": doc.get("ml_score"),
            "record_score": doc.get("record_score"),
            "is_fp": is_fp,
            "reason": reason,
        }
        with FP_TRACE_LOG.open("a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        logger.debug("fp_trace log write failed: %s", exc)

# ---------------------------------------------------------------------------
# Config-file-loaded FP classification lists
# Edit files in config/ to customize for your environment
# ---------------------------------------------------------------------------

_CONFIG_DIR = Path(__file__).resolve().parent / "config"


def _load_config_lines(filename: str) -> list[str]:
    """Load non-empty, non-comment lines from a config/ text file."""
    path = _CONFIG_DIR / filename
    if not path.exists():
        logger.warning("Config file not found: %s — using empty list", path)
        return []
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if stripped and not stripped.startswith("#"):
            lines.append(stripped)
    return lines


def _load_set(filename: str) -> set[str]:
    """Load a config text file as a lowercase set."""
    return {line.lower() for line in _load_config_lines(filename)}


def _load_tuple(filename: str) -> tuple[str, ...]:
    """Load a config text file as a tuple (preserves original case)."""
    return tuple(_load_config_lines(filename))


def _load_int_set(filename: str) -> set[int]:
    """Load a config text file as a set of integers."""
    result: set[int] = set()
    for line in _load_config_lines(filename):
        try:
            result.add(int(line))
        except ValueError:
            logger.warning("Skipping non-integer in %s: %s", filename, line)
    return result


# Known-benign infrastructure processes (exact match, lowercase)
_FP_BENIGN_PROCESSES: set[str] = _load_set("benign_processes.txt")

_FP_BENIGN_PROCESS_PREFIXES: tuple[str, ...] = _load_tuple("benign_process_prefixes.txt")

_SYSTEM_BINARY_PREFIXES: tuple[str, ...] = (
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/bin/", "/sbin/", "/usr/local/bin/", "/snap/", "/opt/",
)

_FP_SERVICE_ACCOUNTS: set[str] = _load_set("service_accounts.txt")

_FP_KNOWN_INFRA_HOSTS: set[str] = _load_set("infrastructure_hosts.txt")

_FP_PUBLIC_FACING_HOSTS: set[str] = _load_set("public_facing_hosts.txt")

_INTERNAL_PREFIXES: tuple[str, ...] = _load_tuple("internal_ip_prefixes.txt")

# Public IPs owned by the platform itself (NAT egress, public WAN IPs of
# our own infra). Traffic to / from these is internal from a trust-
# boundary perspective, even though RFC1918 says otherwise.
_PLATFORM_PUBLIC_PREFIXES: tuple[str, ...] = _load_tuple("platform_public_ips.txt")

_CLOUD_BENIGN_PREFIXES: tuple[str, ...] = _load_tuple("cloud_ip_prefixes.txt")

_PUBLIC_SERVICE_PORTS: set[int] = _load_int_set("public_service_ports.txt")

# Ports that are "benign" when combined with a cloud-benign IP:
# standard web (80, 443, alt-http), git / ssh (22), DNS (53),
# NTP (123), and any port the environment explicitly registers as
# a public-service port.
_CLOUD_BENIGN_PORTS: set[int] = set(_PUBLIC_SERVICE_PORTS) | {22, 53, 123}

# Processes whose entire purpose is to fetch content from the internet
# (package managers, VCS, generic http clients, container runtimes).
# When any of these talks to a cloud-benign IP we treat it as routine
# developer / ops traffic regardless of destination port.
_CLOUD_EGRESS_PROCS: set[str] = {
    "apt", "apt-get", "apt-cache", "apt-helper", "aptd",
    "unattended-upgr", "update-notifier", "package-data-downloader",
    "yum", "dnf", "zypper", "pacman", "microdnf",
    "snap", "snapd", "snap-update-ns",
    "curl", "wget", "fetch", "axel", "aria2c",
    "git", "gh", "hg",
    "pip", "pip3", "pipenv", "poetry", "easy_install",
    "npm", "yarn", "pnpm", "node",
    "go", "cargo", "rustup",
    "docker", "docker-init", "dockerd", "docker-proxy",
    "containerd", "containerd-shim", "runc", "crictl",
    "helm", "kubectl", "k8s-dqlite", "microk8s",
    "chronyd", "ntpd", "systemd-timesyncd",
    "resolvectl", "systemd-resolved", "nscd",
    "python", "python3",
}


def _is_internal_ip(ip: str) -> bool:
    """Return True if the IP is private, loopback, link-local, or a
    platform-owned public IP (NAT egress / our own public WAN IPs)."""
    if not ip:
        return True
    s = str(ip).strip().lower()
    if not s:
        return True
    if any(s.startswith(p) for p in _INTERNAL_PREFIXES):
        return True
    if _PLATFORM_PUBLIC_PREFIXES and any(s.startswith(p) for p in _PLATFORM_PUBLIC_PREFIXES):
        return True
    return False


def _is_platform_public_ip(ip: str) -> bool:
    """Return True if the IP is a declared platform-owned public IP."""
    if not ip or not _PLATFORM_PUBLIC_PREFIXES:
        return False
    s = str(ip).strip().lower()
    return any(s.startswith(p) for p in _PLATFORM_PUBLIC_PREFIXES)


def _is_cloud_benign_ip(ip: str) -> bool:
    """Return True if the IP belongs to a known cloud/CDN provider."""
    if not ip:
        return False
    return any(str(ip).startswith(p) for p in _CLOUD_BENIGN_PREFIXES)


def _is_benign_process(proc_name: str) -> bool:
    """Check if a process name is known-benign."""
    if not proc_name:
        return False
    pn = str(proc_name).lower().strip()
    if pn in _FP_BENIGN_PROCESSES:
        return True
    for prefix in _FP_BENIGN_PROCESS_PREFIXES:
        if pn.startswith(prefix):
            return True
    return False


def is_likely_false_positive(doc: dict[str, Any]) -> tuple[bool, str]:
    """Classify whether an alert is a likely false positive.

    Returns (is_fp, reason). Documents classified as FP are dropped
    before push. Borderline cases pass through.

    Override: suspicious command lines are NEVER classified as FP.

    ATT&CK: prevents suppression of T1059, T1105, T1078, T1548.
    """
    proc_name = str(_doc_get(doc, "process.name") or doc.get("process_name", "") or "").lower().strip()
    cmd_line = str(_doc_get(doc, "process.command_line") or "")
    user_name = str(_doc_get(doc, "user.name") or "").lower().strip()
    host_name = str(_doc_get(doc, "host.name") or "").lower().strip()
    exe_path = str(_doc_get(doc, "process.executable") or "").lower()
    job_id = str(doc.get("job_id", ""))

    # Destination IP info
    dst_ip = str(_doc_get(doc, "destination.ip") or doc.get("destination_ip", "") or "").strip()
    src_ip = str(_doc_get(doc, "source.ip") or doc.get("source_ip", "") or "").strip()
    dst_port: int = 0
    try:
        dst_port = int(_doc_get(doc, "destination.port") or doc.get("destination_port", 0) or 0)
    except (TypeError, ValueError):
        pass

    # --- EARLY FP: loopback /dev/tcp probe (service readiness check) ---
    # Patterns like `timeout 1s bash -c ':> /dev/tcp/127.0.0.1/6333'` are the
    # canonical Linux healthcheck idiom. They look like a reverse shell to
    # the suspicious-cmdline regex (which matches `/dev/tcp/`) but the
    # destination is strictly loopback, so there is no attack surface.
    # Must run BEFORE the suspicious-cmdline override.
    _cmd_low = cmd_line.lower()
    if cmd_line and (
        "/dev/tcp/127.0.0.1/" in _cmd_low or "/dev/tcp/::1/" in _cmd_low
    ):
        return True, f"loopback_tcp_probe(proc={proc_name})"

    # --- EARLY FP: container internal healthcheck curl ---
    # `curl --fail http://host.docker.internal:PORT/...` is the standard
    # Docker Compose healthcheck. host.docker.internal is strictly an
    # in-container DNS alias for the host, never externally reachable.
    if cmd_line and "host.docker.internal" in _cmd_low and "curl" in _cmd_low:
        return True, f"docker_internal_healthcheck(proc={proc_name})"

    # --- OVERRIDE: suspicious command line -> NEVER filter ---
    if cmd_line and _SUSPICIOUS_CMD_RE.search(cmd_line):
        return False, ""

    # --- EARLY FP: APT package manager updates ---
    if user_name == "_apt" and ("apt/methods" in exe_path or "/snapd/" in exe_path):
        return True, f"apt_package_update({user_name})"

    # --- EARLY FP: tokenisation artefact ---
    # Numeric-only or 1-char process tokens almost always mean the
    # upstream tokeniser grabbed a PID/arg index by accident. Drop
    # them so they do not create alert rows that analysts cannot triage.
    if proc_name and (proc_name.isdigit() or len(proc_name) < 2):
        return True, f"tokenization_artifact(proc={proc_name!r})"

    # --- EARLY FP: admin-discovery CLI on known infra host ---
    # The live dashboard is dominated by rare-process alerts for tools
    # like `ip`, `grep`, `ps`, `stat`, `byobu-status` on infrastructure
    # hosts. These are the CLIs that administrators and monitoring
    # agents drive constantly. We only suppress them when:
    #   - job is explicitly discovery / rare-process class,
    #   - host is in the known-infra list,
    #   - there is no external destination (handled below),
    #   - the command line does not look suspicious.
    is_discovery = _is_discovery_job(job_id)
    has_external_dst_probe = bool(dst_ip) and not _is_internal_ip(dst_ip)
    # Broadened: the same admin CLI / infra-host / no-external combo is
    # equally benign when the job class is host_user_deviation or
    # anomalous_host_activity (e.g. `ip neigh show` on oc-ubuntu-server).
    # The suspicious-cmdline override above still protects real misuse.
    if (
        proc_name in _ADMIN_DISCOVERY_CLIS
        and host_name in _FP_KNOWN_INFRA_HOSTS
        and not has_external_dst_probe
    ):
        return True, f"admin_discovery_cli(proc={proc_name},host={host_name})"

    # --- Direction-aware external IP check ---
    has_external_dst = bool(dst_ip) and not _is_internal_ip(dst_ip)
    has_suspicious_ext_dst = has_external_dst and not _is_cloud_benign_ip(dst_ip)

    # Truly suspicious external destination -> NEVER filter
    if has_suspicious_ext_dst:
        return False, ""

    # Cloud-benign egress: internal/missing source -> cloud-benign dst
    # (AWS / Azure / GCP / Cloudflare / GitHub / Fastly / Canonical /
    # public DNS) is the textbook pattern for package-manager, git,
    # CDN, DNS, and NTP traffic. When it happens:
    #   - from an internal (or unresolved) source, AND
    #   - on a standard web / git / DNS / NTP port OR from a process
    #     whose job is to fetch from the internet,
    # we classify it as an FP. Unknown processes going to cloud-benign
    # IPs on non-standard ports still fall through for human review.
    if has_external_dst and _is_cloud_benign_ip(dst_ip):
        src_is_internal_or_missing = (not src_ip) or _is_internal_ip(src_ip)
        if src_is_internal_or_missing and (
            dst_port in _CLOUD_BENIGN_PORTS
            or (dst_port == 0 and proc_name in _CLOUD_EGRESS_PROCS)
            or proc_name in _CLOUD_EGRESS_PROCS
        ):
            return True, (
                f"cloud_benign_egress(proc={proc_name or '-'},"
                f"dst={dst_ip},port={dst_port or '-'})"
            )

    # External dst that is cloud-benign from a non-benign process -> keep (might be C2)
    if has_external_dst and not _is_benign_process(proc_name):
        # Container subnet outbound web to cloud -> FP
        is_container_src = src_ip and any(src_ip.startswith(p) for p in ("172.17.", "172.18.", "172.19.", "172.20."))
        if is_container_src and dst_port in _PUBLIC_SERVICE_PORTS:
            return True, f"container_outbound_web({src_ip})->port{dst_port}"
        return False, ""

    # Cloud-benign inbound: a cloud-benign source sending to an internal
    # destination is the reply half of an outbound call (e.g. Fastly
    # returning the body of an `apt update`, GitHub responding to a
    # `git pull`). Same treatment as egress.
    has_any_external = bool(src_ip) and not _is_internal_ip(src_ip)
    if has_any_external and _is_cloud_benign_ip(src_ip):
        dst_is_internal_or_missing = (not dst_ip) or _is_internal_ip(dst_ip)
        if dst_is_internal_or_missing and (
            dst_port in _CLOUD_BENIGN_PORTS
            or dst_port == 0
            or proc_name in _CLOUD_EGRESS_PROCS
        ):
            return True, (
                f"cloud_benign_inbound(proc={proc_name or '-'},"
                f"src={src_ip},port={dst_port or '-'})"
            )

    # Inbound external on non-public port -> suspicious, keep
    if has_any_external and dst_port not in _PUBLIC_SERVICE_PORTS and dst_port != 0:
        return False, ""

    # --- Below: all IPs are internal/missing OR cloud-benign, cmdline not suspicious ---

    # Rule 1: Loopback-only traffic
    if src_ip and dst_ip:
        if src_ip in ("127.0.0.1", "::1") and dst_ip in ("127.0.0.1", "::1"):
            return True, f"loopback_traffic({src_ip}->{dst_ip})"

    # Rule 1b: East-west traffic between two known-internal endpoints.
    # Both src and dst are in our trust boundary (RFC1918 or a declared
    # platform-owned public IP). Suspicious cmdline is already handled
    # above (returns False before reaching here). To avoid masking
    # lateral movement we additionally require:
    #   - receiver host is in the known-infra list, AND
    #   - the process is either a recognised benign daemon, an admin /
    #     discovery CLI, or the job class is discovery / rare-process.
    # Anything else (unknown proc, unknown host) falls through for
    # human review.
    if src_ip and dst_ip and _is_internal_ip(src_ip) and _is_internal_ip(dst_ip):
        east_west_proc_ok = bool(proc_name) and (
            _is_benign_process(proc_name)
            or proc_name in _ADMIN_DISCOVERY_CLIS
            or is_discovery
        )
        if east_west_proc_ok and host_name in _FP_KNOWN_INFRA_HOSTS:
            return True, (
                f"internal_east_west(proc={proc_name},host={host_name},"
                f"{src_ip}->{dst_ip})"
            )
        if _is_platform_public_ip(src_ip) or _is_platform_public_ip(dst_ip):
            # Traffic to / from the platform NAT gateway is by definition
            # platform-internal even when the other endpoint is RFC1918.
            if proc_name and host_name in _FP_KNOWN_INFRA_HOSTS:
                return True, (
                    f"platform_gateway_traffic(proc={proc_name},"
                    f"host={host_name},{src_ip}->{dst_ip})"
                )

    # Rule 2: Known-benign infrastructure daemon + internal-only traffic
    if _is_benign_process(proc_name):
        return True, f"benign_process({proc_name})+internal_only"

    # Rule 2b: Inbound public port on a public-facing host with no process context
    if dst_port in _PUBLIC_SERVICE_PORTS and not proc_name and host_name in _FP_PUBLIC_FACING_HOSTS:
        return True, f"inbound_public_port({dst_port})+public_host({host_name})"

    # Rule 3: Service account on known host
    if user_name in _FP_SERVICE_ACCOUNTS and host_name in _FP_KNOWN_INFRA_HOSTS:
        return True, f"service_account({user_name})+known_host({host_name})+internal"

    # Rule 4: Service account + no process info
    if user_name in _FP_SERVICE_ACCOUNTS and not proc_name:
        return True, f"service_account({user_name})+no_process+internal"

    # Rule 5: Empty user.name on an internal-only doc from an infra host.
    # Empty user almost always means the signal was generated from a
    # synthetic / imputed row; without a real user it cannot be triaged.
    # Widened from discovery-class only: the same pattern also fires under
    # v3_linux_host_user_deviation and v3_linux_anomalous_host_activity.
    # Guard: only trust the suppression when the host is known infra and
    # there is no external traffic.
    if (
        not user_name
        and not has_any_external
        and host_name in _FP_KNOWN_INFRA_HOSTS
    ):
        return True, f"empty_user_internal({host_name})"

    # Rule 6: Shell / sudo / timeout on a known infra host with no
    # external traffic. Fires in two cases only:
    #  (a) no cmdline at all -> Rancher/k8s automation, container
    #      entrypoints, session wrappers.
    #  (b) cmdline matches a recognised automation pattern
    #      (_AUTOMATION_CMD_RE): cron wrappers, Debian sar,
    #      VirtualBox helpers, microk8s scripts, app startup.sh, etc.
    # An arbitrary, unrecognised cmdline falls through to manual triage
    # so a truly anomalous shell on an infra host still reaches Kibana.
    if (
        proc_name in {"sh", "bash", "sudo", "timeout"}
        and host_name in _FP_KNOWN_INFRA_HOSTS
        and not has_any_external
        and not has_external_dst
        and (not cmd_line or _AUTOMATION_CMD_RE.search(cmd_line))
    ):
        return True, f"shell_on_infra(proc={proc_name},host={host_name})"

    # Rule 7: CrowdStrike falconctl self-checks. The process.name field
    # occasionally tokenises to "http" or "falconctl"; both ultimately
    # point to `/opt/CrowdStrike/falconctl -g --version`, which is a
    # pure local read with no network effect.
    if "/crowdstrike/falconctl" in exe_path or "crowdstrike/falconctl" in _cmd_low:
        return True, "crowdstrike_falconctl_selfcheck"

    # Rule 8: Short-lived system utilities on infra hosts with no external
    # traffic - `sleep`, `ip6tables` teardown, `docker-init --version`,
    # `runc init`, `apt.systemd.daily`, `update-motd-updates-available`.
    # `last` (wtmp login-history read) and `systemctl` (service control)
    # are scoped here rather than the global benign list: they are pure
    # noise from the rare-process detector on infra hosts, but on a
    # non-infra host or alongside external traffic they remain triageable
    # (e.g. systemctl-based persistence, T1543.002). The suspicious-cmdline
    # override above still protects genuine misuse.
    if (
        host_name in _FP_KNOWN_INFRA_HOSTS
        and not has_any_external
        and not has_external_dst
        and proc_name in {
            "sleep", "ip6tables", "iptables", "docker-init", "runc",
            "fwupd", "fwupdmgr", "vboxsvc", "vboxxpcomipcd", "vboxmanage",
            "debian-sa1", "update-motd-updates-available", "update-motd",
            "last", "systemctl",
        }
    ):
        return True, f"system_utility_on_infra(proc={proc_name})"

    return False, ""


# ---------------------------------------------------------------------------
# Context-completeness gate
# ---------------------------------------------------------------------------

# Quarantine log for docs that fail the per-job minimum context contract.
# Quarantine (not drop) is deliberate: analysts can replay this file to
# see whether the gate is tuned correctly before we ever delete data.
CONTEXT_QUARANTINE_LOG: Path = Path("results/incomplete_context_quarantine.jsonl")


def _context_class(job_id: str) -> str:
    """Bucket a job into a context class for gating purposes."""
    jid = (job_id or "").lower()
    if "auth" in jid:
        return "auth"
    if "network" in jid or "destination" in jid or "port_activity" in jid:
        return "network"
    if (
        "discovery" in jid
        or "information" in jid
        or jid.startswith("v3_rare_process_by_host_linux")
        or jid.startswith("v3_linux_anomalous_process_all_hosts")
        or "rare_metadata" in jid
    ):
        return "discovery"
    return "process"


def context_complete(doc: dict[str, Any]) -> tuple[bool, str]:
    """Return (is_complete, reason) for the per-job minimum contract.

    Minimums:
      process jobs:   host.name, host.ip, process.name, and (user.name or process.command_line)
      network jobs:   host.name, and one of source.ip / destination.ip
      auth jobs:      host.name and user.name
      discovery jobs: host.name, host.ip, and a valid process.name token

    The check uses `_doc_field_missing` so placeholder strings like
    "unknown-user" count as missing rather than as populated fields.
    """
    job_id = str(doc.get("job_id", ""))
    cls = _context_class(job_id)

    host_ok = not _doc_field_missing(doc, "host.name")
    host_ip_ok = not _doc_field_missing(doc, "host.ip")
    proc_val = _doc_get(doc, "process.name")
    proc_ok = not _doc_field_missing(doc, "process.name") and _is_valid_process_name(proc_val)
    user_ok = not _doc_field_missing(doc, "user.name")
    cmd_ok = not _doc_field_missing(doc, "process.command_line")
    src_ip_ok = not _doc_field_missing(doc, "source.ip")
    dst_ip_ok = not _doc_field_missing(doc, "destination.ip")

    if cls == "process":
        if not host_ok:
            return False, "process:missing_host_name"
        if not proc_ok:
            return False, "process:missing_valid_process_name"
        if not (user_ok or cmd_ok):
            return False, "process:missing_user_and_cmdline"
        # Endpoint IP context is required: a process anomaly we cannot even
        # tie to a host IP is almost always a synthetic/stale record and is
        # not triageable. host.ip is back-filled by the host-only enrichment
        # fallback, so a real endpoint event will satisfy this.
        if not host_ip_ok:
            return False, "process:missing_host_ip"
        return True, "process:ok"
    if cls == "network":
        if not host_ok:
            return False, "network:missing_host_name"
        if not (src_ip_ok or dst_ip_ok):
            return False, "network:missing_any_ip"
        return True, "network:ok"
    if cls == "auth":
        if not host_ok:
            return False, "auth:missing_host_name"
        if not user_ok:
            return False, "auth:missing_user_name"
        return True, "auth:ok"
    # discovery
    if not host_ok:
        return False, "discovery:missing_host_name"
    if not proc_ok:
        return False, "discovery:missing_valid_process_name"
    if not host_ip_ok:
        return False, "discovery:missing_host_ip"
    return True, "discovery:ok"


def _log_context_quarantine(doc: dict[str, Any], reason: str) -> None:
    """Append a quarantined doc's key fields for analyst review."""
    try:
        CONTEXT_QUARANTINE_LOG.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "anomaly_id": doc.get("anomaly_id"),
            "job_id": doc.get("job_id"),
            "host.name": _doc_get(doc, "host.name"),
            "host.ip": _doc_get(doc, "host.ip"),
            "user.name": _doc_get(doc, "user.name"),
            "process.name": _doc_get(doc, "process.name"),
            "process.command_line": _doc_get(doc, "process.command_line"),
            "source.ip": _doc_get(doc, "source.ip"),
            "destination.ip": _doc_get(doc, "destination.ip"),
            "file.name": _doc_get(doc, "file.name"),
            "ml_score": doc.get("ml_score"),
            "record_score": doc.get("record_score"),
        }
        with CONTEXT_QUARANTINE_LOG.open("a") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
    except OSError as exc:
        logger.debug("context quarantine log write failed: %s", exc)


def apply_context_gate(
    docs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Split docs into (kept, quarantined, counters_by_reason).

    This is a safety gate that runs AFTER enrichment and FP classification
    so that we only quarantine docs which remain low-context even after
    every attempt to fill them.
    """
    kept: list[dict[str, Any]] = []
    quarantined: list[dict[str, Any]] = []
    counters: dict[str, int] = {}
    for doc in docs:
        ok, reason = context_complete(doc)
        if ok:
            kept.append(doc)
            continue
        quarantined.append(doc)
        counters[reason] = counters.get(reason, 0) + 1
        _log_context_quarantine(doc, reason)
    return kept, quarantined, counters


def classify_fp_batch(
    docs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Classify a list of docs as TP or FP.

    Returns (tp_docs, fp_docs, fp_count).
    Each doc gets an 'fp_classification' field added and every decision
    is appended to `results/fp_classification_trace.jsonl` so analysts
    can audit exactly why each document was dropped.
    """
    tp_docs: list[dict[str, Any]] = []
    fp_docs: list[dict[str, Any]] = []

    for doc in docs:
        is_fp, reason = is_likely_false_positive(doc)
        if is_fp:
            doc["fp_classification"] = f"likely_fp:{reason}"
            fp_docs.append(doc)
        else:
            doc["fp_classification"] = "tp_or_likely_tp"
            tp_docs.append(doc)
        _log_fp_decision(doc, is_fp, reason)

    return tp_docs, fp_docs, len(fp_docs)

# ---------------------------------------------------------------------------
# Dedup state (in-process; callers may inject a persistent store)
# ---------------------------------------------------------------------------

# Maps (entity, job_id) -> {"score": float, "window_start": datetime, "count": int}
_DEDUP_STATE: dict[tuple[str, str], dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Adaptive threshold helpers
# ---------------------------------------------------------------------------

def compute_effective_threshold(
    job_id: str,
    entity: str,
    raw_score: float,
    threshold_cfg: AdaptiveThreshold,
    evaluation_time: datetime | None = None,
) -> tuple[float, dict[str, Any]]:
    """Compute the effective push threshold for a single alert.

    Returns (effective_threshold, components_dict) where components_dict
    carries the breakdown written to threshold_audit.json.

    ATT&CK: threshold tuning reduces FN for T1059, T1046, T1548.
    """
    now = evaluation_time or datetime.now(timezone.utc)
    hour = now.hour

    base = threshold_cfg.base_score
    time_adj = 1.0
    host_adj = 1.0

    is_off_hours = hour < threshold_cfg.business_hours_start or hour >= threshold_cfg.business_hours_end
    if is_off_hours:
        time_adj = threshold_cfg.off_hours_multiplier

    is_high_value = entity in threshold_cfg.high_value_hosts
    if is_high_value:
        host_adj = threshold_cfg.high_value_host_multiplier

    effective = base * time_adj * host_adj

    # Per-job override takes precedence over computed value
    if job_id in threshold_cfg.per_job_overrides:
        effective = threshold_cfg.per_job_overrides[job_id] * time_adj * host_adj

    components: dict[str, Any] = {
        "base": base,
        "time_adj": time_adj,
        "host_adj": host_adj,
        "off_hours": is_off_hours,
        "high_value_host": is_high_value,
        "per_job_override": threshold_cfg.per_job_overrides.get(job_id),
    }

    reason_parts = [f"base={base}"]
    if time_adj != 1.0:
        reason_parts.append(f"off_hours=*{time_adj}")
    if host_adj != 1.0:
        reason_parts.append(f"high_value_host=*{host_adj}")
    if components["per_job_override"] is not None:
        reason_parts.append(f"per_job_override={components['per_job_override']}")
    reason_parts.append(f"-> {effective:.4f}")

    decision = "push" if raw_score >= effective else "drop"

    audit_record: dict[str, Any] = {
        "timestamp": now.isoformat(),
        "job_id": job_id,
        "entity": entity,
        "raw_score": raw_score,
        "effective_threshold": round(effective, 4),
        "reason": ", ".join(reason_parts),
        "decision": decision,
    }
    _append_threshold_audit(audit_record)

    return effective, components


def _append_threshold_audit(record: dict[str, Any]) -> None:
    """Append one threshold-decision record to the audit log (JSON lines)."""
    THRESHOLD_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        with THRESHOLD_AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Failed to write threshold audit: %s", exc)


# ---------------------------------------------------------------------------
# Dedup logic
# ---------------------------------------------------------------------------

def dedup_key(entity: str, job_id: str) -> tuple[str, str]:
    """Return the canonical dedup key for an (entity, job_id) pair."""
    return (entity, job_id)


def is_correlated_chain(alert: dict[str, Any]) -> bool:
    """Return True if this alert is part of a post_correlation chain.

    Correlated-chain members always bypass dedup so the full kill-chain
    is visible to analysts.
    """
    return bool(alert.get("correlation_chain_id"))


def dedup_filter(
    alert: dict[str, Any],
    dedup_state: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Apply 4-hour window dedup with score-escalation override.

    Returns (should_push, dedup_status, state_update).

    Dedup statuses:
      "first_occurrence"   — no prior entry in window, push normally
      "escalation"         — score >=20% higher than last pushed, force-push
      "clustered"          — within window and not escalated, suppress
      "chain_bypass"       — part of a correlated chain, always push
    """
    state = dedup_state if dedup_state is not None else _DEDUP_STATE

    entity = alert.get("entity", "")
    job_id = alert.get("job_id", "")
    score = float(alert.get("score", 0.0))
    now = datetime.now(timezone.utc)
    key = dedup_key(entity, job_id)

    # Correlated chains bypass dedup entirely
    if is_correlated_chain(alert):
        return True, "chain_bypass", {}

    prior = state.get(key)
    window_start = prior["window_start"] if prior else None
    in_window = (
        prior is not None
        and isinstance(window_start, datetime)
        and (now - window_start) < timedelta(hours=DEDUP_WINDOW_HOURS)
    )

    if not in_window:
        # New window — first occurrence
        state[key] = {
            "score": score,
            "window_start": now,
            "count": 1,
            "similar_count": 0,
        }
        return True, "first_occurrence", {"score": score, "window_start": now, "count": 1, "similar_count": 0}

    # Within window — check for escalation. in_window being True guarantees
    # prior is not None (see the and-chain above), which mypy can't infer.
    assert prior is not None
    prior_score = prior["score"]
    if score >= prior_score * (1.0 + SCORE_ESCALATION_DELTA):
        logger.info(
            "Score escalation for %s/%s: %.3f -> %.3f (delta %.1f%%)",
            entity, job_id, prior_score, score,
            (score / prior_score - 1.0) * 100,
        )
        state[key] = {
            "score": score,
            "window_start": prior["window_start"],
            "count": prior["count"] + 1,
            "similar_count": prior.get("similar_count", 0),
        }
        return True, "escalation", state[key]

    # Cluster — suppress but track count
    prior["count"] += 1
    prior["similar_count"] = prior.get("similar_count", 0) + 1
    return False, "clustered", prior


# ---------------------------------------------------------------------------
# Core filter pipeline
# ---------------------------------------------------------------------------

def filter_alert(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    dedup_state: dict[tuple[str, str], dict[str, Any]] | None = None,
    evaluation_time: datetime | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Run the full filtering pipeline for a single alert.

    Steps:
      1. Allowlist dampening (benign_lists)
      2. Adaptive threshold gate
      3. Dedup / escalation check

    Returns (push_flag, filter_trace).  The filter_trace is attached to the
    alert before forwarding to Agent 6's enrichment stage.
    """
    process_name: str = alert.get("process_name", alert.get("process.name", ""))
    job_id: str = alert.get("job_id", "")
    entity: str = alert.get("entity", alert.get("host.name", ""))
    raw_score: float = float(alert.get("score", 0.0))

    # --- Step 1: Allowlist dampening ---
    dampened_score, al_trace = allowlist_mgr.apply(process_name, raw_score)

    # --- Step 2: Adaptive threshold ---
    effective_threshold, threshold_components = compute_effective_threshold(
        job_id=job_id,
        entity=entity,
        raw_score=dampened_score,
        threshold_cfg=threshold_cfg,
        evaluation_time=evaluation_time,
    )

    above_threshold = dampened_score >= effective_threshold

    if not above_threshold:
        trace = _build_trace(
            al_trace=al_trace,
            raw_score=raw_score,
            dampened_score=dampened_score,
            threshold_used=effective_threshold,
            threshold_components=threshold_components,
            dedup_status="n/a",
            final_decision="dropped_below_threshold",
        )
        return False, trace

    # --- Step 3: Dedup ---
    alert_with_score = dict(alert)
    alert_with_score["score"] = dampened_score
    should_push, dedup_status, _ = dedup_filter(alert_with_score, dedup_state)

    # Attach similar_count for clustered representative
    if dedup_status == "first_occurrence" and dedup_state is not None:
        key = dedup_key(entity, job_id)
        similar = dedup_state.get(key, {}).get("similar_count", 0)
        if similar > 0:
            alert["similar_count"] = similar

    decision = "push" if should_push else "dropped_dedup"
    trace = _build_trace(
        al_trace=al_trace,
        raw_score=raw_score,
        dampened_score=dampened_score,
        threshold_used=effective_threshold,
        threshold_components=threshold_components,
        dedup_status=dedup_status,
        final_decision=decision,
    )
    return should_push, trace


def _build_trace(
    al_trace: dict[str, Any],
    raw_score: float,
    dampened_score: float,
    threshold_used: float,
    threshold_components: dict[str, Any],
    dedup_status: str,
    final_decision: str,
) -> dict[str, Any]:
    """Assemble the filter_trace dict attached to every processed alert."""
    return {
        "filter_trace": {
            "allowlist_checked": al_trace.get("allowlist_checked", True),
            "allowlist_match": al_trace.get("allowlist_match"),
            "dampening_applied": al_trace.get("dampening_applied", 1.0),
            "lolbin_protected": al_trace.get("lolbin_protected", False),
            "original_score": raw_score,
            "dampened_score": dampened_score,
            "threshold_used": threshold_used,
            "threshold_components": threshold_components,
            "dedup_status": dedup_status,
            "final_decision": final_decision,
        }
    }


def should_push(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    dedup_state: dict[tuple[str, str], dict[str, Any]] | None = None,
    evaluation_time: datetime | None = None,
) -> tuple[bool, dict[str, Any]]:
    """Public entry-point: decide whether an alert should be pushed.

    Returns (push_flag, enriched_alert) where enriched_alert has the
    filter_trace field attached.  Callers should forward enriched_alert
    to Agent 6's bulk-push pipeline.
    """
    push_flag, trace = filter_alert(
        alert=alert,
        allowlist_mgr=allowlist_mgr,
        threshold_cfg=threshold_cfg,
        dedup_state=dedup_state,
        evaluation_time=evaluation_time,
    )
    enriched = dict(alert)
    enriched.update(trace)
    return push_flag, enriched


def is_benign(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    evaluation_time: datetime | None = None,
) -> bool:
    """Convenience check: return True only if an alert is definitively benign.

    An alert is benign when dampened score falls below threshold AND the
    process is not LOLBin-protected.  Callers that need the full trace
    should use should_push() instead.
    """
    process_name: str = alert.get("process_name", alert.get("process.name", ""))
    raw_score: float = float(alert.get("score", 0.0))
    job_id: str = alert.get("job_id", "")
    entity: str = alert.get("entity", alert.get("host.name", ""))

    dampened, al_trace = allowlist_mgr.apply(process_name, raw_score)
    if al_trace.get("lolbin_protected"):
        return False

    effective, _ = compute_effective_threshold(
        job_id=job_id,
        entity=entity,
        raw_score=dampened,
        threshold_cfg=threshold_cfg,
        evaluation_time=evaluation_time,
    )
    return dampened < effective


# ===========================================================================
# AGENT 6 SECTION: Enrichment, Push, Health
# ===========================================================================

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAPPINGS_DIR = Path(__file__).parent / "mappings"
ATTACK_MAPPING_PATH = MAPPINGS_DIR / "attack_mapping.json"

KILL_CHAIN_PHASE_ORDER: dict[str, int] = {
    "reconnaissance": 1,
    "resource_development": 2,
    "initial_access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 7,
    "credential_access": 8,
    "discovery": 9,
    "lateral_movement": 10,
    "collection": 11,
    "command_and_control": 12,
    "exfiltration": 13,
    "impact": 14,
}

INVESTIGATION_TEMPLATES: dict[str, list[str]] = {
    "T1059": [
        "Review full command line arguments for the flagged process",
        "Check parent process — is this expected to spawn {process_name}?",
        "Look for similar commands on peer hosts in the same timeframe",
    ],
    "T1036": [
        "Compare process binary path against known-good baseline",
        "Verify digital signature of the executable if present",
        "Check process start time relative to recent deployments",
    ],
    "T1071": [
        "Inspect full network flow for the destination IP and port",
        "Check if the destination resolves to a known CDN or internal service",
        "Correlate with DNS lookups just prior to the connection",
    ],
    "T1048": [
        "Inspect data volume transferred — large transfers are high-risk",
        "Identify the protocol used and whether encryption was applied",
        "Determine the destination ownership (ASN lookup)",
    ],
    "T1078": [
        "Verify the login source IP with the user or their team",
        "Check if MFA was used for this authentication",
        "Review user login history for the past 30 days",
    ],
    "T1548": [
        "Confirm the sudo command run and whether it matches job duties",
        "Check sudoers configuration for unexpected NOPASSWD rules",
        "Review recent changes to /etc/sudoers or /etc/sudoers.d/",
    ],
    "T1082": [
        "Identify the user context running discovery commands",
        "Look for rapid sequential discovery commands — indicates reconnaissance",
        "Correlate with outbound connections immediately after discovery",
    ],
    "T1016": [
        "Check if network enumeration was followed by lateral movement",
        "Identify the initiating process parent tree",
        "Review firewall rule changes around the same time",
    ],
    "T1049": [
        "Assess whether discovered connections were then contacted externally",
        "Correlate process.name with known attacker tooling",
        "Review /proc/net/tcp for any unusual socket states",
    ],
    "T1057": [
        "Determine if process enumeration preceded privilege escalation attempts",
        "Check for enumeration of security tools (av, edr, siem processes)",
        "Look for similar ps/top patterns on adjacent hosts",
    ],
    "T1033": [
        "Verify whether the running user has anomalous group memberships",
        "Check if user enumeration preceded an account creation event",
        "Review /etc/passwd modifications in the surrounding time window",
    ],
    "T1588": [
        "Identify which compiler was invoked and what source file was compiled",
        "Check the output binary path and subsequent execution",
        "Review development environment policy — is compilation expected here?",
    ],
    "T1027": [
        "Inspect base64 or encoded strings in the command arguments",
        "Run static analysis on any dropped binaries",
        "Check for recent writes to temp directories",
    ],
    "T1571": [
        "Verify whether the non-standard port is part of any known service",
        "Correlate with firewall rule modifications",
        "Check destination IP reputation and geolocation",
    ],
    "T1136": [
        "Identify which account was created and by whom",
        "Check for immediate privilege grants to the new account",
        "Review PAM and /var/log/auth.log around the creation time",
    ],
    "T1087": [
        "Determine if account enumeration preceded privilege escalation",
        "Check LDAP or NIS queries if present",
        "Look for enumeration of service accounts specifically",
    ],
}

DEFAULT_NEXT_STEPS: list[str] = [
    "Review process and network activity on the affected host",
    "Check endpoint logs around the anomaly timestamp",
    "Correlate with other alerts for the same entity",
]


# ---------------------------------------------------------------------------
# ATT&CK mapping loader
# ---------------------------------------------------------------------------

def load_attack_mapping() -> dict[str, Any]:
    """
    Load the MITRE ATT&CK job-to-technique mapping from disk.

    Returns an empty dict if the mapping file cannot be read.
    """
    try:
        with ATTACK_MAPPING_PATH.open() as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Could not load ATT&CK mapping from %s: %s", ATTACK_MAPPING_PATH, exc)
        return {}


_ATTACK_MAPPING: dict[str, Any] = {}


def _get_attack_mapping() -> dict[str, Any]:
    """Return the cached ATT&CK mapping, loading it on first access."""
    global _ATTACK_MAPPING
    if not _ATTACK_MAPPING:
        _ATTACK_MAPPING = load_attack_mapping()
    return _ATTACK_MAPPING


# ---------------------------------------------------------------------------
# MITRE enrichment
# ---------------------------------------------------------------------------

def map_mitre_fields(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Add MITRE ATT&CK technique fields to an anomaly document.

    Looks up the job_id in attack_mapping.json and injects:
      - mitre_tactic
      - mitre_technique_id
      - mitre_technique_name
      - mitre_techniques  (full list)
      - kill_chain_phase
      - kill_chain_phase_order

    ATT&CK: technique IDs are derived from the job mapping.
    """
    job_id = anomaly.get("job_id", "")
    mapping = _get_attack_mapping()

    job_entry = mapping.get(job_id, {})
    techniques: list[dict[str, str]] = job_entry.get("techniques", [])
    phase: str = job_entry.get("kill_chain_phase", "")

    if techniques:
        primary = techniques[0]
        anomaly["mitre_tactic"] = primary.get("tactic", "")
        anomaly["mitre_technique_id"] = primary.get("id", "")
        anomaly["mitre_technique_name"] = primary.get("name", "")
    else:
        anomaly.setdefault("mitre_tactic", "")
        anomaly.setdefault("mitre_technique_id", "")
        anomaly.setdefault("mitre_technique_name", "")

    anomaly["mitre_techniques"] = techniques
    anomaly["kill_chain_phase"] = phase
    anomaly["kill_chain_phase_order"] = KILL_CHAIN_PHASE_ORDER.get(phase, 0)
    return anomaly


def enrich_anomaly(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Apply all enrichment passes to a single anomaly document.

    Runs MITRE mapping and assigns a correlation_id if not already set.
    """
    anomaly = map_mitre_fields(anomaly)
    anomaly.setdefault("correlation_id", str(uuid.uuid4()))
    anomaly.setdefault("pushed_at", datetime.now(tz=timezone.utc).isoformat())
    return anomaly


def enrich_batch(anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich a list of anomaly documents in-place.

    Returns the same list with enrichment fields added to every element.
    """
    return [enrich_anomaly(a) for a in anomalies]


# ---------------------------------------------------------------------------
# Context enrichment
# ---------------------------------------------------------------------------

def _build_next_steps(techniques: list[dict[str, str]], anomaly: dict[str, Any]) -> list[str]:
    """Build templated investigation hints from technique IDs."""
    steps: list[str] = []
    process_name = anomaly.get("process.name", anomaly.get("entity_value", "unknown"))
    for tech in techniques:
        tech_id = tech.get("id", "")
        templates = INVESTIGATION_TEMPLATES.get(tech_id, DEFAULT_NEXT_STEPS)
        for tpl in templates:
            steps.append(tpl.format(process_name=process_name))
    if not steps:
        steps = list(DEFAULT_NEXT_STEPS)
    return steps


def add_context_placeholders(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Attach a context sub-document to an anomaly with investigation hints.

    Fields that require a live ES query (entity_anomaly_count_7d, score_percentile)
    are set to sentinel values here; use enrich_with_context for live data.
    """
    techniques = anomaly.get("mitre_techniques", [])
    anomaly["context"] = {
        "entity_anomaly_count_7d": -1,
        "entity_anomaly_trend": "unknown",
        "score_percentile": -1.0,
        "score_percentile_label": "unknown",
        "source_es_doc_ids": anomaly.get("source_doc_ids", []),
        "source_index": anomaly.get("source_index", ""),
        "recommended_next_steps": _build_next_steps(techniques, anomaly),
    }
    return anomaly


def enrich_with_context(anomaly: dict[str, Any], es: Any) -> dict[str, Any]:
    """
    Add live investigation context to an anomaly before push.

    Queries Elasticsearch for:
    - entity anomaly count over past 7 days
    - score percentile relative to the same job

    Falls back to placeholder values if ES is unavailable.

    ATT&CK: N/A (operational enrichment)
    """
    anomaly = add_context_placeholders(anomaly)

    entity = anomaly.get("entity_value", "")
    job_id = anomaly.get("job_id", "")
    score = float(anomaly.get("anomaly_score", anomaly.get("record_score", 0.0)))

    try:
        count_7d = _count_recent_anomalies(es, entity, job_id, days=7)
        anomaly["context"]["entity_anomaly_count_7d"] = count_7d
        anomaly["context"]["entity_anomaly_trend"] = _compute_trend(es, entity, job_id)

        pct = _compute_percentile(es, score, job_id)
        anomaly["context"]["score_percentile"] = pct
        anomaly["context"]["score_percentile_label"] = _percentile_label(pct)
    except Exception as exc:
        logger.warning("Context enrichment partial failure for entity=%s: %s", entity, exc)

    return anomaly


def _count_recent_anomalies(es: Any, entity: str, job_id: str, days: int) -> int:
    """Query ES for the anomaly count for an entity over the past N days."""
    query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"term": {"entity_value": entity}},
                {"term": {"job_id": job_id}},
                {"range": {"timestamp": {"gte": f"now-{days}d/d"}}},
            ]
        }
    }
    result = es.count(index="ml-anomalies-custom-*", query=query)
    return int(result.get("count", 0))


def _compute_trend(es: Any, entity: str, job_id: str) -> str:
    """
    Compute whether the entity's anomaly rate is increasing, stable, or decreasing.

    Compares the last 7 days vs the preceding 7 days.
    """
    recent = _count_recent_anomalies(es, entity, job_id, days=7)
    prior_query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"term": {"entity_value": entity}},
                {"term": {"job_id": job_id}},
                {"range": {"timestamp": {"gte": "now-14d/d", "lt": "now-7d/d"}}},
            ]
        }
    }
    result = es.count(index="ml-anomalies-custom-*", query=prior_query)
    prior = int(result.get("count", 0))

    if prior == 0:
        return "increasing" if recent > 0 else "stable"
    ratio = recent / prior
    if ratio > 1.2:
        return "increasing"
    if ratio < 0.8:
        return "decreasing"
    return "stable"


def _compute_percentile(es: Any, score: float, job_id: str) -> float:
    """
    Estimate the score percentile relative to all anomalies for the same job.

    Returns a value in [0.0, 100.0].
    """
    count_below_query: dict[str, Any] = {
        "bool": {
            "filter": [
                {"term": {"job_id": job_id}},
                {"range": {"anomaly_score": {"lt": score}}},
            ]
        }
    }
    total_query: dict[str, Any] = {"term": {"job_id": job_id}}
    below = int(es.count(index="ml-anomalies-custom-*", query=count_below_query).get("count", 0))
    total = int(es.count(index="ml-anomalies-custom-*", query=total_query).get("count", 1))
    if total == 0:
        return 0.0
    return round((below / total) * 100.0, 1)


def _percentile_label(percentile: float) -> str:
    """Convert a numeric percentile to a human-readable label."""
    if percentile >= 99.0:
        return "top 1%"
    if percentile >= 98.0:
        return "top 2%"
    if percentile >= 95.0:
        return "top 5%"
    if percentile >= 90.0:
        return "top 10%"
    if percentile >= 75.0:
        return "top 25%"
    return f"top {round(100.0 - percentile)}%"


# ---------------------------------------------------------------------------
# Push / bulk-index functions
# ---------------------------------------------------------------------------

ANOMALIES_INDEX = "ml-anomalies-custom"
CORRELATED_INDEX = "ml-anomalies-correlated"
PUSH_BUFFER_PATH = Path("results/push_buffer.jsonl")


def push_anomaly(es: Any, anomaly: dict[str, Any]) -> bool:
    """
    Index a single enriched anomaly document into Elasticsearch.

    Returns True on success.
    """
    doc_id = anomaly.get("anomaly_id", str(uuid.uuid4()))
    try:
        es.index(index=ANOMALIES_INDEX, id=doc_id, document=anomaly)
        logger.debug("Indexed anomaly %s", doc_id)
        return True
    except Exception as exc:
        logger.error("Failed to index anomaly %s: %s", doc_id, exc)
        return False


def bulk_index_anomalies(es: Any, anomalies: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Bulk-index a list of enriched anomaly documents.

    Returns (success_count, failure_count).
    """
    if not anomalies:
        return 0, 0

    try:
        from elasticsearch.helpers import bulk as es_bulk
    except ImportError:
        # Fallback: index one by one
        success = sum(1 for a in anomalies if push_anomaly(es, a))
        return success, len(anomalies) - success

    actions = [
        {
            "_index": ANOMALIES_INDEX,
            "_id": a.get("anomaly_id", str(uuid.uuid4())),
            "_source": a,
        }
        for a in anomalies
    ]
    try:
        ok, errors = es_bulk(es, actions, raise_on_error=False)
        failure_count = len(errors) if isinstance(errors, list) else 0
        return ok, failure_count
    except Exception as exc:
        logger.error("Bulk index failed: %s", exc)
        return 0, len(anomalies)


def index_correlation_chain(es: Any, chain: dict[str, Any]) -> bool:
    """
    Index a correlated attack chain document into Elasticsearch.

    Returns True on success.
    """
    chain_id = chain.get("chain_id", str(uuid.uuid4()))
    try:
        es.index(index=CORRELATED_INDEX, id=chain_id, document=chain)
        logger.debug("Indexed correlation chain %s", chain_id)
        return True
    except Exception as exc:
        logger.error("Failed to index correlation chain %s: %s", chain_id, exc)
        return False


def push_to_buffer(anomaly: dict[str, Any]) -> None:
    """
    Append an anomaly document to the local push buffer file.

    Used when the circuit breaker is open and ES is unavailable.
    """
    PUSH_BUFFER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PUSH_BUFFER_PATH.open("a") as f:
        f.write(json.dumps(anomaly) + "\n")
    logger.debug("Buffered anomaly %s locally", anomaly.get("anomaly_id", ""))


def flush_push_buffer(es: Any) -> tuple[int, int]:
    """
    Attempt to push all locally buffered anomalies to Elasticsearch.

    Returns (success_count, failure_count). Removes the buffer on full success.
    """
    if not PUSH_BUFFER_PATH.exists():
        return 0, 0

    buffered: list[dict[str, Any]] = []
    with PUSH_BUFFER_PATH.open() as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    buffered.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not buffered:
        return 0, 0

    ok, fail = bulk_index_anomalies(es, buffered)
    logger.info("Flushed buffer: %d ok, %d failed", ok, fail)
    if fail == 0:
        PUSH_BUFFER_PATH.unlink(missing_ok=True)
    return ok, fail


# ---------------------------------------------------------------------------
# Health & metrics functions
# ---------------------------------------------------------------------------

HEALTH_FILE_PATH = Path("results/health.json")


def health_write(metrics: dict[str, Any]) -> None:
    """
    Write the current service health metrics to disk as JSON.

    The health file is read by monitoring systems and the circuit breaker.
    """
    HEALTH_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    metrics["written_at"] = datetime.now(tz=timezone.utc).isoformat()
    with HEALTH_FILE_PATH.open("w") as f:
        json.dump(metrics, f, indent=2)


def health_read() -> dict[str, Any]:
    """
    Read and return the last written health metrics dict.

    Returns an empty dict if the file does not exist.
    """
    if not HEALTH_FILE_PATH.exists():
        return {}
    try:
        with HEALTH_FILE_PATH.open() as f:
            return json.load(f)
    except Exception:
        return {}


def metrics_build(
    last_run_ts: str,
    run_duration_sec: float,
    push_success: int,
    push_failure: int,
    correlation_chains: int,
    es_healthy: bool,
    model_versions: dict[str, str],
    uptime_hours: float,
) -> dict[str, Any]:
    """
    Assemble a health metrics dictionary for writing or logging.

    All parameters correspond directly to health file fields.
    """
    return {
        "last_detection_run": last_run_ts,
        "last_detection_duration_sec": run_duration_sec,
        "last_push_success_count": push_success,
        "last_push_failure_count": push_failure,
        "last_correlation_chains": correlation_chains,
        "es_connection_healthy": es_healthy,
        "model_versions": model_versions,
        "uptime_hours": round(uptime_hours, 2),
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

RESULTS_GLOB = "results/ml_only_anomalies_*.json"


def _load_env() -> None:
    """Load .env file into os.environ for ES credentials."""
    env_path = Path(__file__).parent / ".env"
    try:
        from dotenv import load_dotenv
        load_dotenv(env_path, override=True)
    except ImportError:
        if env_path.exists():
            with env_path.open() as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, val = line.split("=", 1)
                    os.environ[key.strip()] = val.strip().strip('"').strip("'")


def _connect_es(force: bool = False) -> Any:
    """Create an Elasticsearch client from environment variables.

    Returns an Elasticsearch instance or None on failure.
    """
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        logger.error("elasticsearch-py package not installed")
        return None

    host = os.environ.get("ES_HOST", "https://localhost:9200")
    username = os.environ.get("ES_USERNAME", "")
    password = os.environ.get("ES_PASSWORD", "")
    timeout = int(os.environ.get("ES_TIMEOUT", "60"))

    kwargs: dict[str, Any] = {
        "hosts": [host],
        "timeout": timeout,
        "max_retries": 3,
        "retry_on_timeout": True,
        **es_tls_kwargs(),
    }
    if username and password:
        kwargs["basic_auth"] = (username, password)

    es = Elasticsearch(**kwargs)
    try:
        if es.ping():
            logger.info("Connected to Elasticsearch at %s", host)
            return es
        elif force:
            logger.warning("ES ping failed but --force-push set; returning client")
            return es
        else:
            logger.error("Elasticsearch ping failed at %s. %s", host, diagnose_connection_failure(es) or "")
            return None
    except Exception as exc:
        if force:
            logger.warning("ES ping raised %s but --force-push set", exc)
            return es
        logger.error("ES connection error: %s", exc)
        return None


def _normalize_timestamp(raw: str) -> str:
    """Convert a timestamp string to ISO 8601 format for Elasticsearch.

    Handles space-separated datetime and nanosecond precision.
    """
    if not raw:
        return datetime.now(tz=timezone.utc).isoformat()
    # Replace space between date and time with 'T'
    normalized = raw.replace(" ", "T", 1)
    # Truncate nanoseconds to microseconds (max 6 decimal digits before timezone)
    match = re.match(r"(.*\.\d{6})\d*([\+\-Z].*)", normalized)
    if match:
        normalized = match.group(1) + match.group(2)
    return normalized


_JOB_BY_FIELD: dict[str, str] = {
    "v3_linux_anomalous_process_all_hosts": "process.name",
    "v3_rare_process_by_host_linux": "process.name",
    "v3_linux_anomalous_network_activity": "destination.ip",
    "v3_linux_anomalous_network_port_activity": "destination.port",
    "v3_linux_anomalous_user_name": "user.name",
    "v3_linux_rare_sudo_user": "user.name",
    "v3_linux_rare_user_compiler": "user.name",
    "v3_linux_network_configuration_discovery": "process.name",
    "v3_linux_network_connection_discovery": "process.name",
    "v3_linux_system_information_discovery": "process.name",
    "v3_linux_system_process_discovery": "process.name",
    "v3_linux_system_user_discovery": "process.name",
    "v3_linux_rare_metadata_process": "process.name",
    "v3_linux_rare_metadata_user": "user.name",
    "v3_linux_auth_rare_source_ip": "source.ip",
    "v3_linux_auth_high_count_logon_fails": "user.name",
    "v3_linux_auth_rare_user": "user.name",
    "v3_linux_auth_rare_hour": "user.name",
    "v3_linux_anomalous_host_activity": "host.hostname",
    "v3_linux_host_user_deviation": "host.hostname",
}

_JOB_FUNCTION: dict[str, str] = {
    "v3_linux_anomalous_process_all_hosts": "rare",
    "v3_rare_process_by_host_linux": "rare",
    "v3_linux_anomalous_network_activity": "rare",
    "v3_linux_anomalous_network_port_activity": "rare",
    "v3_linux_anomalous_user_name": "rare",
    "v3_linux_rare_sudo_user": "rare",
    "v3_linux_rare_user_compiler": "rare",
    "v3_linux_network_configuration_discovery": "rare",
    "v3_linux_network_connection_discovery": "rare",
    "v3_linux_system_information_discovery": "rare",
    "v3_linux_system_process_discovery": "rare",
    "v3_linux_system_user_discovery": "rare",
    "v3_linux_rare_metadata_process": "rare",
    "v3_linux_rare_metadata_user": "rare",
    "v3_linux_auth_rare_source_ip": "rare",
    "v3_linux_auth_high_count_logon_fails": "high_non_zero_count",
    "v3_linux_auth_rare_user": "rare",
    "v3_linux_auth_rare_hour": "rare",
    "v3_linux_anomalous_host_activity": "rare",
    "v3_linux_host_user_deviation": "rare",
}

DETECTION_BUCKET_SPAN: int = 300


def _is_valid_process_name(val: Any) -> bool:
    """Reject pure-numeric or 1-char process tokens.

    Mirrors the upstream validator in `anomaly_detector.py`. Kept here
    as defence-in-depth so malformed tokens never survive into a pushed
    doc even if the detector's validator is bypassed.
    """
    if val is None:
        return False
    s = str(val).strip()
    if not s:
        return False
    if len(s) < 2:
        return False
    if s.isdigit():
        return False
    return True


def _build_es_doc(job_name: str, anomaly: dict[str, Any]) -> dict[str, Any]:
    """Build an Elasticsearch document from a raw anomaly dict.

    Normalizes field names to match the .ml-anomalies-custom index schema,
    including native ML fields (result_type, by_field_name, bucket_span)
    required by the Kibana Anomaly Explorer.
    """
    entity = anomaly.get("entity", {})
    if isinstance(entity, dict):
        entity_value = entity.get("host", entity.get("process", entity.get("user", "")))
        host_name = entity.get("host", "")
        process_name = entity.get("process", "")
        user_name = entity.get("user", "")
    else:
        entity_value = str(entity)
        host_name = entity_value
        process_name = ""
        user_name = ""

    # Final defence against tokenisation artefacts. If the upstream
    # fallback did not fire, neutralise invalid process tokens here
    # so they do not become alert identities downstream.
    process_name_original = process_name
    if process_name and not _is_valid_process_name(process_name):
        process_name = "invalid-process"

    # Raw model score in [0, 1]. Preserve this as the canonical source
    # of truth so downstream tuning never has to reverse the * 100 scale.
    raw_score = float(anomaly.get("raw_ml_score",
                                  anomaly.get("ml_score",
                                              anomaly.get("anomaly_score", 0.0))))
    # Clamp to [0, 1] so a malformed upstream value cannot escape.
    raw_score = max(0.0, min(1.0, raw_score))
    threshold = float(anomaly.get("threshold_used", 0.0))

    # The promoted/display score is in [0, 100]. It is allowed to be
    # saturated at 100 for genuine high-severity anomalies, but callers
    # that want to filter by real rarity should key off `raw_ml_score`.
    record_score = raw_score * 100.0

    by_field_name = _JOB_BY_FIELD.get(job_name, "process.name")
    function_name = _JOB_FUNCTION.get(job_name, "rare")

    doc: dict[str, Any] = {
        # --- Native ML Anomaly Explorer fields ---
        "result_type": "record",
        "by_field_name": by_field_name,
        "by_field_value": entity_value,
        "function": function_name,
        "function_description": function_name,
        "bucket_span": DETECTION_BUCKET_SPAN,
        "detector_index": 0,
        "is_interim": False,
        "probability": max(1e-10, 1.0 - raw_score),
        "initial_record_score": record_score,
        "typical": [0.0],
        "actual": [float(anomaly.get("event_count", 1))],
        # --- Custom fields ---
        "anomaly_id": str(uuid.uuid4()),
        "job_id": job_name,
        # Store the detection bucket time in `timestamp` (the real date field
        # in .ml-anomalies-custom-* indices; `@timestamp` in these indices is
        # an ALIAS to this field, so writing to it would be rejected).
        # Override the bucket value with "now" so the Kibana rule's
        # `now-360s..now` window (which scans `@timestamp` -> `timestamp`)
        # picks up every freshly pushed doc and promotes it to a signal.
        # The original detection time is preserved in `detection_bucket_time`
        # for analytics/pivots that need it.
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "detection_bucket_time": _normalize_timestamp(
            anomaly.get("timestamp", datetime.now(tz=timezone.utc).isoformat())
        ),
        "anomaly_score": record_score,
        "record_score": record_score,
        # Canonical 0-1 raw model output. New Kibana rule thresholds on this.
        "raw_ml_score": raw_score,
        # Back-compat aliases: `ml_score` and `score` remain in [0, 1].
        "ml_score": raw_score,
        "score": raw_score,
        # Document format version so downstream can detect the new contract.
        "score_contract_version": 2,
        "confidence": float(anomaly.get("confidence", 0.0)),
        "threshold_used": threshold,
        "detection_method": anomaly.get("detection_method", "machine_learning"),
        "ml_methods": anomaly.get("ml_methods", ""),
        "entity_value": entity_value,
        "entity": entity_value,
        "host.name": host_name,
        "process.name": process_name,
        "process_name": process_name,
        "process_name_original": process_name_original,
        "user.name": user_name,
        "description": anomaly.get("description", ""),
        "event_count": int(anomaly.get("event_count", 1)),
        "is_anomalous": True,
        "pushed_at": datetime.now(tz=timezone.utc).isoformat(),
    }

    # Carry over context block if present - serialize to JSON string for ES compatibility
    if "context" in anomaly:
        ctx = anomaly["context"]
        doc["context"] = json.dumps(ctx, default=str) if isinstance(ctx, dict) else str(ctx)

    # Carry over ml_score_details if present - serialize for ES compatibility
    if "ml_score_details" in anomaly:
        details = anomaly["ml_score_details"]
        doc["ml_score_details"] = json.dumps(details, default=str) if isinstance(details, dict) else str(details)

    return doc


def main() -> None:
    """CLI entry point: collect anomaly files, enrich, filter, and push to ES."""
    parser = argparse.ArgumentParser(
        description="Push ML anomalies to Elasticsearch"
    )
    parser.add_argument(
        "--force-push", action="store_true",
        help="Attempt push even if ES ping fails",
    )
    parser.add_argument(
        "--cleanup", action="store_true",
        help="Remove input anomaly files after a fully successful push",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Prepare docs but do not push to ES",
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
        force=True,
    )

    _load_env()

    # Collect anomaly files
    files = sorted(glob.glob(RESULTS_GLOB))
    if not files:
        logger.warning("No ml-only anomaly files found matching %s", RESULTS_GLOB)
        return

    logger.info("Found %d anomaly file(s): %s", len(files), files)

    # Connect to ES
    es = None
    if not args.dry_run:
        es = _connect_es(force=args.force_push)
        if es is None:
            logger.error("Cannot connect to Elasticsearch; aborting push")
            return

    # Load filtering infrastructure
    allowlist_mgr = AllowlistManager()
    threshold_cfg = AdaptiveThreshold()

    # Accumulate docs by target index
    index_docs: dict[str, list[dict[str, Any]]] = {}
    total_prepared = 0

    for fpath in files:
        logger.info("Loading %s", fpath)
        try:
            with open(fpath, encoding="utf-8") as fh:
                payload = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to read %s: %s; skipping", fpath, exc)
            continue

        ml_jobs = payload.get("ml_jobs", {})
        for job_name, job_obj in ml_jobs.items():
            anomalies = job_obj.get("anomalies", [])
            if not anomalies:
                continue

            index_name = f".ml-anomalies-custom-{job_name}"
            index_docs.setdefault(index_name, [])

            for raw_anomaly in anomalies:
                doc = _build_es_doc(job_name, raw_anomaly)
                # Enrich with MITRE ATT&CK fields
                doc = enrich_anomaly(doc)
                # Add context placeholders
                doc = add_context_placeholders(doc)
                index_docs[index_name].append(doc)
                total_prepared += 1

    logger.info(
        "Prepared %d documents across %d target indices",
        total_prepared, len(index_docs),
    )

    if total_prepared == 0:
        logger.warning("No anomalies found in any input file")
        return

    # Enrich with live context from ES (trend, percentile)
    if es is not None:
        # Source-index enrichment: fill process/network/auth context from raw events
        try:
            all_docs = [d for docs in index_docs.values() for d in docs]
            enrich_from_source_indices(es, all_docs, lookback_minutes=30)
        except Exception as exc:
            logger.warning("Source enrichment failed (non-fatal): %s", exc)

        for index_name, docs in index_docs.items():
            for i, doc in enumerate(docs):
                try:
                    docs[i] = enrich_with_context(doc, es)
                except Exception as exc:
                    logger.debug(
                        "Context enrichment failed for %s: %s",
                        doc.get("anomaly_id", ""),
                        exc,
                    )

    # Filter with should_push (allowlist dampening + threshold + dedup)
    total_filtered = 0
    for index_name in list(index_docs.keys()):
        original = index_docs[index_name]
        accepted: list[dict[str, Any]] = []
        for doc in original:
            push_flag, enriched_doc = should_push(
                doc, allowlist_mgr, threshold_cfg, _DEDUP_STATE,
            )
            if push_flag:
                accepted.append(enriched_doc)
            else:
                total_filtered += 1
        index_docs[index_name] = accepted

    # FP classification: only push TP and likely-TP alerts
    total_fp = 0
    for index_name in list(index_docs.keys()):
        tp_docs, fp_docs, fp_count = classify_fp_batch(index_docs[index_name])
        if fp_count > 0:
            logger.info(
                "FP filter %s: %d -> %d docs (%d FPs removed)",
                index_name, len(index_docs[index_name]), len(tp_docs), fp_count,
            )
            for fp in fp_docs[:3]:
                logger.info(
                    "  FP dropped: entity=%s proc=%s reason=%s",
                    fp.get("entity", ""), fp.get("process_name", ""),
                    fp.get("fp_classification", ""),
                )
        total_fp += fp_count
        index_docs[index_name] = tp_docs

    # Context-completeness gate: quarantine docs that still lack the
    # minimum fields their job class requires. Quarantined docs are
    # recorded under results/incomplete_context_quarantine.jsonl for
    # analyst review; they are never pushed to the signals index.
    total_quarantined = 0
    quarantine_counters: dict[str, int] = {}
    for index_name in list(index_docs.keys()):
        kept, quarantined, counters = apply_context_gate(index_docs[index_name])
        if quarantined:
            logger.info(
                "Context gate %s: quarantined %d/%d docs (%s)",
                index_name, len(quarantined),
                len(index_docs[index_name]),
                counters,
            )
        total_quarantined += len(quarantined)
        for k, v in counters.items():
            quarantine_counters[k] = quarantine_counters.get(k, 0) + v
        index_docs[index_name] = kept

    total_to_push = sum(len(docs) for docs in index_docs.values())
    logger.info(
        "After filtering: %d documents to push (%d threshold/dedup, %d FP, %d context-quarantined %s)",
        total_to_push, total_filtered, total_fp,
        total_quarantined, quarantine_counters,
    )

    if args.dry_run:
        logger.info("Dry run - not pushing to ES")
        for index_name, docs in index_docs.items():
            logger.info("  %s: %d docs", index_name, len(docs))
        return

    # Not a dry run, so the earlier `if es is None: return` guarantees a
    # live client here even though mypy can't track that across the loop.
    assert es is not None

    # Push to ES
    total_success = 0
    total_fail = 0
    all_success = True

    for index_name, docs in index_docs.items():
        if not docs:
            continue

        # Ensure target index exists
        try:
            if not es.indices.exists(index=index_name):
                es.indices.create(
                    index=index_name,
                    body={"settings": {"number_of_shards": 1}},
                )
                logger.info("Created index %s", index_name)
        except Exception as exc:
            logger.warning("Index check/create for %s: %s", index_name, exc)

        # Serialize complex object fields to JSON strings for ES mapping compatibility
        for d in docs:
            for key in ("context", "ml_score_details", "mitre_techniques", "filter_trace"):
                val = d.get(key)
                if isinstance(val, (dict, list)):
                    d[key] = json.dumps(val, default=str)

        # Per-index mapping-aware stripping.  Several `.ml-anomalies-custom-v3_*`
        # indices inherit legacy mappings where `source`, `destination`,
        # `destination.geo`, `destination.as` or `file` are declared as
        # `keyword`.  Writing a dotted-path nested structure under those parents
        # (e.g. `source.ip`, `file.name`, `destination.geo.country_name`)
        # triggers `document_parsing_exception` and ES silently drops the doc.
        # We cache the blocked dotted-prefixes per index and strip them here
        # so the remaining fields still index.  Enrichment is not lost for
        # indices whose mappings can accept these fields.
        _blocked = _get_blocked_dotted_fields(es, index_name)
        if _blocked:
            _n_stripped = 0
            for d in docs:
                for dotted_key in list(d.keys()):
                    for prefix in _blocked:
                        if dotted_key == prefix or dotted_key.startswith(prefix + "."):
                            d.pop(dotted_key, None)
                            _n_stripped += 1
                            break
            if _n_stripped:
                logger.info(
                    "Stripped %d conflicting dotted field(s) from %d docs for %s (blocked prefixes=%s)",
                    _n_stripped, len(docs), index_name, sorted(_blocked),
                )

        # Use per-job index in bulk actions
        actions = [
            {
                "_index": index_name,
                "_id": d.get("anomaly_id", str(uuid.uuid4())),
                "_source": d,
            }
            for d in docs
        ]

        try:
            from elasticsearch.helpers import bulk as es_bulk
            ok, errors = es_bulk(es, actions, raise_on_error=False)
            fail_count = len(errors) if isinstance(errors, list) else 0
            total_success += ok
            total_fail += fail_count
            if fail_count > 0:
                all_success = False
                logger.warning(
                    "Index %s: %d ok, %d failed", index_name, ok, fail_count,
                )
                for err_item in (errors if isinstance(errors, list) else [])[:3]:
                    logger.warning("  Bulk error detail: %s", err_item)
            else:
                logger.info("Index %s: %d docs pushed successfully", index_name, ok)
        except ImportError:
            # Fallback: one-by-one
            ok_count = 0
            for d in docs:
                if push_anomaly(es, d):
                    ok_count += 1
            fail_count = len(docs) - ok_count
            total_success += ok_count
            total_fail += fail_count
            if fail_count > 0:
                all_success = False
            logger.info(
                "Index %s: %d ok, %d failed (single-doc mode)",
                index_name, ok_count, fail_count,
            )
        except Exception as exc:
            logger.error("Bulk push to %s failed: %s", index_name, exc)
            total_fail += len(docs)
            all_success = False

            # Write fallback file
            fallback_path = Path("results") / f"failed_push_{index_name.replace('.', '_')}.jsonl"
            fallback_path.parent.mkdir(parents=True, exist_ok=True)
            with fallback_path.open("w") as fh:
                for d in docs:
                    fh.write(json.dumps(d, default=str) + "\n")
            logger.info("Wrote fallback file %s", fallback_path)

    logger.info(
        "Push complete: %d success, %d failed", total_success, total_fail,
    )

    # Cleanup input files if all pushes succeeded
    if args.cleanup and all_success and total_success > 0:
        for fpath in files:
            try:
                os.unlink(fpath)
                logger.info("Cleaned up input file %s", fpath)
            except OSError as exc:
                logger.warning("Failed to cleanup %s: %s", fpath, exc)
    elif args.cleanup and not all_success:
        logger.warning("Not all pushes succeeded; skipping cleanup of input files")

    # Write health metrics
    health_write(
        metrics_build(
            last_run_ts=datetime.now(tz=timezone.utc).isoformat(),
            run_duration_sec=0.0,
            push_success=total_success,
            push_failure=total_fail,
            correlation_chains=0,
            es_healthy=es is not None,
            model_versions={},
            uptime_hours=0.0,
        )
    )


if __name__ == "__main__":
    main()
