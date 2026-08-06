"""
SIEM alert loop audit bundle.

Produces a comparative, repeatable snapshot of the three stages that
generate `ML Anomaly High Score` alerts:

    1. Detection Engine rule JSON in Kibana
    2. Source anomaly docs in `.ml-anomalies-custom-*`
    3. Promoted signals in `.internal.alerts-security.alerts-default-*`

For each stage we capture the same set of quality metrics so that running
this script before and after a remediation step gives a direct diff of
what changed (alert volume, field completeness, top noisy processes,
score distribution).

Output is written under `results/siem_audit/<timestamp>/`:

    rule.json                 Detection Engine rule definition
    ml_anomalies_summary.json Source anomaly histograms, missing-rate,
                              top entities, malformed process counts
    signals_summary.json      Kibana-promoted signal counterparts
    pipeline_samples.json     Paired doc samples (source doc + signal)
    audit_manifest.json       Run metadata, scope, quick-look numbers

Usage:

    python3 scripts/siem_alert_audit.py
    python3 scripts/siem_alert_audit.py --days 7 --sample-size 20
    python3 scripts/siem_alert_audit.py --out results/siem_audit/before_fp

Designed to be safe to run from an analyst workstation: read-only ES
queries, no writes to Elasticsearch, no mutation of any alert.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("siem_audit")

# Make the parent project importable so we can reuse _connect_es and _load_env
_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

ML_ANOMALIES_INDEX = ".ml-anomalies-custom-*"
SIGNALS_INDEX = ".internal.alerts-security.alerts-default-*"
DEFAULT_RULE_NAME = "ML Anomaly High Score"

# Fields we want missing-rate for in both the source docs and the signals.
# These mirror the dashboard columns called out by the user.
_CONTEXT_FIELDS: list[str] = [
    "host.name",
    "user.name",
    "process.name",
    "process.command_line",
    "file.name",
    "source.ip",
    "destination.ip",
]

_MALFORMED_PROC_RE = re.compile(r"^\d+$|^.{1}$")


def _connect() -> Any:
    """Reuse push_all_anomalies' ES connector so env handling is consistent."""
    from push_all_anomalies import _connect_es, _load_env

    _load_env()
    es = _connect_es(force=False)
    if es is None:
        raise SystemExit("Cannot connect to Elasticsearch - check .env credentials")
    return es


def _time_range(days: int) -> tuple[str, str]:
    """Return ISO (from, to) strings for the given lookback window."""
    now = datetime.now(tz=timezone.utc)
    return (now - timedelta(days=days)).isoformat(), now.isoformat()


def _doc_get(doc: dict[str, Any], dotted: str) -> Any:
    """Read a dotted path from a doc, supporting both flat and nested keys."""
    if dotted in doc:
        return doc[dotted]
    cur: Any = doc
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _is_missing(val: Any) -> bool:
    """Standardised missing-value check shared by both stages."""
    if val is None:
        return True
    s = str(val).strip().lower()
    return s in {"", "unknown", "none", "n/a", "unknown-user", "unknown-process"}


def _field_completeness(docs: list[dict[str, Any]], fields: list[str]) -> dict[str, dict[str, Any]]:
    """Return count + missing-rate for each requested field across docs."""
    total = len(docs) or 1
    report: dict[str, dict[str, Any]] = {}
    for f in fields:
        missing = sum(1 for d in docs if _is_missing(_doc_get(d, f)))
        report[f] = {
            "present": total - missing,
            "missing": missing,
            "missing_rate": round(missing / total, 4),
        }
    return report


def _top_values(docs: list[dict[str, Any]], field: str, n: int = 10) -> list[dict[str, Any]]:
    """Top-N values for a dotted field across docs (ignores missing)."""
    ctr: Counter[str] = Counter()
    for d in docs:
        val = _doc_get(d, field)
        if _is_missing(val):
            continue
        ctr[str(val)] += 1
    return [{"value": v, "count": c} for v, c in ctr.most_common(n)]


def _score_histogram(values: list[float], bins: list[float]) -> dict[str, int]:
    """Bucketise scores into predefined bins (upper-exclusive)."""
    hist: dict[str, int] = {}
    for lo, hi in zip(bins, bins[1:]):
        label = f"{lo:.2f}-{hi:.2f}"
        hist[label] = sum(1 for v in values if lo <= v < hi)
    hist[f">= {bins[-1]:.2f}"] = sum(1 for v in values if v >= bins[-1])
    return hist


def _scan_all(
    es: Any,
    index: str,
    query: dict[str, Any],
    size: int = 2000,
    sort_field: str = "@timestamp",
    max_docs: int = 50000,
) -> list[dict[str, Any]]:
    """Pull docs using search_after pagination (avoids scroll complexity)."""
    collected: list[dict[str, Any]] = []
    body = dict(query)
    # Use a stable pair: primary time sort + _doc as tiebreak.
    body["sort"] = [{sort_field: "desc"}, {"_doc": "asc"}]
    body["size"] = size
    body["track_total_hits"] = True
    last_sort: list[Any] | None = None
    while True:
        if last_sort is not None:
            body["search_after"] = last_sort
        try:
            resp = es.search(index=index, body=body)
        except Exception as exc:
            logger.warning("Search on %s failed: %s", index, exc)
            break
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source", {}) or {}
            src.setdefault("_es_id", h.get("_id"))
            src.setdefault("_es_index", h.get("_index"))
            collected.append(src)
        last_sort = hits[-1].get("sort")
        if last_sort is None or len(hits) < size:
            break
        if len(collected) >= max_docs:
            logger.info("Reached %d-doc safety cap for %s", max_docs, index)
            break
    return collected


def _audit_rule(es: Any, rule_name: str) -> dict[str, Any]:
    """Fetch the Detection Engine rule definition via ES alert-internal index.

    The Detection Engine stores rules in `.kibana_alerting_cases*`. This
    query reads them directly without hitting the Kibana API so the
    script keeps working even if the Kibana URL is unavailable.
    """
    try:
        resp = es.search(
            index=".kibana*",
            body={
                "size": 5,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "alert"}},
                            {"match": {"alert.name": rule_name}},
                        ]
                    }
                },
            },
        )
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            return {"found": False, "rule_name": rule_name}
        first = hits[0]["_source"]
        alert = first.get("alert", {}) or {}
        params = alert.get("params", {}) or {}
        return {
            "found": True,
            "rule_name": alert.get("name", rule_name),
            "enabled": alert.get("enabled"),
            "query": params.get("query"),
            "language": params.get("language"),
            "severity": params.get("severity"),
            "risk_score": params.get("riskScore"),
            "risk_score_mapping": params.get("riskScoreMapping"),
            "severity_mapping": params.get("severityMapping"),
            "threat": params.get("threat"),
            "investigation_fields": params.get("investigationFields"),
            "required_fields": params.get("requiredFields"),
            "related_integrations": params.get("relatedIntegrations"),
            "interval": alert.get("schedule", {}).get("interval"),
            "_es_index": hits[0].get("_index"),
            "_es_id": hits[0].get("_id"),
        }
    except Exception as exc:
        return {"found": False, "rule_name": rule_name, "error": str(exc)}


def _audit_ml_anomalies(es: Any, days: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Summary of `.ml-anomalies-custom-*` docs across the lookback window."""
    ts_from, ts_to = _time_range(days)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"timestamp": {"gte": ts_from, "lte": ts_to}}},
                ]
            }
        },
        "_source": True,
    }
    docs = _scan_all(es, ML_ANOMALIES_INDEX, query, sort_field="timestamp")

    ml_scores = [
        float(d["ml_score"])
        for d in docs
        if isinstance(d.get("ml_score"), (int, float))
    ]
    record_scores = [
        float(d["record_score"])
        for d in docs
        if isinstance(d.get("record_score"), (int, float))
    ]

    malformed_proc_count = sum(
        1
        for d in docs
        if isinstance(_doc_get(d, "process.name"), str)
        and _MALFORMED_PROC_RE.match(str(_doc_get(d, "process.name")).strip())
    )

    by_job: Counter[str] = Counter()
    for d in docs:
        jid = str(_doc_get(d, "job_id") or "unknown")
        by_job[jid] += 1

    summary = {
        "scope": {"days": days, "from": ts_from, "to": ts_to, "index": ML_ANOMALIES_INDEX},
        "total_docs": len(docs),
        "by_job_id": [{"job_id": j, "count": c} for j, c in by_job.most_common(20)],
        "ml_score_histogram": _score_histogram(
            ml_scores, [0.0, 0.2, 0.4, 0.6, 0.75, 0.85, 0.95, 0.99]
        ),
        "record_score_histogram": _score_histogram(
            record_scores, [0, 20, 40, 60, 75, 85, 95, 99]
        ),
        "ml_score_stats": _stats(ml_scores),
        "record_score_stats": _stats(record_scores),
        "field_completeness": _field_completeness(docs, _CONTEXT_FIELDS),
        "top_process_name": _top_values(docs, "process.name", 20),
        "top_host_name": _top_values(docs, "host.name", 15),
        "top_user_name": _top_values(docs, "user.name", 15),
        "malformed_process_name_count": malformed_proc_count,
        "malformed_process_name_rate": round(
            malformed_proc_count / (len(docs) or 1), 4
        ),
    }
    return summary, docs


def _audit_signals(es: Any, days: int, rule_name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Summary of promoted signals in `.internal.alerts-security.alerts-default-*`."""
    ts_from, ts_to = _time_range(days)
    query = {
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": ts_from, "lte": ts_to}}},
                    {"term": {"kibana.alert.rule.name": rule_name}},
                ]
            }
        },
        "_source": True,
    }
    docs = _scan_all(es, SIGNALS_INDEX, query, sort_field="@timestamp")

    record_scores = [
        float(d["record_score"])
        for d in docs
        if isinstance(d.get("record_score"), (int, float))
    ]

    by_job: Counter[str] = Counter()
    for d in docs:
        jid = str(_doc_get(d, "job_id") or "unknown")
        by_job[jid] += 1

    reasons: Counter[str] = Counter()
    for d in docs:
        r = str(_doc_get(d, "kibana.alert.reason") or "").strip()
        if r:
            key = r[:120]
            reasons[key] += 1

    empty_user = sum(
        1 for d in docs if _is_missing(_doc_get(d, "user.name"))
    )
    malformed_proc_count = sum(
        1
        for d in docs
        if isinstance(_doc_get(d, "process.name"), str)
        and _MALFORMED_PROC_RE.match(str(_doc_get(d, "process.name")).strip())
    )

    summary = {
        "scope": {
            "days": days,
            "from": ts_from,
            "to": ts_to,
            "rule_name": rule_name,
            "index": SIGNALS_INDEX,
        },
        "total_signals": len(docs),
        "by_job_id": [{"job_id": j, "count": c} for j, c in by_job.most_common(20)],
        "field_completeness": _field_completeness(docs, _CONTEXT_FIELDS),
        "top_process_name": _top_values(docs, "process.name", 20),
        "top_host_name": _top_values(docs, "host.name", 15),
        "top_user_name": _top_values(docs, "user.name", 15),
        "record_score_histogram": _score_histogram(
            record_scores, [0, 20, 40, 60, 75, 85, 95, 99]
        ),
        "record_score_stats": _stats(record_scores),
        "top_reasons": [{"reason": r, "count": c} for r, c in reasons.most_common(15)],
        "empty_user_name": empty_user,
        "malformed_process_name_count": malformed_proc_count,
    }
    return summary, docs


def _stats(values: list[float]) -> dict[str, float]:
    """Min/max/mean/p50/p95/p99/count for a score list."""
    if not values:
        return {"count": 0}
    vs = sorted(values)
    n = len(vs)
    return {
        "count": n,
        "min": round(vs[0], 4),
        "max": round(vs[-1], 4),
        "mean": round(sum(vs) / n, 4),
        "p50": round(vs[n // 2], 4),
        "p95": round(vs[min(n - 1, int(n * 0.95))], 4),
        "p99": round(vs[min(n - 1, int(n * 0.99))], 4),
    }


def _pair_samples(
    ml_docs: list[dict[str, Any]],
    signal_docs: list[dict[str, Any]],
    n: int,
) -> list[dict[str, Any]]:
    """Pair a sample of signals with their originating ml-anomaly doc.

    Uses `kibana.alert.ancestors[].id` when available, otherwise falls
    back to matching on `(job_id, entity, timestamp)`.
    """
    by_id: dict[str, dict[str, Any]] = {
        str(d.get("_es_id") or d.get("anomaly_id")): d for d in ml_docs
    }
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for d in ml_docs:
        key = (
            str(d.get("job_id", "")),
            str(_doc_get(d, "entity") or _doc_get(d, "host.name") or ""),
            str(d.get("timestamp", ""))[:19],
        )
        by_key.setdefault(key, d)

    pairs: list[dict[str, Any]] = []
    for sig in signal_docs[:n]:
        ancestor_id = None
        ancestors = _doc_get(sig, "kibana.alert.ancestors") or []
        if isinstance(ancestors, list) and ancestors:
            ancestor_id = str(ancestors[0].get("id") or "")
        source_doc = by_id.get(ancestor_id) if ancestor_id else None
        if source_doc is None:
            key = (
                str(sig.get("job_id", "")),
                str(_doc_get(sig, "entity") or _doc_get(sig, "host.name") or ""),
                str(sig.get("@timestamp", sig.get("timestamp", "")))[:19],
            )
            source_doc = by_key.get(key)
        pairs.append(
            {
                "signal_id": sig.get("_es_id"),
                "signal_index": sig.get("_es_index"),
                "signal": {
                    "timestamp": sig.get("@timestamp"),
                    "rule": _doc_get(sig, "kibana.alert.rule.name"),
                    "severity": _doc_get(sig, "kibana.alert.severity"),
                    "risk_score": _doc_get(sig, "kibana.alert.risk_score"),
                    "reason": _doc_get(sig, "kibana.alert.reason"),
                    "host.name": _doc_get(sig, "host.name"),
                    "user.name": _doc_get(sig, "user.name"),
                    "process.name": _doc_get(sig, "process.name"),
                    "file.name": _doc_get(sig, "file.name"),
                    "source.ip": _doc_get(sig, "source.ip"),
                    "destination.ip": _doc_get(sig, "destination.ip"),
                    "ml_score": sig.get("ml_score"),
                    "record_score": sig.get("record_score"),
                    "job_id": sig.get("job_id"),
                },
                "source_doc": {
                    "id": (source_doc or {}).get("_es_id"),
                    "index": (source_doc or {}).get("_es_index"),
                    "job_id": (source_doc or {}).get("job_id"),
                    "ml_score": (source_doc or {}).get("ml_score"),
                    "record_score": (source_doc or {}).get("record_score"),
                    "host.name": _doc_get(source_doc or {}, "host.name"),
                    "process.name": _doc_get(source_doc or {}, "process.name"),
                    "user.name": _doc_get(source_doc or {}, "user.name"),
                    "file.name": _doc_get(source_doc or {}, "file.name"),
                    "source.ip": _doc_get(source_doc or {}, "source.ip"),
                    "destination.ip": _doc_get(source_doc or {}, "destination.ip"),
                }
                if source_doc
                else None,
            }
        )
    return pairs


def _quick_look(
    ml_summary: dict[str, Any], sig_summary: dict[str, Any]
) -> dict[str, Any]:
    """Headline numbers the user or a future audit script can diff in one glance."""
    return {
        "ml_anomaly_docs": ml_summary["total_docs"],
        "signals": sig_summary["total_signals"],
        "ml_score_p50": ml_summary["ml_score_stats"].get("p50"),
        "ml_score_p99": ml_summary["ml_score_stats"].get("p99"),
        "record_score_p50": sig_summary["record_score_stats"].get("p50"),
        "record_score_p99": sig_summary["record_score_stats"].get("p99"),
        "missing_rate_file_name": sig_summary["field_completeness"]
        .get("file.name", {})
        .get("missing_rate"),
        "missing_rate_source_ip": sig_summary["field_completeness"]
        .get("source.ip", {})
        .get("missing_rate"),
        "missing_rate_destination_ip": sig_summary["field_completeness"]
        .get("destination.ip", {})
        .get("missing_rate"),
        "missing_rate_user_name": sig_summary["field_completeness"]
        .get("user.name", {})
        .get("missing_rate"),
        "malformed_process_name_signals": sig_summary["malformed_process_name_count"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="SIEM alert loop audit bundle")
    parser.add_argument("--days", type=int, default=7, help="Lookback window in days")
    parser.add_argument(
        "--rule-name", default=DEFAULT_RULE_NAME, help="Detection Engine rule name"
    )
    parser.add_argument(
        "--sample-size", type=int, default=25, help="Number of paired samples"
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output directory (default: results/siem_audit/<utc-timestamp>)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )

    out_dir = Path(
        args.out
        or f"results/siem_audit/{datetime.now(tz=timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    es = _connect()

    logger.info("Auditing rule definition")
    rule = _audit_rule(es, args.rule_name)
    (out_dir / "rule.json").write_text(json.dumps(rule, indent=2, default=str))

    logger.info("Auditing source anomaly docs over last %d day(s)", args.days)
    ml_summary, ml_docs = _audit_ml_anomalies(es, args.days)
    (out_dir / "ml_anomalies_summary.json").write_text(
        json.dumps(ml_summary, indent=2, default=str)
    )

    logger.info("Auditing promoted signals over last %d day(s)", args.days)
    sig_summary, sig_docs = _audit_signals(es, args.days, args.rule_name)
    (out_dir / "signals_summary.json").write_text(
        json.dumps(sig_summary, indent=2, default=str)
    )

    logger.info("Pairing up to %d signal samples with source docs", args.sample_size)
    pairs = _pair_samples(ml_docs, sig_docs, args.sample_size)
    (out_dir / "pipeline_samples.json").write_text(
        json.dumps(pairs, indent=2, default=str)
    )

    manifest = {
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "scope_days": args.days,
        "rule_name": args.rule_name,
        "sample_size": args.sample_size,
        "output_dir": str(out_dir),
        "quick_look": _quick_look(ml_summary, sig_summary),
    }
    (out_dir / "audit_manifest.json").write_text(
        json.dumps(manifest, indent=2, default=str)
    )

    logger.info("Audit bundle written to %s", out_dir)
    logger.info("Quick look: %s", json.dumps(manifest["quick_look"], indent=2))


if __name__ == "__main__":
    main()
