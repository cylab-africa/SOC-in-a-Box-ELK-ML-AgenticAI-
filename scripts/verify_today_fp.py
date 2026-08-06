"""One-shot: pull today's `ML Anomaly High Score` signals from Kibana's
alerts index and replay them through the pipeline FP classifier so we
can see, per alert, whether it is TP or FP.

Output:
    results/siem_audit/today_fp_verdict_<utcstamp>.json
    stdout   - per-signal verdict + aggregate TP/FP counts
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from push_all_anomalies import (  # type: ignore
    _connect_es,
    _doc_get,
    _load_env,
    context_complete,
    is_likely_false_positive,
)

RULE_NAME = "ML Anomaly High Score"
SIGNALS_INDEX = ".internal.alerts-security.alerts-default-*"


def _today_utc_window() -> tuple[str, str]:
    now = datetime.now(tz=timezone.utc)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.isoformat(), now.isoformat()


def _scan_today(es, rule_name: str) -> list[dict]:
    ts_from, ts_to = _today_utc_window()
    body = {
        "size": 1000,
        "sort": [{"@timestamp": "desc"}, {"_doc": "asc"}],
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": ts_from, "lte": ts_to}}},
                    {"term": {"kibana.alert.rule.name": rule_name}},
                ]
            }
        },
    }
    out: list[dict] = []
    last_sort = None
    while True:
        if last_sort is not None:
            body["search_after"] = last_sort
        resp = es.search(index=SIGNALS_INDEX, body=body)
        hits = (resp.get("hits") or {}).get("hits") or []
        if not hits:
            break
        for h in hits:
            src = h.get("_source", {}) or {}
            src["_es_id"] = h.get("_id")
            src["_es_index"] = h.get("_index")
            out.append(src)
        last_sort = hits[-1].get("sort")
        if len(hits) < body["size"]:
            break
    return out


def _signal_to_doc(sig: dict) -> dict:
    """Flatten a Kibana signal into the shape is_likely_false_positive expects."""
    return {
        "anomaly_id": sig.get("_es_id"),
        "job_id": sig.get("job_id") or "",
        "host.name": _doc_get(sig, "host.name") or _doc_get(sig, "kibana.alert.host.name"),
        "user.name": _doc_get(sig, "user.name"),
        "process.name": _doc_get(sig, "process.name"),
        "process.executable": _doc_get(sig, "process.executable"),
        "process.command_line": _doc_get(sig, "process.command_line"),
        "source.ip": _doc_get(sig, "source.ip"),
        "destination.ip": _doc_get(sig, "destination.ip"),
        "destination.port": _doc_get(sig, "destination.port"),
        "file.name": _doc_get(sig, "file.name"),
        "ml_score": sig.get("ml_score"),
        "raw_ml_score": sig.get("raw_ml_score"),
        "record_score": sig.get("record_score"),
    }


def main() -> int:
    _load_env()
    es = _connect_es(force=False)
    if es is None:
        print("ERROR: no ES connection", file=sys.stderr)
        return 2

    sigs = _scan_today(es, RULE_NAME)
    print(f"[verify] pulled {len(sigs)} signals for rule={RULE_NAME!r} today UTC")

    verdicts: list[dict] = []
    tp = fp = 0
    ctx_incomplete = 0
    fp_reason_ctr: Counter[str] = Counter()
    tp_cluster_ctr: Counter[tuple[str, str, str, str]] = Counter()

    for s in sigs:
        d = _signal_to_doc(s)
        is_fp, reason = is_likely_false_positive(d)
        ctx_ok, ctx_reason = context_complete(d)
        if is_fp:
            fp += 1
            fp_reason_ctr[reason] += 1
        else:
            tp += 1
            tp_cluster_ctr[
                (
                    str(d.get("job_id", "")),
                    str(d.get("process.name") or ""),
                    str(d.get("user.name") or ""),
                    str(d.get("host.name") or ""),
                )
            ] += 1
        if not ctx_ok:
            ctx_incomplete += 1

        verdicts.append(
            {
                "signal_id": s.get("_es_id"),
                "ts": s.get("@timestamp"),
                "job_id": d["job_id"],
                "host.name": d["host.name"],
                "user.name": d["user.name"],
                "process.name": d["process.name"],
                "command_80": (str(d.get("process.command_line") or ""))[:80],
                "source.ip": d["source.ip"],
                "destination.ip": d["destination.ip"],
                "record_score": d["record_score"],
                "verdict": "FP" if is_fp else "non_FP",
                "fp_reason": reason,
                "ctx_ok": ctx_ok,
                "ctx_reason": ctx_reason,
            }
        )

    outdir = Path("results/siem_audit")
    outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"today_fp_verdict_{datetime.now(tz=timezone.utc):%Y%m%dT%H%M%SZ}.json"
    out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                "total": len(sigs),
                "fp": fp,
                "non_fp": tp,
                "context_incomplete": ctx_incomplete,
                "fp_reasons": fp_reason_ctr.most_common(),
                "top_non_fp_clusters": [
                    {"job_id": j, "process": p, "user": u, "host": h, "count": c}
                    for (j, p, u, h), c in tp_cluster_ctr.most_common(30)
                ],
                "verdicts": verdicts,
            },
            indent=2,
            default=str,
        )
    )

    print(f"[verify] wrote {out}")
    print(f"[verify] total={len(sigs)} FP={fp} non_FP={tp} ctx_incomplete={ctx_incomplete}")
    print("[verify] top FP reasons:")
    for r, c in fp_reason_ctr.most_common(15):
        print(f"    {c:5d}  {r}")
    print("[verify] top non-FP clusters (would still ship as alerts):")
    for (j, p, u, h), c in tp_cluster_ctr.most_common(15):
        print(f"    {c:5d}  job={j}  proc={p!r}  user={u!r}  host={h!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
