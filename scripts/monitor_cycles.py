#!/usr/bin/env python3
"""
Monitor N detection cycles of the realtime_service and produce a compact
performance + quality snapshot per cycle.

Reads the live service log (default ~/logs/realtime_service.log, override
with --log), waits for
`=== Detection cycle N starting ===` markers, and for each completed
cycle captures:

    - wall-clock duration (from the completion line)
    - detection phase wall time (gap until first push marker)
    - push phase wall time
    - total docs indexed / FP dropped / quarantined / errors
    - distribution of raw_ml_score & record_score snapshot from
      results/fp_classification_trace.jsonl and
      results/incomplete_context_quarantine.jsonl snapshots after cycle
    - hits for the new remediation rules (invalid-process,
      tokenization_artifact, admin_discovery_cli, discovery_no_user,
      context gate quarantines)

Output is a JSON array at results/siem_audit/cycle_monitor_<ts>.json
and a short human summary to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

LOG = Path("~/logs/realtime_service.log").expanduser()
FP_TRACE = Path("results/fp_classification_trace.jsonl")
QUARANTINE = Path("results/incomplete_context_quarantine.jsonl")

CYCLE_START_RE = re.compile(r"=== Detection cycle (\d+) starting ===")
CYCLE_END_RE = re.compile(
    r"=== Cycle (\d+) completed in ([\d.]+)s "
    r"\(push_ok=(\d+), push_fail=(\d+), chains=(\d+)\) ==="
)
PUSH_START_RE = re.compile(r"Running push: .*push_all_anomalies")
PUSH_DONE_RE = re.compile(r"Push completed|Push failed|push_all_anomalies.*exited")
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})")


def _parse_ts(line: str) -> datetime | None:
    m = TS_RE.match(line)
    if not m:
        return None
    return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=timezone.utc)


def _tail_follow(path: Path):
    """Yield new lines appended to path, starting at EOF."""
    with path.open("r", errors="replace") as fh:
        fh.seek(0, os.SEEK_END)
        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def _snapshot_counts(path: Path) -> tuple[int, Counter[str], Counter[str]]:
    """Return (total_rows, reason counter, job_id counter)."""
    if not path.exists():
        return 0, Counter(), Counter()
    reasons: Counter[str] = Counter()
    jobs: Counter[str] = Counter()
    n = 0
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            n += 1
            r = obj.get("reason") or ""
            reasons[r] += 1
            jid = obj.get("job_id") or ""
            jobs[jid] += 1
    return n, reasons, jobs


def _diff(before: Counter[str], after: Counter[str]) -> dict[str, int]:
    out = {}
    for k, v in after.items():
        d = v - before.get(k, 0)
        if d:
            out[k] = d
    return out


def monitor(n_cycles: int, output: Path, log: Path = LOG) -> None:
    cycles: list[dict] = []
    current_cycle: dict | None = None
    print(f"[monitor] waiting for {n_cycles} cycles; log={log}", flush=True)

    # Prime counters so first cycle sees only its own deltas.
    _, fp_reasons_before, fp_jobs_before = _snapshot_counts(FP_TRACE)
    q_before, q_reasons_before, q_jobs_before = _snapshot_counts(QUARANTINE)
    fp_n_before = sum(fp_reasons_before.values())

    for line in _tail_follow(log):
        ts = _parse_ts(line)

        m = CYCLE_START_RE.search(line)
        if m and current_cycle is None:
            cycle_num = int(m.group(1))
            print(f"[monitor] cycle {cycle_num} started at {ts}", flush=True)
            current_cycle = {
                "cycle": cycle_num,
                "start_ts": ts.isoformat() if ts else None,
                "start_mono": time.monotonic(),
                "first_push_ts": None,
                "log_lines": 0,
                "stale_allowlist_spam": 0,
                "errors": 0,
                "warnings": 0,
                "invalid_process_substitutions": 0,
                "new_fp_reasons": {},
                "new_quarantine_reasons": {},
            }
            continue

        if current_cycle is not None:
            current_cycle["log_lines"] += 1
            if "Stale allowlist entry" in line:
                current_cycle["stale_allowlist_spam"] += 1
            if " - ERROR - " in line:
                current_cycle["errors"] += 1
            if " - WARNING - " in line and "Stale allowlist entry" not in line:
                current_cycle["warnings"] += 1
            if "proc=invalid-process" in line:
                current_cycle["invalid_process_substitutions"] += 1
            if current_cycle["first_push_ts"] is None and PUSH_START_RE.search(line):
                current_cycle["first_push_ts"] = ts.isoformat() if ts else None

            m_end = CYCLE_END_RE.search(line)
            if m_end and int(m_end.group(1)) == current_cycle["cycle"]:
                dur = float(m_end.group(2))
                current_cycle["end_ts"] = ts.isoformat() if ts else None
                current_cycle["duration_sec"] = dur
                current_cycle["push_ok"] = int(m_end.group(3))
                current_cycle["push_fail"] = int(m_end.group(4))
                current_cycle["chains"] = int(m_end.group(5))

                _, fp_reasons_after, _ = _snapshot_counts(FP_TRACE)
                q_after_total, q_reasons_after, _ = _snapshot_counts(QUARANTINE)
                fp_n_after = sum(fp_reasons_after.values())

                current_cycle["new_fp_decisions"] = fp_n_after - fp_n_before
                current_cycle["new_fp_reasons"] = _diff(fp_reasons_before, fp_reasons_after)
                current_cycle["new_quarantined"] = q_after_total - q_before
                current_cycle["new_quarantine_reasons"] = _diff(q_reasons_before, q_reasons_after)

                fp_reasons_before = fp_reasons_after
                fp_n_before = fp_n_after
                q_before = q_after_total
                q_reasons_before = q_reasons_after

                cycles.append(current_cycle)
                print(
                    f"[monitor] cycle {current_cycle['cycle']} done "
                    f"dur={dur:.1f}s "
                    f"push_ok={current_cycle['push_ok']} "
                    f"fp_new={current_cycle['new_fp_decisions']} "
                    f"quarantined_new={current_cycle['new_quarantined']} "
                    f"invalid_proc={current_cycle['invalid_process_substitutions']} "
                    f"errors={current_cycle['errors']} "
                    f"spam={current_cycle['stale_allowlist_spam']} "
                    f"lines={current_cycle['log_lines']}",
                    flush=True,
                )
                current_cycle = None
                if len(cycles) >= n_cycles:
                    break

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(cycles, indent=2))
    print(f"[monitor] wrote {output}", flush=True)

    print("\n=== Summary ===")
    for c in cycles:
        print(
            f"cycle {c['cycle']}: "
            f"{c['duration_sec']:.1f}s, "
            f"push_ok={c['push_ok']}, push_fail={c['push_fail']}, "
            f"new_fp={c['new_fp_decisions']}, "
            f"new_quarantine={c['new_quarantined']}, "
            f"invalid_proc={c['invalid_process_substitutions']}, "
            f"errors={c['errors']}"
        )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--cycles", type=int, default=3)
    p.add_argument("--log", type=Path, default=LOG, help="realtime_service log to follow")
    p.add_argument(
        "--out",
        type=Path,
        default=Path(f"results/siem_audit/cycle_monitor_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"),
    )
    args = p.parse_args()
    monitor(args.cycles, args.out, args.log)
    return 0


if __name__ == "__main__":
    sys.exit(main())
