#!/usr/bin/env python3
"""
gvm-siem-push
Ships finished Greenbone / OpenVAS (GVM) scan results to Elasticsearch.

For each scan task, the script takes the task's most recent finished report,
compares it with the task's previous report, and indexes the findings into
Elasticsearch with a delta_status field:
    new       found in this scan, not in the previous one
    same      found in both scans
    changed   found in both scans, but something about it changed
    fixed     found in the previous scan, gone from this one
    baseline  the task's first scan, nothing to compare with
    unknown   the comparison failed; the findings are still indexed

Every finding is stored under its GVM result ID, so sending the same report
again overwrites the existing documents instead of creating duplicates.
Dashboards that count open vulnerabilities should exclude delta_status: fixed.

Usage:
    python3 gvm_siem_push.py              # push reports finished since the last successful run
    python3 gvm_siem_push.py --full       # push the latest report of every task
    python3 gvm_siem_push.py --dry-run    # show what would be pushed, send nothing
    python3 gvm_siem_push.py --env-file /path/to/settings.env

Configuration comes from environment variables or an env file
(default ~/.gvm_elastic.env). Variables already set in the environment take
priority over the env file. See README.md for every setting.
"""

import argparse
import logging
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler

from dotenv import load_dotenv
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform

__version__ = "1.0.0"

log = logging.getLogger("gvm_siem_push")

INDEX_MAPPING = {
    "properties": {
        # Identity
        "gvm_result_id":      {"type": "keyword"},
        "report_id":          {"type": "keyword"},
        "previous_report_id": {"type": "keyword"},
        "task_id":            {"type": "keyword"},
        "task_name":          {"type": "keyword"},
        "delta_status":       {"type": "keyword"},

        # Timing (scan times, not index time)
        "detection_time":     {"type": "date"},
        "modification_time":  {"type": "date"},
        "scan_end":           {"type": "date"},
        "indexed_at":         {"type": "date"},

        # Target
        "host":               {"type": "keyword"},
        "hostname":           {"type": "keyword"},
        "asset_id":           {"type": "keyword"},
        "port":               {"type": "keyword"},
        "port_number":        {"type": "integer"},
        "protocol":           {"type": "keyword"},

        # Finding
        "name":               {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "threat":             {"type": "keyword"},
        "severity":           {"type": "float"},
        "severity_label":     {"type": "keyword"},
        "original_threat":    {"type": "keyword"},
        "original_severity":  {"type": "float"},
        "qod":                {"type": "integer"},
        "description":        {"type": "text"},

        # Remediation
        "solution":           {"type": "text"},
        "solution_type":      {"type": "keyword"},

        # NVT / CVE
        "nvt_oid":            {"type": "keyword"},
        "nvt_name":           {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "family":             {"type": "keyword"},
        "cvss_base":          {"type": "float"},
        "cvss_vector":        {"type": "keyword"},
        "cve":                {"type": "keyword"},
        "refs":               {"type": "keyword"},

        # NVT tags
        "summary":            {"type": "text"},
        "insight":            {"type": "text"},
        "affected":           {"type": "text"},
        "impact":             {"type": "text"},
        "vuldetect":          {"type": "text"},
    }
}


# --- Configuration and logging ---------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ship finished GVM scan results to Elasticsearch.")
    parser.add_argument(
        "--env-file",
        default=os.getenv("GVM_ES_ENV_FILE", "~/.gvm_elastic.env"),
        help="Env file with settings (default: ~/.gvm_elastic.env)")
    parser.add_argument(
        "--full", action="store_true",
        help="Ignore the last-run timestamp and push the latest report of every task")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be pushed without sending anything")
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


def _bool(value, default):
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def setup_logging():
    """Log to the console, and also to LOG_FILE if it is set.

    When LOG_FILE is set and the script is not run from a terminal (e.g. cron),
    the console only gets warnings and errors, so cron output stays quiet.
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    root = logging.getLogger()
    root.setLevel(level)

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    log_file = os.getenv("LOG_FILE")
    if log_file:
        try:
            handler = RotatingFileHandler(
                os.path.expanduser(log_file), maxBytes=5 * 1024 * 1024, backupCount=5)
            handler.setFormatter(fmt)
            root.addHandler(handler)
            if not sys.stderr.isatty():
                console.setLevel(logging.WARNING)
        except OSError as e:
            log.warning(f"Cannot write log file {log_file} ({e}) - logging to console only")

    # Keep the Elasticsearch client's own request logs out of our output.
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)
    logging.getLogger("elasticsearch").setLevel(logging.WARNING)


def read_config():
    cfg = {
        "gvm_socket":        os.getenv("GVM_SOCKET"),
        "gvm_username":      os.getenv("GVM_USERNAME", "admin"),
        "gvm_password":      os.getenv("GVM_PASSWORD"),
        "es_host":           os.getenv("ES_HOST"),
        "es_username":       os.getenv("ES_USERNAME"),
        "es_password":       os.getenv("ES_PASSWORD"),
        "es_index":          os.getenv("ES_INDEX", "gvm-vulnerabilities"),
        "es_verify_certs":   _bool(os.getenv("ES_VERIFY_CERTS"), True),
        "es_ca_certs":       os.getenv("ES_CA_CERTS"),
        "es_compat_version": os.getenv("ES_COMPAT_VERSION"),
        "state_file":        os.path.expanduser(os.getenv("STATE_FILE", "~/.gvm_last_run")),
        "apply_overrides":   1 if _bool(os.getenv("APPLY_OVERRIDES"), True) else 0,
        "compare_previous":  _bool(os.getenv("COMPARE_PREVIOUS"), True),
    }

    required = {
        "GVM_SOCKET":   "gvm_socket",
        "GVM_PASSWORD": "gvm_password",
        "ES_HOST":      "es_host",
        "ES_USERNAME":  "es_username",
        "ES_PASSWORD":  "es_password",
    }
    missing = [name for name, key in required.items() if not cfg[key]]
    if missing:
        log.error(f"Missing required settings: {', '.join(missing)}")
        sys.exit(1)

    try:
        cfg["min_severity"] = float(os.getenv("MIN_SEVERITY", "0.0"))
        cfg["min_qod"] = int(os.getenv("MIN_QOD", "70"))
        cfg["gvm_timeout"] = int(os.getenv("GVM_TIMEOUT", "600"))
    except ValueError:
        log.error("MIN_SEVERITY, MIN_QOD and GVM_TIMEOUT must be numbers")
        sys.exit(1)

    return cfg


# --- Last-run timestamp ----------------------------------------------------

def load_last_run(path):
    """Return the previous successful run time (UTC), or None."""
    if not os.path.exists(path):
        log.info("No previous run timestamp - pushing the latest report of every task.")
        return None
    try:
        with open(path) as f:
            ts = _to_datetime(f.read().strip())
        if ts is None:
            raise ValueError("empty or unreadable timestamp")
        log.info(f"Last successful run: {ts.isoformat()} - pushing only reports finished after it.")
        return ts
    except Exception as e:
        log.warning(f"Could not read {path} ({e}) - pushing the latest report of every task.")
        return None


def save_last_run(path, ts):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(ts.isoformat())
    os.replace(tmp, path)
    log.info(f"Saved run timestamp to {path}: {ts.isoformat()}")


# --- Elasticsearch ---------------------------------------------------------

def connect_elasticsearch(cfg):
    kwargs = {
        "basic_auth":   (cfg["es_username"], cfg["es_password"]),
        "verify_certs": cfg["es_verify_certs"],
    }
    if not cfg["es_verify_certs"]:
        kwargs["ssl_show_warn"] = False
    if cfg["es_ca_certs"]:
        kwargs["ca_certs"] = cfg["es_ca_certs"]
    if cfg["es_compat_version"]:
        mime = f"application/vnd.elasticsearch+json; compatible-with={cfg['es_compat_version']}"
        kwargs["headers"] = {"Accept": mime, "Content-Type": mime}

    es = Elasticsearch(cfg["es_host"], **kwargs)
    es.info()
    log.info("Connected to Elasticsearch")
    return es


def ensure_index(es, index):
    if es.indices.exists(index=index):
        # Add any new fields to an index created by an older version of this script.
        es.indices.put_mapping(index=index, properties=INDEX_MAPPING["properties"])
        log.info(f"Index exists: {index}")
    else:
        es.indices.create(index=index, mappings=INDEX_MAPPING)
        log.info(f"Created index: {index}")


def index_documents(es, index, docs):
    """Index docs; return True if every document was stored."""
    if not docs:
        log.info("  No findings to index.")
        return True

    actions = [
        {
            "_index":  index,
            "_id":     doc.get("doc_id") or doc["gvm_result_id"],
            "_source": {k: v for k, v in doc.items() if v is not None and k != "doc_id"},
        }
        for doc in docs
    ]
    success, errors = bulk(es, actions, raise_on_error=False)
    log.info(f"  Indexed {success} document(s).")
    if errors:
        log.error(f"  {len(errors)} document(s) failed. First error: {errors[0]}")
        return False
    return True


# --- Parsing helpers -------------------------------------------------------

def _text(el, path, default=None):
    if el is None:
        return default
    node = el.find(path)
    val = node.text.strip() if node is not None and node.text else None
    return val if val else default


def _float(el, path, default=0.0):
    try:
        return float(_text(el, path, str(default)))
    except (ValueError, TypeError):
        return default


def _to_datetime(date_str):
    """Parse an ISO-8601 string into a timezone-aware UTC datetime, or None."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_iso(date_str):
    dt = _to_datetime(date_str)
    return dt.isoformat() if dt else None


def _parse_port(raw_port):
    """Split '8080/tcp' into (8080, 'tcp'); 'general/tcp' gives (None, 'tcp')."""
    if not raw_port:
        return None, None
    match = re.match(r"^(\d+)/(\w+)$", raw_port)
    if match:
        return int(match.group(1)), match.group(2).lower()
    parts = raw_port.split("/")
    return None, parts[-1].lower() if len(parts) == 2 else None


def _parse_tags(tags_str):
    """Parse the pipe-delimited NVT tags string into a dict."""
    result = {}
    if not tags_str:
        return result
    for part in tags_str.split("|"):
        if "=" in part:
            key, _, val = part.partition("=")
            val = val.strip()
            result[key.strip()] = val if val else None
    return result


def _severity_label(severity):
    if severity >= 9.0:
        return "Critical"
    if severity >= 7.0:
        return "High"
    if severity >= 4.0:
        return "Medium"
    if severity > 0.0:
        return "Low"
    if severity == 0.0:
        return "Log"
    return "False Positive"


def parse_result(result, task_id, task_name):
    """Turn a GVM <result> element into a flat document."""
    nvt_el = result.find("nvt")

    cves, refs = [], []
    if nvt_el is not None:
        for ref in nvt_el.findall("refs/ref"):
            ref_type = ref.get("type", "").lower()
            ref_id = ref.get("id", "")
            if ref_type == "cve":
                cves.append(ref_id)
            elif ref_id:
                refs.append(ref_id)

    tags = _parse_tags(_text(nvt_el, "tags"))
    raw_port = _text(result, "port")
    port_number, protocol = _parse_port(raw_port)
    severity = _float(result, "severity")

    host_el = result.find("host")
    host_ip = host_el.text.strip() if host_el is not None and host_el.text else None
    asset_el = host_el.find("asset") if host_el is not None else None

    solution_el = nvt_el.find("solution") if nvt_el is not None else None
    solution_text = solution_el.text.strip() if solution_el is not None and solution_el.text else None
    solution_type = (solution_el.get("type") or None) if solution_el is not None else None

    try:
        qod = int(float(_text(result, "qod/value") or "0"))
    except ValueError:
        qod = 0

    return {
        "gvm_result_id":     result.get("id"),
        "task_id":           task_id,
        "task_name":         task_name,

        "detection_time":    _parse_iso(_text(result, "creation_time")),
        "modification_time": _parse_iso(_text(result, "modification_time")),
        "indexed_at":        datetime.now(timezone.utc).isoformat(),

        "host":              host_ip,
        "hostname":          _text(host_el, "hostname"),
        "asset_id":          asset_el.get("asset_id") if asset_el is not None else None,
        "port":              raw_port,
        "port_number":       port_number,
        "protocol":          protocol,

        "name":              _text(result, "name"),
        "threat":            _text(result, "threat"),
        "severity":          severity,
        "severity_label":    _severity_label(severity),
        "original_threat":   _text(result, "original_threat"),
        "original_severity": _float(result, "original_severity"),
        "qod":               qod,
        "description":       _text(result, "description"),

        "solution":          solution_text,
        "solution_type":     solution_type,

        "nvt_oid":           nvt_el.get("oid") if nvt_el is not None else None,
        "nvt_name":          _text(nvt_el, "name"),
        "family":            _text(nvt_el, "family"),
        "cvss_base":         _float(nvt_el, "cvss_base") if nvt_el is not None else 0.0,
        "cvss_vector":       tags.get("cvss_base_vector"),
        "cve":               cves or None,
        "refs":              refs or None,

        "summary":           tags.get("summary"),
        "insight":           tags.get("insight"),
        "affected":          tags.get("affected"),
        "impact":            tags.get("impact"),
        "vuldetect":         tags.get("vuldetect"),
    }


# --- GVM -------------------------------------------------------------------

def results_filter(cfg):
    return (
        f"severity>{cfg['min_severity']} min_qod={cfg['min_qod']} "
        f"apply_overrides={cfg['apply_overrides']} rows=-1"
    )


def fetch_report_results(gmp, report_id, cfg):
    """Fetch the results of one report, filtered the same way as GSA's report view.

    The report is read directly with get_report. Filtering get_results by
    report_id= is not reliable on all gvmd versions.
    """
    response = gmp.get_report(
        report_id,
        filter_string=results_filter(cfg),
        details=True,
        ignore_pagination=True,
    )
    return response.findall("report/report/results/result")


_report_history = None


def find_previous_report(gmp, task_id, report_id):
    """Return the ID of the finished report before report_id for this task, or None.

    The list of finished reports is fetched once per run and reused for every
    task. Reports are matched to tasks here because some gvmd versions ignore
    task_id= in report filters.
    """
    global _report_history
    if _report_history is None:
        response = gmp.get_reports(
            filter_string="status=Done sort-reverse=date rows=-1",
            details=False,
            ignore_pagination=True,
        )
        history = {}
        for r in response.findall("report"):
            task_el = r.find("task")
            if task_el is None:
                task_el = r.find("report/task")
            if task_el is not None and r.get("id"):
                history.setdefault(task_el.get("id"), []).append(r.get("id"))
        _report_history = history

    ids = _report_history.get(task_id, [])
    if report_id in ids:
        i = ids.index(report_id)
        if i + 1 < len(ids):
            return ids[i + 1]
    return None


def fetch_delta(gmp, report_id, previous_id, cfg, current_ids):
    """Compare report_id with previous_id.

    Returns (states, fixed):
      states  {result_id: 'new' | 'same' | 'changed'} for results of the current report
      fixed   list of <result> elements that were in the previous report but are gone now
    """
    response = gmp.get_report(
        report_id,
        delta_report_id=previous_id,
        filter_string=results_filter(cfg) + " delta_states=cgns",
        details=True,
        ignore_pagination=True,
    )

    current, other = {}, []
    for r in response.findall("report/report/results/result"):
        state = (r.findtext("delta") or "").strip().lower()
        if r.get("id") in current_ids:
            current[r.get("id")] = state
        else:
            other.append((r, state))

    # If results of the current scan come back as "gone", GVM compared in the
    # other direction, so swap new and gone.
    reverse = "gone" in current.values()

    def normalise(state):
        if reverse:
            state = {"new": "gone", "gone": "new"}.get(state, state)
        return "fixed" if state == "gone" else state

    states = {rid: normalise(s) for rid, s in current.items()}
    fixed = [r for r, s in other if normalise(s) == "fixed"]
    return states, fixed


def build_documents(gmp, cfg, task_id, task_name, report_id, scan_end):
    """Return the documents to index for one report, with delta labels."""
    results = fetch_report_results(gmp, report_id, cfg)
    current_ids = {r.get("id") for r in results}

    previous_id, states, fixed = None, {}, []
    if cfg["compare_previous"]:
        try:
            previous_id = find_previous_report(gmp, task_id, report_id)
            if previous_id:
                states, fixed = fetch_delta(gmp, report_id, previous_id, cfg, current_ids)
        except Exception as e:
            log.warning(f"  Could not compare with the previous scan ({e}) - labelling as 'unknown'")
            previous_id, states, fixed = None, None, []

    docs = []
    for r in results:
        doc = parse_result(r, task_id, task_name)
        doc["report_id"] = report_id
        doc["previous_report_id"] = previous_id
        doc["scan_end"] = scan_end
        if states is None:
            doc["delta_status"] = "unknown"
        elif previous_id is None:
            doc["delta_status"] = "baseline"
        else:
            doc["delta_status"] = states.get(doc["gvm_result_id"], "same")
        docs.append(doc)

    for r in fixed:
        doc = parse_result(r, task_id, task_name)
        doc["doc_id"] = f"{doc['gvm_result_id']}-fixed-{report_id}"
        doc["report_id"] = report_id
        doc["previous_report_id"] = previous_id
        doc["scan_end"] = scan_end
        doc["delta_status"] = "fixed"
        docs.append(doc)

    counts = Counter(d["delta_status"] for d in docs)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing"
    log.info(f"  {len(results)} finding(s) in this scan; compared with "
             f"{previous_id or 'no previous scan'}: {summary}")
    return docs


# --- Main ------------------------------------------------------------------

def open_gmp(cfg):
    """Open a new GMP session to gvmd."""
    connection = UnixSocketConnection(path=cfg["gvm_socket"], timeout=cfg["gvm_timeout"])
    return Gmp(connection=connection, transform=EtreeTransform())


def main():
    args = parse_args()

    env_file = os.path.expanduser(args.env_file)
    if os.path.exists(env_file):
        load_dotenv(env_file)

    setup_logging()
    log.info("Starting GVM -> Elasticsearch push" + (" (dry run)" if args.dry_run else ""))

    cfg = read_config()
    run_start = datetime.now(timezone.utc)
    last_run = None if args.full else load_last_run(cfg["state_file"])

    es = None
    if not args.dry_run:
        try:
            es = connect_elasticsearch(cfg)
            ensure_index(es, cfg["es_index"])
        except Exception as e:
            log.error(f"Elasticsearch error: {e}")
            return 1

    pushed, skipped, failed = 0, 0, False
    try:
        with open_gmp(cfg) as gmp:
            gmp.authenticate(cfg["gvm_username"], cfg["gvm_password"])
            log.info("Authenticated with GVM")
            tasks = gmp.get_tasks(filter_string="rows=-1").findall("task")
        log.info(f"Found {len(tasks)} task(s)")

        for task in tasks:
            task_id = task.get("id")
            task_name = _text(task, "name", task_id)

            report_el = task.find("last_report/report")
            if report_el is None:
                log.debug(f"Skipping {task_name}: no finished report")
                skipped += 1
                continue

            report_id = report_el.get("id")
            scan_end_dt = _to_datetime(_text(report_el, "scan_end"))
            if last_run is not None and scan_end_dt is not None and scan_end_dt <= last_run:
                log.info(f"Skipping {task_name}: latest report already pushed")
                skipped += 1
                continue

            scan_end = scan_end_dt.isoformat() if scan_end_dt else None
            log.info(f"{task_name}: report {report_id} (finished {scan_end or 'unknown'})")

            # A fresh session per task, so a timeout on one task cannot affect the next.
            with open_gmp(cfg) as gmp:
                gmp.authenticate(cfg["gvm_username"], cfg["gvm_password"])
                docs = build_documents(gmp, cfg, task_id, task_name, report_id, scan_end)

            if args.dry_run:
                log.info(f"  Dry run: would index {len(docs)} document(s)")
                continue

            if index_documents(es, cfg["es_index"], docs):
                pushed += 1
            else:
                failed = True

    except Exception as e:
        log.error(f"Error while reading from GVM or indexing: {e}")
        return 1

    if args.dry_run:
        log.info("Dry run finished. Nothing was sent and the timestamp was not changed.")
        return 0

    if failed:
        log.error("Some documents failed to index. Timestamp not saved, so the next run will retry.")
        return 1

    save_last_run(cfg["state_file"], run_start)
    log.info(f"Done. {pushed} report(s) pushed, {skipped} skipped. Index: {cfg['es_index']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
