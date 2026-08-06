"""
Apply a SIEM detection-rule JSON file to Kibana via the Detection Engine API.

Designed for the `ML Anomaly High Score` rule but works for any rule
definition that follows the Kibana Detection Engine create/update
schema.  Reads credentials and `KIBANA_HOST` from the local `.env` via
the same loader used by the push pipeline.

Usage:

    python3 scripts/siem_rule_apply.py --dry-run
        Fetch the live rule definition and show the diff with the
        local JSON without performing any change.

    python3 scripts/siem_rule_apply.py
        Upsert the rule in Kibana.  A backup of the live rule
        definition is written to `results/siem_rule_backups/<ts>/`
        before any change is applied.

    python3 scripts/siem_rule_apply.py --rule config/siem_rules/other_rule.json
        Apply a different rule file.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("siem_rule_apply")

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

DEFAULT_RULE = "config/siem_rules/ml_anomaly_high_score.json"
BACKUP_DIR = Path("results/siem_rule_backups")


def _load_env() -> None:
    """Reuse push_all_anomalies' env loader for consistency."""
    from push_all_anomalies import _load_env as _load

    _load()


def _kibana_host() -> str:
    """Resolve Kibana base URL from env (`KIBANA_HOST`), stripping trailing slashes."""
    host = os.environ.get("KIBANA_HOST")
    if not host:
        # Fall back to ES_HOST with Kibana's conventional 5601 port.
        es_host = os.environ.get("ES_HOST", "https://localhost:9200")
        host = es_host.replace(":9200", ":5601")
    return host.rstrip("/")


def _auth() -> tuple[str, str]:
    """Kibana uses the same auth as Elasticsearch in this environment."""
    user = os.environ.get("KIBANA_USERNAME") or os.environ.get("ES_USERNAME", "")
    pw = os.environ.get("KIBANA_PASSWORD") or os.environ.get("ES_PASSWORD", "")
    return user, pw


def _headers() -> dict[str, str]:
    return {"Content-Type": "application/json", "kbn-xsrf": "true"}


def _session() -> Any:
    """Return a configured `requests` session with auth + TLS behaviour."""
    import requests  # Imported lazily so the rest of the repo stays usable without it

    sess = requests.Session()
    sess.auth = _auth()
    sess.headers.update(_headers())
    sess.verify = os.environ.get("KIBANA_VERIFY_CERTS", "false").lower() == "true"
    if not sess.verify:
        # Silence the urllib3 noise so CI logs stay readable
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return sess


def _fetch_rule(sess: Any, kb: str, rule_id: str) -> dict[str, Any] | None:
    """Return the live rule definition, or None if the rule does not exist."""
    url = f"{kb}/api/detection_engine/rules"
    resp = sess.get(url, params={"rule_id": rule_id}, timeout=30)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()


def _upsert_rule(sess: Any, kb: str, rule: dict[str, Any]) -> dict[str, Any]:
    """Create or update a rule via the Detection Engine API."""
    url = f"{kb}/api/detection_engine/rules"
    existing = _fetch_rule(sess, kb, rule.get("rule_id", ""))
    if existing is None:
        logger.info("Creating new rule rule_id=%s", rule.get("rule_id"))
        resp = sess.post(url, data=json.dumps(rule), timeout=30)
    else:
        logger.info("Updating existing rule rule_id=%s", rule.get("rule_id"))
        resp = sess.put(url, data=json.dumps(rule), timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Rule apply failed: HTTP {resp.status_code} - {resp.text[:500]}"
        )
    return resp.json()


def _diff_keys(a: dict[str, Any], b: dict[str, Any]) -> list[dict[str, Any]]:
    """Shallow key-by-key diff useful for a human audit trail."""
    diffs: list[dict[str, Any]] = []
    keys = sorted(set(a.keys()) | set(b.keys()))
    for k in keys:
        if a.get(k) != b.get(k):
            diffs.append({"key": k, "live": a.get(k), "proposed": b.get(k)})
    return diffs


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply a SIEM rule JSON to Kibana")
    parser.add_argument("--rule", default=DEFAULT_RULE, help="Path to rule JSON")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show the diff without applying"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    )

    _load_env()

    rule_path = Path(args.rule)
    rule = json.loads(rule_path.read_text())
    if "rule_id" not in rule:
        raise SystemExit("Rule JSON must include rule_id")

    kb = _kibana_host()
    sess = _session()

    live = _fetch_rule(sess, kb, rule["rule_id"]) or {}
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = BACKUP_DIR / ts
    backup_dir.mkdir(parents=True, exist_ok=True)
    (backup_dir / "live_before.json").write_text(json.dumps(live, indent=2, default=str))
    (backup_dir / "proposed.json").write_text(json.dumps(rule, indent=2, default=str))

    diffs = _diff_keys(live, rule)
    (backup_dir / "diff.json").write_text(json.dumps(diffs, indent=2, default=str))

    for d in diffs:
        logger.info(
            "diff key=%s live=%s proposed=%s",
            d["key"],
            _short(d["live"]),
            _short(d["proposed"]),
        )

    if args.dry_run:
        logger.info("Dry run; backup+diff written to %s", backup_dir)
        return

    result = _upsert_rule(sess, kb, rule)
    (backup_dir / "result.json").write_text(json.dumps(result, indent=2, default=str))
    logger.info("Rule applied; result written to %s", backup_dir)


def _short(val: Any) -> str:
    """Truncate long values for log readability."""
    s = json.dumps(val, default=str)
    return s if len(s) <= 160 else s[:160] + "..."


if __name__ == "__main__":
    main()
