"""
Install Elasticsearch index templates for the ML anomaly detection pipeline.

Reads mapping definitions from the mappings/ directory and registers them
as index templates in the configured Elasticsearch cluster.

ATT&CK: N/A (operational tooling, not a detection capability)
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAPPINGS_DIR = Path(__file__).parent
TEMPLATES: list[tuple[str, Path]] = [
    ("ml-anomalies-custom", MAPPINGS_DIR / "ml-anomalies-custom.json"),
    ("ml-anomalies-correlated", MAPPINGS_DIR / "ml-anomalies-correlated.json"),
]


def load_mapping(path: Path) -> dict[str, Any]:
    """Load an index template definition from a JSON file."""
    with path.open() as f:
        return json.load(f)


def install_template(es_client: Any, name: str, mapping: dict[str, Any]) -> bool:
    """
    Install a single index template into Elasticsearch.

    Returns True on success, False on failure.
    """
    try:
        es_client.indices.put_index_template(name=name, body=mapping)
        logger.info("Installed index template: %s", name)
        return True
    except Exception as exc:
        logger.error("Failed to install template %s: %s", name, exc)
        return False


def install_all_templates(es_client: Any) -> bool:
    """
    Install all index templates defined in the mappings/ directory.

    Returns True if all templates installed successfully.
    """
    success = True
    for name, path in TEMPLATES:
        mapping = load_mapping(path)
        ok = install_template(es_client, name, mapping)
        if not ok:
            success = False
    return success


def main() -> None:
    """
    CLI entry point: connect to ES and install all templates.

    Reads ES_HOST, ES_USER, ES_PASSWORD from environment variables.
    """
    try:
        from elasticsearch import Elasticsearch
    except ImportError:
        print("elasticsearch-py not installed — run: pip install elasticsearch", file=sys.stderr)
        sys.exit(1)

    host = os.environ.get("ES_HOST", "https://localhost:9200")
    user = os.environ.get("ES_USER", "")
    password = os.environ.get("ES_PASSWORD", "")

    if not user or not password:
        print("ES_USER and ES_PASSWORD environment variables required", file=sys.stderr)
        sys.exit(1)

    es = Elasticsearch(host, basic_auth=(user, password), verify_certs=False)

    logging.basicConfig(level=logging.INFO)
    ok = install_all_templates(es)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
