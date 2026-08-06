"""File-output backend for testing and offline analysis.

Writes enriched anomalies to JSONL files instead of a SIEM.
Reads from local JSON/CSV files instead of querying Elasticsearch.
Useful for development, testing, and environments without a SIEM.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

from backends.base import SIEMBackend

logger = logging.getLogger(__name__)


class FileBackend(SIEMBackend):
    """Local file-system backend — reads/writes JSON/JSONL files."""

    def __init__(self, output_dir: str = "./output") -> None:
        """Initialise the file backend.

        Args:
            output_dir: Directory to write output JSONL files.
        """
        self._output_dir = Path(output_dir)
        self._connected = False

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Create the output directory if needed."""
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._connected = True
        logger.info("File backend ready — writing to %s", self._output_dir)

    def ping(self) -> bool:
        """Return True if connected."""
        return self._connected

    def close(self) -> None:
        """No-op for file backend."""
        self._connected = False

    # ------------------------------------------------------------------
    # Query (read from local JSONL files)
    # ------------------------------------------------------------------

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 1000,
        sort: Optional[list[dict[str, Any]]] = None,
    ) -> list[dict[str, Any]]:
        """Read documents from a local JSONL file named after the index.

        The ``query`` parameter is ignored for file-based reads;
        all documents from the file are returned up to ``size``.
        """
        safe_name = index.replace("*", "_star_").replace("/", "_")
        path = self._output_dir / f"{safe_name}.jsonl"
        if not path.exists():
            return []
        docs: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                docs.append(json.loads(line))
                if len(docs) >= size:
                    break
        return docs

    def msearch(
        self,
        body: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Simulate multi-search by running individual searches."""
        results: list[dict[str, Any]] = []
        i = 0
        while i < len(body) - 1:
            header = body[i]
            search_body = body[i + 1]
            index = header.get("index", "default")
            query = search_body.get("query", {"match_all": {}})
            size = search_body.get("size", 1)
            hits = self.search(index, query, size=size)
            results.append({
                "hits": {
                    "total": {"value": len(hits)},
                    "hits": [{"_source": h} for h in hits],
                }
            })
            i += 2
        return results

    def scroll_search(
        self,
        index: str,
        query: dict[str, Any],
        scroll_size: int = 5000,
        scroll_timeout: str = "2m",
    ) -> list[dict[str, Any]]:
        """Read all docs from the file (scroll not needed for files)."""
        return self.search(index, query, size=999_999)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def bulk_push(
        self,
        index: str,
        docs: list[dict[str, Any]],
    ) -> tuple[int, list[dict[str, Any]]]:
        """Append documents to a JSONL file."""
        safe_name = index.replace("*", "_star_").replace("/", "_")
        path = self._output_dir / f"{safe_name}.jsonl"
        with path.open("a", encoding="utf-8") as f:
            for doc in docs:
                f.write(json.dumps(doc, default=str) + "\n")
        logger.info("Wrote %d docs to %s", len(docs), path)
        return len(docs), []

    def index_doc(
        self,
        index: str,
        doc: dict[str, Any],
        doc_id: Optional[str] = None,
    ) -> bool:
        """Append a single document to a JSONL file."""
        count, _ = self.bulk_push(index, [doc])
        return count == 1

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def index_exists(self, index: str) -> bool:
        """Check if the JSONL file exists."""
        safe_name = index.replace("*", "_star_").replace("/", "_")
        return (self._output_dir / f"{safe_name}.jsonl").exists()
