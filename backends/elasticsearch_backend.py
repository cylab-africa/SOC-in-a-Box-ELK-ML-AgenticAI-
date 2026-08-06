"""Elasticsearch backend implementation.

Wraps the ``elasticsearch`` Python client behind the ``SIEMBackend`` interface
so the detection pipeline can run against Elasticsearch 7.x / 8.x clusters.

Configuration is read from environment variables (see ``.env.example``).
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from backends.base import SIEMBackend

logger = logging.getLogger(__name__)


class ElasticsearchBackend(SIEMBackend):
    """Elasticsearch 7.x / 8.x backend."""

    def __init__(
        self,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_certs: bool = False,
        timeout: int = 60,
    ) -> None:
        """Initialise the backend.

        Args:
            host: ES URL (falls back to ``ES_HOST`` env var).
            username: ES username (falls back to ``ES_USERNAME``).
            password: ES password (falls back to ``ES_PASSWORD``).
            verify_certs: Whether to verify TLS certificates.
            timeout: Request timeout in seconds.
        """
        self._host = host or os.getenv("ES_HOST", "")
        self._username = username or os.getenv("ES_USERNAME", "")
        self._password = password or os.getenv("ES_PASSWORD", "")
        self._verify_certs = verify_certs
        self._timeout = timeout
        self._client: Any = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Connect to the Elasticsearch cluster."""
        try:
            from elasticsearch import Elasticsearch
        except ImportError as exc:
            raise ImportError(
                "elasticsearch package is required: pip install elasticsearch>=8.0.0"
            ) from exc

        if not self._host:
            raise ConnectionError(
                "ES_HOST not set. Configure via environment variable or constructor arg."
            )

        self._client = Elasticsearch(
            self._host,
            basic_auth=(self._username, self._password) if self._username else None,
            verify_certs=self._verify_certs,
            ssl_show_warn=False,
            request_timeout=self._timeout,
        )
        if not self._client.ping():
            raise ConnectionError(f"Cannot reach Elasticsearch at {self._host}")
        logger.info("Connected to Elasticsearch at %s", self._host)

    def ping(self) -> bool:
        """Return True if ES is reachable."""
        if self._client is None:
            return False
        try:
            return bool(self._client.ping())
        except Exception:
            return False

    def close(self) -> None:
        """Close the ES transport."""
        if self._client is not None:
            self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 1000,
        sort: Optional[list[dict[str, Any]]] = None,
    ) -> list[dict[str, Any]]:
        """Run a search and return source dicts."""
        assert self._client is not None, "Call connect() first"
        body: dict[str, Any] = {"query": query, "size": size}
        if sort:
            body["sort"] = sort
        resp = self._client.search(index=index, body=body)
        return [hit["_source"] for hit in resp["hits"]["hits"]]

    def msearch(
        self,
        body: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Execute a multi-search request."""
        assert self._client is not None, "Call connect() first"
        resp = self._client.msearch(body=body)
        return resp.get("responses", [])

    def scroll_search(
        self,
        index: str,
        query: dict[str, Any],
        scroll_size: int = 5000,
        scroll_timeout: str = "2m",
    ) -> list[dict[str, Any]]:
        """Fetch all docs via scroll API."""
        assert self._client is not None, "Call connect() first"
        results: list[dict[str, Any]] = []
        resp = self._client.search(
            index=index,
            body={"query": query, "size": scroll_size},
            scroll=scroll_timeout,
        )
        scroll_id = resp.get("_scroll_id")
        hits = resp["hits"]["hits"]
        results.extend(h["_source"] for h in hits)

        while hits:
            resp = self._client.scroll(scroll_id=scroll_id, scroll=scroll_timeout)
            scroll_id = resp.get("_scroll_id")
            hits = resp["hits"]["hits"]
            results.extend(h["_source"] for h in hits)

        if scroll_id:
            try:
                self._client.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass
        return results

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def bulk_push(
        self,
        index: str,
        docs: list[dict[str, Any]],
    ) -> tuple[int, list[dict[str, Any]]]:
        """Bulk-index documents."""
        assert self._client is not None, "Call connect() first"
        from elasticsearch.helpers import bulk

        actions = [{"_index": index, "_source": doc} for doc in docs]
        success, errors = bulk(self._client, actions, raise_on_error=False)
        return success, errors if isinstance(errors, list) else []

    def index_doc(
        self,
        index: str,
        doc: dict[str, Any],
        doc_id: Optional[str] = None,
    ) -> bool:
        """Index a single document."""
        assert self._client is not None, "Call connect() first"
        try:
            self._client.index(index=index, id=doc_id, document=doc)
            return True
        except Exception as exc:
            logger.error("Failed to index doc to %s: %s", index, exc)
            return False

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    def index_exists(self, index: str) -> bool:
        """Check if an index exists."""
        assert self._client is not None, "Call connect() first"
        return bool(self._client.indices.exists(index=index))
