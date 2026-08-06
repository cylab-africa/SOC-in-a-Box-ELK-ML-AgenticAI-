"""Abstract SIEM backend interface.

All backend implementations must subclass ``SIEMBackend`` and implement
the abstract methods.  This allows the detection pipeline to work with
Elasticsearch, OpenSearch, Splunk, or even a plain JSON file store.
"""

from __future__ import annotations

import abc
from typing import Any, Optional


class SIEMBackend(abc.ABC):
    """Abstract base class for SIEM / data-store backends."""

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def connect(self) -> None:
        """Establish a connection to the backend.

        Raises ``ConnectionError`` on failure.
        """

    @abc.abstractmethod
    def ping(self) -> bool:
        """Return True if the backend is reachable."""

    @abc.abstractmethod
    def close(self) -> None:
        """Gracefully close the connection."""

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 1000,
        sort: Optional[list[dict[str, Any]]] = None,
    ) -> list[dict[str, Any]]:
        """Run a search query and return the list of hit ``_source`` dicts.

        Args:
            index: Index pattern (may contain wildcards).
            query: Query DSL body (Elasticsearch-style).
            size: Maximum number of documents to return.
            sort: Optional sort specification.

        Returns:
            List of source documents.
        """

    @abc.abstractmethod
    def msearch(
        self,
        body: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Execute a multi-search request.

        Args:
            body: Alternating header / body dicts (ES ``_msearch`` format).

        Returns:
            List of response dicts, one per sub-query.
        """

    @abc.abstractmethod
    def scroll_search(
        self,
        index: str,
        query: dict[str, Any],
        scroll_size: int = 5000,
        scroll_timeout: str = "2m",
    ) -> list[dict[str, Any]]:
        """Fetch all matching documents using scroll / cursor pagination.

        Args:
            index: Index pattern.
            query: Query DSL body.
            scroll_size: Documents per batch.
            scroll_timeout: Keep-alive timeout for the scroll context.

        Returns:
            Complete list of source documents.
        """

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def bulk_push(
        self,
        index: str,
        docs: list[dict[str, Any]],
    ) -> tuple[int, list[dict[str, Any]]]:
        """Bulk-index a list of documents.

        Args:
            index: Target index name.
            docs: Documents to index.

        Returns:
            Tuple of (success_count, error_list).
        """

    @abc.abstractmethod
    def index_doc(
        self,
        index: str,
        doc: dict[str, Any],
        doc_id: Optional[str] = None,
    ) -> bool:
        """Index a single document.

        Args:
            index: Target index name.
            doc: Document body.
            doc_id: Optional document ID.

        Returns:
            True on success.
        """

    # ------------------------------------------------------------------
    # Index management
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def index_exists(self, index: str) -> bool:
        """Return True if the index exists."""
