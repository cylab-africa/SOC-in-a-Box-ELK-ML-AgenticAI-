"""Async Elasticsearch client — API key or basic auth, supports v2 investigation ops."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ElasticClient:
    def __init__(
        self,
        url: str,
        username: str = "",
        password: str = "",
        api_key: str = "",
        verify_ssl: bool = False,
        index: str = ".alerts-security.alerts-default",
        event_indices: str = "logs-*,filebeat-*,winlogbeat-*,auditbeat-*",
        timeout: int = 30,
    ) -> None:
        if not url:
            raise ValueError("ELASTIC_URL is required")
        # An API key wins: it can be scoped to read-only and revoked on its own.
        headers = {"Content-Type": "application/json"}
        auth: tuple[str, str] | None = None
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        elif username and password:
            auth = (username, password)
        else:
            raise ValueError("Set ELASTIC_API_KEY, or ELASTIC_USERNAME and ELASTIC_PASSWORD")

        self._url = url.rstrip("/")
        self._index = index
        self._event_indices = event_indices
        self._client = httpx.AsyncClient(
            base_url=self._url,
            auth=auth,
            headers=headers,
            verify=verify_ssl,
            timeout=timeout,
        )

    async def __aenter__(self) -> "ElasticClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._client.aclose()

    async def fetch_open_alerts(
        self,
        limit: int = 10,
        since_ts: str | None = None,
        until_ts: str | None = None,
        rule: str | None = None,
    ) -> list[dict[str, Any]]:
        filters: list[dict[str, Any]] = [
            {"term": {"kibana.alert.workflow_status": "open"}}
        ]
        if rule:
            filters.append({"term": {"kibana.alert.rule.name": rule}})
        if since_ts or until_ts:
            ts_range: dict[str, str] = {}
            if since_ts:
                ts_range["gte"] = since_ts
            if until_ts:
                ts_range["lte"] = until_ts
            filters.append({"range": {"@timestamp": ts_range}})

        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
            "_source": [
                "@timestamp",
                "kibana.alert.rule.name",
                "kibana.alert.severity",
                "kibana.alert.risk_score",
                "kibana.alert.reason",
                "kibana.alert.workflow_status",
                "host.name", "host.hostname",
                "user.name", "source.ip", "destination.ip",
            ],
        }
        resp = await self._post(f"/{self._index}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        results = []
        for h in hits:
            doc = h.get("_source", {})
            doc["_alert_id"] = h.get("_id")
            results.append(doc)
        return results

    async def aggregate_rules(
        self,
        since_ts: str | None = None,
        until_ts: str | None = None,
        max_rules: int = 500,
    ) -> list[dict[str, Any]]:
        """Group open alerts by rule name — every rule with open alerts,
        regardless of any fetch limit, with per-severity counts."""
        filters: list[dict[str, Any]] = [
            {"term": {"kibana.alert.workflow_status": "open"}}
        ]
        if since_ts or until_ts:
            ts_range: dict[str, str] = {}
            if since_ts:
                ts_range["gte"] = since_ts
            if until_ts:
                ts_range["lte"] = until_ts
            filters.append({"range": {"@timestamp": ts_range}})

        body = {
            "size": 0,
            "query": {"bool": {"filter": filters}},
            "aggs": {
                "rules": {
                    "terms": {
                        "field": "kibana.alert.rule.name",
                        "size": max_rules,
                        "order": {"_count": "desc"},
                    },
                    "aggs": {
                        "severities": {
                            "terms": {"field": "kibana.alert.severity", "size": 5}
                        },
                        "latest": {"max": {"field": "@timestamp"}},
                    },
                }
            },
        }
        resp = await self._post(f"/{self._index}/_search", body)
        buckets = resp.get("aggregations", {}).get("rules", {}).get("buckets", [])
        rules = []
        for b in buckets:
            rules.append({
                "rule": b.get("key", ""),
                "count": b.get("doc_count", 0),
                "severities": {
                    s.get("key"): s.get("doc_count", 0)
                    for s in b.get("severities", {}).get("buckets", [])
                },
                "latest": (b.get("latest") or {}).get("value_as_string", ""),
            })
        return rules

    async def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        # Use term on _id inside bool/should — the ids query triggers the
        # multi-index alias restriction on .alerts-security.alerts-default
        # even with _search.  A regular term query does not.
        # Also match kibana.alert.uuid so deep links built from Kibana
        # drilldowns/templates resolve even if they pass the uuid field.
        body = {
            "size": 1,
            "query": {"bool": {
                "should": [
                    {"term": {"_id": alert_id}},
                    {"term": {"kibana.alert.uuid": alert_id}},
                ],
                "minimum_should_match": 1,
            }},
        }
        resp = await self._post(f"/{self._index}/_search", body)
        hits = resp.get("hits", {}).get("hits", [])
        if not hits:
            return None
        doc = hits[0].get("_source", {})
        doc["_alert_id"] = hits[0].get("_id")
        return doc

    async def get_related_events(
        self,
        host: str | None,
        user: str | None,
        center_ts: str,
        window_minutes: int = 15,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not host and not user:
            return []
        try:
            center = datetime.fromisoformat(center_ts.replace("Z", "+00:00"))
        except ValueError:
            logger.warning("Could not parse timestamp: %s", center_ts)
            return []

        start = (center - timedelta(minutes=window_minutes)).isoformat()
        end   = (center + timedelta(minutes=window_minutes)).isoformat()

        should: list[dict[str, Any]] = []
        if host:
            should.append({"term": {"host.name": host}})
            should.append({"term": {"host.hostname": host}})
        if user:
            should.append({"term": {"user.name": user}})

        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "asc"}}],
            "query": {"bool": {
                "filter": [{"range": {"@timestamp": {"gte": start, "lte": end}}}],
                "should": should,
                "minimum_should_match": 1,
            }},
            "_source": [
                "@timestamp", "event.action", "event.category", "event.type",
                "event.outcome", "host.name", "host.hostname", "user.name",
                "process.name", "process.command_line", "process.executable",
                "process.parent.name", "source.ip", "destination.ip",
                "destination.port", "destination.domain",
                "file.path", "file.hash.sha256", "message",
            ],
        }
        resp = await self._post(f"/{self._event_indices}/_search", body)
        return [h.get("_source", {}) for h in resp.get("hits", {}).get("hits", [])]

    async def _post(self, path: str, body: dict) -> dict:
        logger.debug("POST %s", path)
        resp = await self._client.post(path, json=body)
        if resp.status_code >= 400:
            raise RuntimeError(
                f"Elasticsearch returned {resp.status_code}: {resp.text[:500]}"
            )
        return resp.json()
