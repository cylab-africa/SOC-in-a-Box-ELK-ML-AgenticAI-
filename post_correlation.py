"""
Kill-chain correlation engine for anomaly alerts.

Groups individual anomaly alerts into attack chains by host, time window,
kill-chain phase ordering, and entity linkage (user + process + network).

ATT&CK alignment: produces correlated alert chains that map to multi-phase
attack progressions rather than isolated anomaly blips.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Kill chain phase ordering (for chain scoring)
KILL_CHAIN_ORDER: dict[str, int] = {
    "reconnaissance": 1,
    "resource_development": 2,
    "initial_access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 7,
    "credential_access": 8,
    "discovery": 9,
    "lateral_movement": 10,
    "collection": 11,
    "command_and_control": 12,
    "exfiltration": 13,
    "impact": 14,
}

ALL_PHASES: list[str] = sorted(KILL_CHAIN_ORDER, key=KILL_CHAIN_ORDER.get)  # type: ignore[arg-type]
TOTAL_PHASES: int = len(KILL_CHAIN_ORDER)

# Correlation output path
CORRELATION_OUTPUT: Path = Path("results/correlated_chains.jsonl")


@dataclass
class CorrelatedChain:
    """A group of anomalies forming an attack chain on a single host."""

    chain_id: str = ""
    host: str = ""
    chain_score: float = 0.0
    chain_completeness: float = 0.0
    phases_observed: list[str] = field(default_factory=list)
    phases_missing: list[str] = field(default_factory=list)
    member_anomalies: list[str] = field(default_factory=list)
    linked_entities: dict[str, list[str]] = field(default_factory=dict)
    time_span_minutes: float = 0.0
    first_seen: str = ""
    last_seen: str = ""
    investigation_priority: str = "low"

    def to_dict(self) -> dict[str, Any]:
        """Serialize chain to a JSON-compatible dict.

        Returns:
            Dict representation of the chain.
        """
        return {
            "chain_id": self.chain_id,
            "host": self.host,
            "chain_score": round(self.chain_score, 4),
            "chain_completeness": round(self.chain_completeness, 4),
            "phases_observed": self.phases_observed,
            "phases_missing": self.phases_missing,
            "member_anomalies": self.member_anomalies,
            "linked_entities": self.linked_entities,
            "time_span_minutes": round(self.time_span_minutes, 1),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "investigation_priority": self.investigation_priority,
        }


class KillChainCorrelator:
    """Correlate anomaly alerts into kill-chain attack chains.

    Groups anomalies by host and time window, then scores chains based
    on kill-chain phase coverage, logical ordering, and entity linkage.
    """

    def __init__(
        self,
        time_window_minutes: int = 60,
        min_chain_length: int = 2,
    ) -> None:
        """Initialize the correlator.

        Args:
            time_window_minutes: Maximum time span for grouping anomalies.
            min_chain_length: Minimum anomalies required to form a chain.
        """
        self._time_window = timedelta(minutes=time_window_minutes)
        self._min_chain_length = min_chain_length

    def correlate(
        self, anomalies: list[dict[str, Any]],
    ) -> list[CorrelatedChain]:
        """Group anomalies into attack chains.

        Steps:
        1. Group by host AND overlapping time window
        2. Score by kill chain phase coverage and ordering
        3. Link entities (users, processes, destination IPs)
        4. Assign investigation priority

        Args:
            anomalies: List of enriched anomaly dicts. Each should have:
                - host.name or hostname
                - @timestamp or timestamp
                - mitre.kill_chain_phase or kill_chain_phase
                - user.name (optional)
                - process.name (optional)
                - destination.ip (optional)
                - record_score or anomaly_score (optional)
                - _id or doc_id (optional)

        Returns:
            List of CorrelatedChain objects, sorted by score descending.
        """
        # Group anomalies by host
        host_groups: dict[str, list[dict]] = defaultdict(list)
        for anom in anomalies:
            host = self._extract_host(anom)
            host_groups[host].append(anom)

        chains: list[CorrelatedChain] = []

        for host, group in host_groups.items():
            # Sort by timestamp
            group.sort(key=lambda a: self._extract_timestamp(a))
            # Sliding window grouping
            window_groups = self._group_by_time_window(group)

            for window in window_groups:
                if len(window) < self._min_chain_length:
                    continue
                chain = self._build_chain(host, window)
                chains.append(chain)

        # Sort by chain_score descending
        chains.sort(key=lambda c: c.chain_score, reverse=True)
        return chains

    def correlate_and_write(
        self,
        anomalies: list[dict[str, Any]],
        output_path: Path | None = None,
    ) -> list[CorrelatedChain]:
        """Correlate anomalies and write chains to JSONL file.

        Args:
            anomalies: List of enriched anomaly dicts.
            output_path: Output file path (default: results/correlated_chains.jsonl).

        Returns:
            List of CorrelatedChain objects.
        """
        chains = self.correlate(anomalies)
        out = output_path or CORRELATION_OUTPUT
        out.parent.mkdir(parents=True, exist_ok=True)

        with out.open("a") as fh:
            for chain in chains:
                fh.write(json.dumps(chain.to_dict(), default=str) + "\n")

        logger.info(
            "Correlated %d anomalies into %d chains, wrote to %s",
            len(anomalies),
            len(chains),
            out,
        )
        return chains

    def _group_by_time_window(
        self, sorted_anomalies: list[dict],
    ) -> list[list[dict]]:
        """Group time-sorted anomalies into overlapping windows.

        Args:
            sorted_anomalies: Anomalies sorted by timestamp.

        Returns:
            List of groups, each a list of anomalies within one window.
        """
        if not sorted_anomalies:
            return []

        groups: list[list[dict]] = []
        current_group: list[dict] = [sorted_anomalies[0]]
        group_start = self._extract_timestamp(sorted_anomalies[0])

        for anom in sorted_anomalies[1:]:
            ts = self._extract_timestamp(anom)
            if (ts - group_start) <= self._time_window:
                current_group.append(anom)
            else:
                groups.append(current_group)
                current_group = [anom]
                group_start = ts

        if current_group:
            groups.append(current_group)

        return groups

    def _build_chain(
        self, host: str, anomalies: list[dict],
    ) -> CorrelatedChain:
        """Build a CorrelatedChain from a group of anomalies.

        Args:
            host: Host identifier.
            anomalies: Group of anomalies on this host.

        Returns:
            Populated CorrelatedChain.
        """
        # Extract entities
        users: set[str] = set()
        processes: set[str] = set()
        dest_ips: set[str] = set()
        phases: set[str] = set()
        member_ids: list[str] = []
        scores: list[float] = []

        for anom in anomalies:
            user = self._extract_field(anom, ("user.name",))
            if user:
                users.add(user)

            proc = self._extract_field(anom, ("process.name",))
            if proc:
                processes.add(proc)

            ip = self._extract_field(anom, ("destination.ip",))
            if ip:
                dest_ips.add(ip)

            phase = self._extract_phase(anom)
            if phase:
                phases.add(phase)

            doc_id = self._extract_field(anom, ("_id", "doc_id"))
            member_ids.append(doc_id or f"anon-{len(member_ids)}")

            score = self._extract_score(anom)
            scores.append(score)

        # Compute timestamps
        timestamps = [self._extract_timestamp(a) for a in anomalies]
        first = min(timestamps)
        last = max(timestamps)
        time_span = (last - first).total_seconds() / 60.0

        # Compute chain metrics
        phases_list = sorted(phases, key=lambda p: KILL_CHAIN_ORDER.get(p, 99))
        phases_missing = [p for p in ALL_PHASES if p not in phases]
        completeness = len(phases) / TOTAL_PHASES

        # Chain score: weighted by phase count, ordering, entity diversity
        phase_score = min(len(phases) / 3.0, 1.0)
        ordering_score = self._ordering_score(phases_list)
        entity_types = sum([bool(users), bool(processes), bool(dest_ips)])
        entity_score = min(entity_types / 3.0, 1.0)
        avg_anomaly_score = sum(scores) / max(len(scores), 1)

        chain_score = (
            0.35 * phase_score
            + 0.25 * ordering_score
            + 0.20 * entity_score
            + 0.20 * avg_anomaly_score
        )

        # Generate chain ID
        chain_id = self._generate_chain_id(host, first, member_ids)

        # Assign priority
        priority = self._assign_priority(
            phases, entity_types, chain_score
        )

        return CorrelatedChain(
            chain_id=chain_id,
            host=host,
            chain_score=chain_score,
            chain_completeness=completeness,
            phases_observed=phases_list,
            phases_missing=phases_missing,
            member_anomalies=member_ids,
            linked_entities={
                "users": sorted(users),
                "processes": sorted(processes),
                "dest_ips": sorted(dest_ips),
            },
            time_span_minutes=time_span,
            first_seen=first.isoformat(),
            last_seen=last.isoformat(),
            investigation_priority=priority,
        )

    def _ordering_score(self, phases: list[str]) -> float:
        """Score how well the phases follow kill-chain ordering.

        Args:
            phases: Sorted list of observed phases.

        Returns:
            Float score in [0, 1]. 1.0 means perfect logical progression.
        """
        if len(phases) < 2:
            return 0.5

        orders = [KILL_CHAIN_ORDER.get(p, 99) for p in phases]
        in_order = sum(
            1 for i in range(len(orders) - 1) if orders[i] <= orders[i + 1]
        )
        return in_order / (len(orders) - 1)

    def _assign_priority(
        self,
        phases: set[str],
        entity_types: int,
        chain_score: float,
    ) -> str:
        """Assign investigation priority based on chain characteristics.

        Args:
            phases: Set of observed kill chain phases.
            entity_types: Count of linked entity types (0-3).
            chain_score: Computed chain score.

        Returns:
            Priority string: "critical", "high", "medium", or "low".
        """
        high_impact = {"exfiltration", "lateral_movement", "impact"}
        has_lateral_or_exfil = bool(phases & high_impact)
        has_privesc = "privilege_escalation" in phases

        if len(phases) >= 3 and has_lateral_or_exfil:
            return "critical"
        if len(phases) >= 2 and (has_privesc or has_lateral_or_exfil):
            return "high"
        if len(phases) >= 2:
            return "medium"
        if entity_types >= 2:
            return "medium"
        return "low"

    @staticmethod
    def _extract_host(anom: dict[str, Any]) -> str:
        """Extract host name from an anomaly dict.

        Args:
            anom: Anomaly dict.

        Returns:
            Host name string.
        """
        for key in ("host.name", "hostname", "host"):
            val = anom.get(key)
            if val and isinstance(val, str):
                return val
        # Try nested
        host_obj = anom.get("host", {})
        if isinstance(host_obj, dict):
            return host_obj.get("name", "unknown")
        return "unknown"

    @staticmethod
    def _extract_timestamp(anom: dict[str, Any]) -> datetime:
        """Parse timestamp from anomaly dict.

        Args:
            anom: Anomaly dict.

        Returns:
            datetime object (UTC).
        """
        for key in ("@timestamp", "timestamp"):
            val = anom.get(key)
            if val:
                try:
                    ts_str = str(val).replace("Z", "+00:00")
                    return datetime.fromisoformat(ts_str)
                except (ValueError, TypeError):
                    continue
        return datetime.now(timezone.utc)

    @staticmethod
    def _extract_phase(anom: dict[str, Any]) -> str:
        """Extract kill chain phase from anomaly dict.

        Args:
            anom: Anomaly dict.

        Returns:
            Phase string or empty string.
        """
        # Try enriched MITRE field
        mitre = anom.get("mitre", {})
        if isinstance(mitre, dict):
            phase = mitre.get("kill_chain_phase", "")
            if phase:
                return phase
        # Try flat field
        return anom.get("kill_chain_phase", "")

    @staticmethod
    def _extract_field(
        anom: dict[str, Any], keys: tuple[str, ...],
    ) -> str:
        """Extract first non-empty field from anomaly dict.

        Args:
            anom: Anomaly dict.
            keys: Field names to try in order.

        Returns:
            Field value or empty string.
        """
        for key in keys:
            val = anom.get(key)
            if val and isinstance(val, str):
                return val
        return ""

    @staticmethod
    def _extract_score(anom: dict[str, Any]) -> float:
        """Extract anomaly score from dict.

        Args:
            anom: Anomaly dict.

        Returns:
            Float score in [0, 1], default 0.5.
        """
        for key in ("record_score", "anomaly_score", "score"):
            val = anom.get(key)
            if val is not None:
                try:
                    return float(val)
                except (ValueError, TypeError):
                    continue
        return 0.5

    @staticmethod
    def _generate_chain_id(
        host: str, first_seen: datetime, member_ids: list[str],
    ) -> str:
        """Generate a deterministic chain ID.

        Args:
            host: Host name.
            first_seen: First timestamp in chain.
            member_ids: List of member anomaly IDs.

        Returns:
            Chain ID string like 'chain-abc12345'.
        """
        data = f"{host}:{first_seen.isoformat()}:{','.join(member_ids)}"
        digest = hashlib.sha256(data.encode()).hexdigest()[:12]
        return f"chain-{digest}"
