"""
Network-based security feature transformers.

Covers MITRE ATT&CK techniques:
  T1071 - Application Layer Protocol
  T1048 - Exfiltration Over Alternative Protocol
  T1568 - Dynamic Resolution (DGA)
  T1071.004 - DNS
  T1041 - Exfiltration Over C2 Channel

All transformers implement the FeatureTransformer ABC defined in base.py.
"""

import math
from collections import Counter

import numpy as np
import pandas as pd

from features.base import FeatureTransformer
from features.utils import (
    EPSILON,
    domain_entropy,
    safe_log_frequency,
)


class DestinationRarityTransformer(FeatureTransformer):
    """Measure destination IP rarity based on training frequency.

    ATT&CK: T1071 - Application Layer Protocol.
    Rare destination IPs may indicate C2 infrastructure or data exfiltration
    to attacker-controlled hosts.
    """

    FEATURE_NAMES: list[str] = ["dest_ip_rarity", "dest_port_rarity"]
    _MAX_RARITY_BITS: float = 20.0

    def __init__(self) -> None:
        """Initialize with empty IP and port frequency tables."""
        super().__init__()
        self._ip_counts: Counter = Counter()
        self._port_counts: Counter = Counter()
        self._total_ips: int = 0
        self._total_ports: int = 0

    def fit(self, df: pd.DataFrame) -> "DestinationRarityTransformer":
        """Build destination IP and port frequency tables from training data.

        Args:
            df: Training DataFrame; uses 'destination.ip' and 'destination.port'.

        Returns:
            self
        """
        if "destination.ip" in df.columns:
            ips = df["destination.ip"].dropna().astype(str)
            self._ip_counts.update(ips)
            self._total_ips = len(ips)

        if "destination.port" in df.columns:
            ports = df["destination.port"].dropna().astype(str)
            self._port_counts.update(ports)
            self._total_ports = len(ports)

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append dest_ip_rarity and dest_port_rarity columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with rarity features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "dest_ip_rarity" in to_add:
            df["dest_ip_rarity"] = self._compute_rarity(
                df, "destination.ip", self._ip_counts, self._total_ips
            )

        if "dest_port_rarity" in to_add:
            df["dest_port_rarity"] = self._compute_rarity(
                df, "destination.port", self._port_counts, self._total_ports
            )

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "dest_ip_rarity": "T1071 - Application Layer Protocol",
            "dest_port_rarity": "T1071 - Application Layer Protocol",
        }

    def _compute_rarity(
        self,
        df: pd.DataFrame,
        col: str,
        counts: Counter,
        total: int,
    ) -> pd.Series:
        """Compute -log2(P(value)) rarity normalized to [0, 1].

        Args:
            df: Input DataFrame.
            col: Column name to compute rarity for.
            counts: Frequency counter from training.
            total: Total observations from training.

        Returns:
            Float64 series in [0.0, 1.0].
        """
        if col not in df.columns or total == 0:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        values = df[col].fillna("unknown").astype(str)
        raw_counts = values.map(lambda v: counts.get(v, 0))
        raw_rarity = safe_log_frequency(raw_counts, total)
        return (raw_rarity / self._MAX_RARITY_BITS).clip(0.0, 1.0).astype(np.float64)


class DNSEntropyTransformer(FeatureTransformer):
    """Detect DGA and tunneling via DNS domain entropy analysis.

    ATT&CK: T1568 - Dynamic Resolution / T1071.004 - DNS.
    DGA-generated domains have high Shannon entropy compared to legitimate
    domains. DNS tunneling uses unusually long subdomains.
    """

    FEATURE_NAMES: list[str] = ["dns_entropy", "dns_label_length"]
    _MAX_LABEL_LENGTH: float = 63.0  # RFC 1035 max label length

    def __init__(self) -> None:
        """Initialize transformer."""
        super().__init__()

    def fit(self, df: pd.DataFrame) -> "DNSEntropyTransformer":
        """No statistics needed; marks as fitted.

        Args:
            df: Unused training DataFrame.

        Returns:
            self
        """
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append dns_entropy and dns_label_length columns.

        Args:
            df: Input DataFrame; uses 'dns.question.name' or 'destination.domain'.

        Returns:
            df with DNS features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        domain_col = self._get_domain_col(df)
        if domain_col is None:
            for col in to_add:
                df[col] = np.float64(0.0)
            return df

        domains = df[domain_col].fillna("").astype(str)

        if "dns_entropy" in to_add:
            df["dns_entropy"] = domains.apply(domain_entropy).astype(np.float64)
            # Normalize: typical DGA entropy is 3-4 bits, legit is 2-3
            max_entropy = math.log2(36)  # alphanumeric character set
            df["dns_entropy"] = (df["dns_entropy"] / max_entropy).clip(0.0, 1.0)

        if "dns_label_length" in to_add:
            df["dns_label_length"] = domains.apply(
                lambda d: len(d.split(".")[0]) if d else 0.0
            ).astype(np.float64)
            df["dns_label_length"] = (
                df["dns_label_length"] / self._MAX_LABEL_LENGTH
            ).clip(0.0, 1.0).astype(np.float64)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "dns_entropy": "T1568 - Dynamic Resolution",
            "dns_label_length": "T1071.004 - DNS",
        }

    def _get_domain_col(self, df: pd.DataFrame) -> str | None:
        """Return best available domain column from df."""
        for col in ("dns.question.name", "destination.domain", "dns.resolved_ip"):
            if col in df.columns:
                return col
        return None


class BeaconDetectorTransformer(FeatureTransformer):
    """Detect periodic beaconing behavior in network connections.

    ATT&CK: T1041 - Exfiltration Over C2 Channel / T1071 - Application Layer Protocol.
    C2 beacons typically exhibit regular inter-arrival times. This transformer
    computes a beacon score based on timing regularity of connections to each
    destination IP.
    """

    FEATURE_NAMES: list[str] = ["beacon_score", "conn_burst_ratio"]
    _JITTER_THRESHOLD: float = 0.15  # Max CV for strong beacon signal

    def __init__(self) -> None:
        """Initialize with empty baseline connection rates."""
        super().__init__()
        self._baseline_rates: dict[str, float] = {}

    def fit(self, df: pd.DataFrame) -> "BeaconDetectorTransformer":
        """Learn baseline connection rates per destination IP.

        Args:
            df: Training DataFrame; uses '@timestamp' and 'destination.ip'.

        Returns:
            self
        """
        if "@timestamp" in df.columns and "destination.ip" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            grouped = df.assign(_ts=ts).dropna(subset=["_ts"]).groupby("destination.ip")
            for ip, group in grouped:
                if len(group) < 3:
                    continue
                diffs = group["_ts"].sort_values().diff().dropna()
                mean_interval = diffs.dt.total_seconds().mean()
                if mean_interval > 0:
                    self._baseline_rates[str(ip)] = mean_interval

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append beacon_score and conn_burst_ratio columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with beacon features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "beacon_score" in to_add:
            df["beacon_score"] = self._compute_beacon_score(df)

        if "conn_burst_ratio" in to_add:
            df["conn_burst_ratio"] = self._compute_burst_ratio(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "beacon_score": "T1041 - Exfiltration Over C2 Channel",
            "conn_burst_ratio": "T1071 - Application Layer Protocol",
        }

    def _compute_beacon_score(self, df: pd.DataFrame) -> pd.Series:
        """Compute per-row beacon regularity score.

        Uses coefficient of variation (CV) of inter-arrival times to the
        same destination. Low CV = high regularity = high beacon score.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0]; 0.0 = no data or irregular.
        """
        if "@timestamp" not in df.columns or "destination.ip" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        result = pd.Series(0.0, index=df.index, dtype=np.float64)

        grouped = df.assign(_ts=ts).dropna(subset=["_ts"]).groupby("destination.ip")
        for _ip, group in grouped:
            if len(group) < 3:
                continue
            diffs = group["_ts"].sort_values().diff().dropna().dt.total_seconds()
            if len(diffs) < 2:
                continue
            mean_diff = diffs.mean()
            std_diff = diffs.std()
            if mean_diff > 0:
                cv = std_diff / mean_diff
                # Low CV = regular = high beacon score
                score = max(0.0, 1.0 - (cv / self._JITTER_THRESHOLD))
                score = min(score, 1.0)
                result.loc[group.index] = score

        return result.astype(np.float64)

    def _compute_burst_ratio(self, df: pd.DataFrame) -> pd.Series:
        """Compute ratio of connections in short bursts vs baseline.

        High burst ratios indicate port scanning or brute-force activity.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0].
        """
        if "@timestamp" not in df.columns or "destination.ip" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        result = pd.Series(0.0, index=df.index, dtype=np.float64)

        grouped = df.assign(_ts=ts).dropna(subset=["_ts"]).groupby("destination.ip")
        for _ip, group in grouped:
            if len(group) < 2:
                continue
            diffs = group["_ts"].sort_values().diff().dropna().dt.total_seconds()
            if len(diffs) == 0:
                continue
            # Burst = connections within 1 second of each other
            burst_count = (diffs < 1.0).sum()
            burst_ratio = burst_count / len(diffs)
            result.loc[group.index] = min(burst_ratio, 1.0)

        return result.astype(np.float64)


class BytesRatioTransformer(FeatureTransformer):
    """Ratio of bytes sent to bytes received per connection.

    ATT&CK: T1041 - Exfiltration Over C2 Channel.
    A high outbound/inbound byte ratio suggests data exfiltration.
    A very low ratio with high volume may indicate C2 downloads.
    """

    FEATURE_NAMES: list[str] = ["bytes_out_in_ratio"]

    def __init__(self) -> None:
        """Initialize with empty baseline statistics."""
        super().__init__()
        self._mean_ratio: float = 1.0
        self._std_ratio: float = 1.0

    def fit(self, df: pd.DataFrame) -> "BytesRatioTransformer":
        """Learn nominal bytes ratio distribution from training data.

        Args:
            df: Training DataFrame; uses 'source.bytes' and 'destination.bytes'.

        Returns:
            self
        """
        src_col = self._find_col(df, ("source.bytes", "network.bytes_out"))
        dst_col = self._find_col(df, ("destination.bytes", "network.bytes_in"))

        if src_col and dst_col:
            src = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0)
            dst = pd.to_numeric(df[dst_col], errors="coerce").fillna(0.0)
            ratio = src / (dst + EPSILON)
            self._mean_ratio = float(ratio.mean())
            self._std_ratio = max(float(ratio.std()), EPSILON)

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append bytes_out_in_ratio feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with bytes ratio feature appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        src_col = self._find_col(df, ("source.bytes", "network.bytes_out"))
        dst_col = self._find_col(df, ("destination.bytes", "network.bytes_in"))

        if not src_col or not dst_col:
            df["bytes_out_in_ratio"] = np.float64(0.0)
            return df

        src = pd.to_numeric(df[src_col], errors="coerce").fillna(0.0)
        dst = pd.to_numeric(df[dst_col], errors="coerce").fillna(0.0)
        ratio = src / (dst + EPSILON)
        zscore = (ratio - self._mean_ratio) / self._std_ratio
        df["bytes_out_in_ratio"] = zscore.clip(0.0, 1.0).astype(np.float64)
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"bytes_out_in_ratio": "T1041 - Exfiltration Over C2 Channel"}

    @staticmethod
    def _find_col(df: pd.DataFrame, candidates: tuple[str, ...]) -> str | None:
        """Return first column present in DataFrame.

        Args:
            df: Input DataFrame.
            candidates: Column name candidates in priority order.

        Returns:
            Column name or None.
        """
        for col in candidates:
            if col in df.columns:
                return col
        return None


class NewDestTransformer(FeatureTransformer):
    """Flag connections to previously-unseen destination IPs.

    ATT&CK: T1048 - Exfiltration Over Alternative Protocol.
    Connections to new destinations not observed in the training baseline
    may indicate lateral movement or exfiltration to a new C2.
    """

    FEATURE_NAMES: list[str] = ["is_new_dest"]

    def __init__(self) -> None:
        """Initialize with empty known-destination set."""
        super().__init__()
        self._known_dests: set[str] = set()

    def fit(self, df: pd.DataFrame) -> "NewDestTransformer":
        """Record all destination IPs seen in training data.

        Args:
            df: Training DataFrame; uses 'destination.ip'.

        Returns:
            self
        """
        if "destination.ip" in df.columns:
            self._known_dests = set(
                df["destination.ip"].dropna().astype(str).unique()
            )
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append is_new_dest binary feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with is_new_dest (1.0 = never seen, 0.0 = known).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "destination.ip" not in df.columns:
            df["is_new_dest"] = np.float64(0.0)
            return df

        dests = df["destination.ip"].fillna("").astype(str)
        df["is_new_dest"] = dests.apply(
            lambda d: 0.0 if d in self._known_dests or d == "" else 1.0
        ).astype(np.float64)
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"is_new_dest": "T1048 - Exfiltration Over Alternative Protocol"}
