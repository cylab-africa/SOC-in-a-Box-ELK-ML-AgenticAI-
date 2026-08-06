"""
Temporal and volume-based feature transformers.

Covers cross-group temporal aggregations for detecting discovery sweeps,
burst activity, and abnormal baseline shifts.

MITRE ATT&CK techniques:
  T1046 - Network Service Discovery (volume spikes)
  General - event rate monitoring across all data groups
"""

from __future__ import annotations

from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from features.base import FeatureTransformer
from features.utils import EPSILON, clip_score


class EventCountTransformer(FeatureTransformer):
    """Rolling event count features per host.

    ATT&CK: General anomaly detection support.
    Sudden spikes in event count may indicate discovery sweeps (T1046),
    brute-force attempts (T1110), or data staging (T1074).
    """

    FEATURE_NAMES: list[str] = ["evt_count_5min", "evt_count_1hr"]
    _WINDOW_5MIN: str = "5min"
    _WINDOW_1HR: str = "1h"

    def __init__(self) -> None:
        """Initialize with empty baselines."""
        super().__init__()
        self._host_5min_mean: float = 0.0
        self._host_5min_std: float = 1.0
        self._host_1hr_mean: float = 0.0
        self._host_1hr_std: float = 1.0

    def fit(self, df: pd.DataFrame) -> EventCountTransformer:
        """Learn per-host event rate baselines from training data.

        Args:
            df: Training DataFrame; uses '@timestamp' and 'host.name'.

        Returns:
            self
        """
        if "@timestamp" in df.columns and "host.name" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            temp = df.assign(_ts=ts).dropna(subset=["_ts"]).set_index("_ts")

            if len(temp) > 0:
                counts_5m = temp.groupby("host.name").resample(self._WINDOW_5MIN).size()
                counts_1h = temp.groupby("host.name").resample(self._WINDOW_1HR).size()

                self._host_5min_mean = float(counts_5m.mean()) if len(counts_5m) > 0 else 0.0
                self._host_5min_std = max(float(counts_5m.std()), EPSILON) if len(counts_5m) > 1 else 1.0
                self._host_1hr_mean = float(counts_1h.mean()) if len(counts_1h) > 0 else 0.0
                self._host_1hr_std = max(float(counts_1h.std()), EPSILON) if len(counts_1h) > 1 else 1.0

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append evt_count_5min and evt_count_1hr normalized features.

        Args:
            df: Input DataFrame.

        Returns:
            df with rolling event count features appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "@timestamp" not in df.columns or "host.name" not in df.columns:
            for col in to_add:
                df[col] = np.float64(0.0)
            return df

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)

        if "evt_count_5min" in to_add:
            counts = self._rolling_count(df, ts, self._WINDOW_5MIN)
            df["evt_count_5min"] = clip_score(
                (counts - self._host_5min_mean) / self._host_5min_std
            ).astype(np.float64)

        if "evt_count_1hr" in to_add:
            counts = self._rolling_count(df, ts, self._WINDOW_1HR)
            df["evt_count_1hr"] = clip_score(
                (counts - self._host_1hr_mean) / self._host_1hr_std
            ).astype(np.float64)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {
            "evt_count_5min": "T1046 - Network Service Discovery",
            "evt_count_1hr": "T1046 - Network Service Discovery",
        }

    def _rolling_count(
        self, df: pd.DataFrame, ts: pd.Series, window: str,
    ) -> pd.Series:
        """Count events per host in rolling window.

        Args:
            df: Input DataFrame.
            ts: Parsed timestamp series.
            window: Pandas frequency string.

        Returns:
            Per-row event count in the window.
        """
        result = pd.Series(0.0, index=df.index, dtype=np.float64)
        temp = df.assign(_ts=ts).dropna(subset=["_ts"])
        if len(temp) == 0:
            return result

        for _host, group in temp.groupby("host.name"):
            sorted_g = group.sort_values("_ts")
            win_delta = pd.Timedelta(window)
            counts = []
            for _i, row in sorted_g.iterrows():
                t = row["_ts"]
                window_start = t - win_delta
                count = ((sorted_g["_ts"] >= window_start) & (sorted_g["_ts"] <= t)).sum()
                counts.append(float(count))
            result.loc[sorted_g.index] = counts

        return result


class VolumeZscoreTransformer(FeatureTransformer):
    """Detect abnormal event volume vs 7-day per-host baseline.

    ATT&CK: T1046 - Network Service Discovery.
    Significant volume increases may indicate automated scanning or
    reconnaissance activity.
    """

    FEATURE_NAMES: list[str] = ["volume_zscore_7d"]

    def __init__(self) -> None:
        """Initialize with empty per-host daily volume stats."""
        super().__init__()
        self._host_daily_mean: dict[str, float] = {}
        self._host_daily_std: dict[str, float] = {}
        self._global_mean: float = 0.0
        self._global_std: float = 1.0

    def fit(self, df: pd.DataFrame) -> VolumeZscoreTransformer:
        """Learn per-host daily event volume baselines.

        Args:
            df: Training DataFrame; uses '@timestamp' and 'host.name'.

        Returns:
            self
        """
        if "@timestamp" in df.columns and "host.name" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            temp = df.assign(_ts=ts).dropna(subset=["_ts"])
            temp = temp.assign(_date=temp["_ts"].dt.date)

            daily = temp.groupby(["host.name", "_date"]).size().reset_index(name="count")

            for host, grp in daily.groupby("host.name"):
                self._host_daily_mean[str(host)] = float(grp["count"].mean())
                raw_std = grp["count"].std()
                self._host_daily_std[str(host)] = max(float(raw_std), EPSILON) if not np.isnan(raw_std) else 1.0

            self._global_mean = float(daily["count"].mean()) if len(daily) > 0 else 0.0
            raw_global_std = daily["count"].std() if len(daily) > 1 else float("nan")
            self._global_std = max(float(raw_global_std), EPSILON) if not np.isnan(raw_global_std) else 1.0

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append volume_zscore_7d feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with volume z-score feature appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "@timestamp" not in df.columns or "host.name" not in df.columns:
            df["volume_zscore_7d"] = np.float64(0.0)
            return df

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        temp = df.assign(_ts=ts).dropna(subset=["_ts"])

        result = pd.Series(0.0, index=df.index, dtype=np.float64)

        # Count events per host within the current batch
        host_counts = temp.groupby("host.name").size()

        for host, count in host_counts.items():
            host_str = str(host)
            mean = self._host_daily_mean.get(host_str, self._global_mean)
            std = self._host_daily_std.get(host_str, self._global_std)
            zscore = (count - mean) / std
            mask = df.get("host.name") == host
            clipped = float(np.clip(zscore, 0.0, 10.0)) / 10.0
            result.loc[mask] = clipped

        df["volume_zscore_7d"] = result.astype(np.float64)
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"volume_zscore_7d": "T1046 - Network Service Discovery"}


class TransitionSurpriseTransformer(FeatureTransformer):
    """Measure event type transition surprise using a Markov chain.

    ATT&CK: General anomaly detection.
    Unusual event type sequences (e.g. auth failure -> sudo -> network connect)
    may indicate multi-stage attack progression.
    """

    FEATURE_NAMES: list[str] = ["transition_surprise"]

    def __init__(self) -> None:
        """Initialize with empty transition probability matrix."""
        super().__init__()
        self._transition_probs: dict[str, dict[str, float]] = {}
        self._event_type_col: str = "event.action"

    def fit(self, df: pd.DataFrame) -> TransitionSurpriseTransformer:
        """Learn event type transition probabilities per host.

        Args:
            df: Training DataFrame; uses event type column and 'host.name'.

        Returns:
            self
        """
        col = self._find_event_col(df)
        if col is None or "host.name" not in df.columns:
            self._is_fitted = True
            return self

        self._event_type_col = col
        transition_counts: dict[str, Counter] = defaultdict(Counter)

        if "@timestamp" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            temp = df.assign(_ts=ts).dropna(subset=["_ts"]).sort_values(["host.name", "_ts"])
        else:
            temp = df.copy()

        for _host, group in temp.groupby("host.name"):
            events = group[col].fillna("unknown").astype(str).tolist()
            for i in range(len(events) - 1):
                transition_counts[events[i]][events[i + 1]] += 1

        # Convert to probabilities
        for from_event, to_counts in transition_counts.items():
            total = sum(to_counts.values())
            self._transition_probs[from_event] = {
                to: count / total for to, count in to_counts.items()
            }

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append transition_surprise feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with transition surprise feature appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        col = self._find_event_col(df)
        if col is None or "host.name" not in df.columns:
            df["transition_surprise"] = np.float64(0.0)
            return df

        result = pd.Series(0.0, index=df.index, dtype=np.float64)
        max_surprise = 10.0  # Cap for normalization

        if "@timestamp" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            temp = df.assign(_ts=ts).dropna(subset=["_ts"]).sort_values(["host.name", "_ts"])
        else:
            temp = df.copy()

        for _host, group in temp.groupby("host.name"):
            events = group[col].fillna("unknown").astype(str).tolist()
            indices = group.index.tolist()
            for i in range(1, len(events)):
                prev_event = events[i - 1]
                curr_event = events[i]
                prob = self._transition_probs.get(prev_event, {}).get(curr_event, EPSILON)
                surprise = -np.log(prob + EPSILON)
                result.loc[indices[i]] = min(surprise / max_surprise, 1.0)

        df["transition_surprise"] = result.astype(np.float64)
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"transition_surprise": "T1046 - Network Service Discovery"}

    def _find_event_col(self, df: pd.DataFrame) -> str | None:
        """Find the best available event type column.

        Args:
            df: Input DataFrame.

        Returns:
            Column name or None.
        """
        for col in ("event.action", "event.category", "event.type", "process.name"):
            if col in df.columns:
                return col
        return None
