"""
Process-based security feature transformers.

Covers MITRE ATT&CK techniques:
  T1059 - Command and Scripting Interpreter
  T1053 - Scheduled Task/Job
  T1055 - Process Injection
  T1036 - Masquerading

All transformers implement the FeatureTransformer ABC defined in base.py.
"""

import math
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

from features.base import FeatureTransformer
from features.utils import (
    EPSILON,
    cyclical_encode,
    normalized_entropy,
    safe_log_frequency,
    tokenize_command,
)


class CommandLineEntropyTransformer(FeatureTransformer):
    """Compute Shannon entropy and token rarity of process command lines.

    ATT&CK: T1059 - Command and Scripting Interpreter.
    High entropy or rare tokens indicate obfuscated or unusual commands.
    """

    FEATURE_NAMES: list[str] = ["cmd_entropy", "cmd_token_rarity"]

    def __init__(self) -> None:
        """Initialize with empty token corpus."""
        super().__init__()
        self._token_counts: Counter = Counter()
        self._total_tokens: int = 0

    def fit(self, df: pd.DataFrame) -> "CommandLineEntropyTransformer":
        """Build token frequency corpus from training command lines.

        Args:
            df: Training DataFrame; uses 'process.command_line' or 'process.args'.

        Returns:
            self
        """
        cmd_col = self._get_cmd_col(df)
        if cmd_col is None:
            self._is_fitted = True
            return self
        for cmd in df[cmd_col].dropna():
            tokens = tokenize_command(str(cmd))
            self._token_counts.update(tokens)
            self._total_tokens += len(tokens)
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append cmd_entropy and cmd_token_rarity columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with cmd_entropy (float64) and cmd_token_rarity (float64) added.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        cmd_col = self._get_cmd_col(df)
        if cmd_col is None or cmd_col not in df.columns:
            for col in to_add:
                df[col] = np.float64(0.0)
            return df

        cmds = df[cmd_col].fillna("").astype(str)

        if "cmd_entropy" in to_add:
            df["cmd_entropy"] = cmds.apply(normalized_entropy).astype(np.float64)

        if "cmd_token_rarity" in to_add:
            df["cmd_token_rarity"] = cmds.apply(self._token_rarity).astype(np.float64)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "cmd_entropy": "T1059 - Command and Scripting Interpreter",
            "cmd_token_rarity": "T1059 - Command and Scripting Interpreter",
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_cmd_col(self, df: pd.DataFrame) -> str | None:
        """Return the best available command column name from df."""
        for col in ("process.command_line", "process.args"):
            if col in df.columns:
                return col
        return None

    def _token_rarity(self, cmd: str) -> float:
        """Compute mean -log2(P(token)) rarity score for a command.

        Args:
            cmd: Raw command-line string.

        Returns:
            Float rarity score in [0.0, ~20.0]; clipped and normalized to [0, 1].
        """
        tokens = tokenize_command(cmd)
        if not tokens or self._total_tokens == 0:
            return 0.0
        scores: list[float] = []
        for token in tokens:
            count = self._token_counts.get(token, 0)
            prob = max(count, 1) / max(self._total_tokens, 1)
            scores.append(-math.log2(max(prob, EPSILON)))
        mean_score = float(np.mean(scores))
        # Normalize to [0, 1] with soft cap at 20 bits
        return min(mean_score / 20.0, 1.0)


class ProcessTreeTransformer(FeatureTransformer):
    """Detect anomalous process ancestry patterns.

    ATT&CK: T1055 - Process Injection / T1036 - Masquerading.
    Tracks parent->child process name pairs seen during training to flag
    unusual parent-child relationships at inference time.
    """

    FEATURE_NAMES: list[str] = ["proc_tree_depth", "parent_anomaly"]
    # Synthetic depth via PID gap heuristic upper bound
    _MAX_DEPTH: float = 20.0

    def __init__(self) -> None:
        """Initialize with empty parent->child frequency table."""
        super().__init__()
        self._pair_counts: Counter = Counter()
        self._total_pairs: int = 0
        # Rarity threshold: pairs below this probability are anomalous
        self._anomaly_threshold: float = 1e-4

    def fit(self, df: pd.DataFrame) -> "ProcessTreeTransformer":
        """Build parent->child pair frequency table from training data.

        Args:
            df: Training DataFrame; uses 'process.parent.name' and 'process.name'.

        Returns:
            self
        """
        if "process.parent.name" in df.columns and "process.name" in df.columns:
            parents = df["process.parent.name"].fillna("unknown").astype(str)
            children = df["process.name"].fillna("unknown").astype(str)
            pairs = list(zip(parents, children))
            self._pair_counts.update(pairs)
            self._total_pairs = len(pairs)
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append proc_tree_depth and parent_anomaly columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with proc_tree_depth (float64) and parent_anomaly (float64) appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "proc_tree_depth" in to_add:
            df["proc_tree_depth"] = self._compute_depth(df)

        if "parent_anomaly" in to_add:
            df["parent_anomaly"] = self._compute_parent_anomaly(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "proc_tree_depth": "T1055 - Process Injection",
            "parent_anomaly": "T1055 - Process Injection",
        }

    # ------------------------------------------------------------------

    def _compute_depth(self, df: pd.DataFrame) -> pd.Series:
        """Approximate process tree depth via PID distance heuristic.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series normalized to [0, 1].
        """
        if "process.pid" in df.columns and "process.parent.pid" in df.columns:
            pid = pd.to_numeric(df["process.pid"], errors="coerce").fillna(0)
            ppid = pd.to_numeric(df["process.parent.pid"], errors="coerce").fillna(0)
            raw_depth = (pid - ppid).abs().clip(lower=0, upper=self._MAX_DEPTH)
            return (raw_depth / self._MAX_DEPTH).astype(np.float64)
        return pd.Series(0.0, index=df.index, dtype=np.float64)

    def _compute_parent_anomaly(self, df: pd.DataFrame) -> pd.Series:
        """Flag rare parent->child pairs as anomalous (1.0) or normal (0.0).

        Args:
            df: Input DataFrame.

        Returns:
            Float64 binary series (0.0 normal, 1.0 anomalous).
        """
        if "process.parent.name" not in df.columns or "process.name" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        parents = df["process.parent.name"].fillna("unknown").astype(str)
        children = df["process.name"].fillna("unknown").astype(str)

        def is_anomalous(pair: tuple[str, str]) -> float:
            """Return 1.0 if parent-child pair is rare, else 0.0."""
            if self._total_pairs == 0:
                return 0.0
            count = self._pair_counts.get(pair, 0)
            prob = count / self._total_pairs
            return 1.0 if prob < self._anomaly_threshold else 0.0

        result = [is_anomalous(pair) for pair in zip(parents, children)]
        return pd.Series(result, index=df.index, dtype=np.float64)


class ProcessRarityTransformer(FeatureTransformer):
    """Measure binary/process name novelty via frequency rarity.

    ATT&CK: T1036 - Masquerading.
    Rare or first-seen process names often indicate masqueraded or novel malware.
    """

    FEATURE_NAMES: list[str] = ["binary_age_hours", "proc_name_rarity"]

    def __init__(self) -> None:
        """Initialize with empty first-seen registry and name frequencies."""
        super().__init__()
        self._name_counts: Counter = Counter()
        self._total_procs: int = 0
        self._first_seen: dict[str, pd.Timestamp] = {}
        self._fit_time: pd.Timestamp = pd.Timestamp.utcnow()

    def fit(self, df: pd.DataFrame) -> "ProcessRarityTransformer":
        """Build process name frequency table and first-seen registry.

        Args:
            df: Training DataFrame; uses 'process.name' and '@timestamp'.

        Returns:
            self
        """
        self._fit_time = pd.Timestamp.utcnow()

        if "process.name" in df.columns:
            names = df["process.name"].dropna().astype(str)
            self._name_counts.update(names)
            self._total_procs = len(names)

            if "@timestamp" in df.columns:
                ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
                for name, timestamp in zip(names, ts):
                    if pd.isna(timestamp):
                        continue
                    if name not in self._first_seen or timestamp < self._first_seen[name]:
                        self._first_seen[name] = timestamp

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append binary_age_hours and proc_name_rarity columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with binary_age_hours (float64) and proc_name_rarity (float64) appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "proc_name_rarity" in to_add:
            df["proc_name_rarity"] = self._compute_rarity(df)

        if "binary_age_hours" in to_add:
            df["binary_age_hours"] = self._compute_age(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "binary_age_hours": "T1036 - Masquerading",
            "proc_name_rarity": "T1036 - Masquerading",
        }

    # ------------------------------------------------------------------

    def _compute_rarity(self, df: pd.DataFrame) -> pd.Series:
        """Compute -log2(P(name)) rarity, normalized to [0, 1].

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series.
        """
        if "process.name" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        names = df["process.name"].fillna("unknown").astype(str)
        counts = names.map(lambda n: self._name_counts.get(n, 0))
        raw = safe_log_frequency(counts, max(self._total_procs, 1))
        # Normalize: cap at log2(total) which is ≤ ~17 bits for 100k procs
        max_bits = math.log2(max(self._total_procs, 2))
        return (raw / max_bits).clip(0.0, 1.0).astype(np.float64)

    def _compute_age(self, df: pd.DataFrame) -> pd.Series:
        """Compute hours since first observation of each process name.

        Normalized to [0, 1] with a 30-day cap (720 hours).
        New/unseen binaries get age = 0 (first seen = now).

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series.
        """
        _MAX_HOURS = 720.0  # 30 days

        if "process.name" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        names = df["process.name"].fillna("unknown").astype(str)

        if "@timestamp" in df.columns:
            now = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        else:
            now = pd.Series(self._fit_time, index=df.index)

        ages: list[float] = []
        for name, current_ts in zip(names, now):
            first = self._first_seen.get(str(name))
            if first is None or pd.isna(current_ts):
                ages.append(0.0)
            else:
                delta_hours = (current_ts - first).total_seconds() / 3600.0
                ages.append(max(delta_hours, 0.0))

        raw = pd.Series(ages, index=df.index, dtype=np.float64)
        return (raw.clip(0.0, _MAX_HOURS) / _MAX_HOURS).astype(np.float64)


class TemporalCyclicalTransformer(FeatureTransformer):
    """Encode time-of-day and day-of-week as cyclical (sin/cos) features.

    ATT&CK: T1053 - Scheduled Task/Job.
    Attackers using scheduled tasks often trigger at specific hours;
    cyclical encoding preserves the periodic structure without ordinal bias.
    """

    FEATURE_NAMES: list[str] = ["hour_sin", "hour_cos", "dow_sin", "dow_cos"]

    def fit(self, df: pd.DataFrame) -> "TemporalCyclicalTransformer":
        """No statistics to learn; marks transformer as fitted.

        Args:
            df: Unused training DataFrame.

        Returns:
            self
        """
        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append hour_sin, hour_cos, dow_sin, dow_cos columns.

        Args:
            df: Input DataFrame; uses '@timestamp' if present.

        Returns:
            df with cyclical time features appended (float64).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        hour_series, dow_series = self._extract_time(df)

        if "hour_sin" in to_add or "hour_cos" in to_add:
            h_sin, h_cos = cyclical_encode(hour_series, period=24.0)
            if "hour_sin" in to_add:
                df["hour_sin"] = h_sin
            if "hour_cos" in to_add:
                df["hour_cos"] = h_cos

        if "dow_sin" in to_add or "dow_cos" in to_add:
            d_sin, d_cos = cyclical_encode(dow_series, period=7.0)
            if "dow_sin" in to_add:
                df["dow_sin"] = d_sin
            if "dow_cos" in to_add:
                df["dow_cos"] = d_cos

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "hour_sin": "T1053 - Scheduled Task/Job",
            "hour_cos": "T1053 - Scheduled Task/Job",
            "dow_sin": "T1053 - Scheduled Task/Job",
            "dow_cos": "T1053 - Scheduled Task/Job",
        }

    # ------------------------------------------------------------------

    def _extract_time(self, df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
        """Extract hour-of-day and day-of-week from timestamp.

        Args:
            df: Input DataFrame.

        Returns:
            Tuple of (hour_series [0-23], dow_series [0-6]).
        """
        if "@timestamp" in df.columns:
            ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
            hour = ts.dt.hour.fillna(12.0).astype(np.float64)
            dow = ts.dt.dayofweek.fillna(0.0).astype(np.float64)
        elif "hour_of_day" in df.columns:
            hour = pd.to_numeric(df["hour_of_day"], errors="coerce").fillna(12.0)
            dow = pd.Series(0.0, index=df.index)
        else:
            hour = pd.Series(12.0, index=df.index)
            dow = pd.Series(0.0, index=df.index)

        return hour, dow
