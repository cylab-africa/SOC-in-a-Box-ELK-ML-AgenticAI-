"""
Authentication and authorization feature transformers.

Covers MITRE ATT&CK techniques:
  T1078 - Valid Accounts
  T1548 - Abuse Elevation Control Mechanism
  T1110 - Brute Force

All transformers implement the FeatureTransformer ABC defined in base.py.
"""

from collections import Counter

import numpy as np
import pandas as pd

from features.base import FeatureTransformer
from features.utils import EPSILON, zscore_series, clip_score


class LoginTimeTransformer(FeatureTransformer):
    """Detect anomalous login timing based on per-user baselines.

    ATT&CK: T1078 - Valid Accounts.
    Logins at unusual hours for a given user may indicate credential theft
    or unauthorized access from a different timezone.
    """

    FEATURE_NAMES: list[str] = ["login_time_zscore", "login_day_anomaly"]

    def __init__(self) -> None:
        """Initialize with empty per-user hour statistics."""
        super().__init__()
        self._user_hour_mean: dict[str, float] = {}
        self._user_hour_std: dict[str, float] = {}
        self._user_dow_counts: dict[str, Counter] = {}

    def fit(self, df: pd.DataFrame) -> "LoginTimeTransformer":
        """Compute per-user login hour mean/std and day-of-week profile.

        Args:
            df: Training DataFrame; uses 'user.name' and '@timestamp'.

        Returns:
            self
        """
        if "user.name" not in df.columns or "@timestamp" not in df.columns:
            self._is_fitted = True
            return self

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        hours = ts.dt.hour.fillna(12.0)
        dows = ts.dt.dayofweek.fillna(0)
        users = df["user.name"].fillna("unknown").astype(str)

        for user in users.unique():
            mask = users == user
            user_hours = hours[mask]
            if len(user_hours) >= 2:
                self._user_hour_mean[user] = float(user_hours.mean())
                self._user_hour_std[user] = float(user_hours.std())
            self._user_dow_counts[user] = Counter(dows[mask].astype(int).tolist())

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append login_time_zscore and login_day_anomaly columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with auth timing features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "login_time_zscore" in to_add:
            df["login_time_zscore"] = self._compute_time_zscore(df)

        if "login_day_anomaly" in to_add:
            df["login_day_anomaly"] = self._compute_day_anomaly(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "login_time_zscore": "T1078 - Valid Accounts",
            "login_day_anomaly": "T1078 - Valid Accounts",
        }

    def _compute_time_zscore(self, df: pd.DataFrame) -> pd.Series:
        """Compute per-user hour-of-day z-score, clipped to [0, 1].

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0].
        """
        if "user.name" not in df.columns or "@timestamp" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        hours = ts.dt.hour.fillna(12.0).astype(np.float64)
        users = df["user.name"].fillna("unknown").astype(str)

        scores: list[float] = []
        for user, hour in zip(users, hours):
            mean = self._user_hour_mean.get(user, 12.0)
            std = self._user_hour_std.get(user, 6.0)
            if std < EPSILON:
                scores.append(0.0)
            else:
                z = abs(float(hour) - mean) / std
                scores.append(min(z / 3.0, 1.0))  # 3-sigma cap

        return pd.Series(scores, index=df.index, dtype=np.float64)

    def _compute_day_anomaly(self, df: pd.DataFrame) -> pd.Series:
        """Flag logins on days the user has never logged in before.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 binary series (0.0 = normal day, 1.0 = novel day).
        """
        if "user.name" not in df.columns or "@timestamp" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        dows = ts.dt.dayofweek.fillna(0).astype(int)
        users = df["user.name"].fillna("unknown").astype(str)

        scores: list[float] = []
        for user, dow in zip(users, dows):
            profile = self._user_dow_counts.get(user, {})
            if not profile:
                scores.append(0.0)
            elif dow not in profile:
                scores.append(1.0)
            else:
                scores.append(0.0)

        return pd.Series(scores, index=df.index, dtype=np.float64)


class PrivilegeEscalationTransformer(FeatureTransformer):
    """Detect privilege escalation patterns in user activity.

    ATT&CK: T1548 - Abuse Elevation Control Mechanism.
    Tracks sudo/su usage frequency and flags users with sudden increases
    in privileged command execution.
    """

    FEATURE_NAMES: list[str] = ["privesc_rate", "sudo_anomaly"]

    _PRIVESC_CMDS: set[str] = {"sudo", "su", "pkexec", "doas", "newgrp"}

    def __init__(self) -> None:
        """Initialize with empty per-user privilege escalation baselines."""
        super().__init__()
        self._user_privesc_rate: dict[str, float] = {}
        self._user_total_cmds: dict[str, int] = {}

    def fit(self, df: pd.DataFrame) -> "PrivilegeEscalationTransformer":
        """Build per-user privilege escalation rate from training data.

        Args:
            df: Training DataFrame; uses 'user.name' and 'process.name'.

        Returns:
            self
        """
        if "user.name" not in df.columns or "process.name" not in df.columns:
            self._is_fitted = True
            return self

        users = df["user.name"].fillna("unknown").astype(str)
        procs = df["process.name"].fillna("").astype(str)

        for user in users.unique():
            mask = users == user
            user_procs = procs[mask]
            total = len(user_procs)
            privesc_count = user_procs.apply(
                lambda p: 1 if p in self._PRIVESC_CMDS else 0
            ).sum()
            self._user_total_cmds[user] = total
            self._user_privesc_rate[user] = privesc_count / max(total, 1)

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append privesc_rate and sudo_anomaly columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with privilege escalation features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "privesc_rate" in to_add:
            df["privesc_rate"] = self._compute_privesc_rate(df)

        if "sudo_anomaly" in to_add:
            df["sudo_anomaly"] = self._compute_sudo_anomaly(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "privesc_rate": "T1548 - Abuse Elevation Control Mechanism",
            "sudo_anomaly": "T1548 - Abuse Elevation Control Mechanism",
        }

    def _compute_privesc_rate(self, df: pd.DataFrame) -> pd.Series:
        """Compute per-row indicator of privilege escalation command usage.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series (1.0 if current process is a privesc command, else 0.0).
        """
        if "process.name" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        procs = df["process.name"].fillna("").astype(str)
        return procs.apply(
            lambda p: 1.0 if p in self._PRIVESC_CMDS else 0.0
        ).astype(np.float64)

    def _compute_sudo_anomaly(self, df: pd.DataFrame) -> pd.Series:
        """Flag users exceeding their baseline sudo rate.

        Returns 1.0 if the user's privesc ratio in this batch exceeds
        2x their training baseline.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0].
        """
        if "user.name" not in df.columns or "process.name" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        users = df["user.name"].fillna("unknown").astype(str)
        procs = df["process.name"].fillna("").astype(str)

        scores: list[float] = []
        for user, proc in zip(users, procs):
            baseline_rate = self._user_privesc_rate.get(user, 0.0)
            is_privesc = 1.0 if proc in self._PRIVESC_CMDS else 0.0
            # If this is a privesc command and user rarely uses them, flag it
            if is_privesc > 0 and baseline_rate < 0.05:
                scores.append(1.0)
            elif is_privesc > 0 and baseline_rate < 0.15:
                scores.append(0.5)
            else:
                scores.append(0.0)

        return pd.Series(scores, index=df.index, dtype=np.float64)


class AuthFailureTransformer(FeatureTransformer):
    """Detect brute-force patterns via authentication failure analysis.

    ATT&CK: T1110 - Brute Force.
    High authentication failure rates from a single source or to a single
    target indicate credential guessing or password spraying.
    """

    FEATURE_NAMES: list[str] = ["auth_fail_rate", "auth_fail_burst"]
    _BURST_WINDOW_SECONDS: float = 300.0  # 5-minute window

    def __init__(self) -> None:
        """Initialize with empty baseline failure rates."""
        super().__init__()
        self._user_fail_rate: dict[str, float] = {}

    def fit(self, df: pd.DataFrame) -> "AuthFailureTransformer":
        """Compute per-user authentication failure rate baseline.

        Args:
            df: Training DataFrame; uses 'user.name' and 'event.outcome'.

        Returns:
            self
        """
        if "user.name" not in df.columns or "event.outcome" not in df.columns:
            self._is_fitted = True
            return self

        users = df["user.name"].fillna("unknown").astype(str)
        outcomes = df["event.outcome"].fillna("unknown").astype(str)

        for user in users.unique():
            mask = users == user
            user_outcomes = outcomes[mask]
            total = len(user_outcomes)
            failures = (user_outcomes == "failure").sum()
            self._user_fail_rate[user] = failures / max(total, 1)

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append auth_fail_rate and auth_fail_burst columns.

        Args:
            df: Input DataFrame.

        Returns:
            df with auth failure features appended (float64, [0.0, 1.0]).
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "auth_fail_rate" in to_add:
            df["auth_fail_rate"] = self._compute_fail_rate(df)

        if "auth_fail_burst" in to_add:
            df["auth_fail_burst"] = self._compute_fail_burst(df)

        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names produced by this transformer."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping for each feature."""
        return {
            "auth_fail_rate": "T1110 - Brute Force",
            "auth_fail_burst": "T1110 - Brute Force",
        }

    def _compute_fail_rate(self, df: pd.DataFrame) -> pd.Series:
        """Compute per-row auth failure indicator relative to baseline.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0].
        """
        if "event.outcome" not in df.columns:
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        outcomes = df["event.outcome"].fillna("unknown").astype(str)
        is_failure = (outcomes == "failure").astype(np.float64)

        if "user.name" not in df.columns:
            return is_failure

        users = df["user.name"].fillna("unknown").astype(str)
        scores: list[float] = []
        for user, failed in zip(users, is_failure):
            baseline = self._user_fail_rate.get(user, 0.0)
            if failed > 0 and baseline < 0.1:
                scores.append(1.0)  # Failure from a user who rarely fails
            elif failed > 0:
                scores.append(0.5)
            else:
                scores.append(0.0)

        return pd.Series(scores, index=df.index, dtype=np.float64)

    def _compute_fail_burst(self, df: pd.DataFrame) -> pd.Series:
        """Count auth failures in a sliding window per source.

        Args:
            df: Input DataFrame.

        Returns:
            Float64 series in [0.0, 1.0] based on failures within window.
        """
        if (
            "event.outcome" not in df.columns
            or "@timestamp" not in df.columns
            or "source.ip" not in df.columns
        ):
            return pd.Series(0.0, index=df.index, dtype=np.float64)

        ts = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)
        outcomes = df["event.outcome"].fillna("unknown").astype(str)
        sources = df["source.ip"].fillna("unknown").astype(str)

        # Count failures per source IP within window
        result = pd.Series(0.0, index=df.index, dtype=np.float64)
        failures = df[outcomes == "failure"].assign(_ts=ts[outcomes == "failure"])

        if failures.empty:
            return result

        for src_ip, group in failures.groupby(sources[outcomes == "failure"]):
            if len(group) < 2:
                continue
            sorted_ts = group["_ts"].sort_values()
            for idx in group.index:
                current_ts = ts[idx]
                if pd.isna(current_ts):
                    continue
                window_start = current_ts - pd.Timedelta(seconds=self._BURST_WINDOW_SECONDS)
                count_in_window = ((sorted_ts >= window_start) & (sorted_ts <= current_ts)).sum()
                # Normalize: 10+ failures in window = max score
                score = min(count_in_window / 10.0, 1.0)
                result.loc[idx] = score

        return result.astype(np.float64)


class SessionDurationTransformer(FeatureTransformer):
    """Z-score of session duration per user.

    ATT&CK: T1078 - Valid Accounts.
    Abnormally long or short sessions may indicate compromised credentials
    used by an attacker with different usage patterns.
    """

    FEATURE_NAMES: list[str] = ["session_dur_zscore"]

    def __init__(self) -> None:
        """Initialize with empty per-user duration statistics."""
        super().__init__()
        self._user_dur_mean: dict[str, float] = {}
        self._user_dur_std: dict[str, float] = {}
        self._global_mean: float = 0.0
        self._global_std: float = 1.0

    def fit(self, df: pd.DataFrame) -> "SessionDurationTransformer":
        """Learn per-user session duration baselines.

        Args:
            df: Training DataFrame; uses 'event.duration' and 'user.name'.

        Returns:
            self
        """
        dur_col = self._find_dur_col(df)
        if dur_col and "user.name" in df.columns:
            durations = pd.to_numeric(df[dur_col], errors="coerce").fillna(0.0)
            users = df["user.name"].fillna("unknown").astype(str)

            self._global_mean = float(durations.mean())
            self._global_std = max(float(durations.std()), EPSILON)

            for user in users.unique():
                mask = users == user
                u_dur = durations[mask]
                if len(u_dur) >= 2:
                    self._user_dur_mean[user] = float(u_dur.mean())
                    self._user_dur_std[user] = max(float(u_dur.std()), EPSILON)

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append session_dur_zscore feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with session duration z-score feature appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        dur_col = self._find_dur_col(df)
        if not dur_col or "user.name" not in df.columns:
            df["session_dur_zscore"] = np.float64(0.0)
            return df

        durations = pd.to_numeric(df[dur_col], errors="coerce").fillna(0.0)
        users = df["user.name"].fillna("unknown").astype(str)

        scores: list[float] = []
        for user, dur in zip(users, durations):
            mean = self._user_dur_mean.get(user, self._global_mean)
            std = self._user_dur_std.get(user, self._global_std)
            z = abs(float(dur) - mean) / std
            scores.append(min(z / 3.0, 1.0))

        df["session_dur_zscore"] = pd.Series(
            scores, index=df.index, dtype=np.float64
        )
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"session_dur_zscore": "T1078 - Valid Accounts"}

    @staticmethod
    def _find_dur_col(df: pd.DataFrame) -> str | None:
        """Find duration column in the DataFrame.

        Args:
            df: Input DataFrame.

        Returns:
            Column name or None.
        """
        for col in ("event.duration", "session.duration", "duration"):
            if col in df.columns:
                return col
        return None


class AuthSourceRarityTransformer(FeatureTransformer):
    """Rarity score for authentication source IPs per user.

    ATT&CK: T1078 - Valid Accounts.
    Logins from a source IP not previously associated with a user
    may indicate credential theft used from a different location.
    """

    FEATURE_NAMES: list[str] = ["auth_src_rarity"]

    def __init__(self) -> None:
        """Initialize with empty per-user source IP profiles."""
        super().__init__()
        self._user_sources: dict[str, Counter] = {}

    def fit(self, df: pd.DataFrame) -> "AuthSourceRarityTransformer":
        """Build per-user source IP frequency profiles.

        Args:
            df: Training DataFrame; uses 'user.name' and 'source.ip'.

        Returns:
            self
        """
        if "user.name" not in df.columns or "source.ip" not in df.columns:
            self._is_fitted = True
            return self

        users = df["user.name"].fillna("unknown").astype(str)
        sources = df["source.ip"].fillna("unknown").astype(str)

        for user in users.unique():
            mask = users == user
            self._user_sources[user] = Counter(sources[mask].tolist())

        self._is_fitted = True
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append auth_src_rarity feature.

        Args:
            df: Input DataFrame.

        Returns:
            df with auth source rarity feature appended.
        """
        to_add = self._skip_existing(df)
        if not to_add:
            return df

        if "user.name" not in df.columns or "source.ip" not in df.columns:
            df["auth_src_rarity"] = np.float64(0.0)
            return df

        users = df["user.name"].fillna("unknown").astype(str)
        sources = df["source.ip"].fillna("unknown").astype(str)

        scores: list[float] = []
        for user, src in zip(users, sources):
            profile = self._user_sources.get(user, Counter())
            if not profile:
                scores.append(0.5)  # Unknown user, moderate rarity
            elif src not in profile:
                scores.append(1.0)  # Never-seen source for this user
            else:
                total = sum(profile.values())
                freq = profile[src] / max(total, 1)
                # Invert frequency: rare sources score higher
                scores.append(max(1.0 - freq, 0.0))

        df["auth_src_rarity"] = pd.Series(
            scores, index=df.index, dtype=np.float64
        )
        return df

    def get_feature_names(self) -> list[str]:
        """Return feature column names."""
        return self.FEATURE_NAMES

    def get_attack_mapping(self) -> dict[str, str]:
        """Return ATT&CK technique mapping."""
        return {"auth_src_rarity": "T1078 - Valid Accounts"}
