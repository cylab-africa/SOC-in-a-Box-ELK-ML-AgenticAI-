"""
Feature distribution drift tracking using PSI and KS-test.

Monitors when the incoming data distribution diverges from the training
distribution, which can indicate concept drift, infrastructure changes, or
an attacker manipulating telemetry to cause model staleness.

MITRE ATT&CK: T1562 (Impair Defenses), T1565 (Data Manipulation)

PSI thresholds (standard industry convention):
  PSI < 0.10  -> no significant drift (stable)
  PSI 0.10-0.25 -> moderate drift (monitor)
  PSI > 0.25  -> significant drift (retrain recommended)
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import numpy as np
from scipy import stats

logger = logging.getLogger(__name__)

PSI_BINS = 10
PSI_MODERATE_THRESHOLD = 0.10
PSI_CRITICAL_THRESHOLD = 0.25
KS_SIGNIFICANCE_LEVEL = 0.01
PSI_EPSILON = 1e-6


@dataclass
class FeatureDriftInfo:
    """Drift statistics for a single feature.

    Attributes:
        psi: Population Stability Index.
        ks_statistic: KS test statistic.
        ks_pvalue: KS test p-value.
        status: One of 'stable', 'moderate', 'drifted'.
    """

    psi: float
    ks_statistic: float
    ks_pvalue: float
    status: str


@dataclass
class DriftReport:
    """Complete drift analysis report for a data window.

    Attributes:
        timestamp: ISO-8601 UTC timestamp.
        data_group: Logical name for the data type (e.g. 'process', 'network').
        overall_psi: Mean PSI across all features.
        drift_level: One of 'stable', 'moderate', 'significant'.
        retrain_recommended: True when overall_psi exceeds critical threshold.
        feature_drift: Per-feature drift details keyed by feature name.
        window_size: Number of samples in the current window.
        reference_size: Number of samples in the reference distribution.
    """

    timestamp: str
    data_group: str
    overall_psi: float
    drift_level: str
    retrain_recommended: bool
    feature_drift: dict[str, FeatureDriftInfo]
    window_size: int
    reference_size: int

    def to_dict(self) -> dict:
        """Serialize the report to a JSON-compatible dictionary.

        Returns:
            Dictionary representation suitable for json.dumps.
        """
        return {
            "timestamp": self.timestamp,
            "data_group": self.data_group,
            "overall_psi": round(self.overall_psi, 6),
            "drift_level": self.drift_level,
            "retrain_recommended": self.retrain_recommended,
            "feature_drift": {
                name: {
                    "psi": round(info.psi, 6),
                    "ks_statistic": round(info.ks_statistic, 6),
                    "ks_pvalue": round(info.ks_pvalue, 6),
                    "status": info.status,
                }
                for name, info in self.feature_drift.items()
            },
            "window_size": self.window_size,
            "reference_size": self.reference_size,
        }

    def to_json(self) -> str:
        """Serialize the report to a JSON string.

        Returns:
            Indented JSON string.
        """
        return json.dumps(self.to_dict(), indent=2)


class DriftMonitor:
    """Monitors feature distribution drift between a reference and current window.

    Uses Population Stability Index (PSI) and the Kolmogorov-Smirnov test to
    detect when current data has drifted away from the training distribution.

    MITRE ATT&CK: T1562.001 (Disable or Modify Tools)
    """

    def __init__(self, n_bins: int = PSI_BINS) -> None:
        """Initialize DriftMonitor.

        Args:
            n_bins: Number of histogram bins for PSI calculation.
        """
        self.n_bins = n_bins
        self._reference: np.ndarray | None = None
        self._feature_names: list[str] = []
        self._fitted: bool = False

    def set_reference(
        self, X_reference: np.ndarray, feature_names: list[str]
    ) -> None:
        """Set the reference distribution from training data.

        Args:
            X_reference: Reference feature matrix of shape (n_samples, n_features).
            feature_names: Names for each feature column.
        """
        if X_reference.ndim != 2:
            raise ValueError(
                f"X_reference must be 2D, got shape {X_reference.shape}"
            )
        if len(feature_names) != X_reference.shape[1]:
            raise ValueError(
                f"feature_names length {len(feature_names)} does not match "
                f"n_features {X_reference.shape[1]}"
            )
        self._reference = X_reference.copy()
        self._feature_names = list(feature_names)
        self._fitted = True

        logger.info(
            json.dumps({
                "event": "drift_monitor_reference_set",
                "n_samples": int(X_reference.shape[0]),
                "n_features": int(X_reference.shape[1]),
            })
        )

    def check_drift(
        self, X_current: np.ndarray, data_group: str = "unknown"
    ) -> DriftReport:
        """Compare a current data window against the reference distribution.

        Computes per-feature PSI and KS-test, then aggregates to an overall
        drift level and retraining recommendation.

        Args:
            X_current: Current window feature matrix of shape (n_samples, n_features).
            data_group: Logical label for the data type (e.g. 'process').

        Returns:
            DriftReport with per-feature and overall drift statistics.
        """
        if not self._fitted:
            raise RuntimeError(
                "DriftMonitor must have a reference set before calling check_drift()"
            )
        if X_current.ndim != 2:
            raise ValueError(f"X_current must be 2D, got shape {X_current.shape}")

        feature_drift: dict[str, FeatureDriftInfo] = {}
        psi_values: list[float] = []

        for col_idx, feat_name in enumerate(self._feature_names):
            ref_col = self._reference[:, col_idx]
            cur_col = X_current[:, col_idx]

            psi_val = self._compute_psi(ref_col, cur_col)
            ks_stat, ks_pval = stats.ks_2samp(ref_col, cur_col)

            status = _drift_status(psi_val)
            feature_drift[feat_name] = FeatureDriftInfo(
                psi=psi_val,
                ks_statistic=float(ks_stat),
                ks_pvalue=float(ks_pval),
                status=status,
            )
            psi_values.append(psi_val)

        overall_psi = float(np.mean(psi_values)) if psi_values else 0.0
        drift_level = _drift_status(overall_psi)
        retrain_recommended = overall_psi > PSI_CRITICAL_THRESHOLD

        report = DriftReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            data_group=data_group,
            overall_psi=overall_psi,
            drift_level=drift_level,
            retrain_recommended=retrain_recommended,
            feature_drift=feature_drift,
            window_size=int(X_current.shape[0]),
            reference_size=int(self._reference.shape[0]),
        )

        logger.info(
            json.dumps({
                "event": "drift_check",
                "data_group": data_group,
                "overall_psi": round(overall_psi, 4),
                "drift_level": drift_level,
                "retrain_recommended": retrain_recommended,
            })
        )

        return report

    def _compute_psi(
        self, reference: np.ndarray, current: np.ndarray
    ) -> float:
        """Compute the Population Stability Index between two distributions.

        Args:
            reference: Reference 1D feature array.
            current: Current 1D feature array.

        Returns:
            PSI value (non-negative float; higher = more drift).
        """
        # Build histogram bins from combined range
        combined_min = min(reference.min(), current.min())
        combined_max = max(reference.max(), current.max())

        if combined_min == combined_max:
            # Constant feature — no drift possible
            return 0.0

        bins = np.linspace(combined_min, combined_max, self.n_bins + 1)

        ref_counts, _ = np.histogram(reference, bins=bins)
        cur_counts, _ = np.histogram(current, bins=bins)

        ref_pct = ref_counts / (ref_counts.sum() + PSI_EPSILON)
        cur_pct = cur_counts / (cur_counts.sum() + PSI_EPSILON)

        # Replace zeros to avoid log(0)
        ref_pct = np.where(ref_pct == 0, PSI_EPSILON, ref_pct)
        cur_pct = np.where(cur_pct == 0, PSI_EPSILON, cur_pct)

        psi = float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))
        return max(0.0, psi)


def _drift_status(psi: float) -> str:
    """Map a PSI value to a human-readable drift status string.

    Args:
        psi: Population Stability Index value.

    Returns:
        One of 'stable', 'moderate', or 'drifted'.
    """
    if psi < PSI_MODERATE_THRESHOLD:
        return "stable"
    if psi < PSI_CRITICAL_THRESHOLD:
        return "moderate"
    return "drifted"
