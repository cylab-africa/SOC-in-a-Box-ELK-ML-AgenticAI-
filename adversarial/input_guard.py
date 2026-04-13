"""
Input validation and anomaly-of-anomaly detection for the ML pipeline.

Validates feature vectors before they reach detection models, guarding against
data pipeline failures, adversarial inputs, and sensor tampering.

MITRE ATT&CK: T1562 (Impair Defenses), T1565 (Data Manipulation)
"""

import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

SIGMA_THRESHOLD = 5.0
MARGIN_MULTIPLIER = 0.1
OUTPUT_DIR = Path("results")
OUTPUT_FILE = OUTPUT_DIR / "input_anomalies.jsonl"


@dataclass
class InputCheckResult:
    """Result of input validation for a batch of feature vectors.

    Attributes:
        flagged_rows: Boolean mask indicating which rows are suspicious.
        flag_reasons: Per-row list of flag reason strings.
        out_of_bounds_features: Per-row dict mapping feature index to sigma distance.
        nan_inf_rows: Indices of rows with NaN or Inf values.
        zero_rows: Indices of all-zero rows.
        total_rows: Total number of rows checked.
        flagged_count: Number of rows flagged.
    """

    flagged_rows: np.ndarray
    flag_reasons: list[list[str]]
    out_of_bounds_features: list[dict[int, float]]
    nan_inf_rows: list[int]
    zero_rows: list[int]
    total_rows: int
    flagged_count: int


class InputGuard:
    """Validates feature vectors before they reach anomaly detection models.

    Learns the expected feature distribution from training data and flags
    inputs that deviate significantly, which may indicate adversarial manipulation
    or data pipeline failures.

    MITRE ATT&CK: T1562.001 (Disable or Modify Tools), T1565.001 (Stored Data Manipulation)
    """

    def __init__(self) -> None:
        """Initialize InputGuard with empty learned statistics."""
        self.feature_mins: np.ndarray | None = None
        self.feature_maxs: np.ndarray | None = None
        self.feature_means: np.ndarray | None = None
        self.feature_stds: np.ndarray | None = None
        self.feature_q1: np.ndarray | None = None
        self.feature_q3: np.ndarray | None = None
        self.feature_iqr: np.ndarray | None = None
        self.n_features: int = 0
        self._fitted: bool = False

    def fit(self, X_train: np.ndarray) -> "InputGuard":
        """Learn feature bounds and distributions from training data.

        Args:
            X_train: Training feature matrix of shape (n_samples, n_features).

        Returns:
            Self, for method chaining.
        """
        if X_train.ndim != 2:
            raise ValueError(f"X_train must be 2D, got shape {X_train.shape}")

        self.feature_mins = X_train.min(axis=0)
        self.feature_maxs = X_train.max(axis=0)
        self.feature_means = X_train.mean(axis=0)
        self.feature_stds = X_train.std(axis=0)
        self.feature_q1 = np.percentile(X_train, 25, axis=0)
        self.feature_q3 = np.percentile(X_train, 75, axis=0)
        self.feature_iqr = self.feature_q3 - self.feature_q1
        self.n_features = X_train.shape[1]
        self._fitted = True

        logger.info(
            json.dumps({
                "event": "input_guard_fitted",
                "n_samples": int(X_train.shape[0]),
                "n_features": self.n_features,
            })
        )
        return self

    def check(self, X: np.ndarray) -> InputCheckResult:
        """Check feature vectors for suspicious inputs and return per-row flags.

        Flags rows for any of the following conditions:
        - Any feature more than SIGMA_THRESHOLD standard deviations from training mean
        - Any feature outside [min - margin, max + margin]
        - NaN or Inf values
        - All-zero rows (likely data pipeline failure)

        Args:
            X: Feature matrix of shape (n_samples, n_features).

        Returns:
            InputCheckResult with per-row flag details.
        """
        if not self._fitted:
            raise RuntimeError("InputGuard must be fitted before calling check()")

        if X.ndim != 2:
            raise ValueError(f"X must be 2D, got shape {X.shape}")

        n_rows = X.shape[0]
        flagged_rows = np.zeros(n_rows, dtype=bool)
        flag_reasons: list[list[str]] = [[] for _ in range(n_rows)]
        out_of_bounds_features: list[dict[int, float]] = [{} for _ in range(n_rows)]
        nan_inf_rows: list[int] = []
        zero_rows: list[int] = []

        # Check for NaN or Inf
        for i in range(n_rows):
            row = X[i]
            if not np.all(np.isfinite(row)):
                flagged_rows[i] = True
                flag_reasons[i].append("nan_or_inf")
                nan_inf_rows.append(i)

        # Check for all-zero rows
        for i in range(n_rows):
            if np.all(X[i] == 0.0):
                flagged_rows[i] = True
                flag_reasons[i].append("all_zero_row")
                zero_rows.append(i)

        # Check sigma bounds and feature range bounds on finite rows
        finite_mask = np.all(np.isfinite(X), axis=1)
        X_finite_idx = np.where(finite_mask)[0]

        if len(X_finite_idx) > 0:
            X_finite = X[X_finite_idx]

            # Sigma distance from training mean
            safe_stds = np.where(self.feature_stds > 0, self.feature_stds, 1.0)
            sigmas = np.abs(X_finite - self.feature_means) / safe_stds

            # Feature range margins
            ranges = self.feature_maxs - self.feature_mins
            margins = ranges * MARGIN_MULTIPLIER
            lower_bounds = self.feature_mins - margins
            upper_bounds = self.feature_maxs + margins

            for local_i, global_i in enumerate(X_finite_idx):
                row = X_finite[local_i]
                row_sigmas = sigmas[local_i]

                # Extreme sigma deviations
                extreme_features = np.where(row_sigmas > SIGMA_THRESHOLD)[0]
                for feat_idx in extreme_features:
                    sigma_val = float(row_sigmas[feat_idx])
                    out_of_bounds_features[global_i][int(feat_idx)] = sigma_val
                    flag_reasons[global_i].append(
                        f"feature_{feat_idx}_sigma_{sigma_val:.1f}"
                    )
                    flagged_rows[global_i] = True

                # Outside observed range with margin
                below_min = row < lower_bounds
                above_max = row > upper_bounds
                for feat_idx in np.where(below_min | above_max)[0]:
                    if int(feat_idx) not in out_of_bounds_features[global_i]:
                        sigma_val = float(row_sigmas[feat_idx])
                        out_of_bounds_features[global_i][int(feat_idx)] = sigma_val
                        flag_reasons[global_i].append(
                            f"feature_{feat_idx}_out_of_range"
                        )
                        flagged_rows[global_i] = True

        result = InputCheckResult(
            flagged_rows=flagged_rows,
            flag_reasons=flag_reasons,
            out_of_bounds_features=out_of_bounds_features,
            nan_inf_rows=nan_inf_rows,
            zero_rows=zero_rows,
            total_rows=n_rows,
            flagged_count=int(flagged_rows.sum()),
        )

        self._log_flagged(X, result)
        return result

    def _log_flagged(self, X: np.ndarray, result: InputCheckResult) -> None:
        """Append flagged input records to the output JSONL file.

        Args:
            X: Original feature matrix.
            result: Check result containing flag details.
        """
        if result.flagged_count == 0:
            return

        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()

        with OUTPUT_FILE.open("a") as fh:
            for i in range(result.total_rows):
                if not result.flagged_rows[i]:
                    continue
                row = X[i]
                record = {
                    "timestamp": timestamp,
                    "row_index": i,
                    "reasons": result.flag_reasons[i],
                    "out_of_bounds_features": {
                        str(k): v
                        for k, v in result.out_of_bounds_features[i].items()
                    },
                    "raw_features": [
                        None if not math.isfinite(v) else float(v)
                        for v in row.tolist()
                    ],
                }
                fh.write(json.dumps(record) + "\n")
