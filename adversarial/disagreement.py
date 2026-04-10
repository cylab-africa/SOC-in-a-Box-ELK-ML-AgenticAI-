"""
Ensemble disagreement monitoring for anomaly detection models.

When multiple models in an ensemble disagree strongly on a sample's
anomaly score, it may indicate adversarial manipulation targeting
a specific model's blind spot.

ATT&CK alignment: detects evasion attempts where one model is fooled
but others are not (defense in depth monitoring).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class DisagreementReport:
    """Report of ensemble disagreement analysis."""

    n_samples: int = 0
    n_high_disagreement: int = 0
    mean_disagreement: float = 0.0
    max_disagreement: float = 0.0
    flagged_indices: list[int] = field(default_factory=list)


class DisagreementMonitor:
    """Monitor disagreement between ensemble model scores.

    Flags samples where the range (max - min) of individual model scores
    exceeds a configurable threshold, indicating potential adversarial input.
    """

    def __init__(self, threshold: float = 0.4) -> None:
        """Initialize disagreement monitor.

        Args:
            threshold: Score range above which a sample is flagged.
        """
        self._threshold = threshold

    def check(
        self,
        score_matrix: np.ndarray | dict[str, np.ndarray],
    ) -> DisagreementReport:
        """Analyze disagreement across model scores per sample.

        Args:
            score_matrix: Either an array of shape (n_samples, n_models) where
                each column is one model's normalized [0,1] anomaly scores,
                or a dict mapping model names to 1-D score arrays.

        Returns:
            DisagreementReport with flagged samples.
        """
        if isinstance(score_matrix, dict):
            if len(score_matrix) < 2:
                n = len(next(iter(score_matrix.values()))) if score_matrix else 0
                return DisagreementReport(n_samples=n)
            arrays = list(score_matrix.values())
            score_matrix = np.column_stack(arrays)

        if score_matrix.ndim != 2 or score_matrix.shape[1] < 2:
            return DisagreementReport(n_samples=score_matrix.shape[0])

        # Use std across models per sample as disagreement measure
        stds = np.std(score_matrix, axis=1)
        flagged = np.where(stds > self._threshold)[0].tolist()

        return DisagreementReport(
            n_samples=score_matrix.shape[0],
            n_high_disagreement=len(flagged),
            mean_disagreement=float(np.mean(stds)),
            max_disagreement=float(np.max(stds)),
            flagged_indices=flagged,
        )
