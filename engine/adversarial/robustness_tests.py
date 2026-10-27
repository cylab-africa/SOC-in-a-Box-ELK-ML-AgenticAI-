"""
Model robustness tests via input perturbation and temporal stability.

Tests that models produce stable scores under small feature perturbations
and do not rely on fragile feature interactions that adversaries can exploit.

ATT&CK alignment: guards against evasion via T1059 (obfuscation) and
T1036 (masquerading) by verifying model stability.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from models.base_model import AnomalyModel

logger = logging.getLogger(__name__)


@dataclass
class RobustnessResult:
    """Result of a single robustness test run."""

    test_name: str
    passed: bool
    max_score_delta: float
    mean_score_delta: float
    detail: str = ""


class RobustnessTest:
    """Robustness testing for anomaly detection models.

    Verifies that small perturbations to input features do not cause
    large swings in anomaly scores — a sign of adversarial vulnerability.
    """

    def __init__(
        self,
        perturbation_scale: float = 0.01,
        max_allowed_delta: float = 0.10,
    ) -> None:
        """Initialize robustness tester.

        Args:
            perturbation_scale: Scale of Gaussian noise to add (fraction of std).
            max_allowed_delta: Maximum acceptable score change per sample.
        """
        self._perturbation_scale = perturbation_scale
        self._max_allowed_delta = max_allowed_delta

    def test_perturbation_stability(
        self,
        model: AnomalyModel,
        X: np.ndarray,
        n_trials: int = 10,
    ) -> RobustnessResult:
        """Test score stability under small input perturbations.

        Args:
            model: Model with decision_function(X) -> np.ndarray.
            X: Feature matrix to perturb.
            n_trials: Number of perturbation trials.

        Returns:
            RobustnessResult with pass/fail and delta statistics.
        """
        base_scores = model.decision_function(X)
        max_deltas: list[float] = []
        mean_deltas: list[float] = []

        for _ in range(n_trials):
            noise = np.random.default_rng().normal(
                0, self._perturbation_scale, size=X.shape
            )
            X_perturbed = X + noise
            perturbed_scores = model.decision_function(X_perturbed)
            deltas = np.abs(perturbed_scores - base_scores)
            max_deltas.append(float(np.max(deltas)))
            mean_deltas.append(float(np.mean(deltas)))

        overall_max = max(max_deltas)
        overall_mean = float(np.mean(mean_deltas))
        passed = overall_max <= self._max_allowed_delta

        return RobustnessResult(
            test_name="perturbation_stability",
            passed=passed,
            max_score_delta=overall_max,
            mean_score_delta=overall_mean,
            detail=f"max_delta={overall_max:.4f}, threshold={self._max_allowed_delta}",
        )

    def test_temporal_stability(
        self,
        model: AnomalyModel,
        X: np.ndarray,
        n_repeats: int = 5,
    ) -> RobustnessResult:
        """Test that repeated scoring of identical input produces identical output.

        Args:
            model: Model with decision_function(X) -> np.ndarray.
            X: Feature matrix.
            n_repeats: Number of identical scoring runs.

        Returns:
            RobustnessResult checking for non-determinism.
        """
        scores_list = [model.decision_function(X) for _ in range(n_repeats)]
        deltas = [
            float(np.max(np.abs(s - scores_list[0])))
            for s in scores_list[1:]
        ]
        max_delta = max(deltas) if deltas else 0.0
        passed = max_delta < 1e-6  # Should be exactly reproducible

        return RobustnessResult(
            test_name="temporal_stability",
            passed=passed,
            max_score_delta=max_delta,
            mean_score_delta=float(np.mean(deltas)) if deltas else 0.0,
            detail=f"max_delta={max_delta:.8f} (expected ~0)",
        )

    def run_all(self, model: AnomalyModel, X: np.ndarray) -> list[RobustnessResult]:
        """Run all robustness tests on a model.

        Args:
            model: Model with decision_function(X) -> np.ndarray.
            X: Feature matrix.

        Returns:
            List of RobustnessResult objects.
        """
        results = [
            self.test_perturbation_stability(model, X),
            self.test_temporal_stability(model, X),
            self.test_feature_importance_attack(model, X),
        ]
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            logger.info("%s: [%s] %s", r.test_name, status, r.detail)
        return results

    def test_feature_importance_attack(
        self,
        model: AnomalyModel,
        X: np.ndarray,
        top_k: int = 3,
    ) -> RobustnessResult:
        """Test if zeroing top-influence features causes excessive score drop.

        An adversary who knows which features matter most could selectively
        suppress them.  This test zeros the top-k most influential features
        and checks that scores do not collapse entirely.

        Args:
            model: Model with decision_function(X) -> np.ndarray.
            X: Feature matrix.
            top_k: Number of most influential features to zero out.

        Returns:
            RobustnessResult with pass/fail.
        """
        base_scores = model.decision_function(X)
        n_features = X.shape[1]
        top_k = min(top_k, n_features)

        # Estimate feature importance by mean absolute score change
        importances = np.zeros(n_features, dtype=np.float64)
        for f_idx in range(n_features):
            X_zeroed = X.copy()
            X_zeroed[:, f_idx] = 0.0
            zeroed_scores = model.decision_function(X_zeroed)
            importances[f_idx] = float(np.mean(np.abs(zeroed_scores - base_scores)))

        # Zero out the top-k features simultaneously
        top_features = np.argsort(importances)[-top_k:]
        X_attacked = X.copy()
        for f_idx in top_features:
            X_attacked[:, f_idx] = 0.0

        attacked_scores = model.decision_function(X_attacked)
        delta = np.abs(attacked_scores - base_scores)
        max_delta = float(np.max(delta))
        mean_delta = float(np.mean(delta))

        # Model should not lose more than 80% of its score on average
        mean_base = float(np.mean(base_scores))
        mean_attacked = float(np.mean(attacked_scores))
        if mean_base > 0.01:
            score_retention = mean_attacked / mean_base
        else:
            score_retention = 1.0

        passed = score_retention >= 0.2  # retain at least 20% of scoring power

        return RobustnessResult(
            test_name="feature_importance_attack",
            passed=passed,
            max_score_delta=max_delta,
            mean_score_delta=mean_delta,
            detail=(
                f"top_{top_k}_features={top_features.tolist()}, "
                f"score_retention={score_retention:.2%}"
            ),
        )
