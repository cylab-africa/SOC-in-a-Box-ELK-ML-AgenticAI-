"""Tests for the adversarial/ package (Agent 5).

Validates InputGuard, DriftMonitor, and AttackGenerator functionality.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


class TestInputGuard:
    """Validate input validation and anomaly flagging."""

    def test_fit_records_statistics(self) -> None:
        """InputGuard learns mean/std from training data."""
        from adversarial.input_guard import InputGuard

        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, size=(100, 5))
        guard = InputGuard()
        guard.fit(X_train)

        assert guard.feature_means is not None
        assert guard.feature_stds is not None
        assert guard.feature_means.shape == (5,)

    def test_flags_extreme_values(self) -> None:
        """InputGuard flags values beyond 5 sigma."""
        from adversarial.input_guard import InputGuard

        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, size=(200, 3))
        guard = InputGuard()
        guard.fit(X_train)

        # Create extreme test input
        X_test = np.array([[0.0, 0.0, 100.0]])  # 100-sigma on feature 2
        result = guard.check(X_test)

        assert result.flagged_count > 0

    def test_accepts_normal_input(self) -> None:
        """InputGuard does not flag normal-range inputs."""
        from adversarial.input_guard import InputGuard

        rng = np.random.default_rng(42)
        X_train = rng.normal(0, 1, size=(200, 3))
        guard = InputGuard()
        guard.fit(X_train)

        X_test = rng.normal(0, 1, size=(10, 3))
        result = guard.check(X_test)

        # Most should pass (allow for some statistical noise)
        assert result.flagged_count <= 2


class TestDriftMonitor:
    """Validate distribution drift detection."""

    def test_no_drift_same_distribution(self) -> None:
        """No drift detected when reference and test come from same distribution."""
        from adversarial.drift_monitor import DriftMonitor

        rng = np.random.default_rng(42)
        feat_names = [f"f{i}" for i in range(4)]
        X_ref = rng.normal(0, 1, size=(2000, 4))
        X_test = rng.normal(0, 1, size=(1000, 4))

        monitor = DriftMonitor()
        monitor.set_reference(X_ref, feat_names)
        report = monitor.check_drift(X_test, "process")

        assert not report.retrain_recommended

    def test_detects_mean_shift(self) -> None:
        """Drift detected when test distribution has shifted mean."""
        from adversarial.drift_monitor import DriftMonitor

        rng = np.random.default_rng(42)
        feat_names = [f"f{i}" for i in range(4)]
        X_ref = rng.normal(0, 1, size=(1000, 4))
        X_test = rng.normal(5, 1, size=(1000, 4))  # Mean shifted by 5

        monitor = DriftMonitor()
        monitor.set_reference(X_ref, feat_names)
        report = monitor.check_drift(X_test, "process")

        assert report.retrain_recommended


class TestAttackGenerator:
    """Validate synthetic attack scenario generation."""

    def test_generates_all_scenarios(self) -> None:
        """AttackGenerator produces DataFrames for all 8 scenarios."""
        from adversarial.synthetic_attacks import AttackGenerator

        rng = np.random.default_rng(42)
        bg = pd.DataFrame(
            rng.normal(0, 1, (100, 3)),
            columns=["cmd_entropy", "cmd_length", "proc_tree_depth"],
        )
        gen = AttackGenerator(random_seed=42)
        scenarios = gen.available_scenarios()

        assert len(scenarios) == 8
        for scenario in scenarios:
            df = gen.generate(scenario, 50, bg, attack_density=0.1)
            assert len(df) > 0, f"Empty DataFrame for scenario: {scenario}"
            assert "is_attack" in df.columns

    def test_scenario_has_attack_labels(self) -> None:
        """Each scenario includes ATT&CK technique labels."""
        from adversarial.synthetic_attacks import AttackGenerator

        rng = np.random.default_rng(42)
        bg = pd.DataFrame(
            rng.normal(0, 1, (100, 3)),
            columns=["cmd_entropy", "cmd_length", "proc_tree_depth"],
        )
        gen = AttackGenerator(random_seed=42)

        for scenario in gen.available_scenarios():
            df = gen.generate(scenario, 50, bg, attack_density=0.1)
            attack_rows = df[df["is_attack"]]
            assert all(attack_rows["attack_technique"].str.startswith("T"))
