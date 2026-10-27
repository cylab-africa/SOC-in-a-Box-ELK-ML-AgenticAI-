"""
Adversarial hardening package for the Linux threat detection pipeline.

Provides input validation, concept drift monitoring, synthetic ATT&CK attack
generation, model robustness testing, and ensemble disagreement monitoring.

MITRE ATT&CK coverage: T1059, T1048, T1053, T1078, T1046, T1018, T1021, T1568
"""

from adversarial.disagreement import DisagreementMonitor
from adversarial.drift_monitor import DriftMonitor, DriftReport
from adversarial.input_guard import InputCheckResult, InputGuard
from adversarial.robustness_tests import RobustnessTest
from adversarial.synthetic_attacks import AttackGenerator

__all__ = [
    "InputGuard",
    "InputCheckResult",
    "DriftMonitor",
    "DriftReport",
    "AttackGenerator",
    "RobustnessTest",
    "DisagreementMonitor",
]
