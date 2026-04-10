"""
Security-aware feature engineering package for Linux anomaly detection.

All transformers inherit from FeatureTransformer (base.py) and map to
MITRE ATT&CK techniques. Features are float64, NaN-safe, and idempotent.
"""

from features.base import FeatureTransformer
from features.process_features import (
    CommandLineEntropyTransformer,
    ProcessRarityTransformer,
    ProcessTreeTransformer,
    TemporalCyclicalTransformer,
)
from features.network_features import (
    DestinationRarityTransformer,
    DNSEntropyTransformer,
    BeaconDetectorTransformer,
)
from features.auth_features import (
    LoginTimeTransformer,
    PrivilegeEscalationTransformer,
    AuthFailureTransformer,
)

# Registry: all available transformers keyed by short name
TRANSFORMER_REGISTRY: dict[str, type[FeatureTransformer]] = {
    "cmd_entropy": CommandLineEntropyTransformer,
    "process_tree": ProcessTreeTransformer,
    "process_rarity": ProcessRarityTransformer,
    "temporal_cyclical": TemporalCyclicalTransformer,
    "dest_rarity": DestinationRarityTransformer,
    "dns_entropy": DNSEntropyTransformer,
    "beacon_detector": BeaconDetectorTransformer,
    "login_time": LoginTimeTransformer,
    "privesc": PrivilegeEscalationTransformer,
    "auth_failure": AuthFailureTransformer,
}

__all__ = [
    "FeatureTransformer",
    "CommandLineEntropyTransformer",
    "ProcessRarityTransformer",
    "ProcessTreeTransformer",
    "TemporalCyclicalTransformer",
    "DestinationRarityTransformer",
    "DNSEntropyTransformer",
    "BeaconDetectorTransformer",
    "LoginTimeTransformer",
    "PrivilegeEscalationTransformer",
    "AuthFailureTransformer",
    "TRANSFORMER_REGISTRY",
]
