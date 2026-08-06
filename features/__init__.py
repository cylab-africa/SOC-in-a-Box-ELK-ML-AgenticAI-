"""
Security-aware feature engineering package for Linux anomaly detection.

All transformers inherit from FeatureTransformer (base.py) and map to
MITRE ATT&CK techniques. Features are float64, NaN-safe, and idempotent.
"""

from features.auth_features import (
    AuthFailureTransformer,
    AuthSourceRarityTransformer,
    LoginTimeTransformer,
    PrivilegeEscalationTransformer,
    SessionDurationTransformer,
)
from features.base import FeatureTransformer
from features.network_features import (
    BeaconDetectorTransformer,
    BytesRatioTransformer,
    DestinationRarityTransformer,
    DNSEntropyTransformer,
    NewDestTransformer,
)
from features.process_features import (
    CommandLineEntropyTransformer,
    ProcessRarityTransformer,
    ProcessTreeTransformer,
    TemporalCyclicalTransformer,
)
from features.temporal_features import (
    EventCountTransformer,
    TransitionSurpriseTransformer,
    VolumeZscoreTransformer,
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
    "bytes_ratio": BytesRatioTransformer,
    "new_dest": NewDestTransformer,
    "login_time": LoginTimeTransformer,
    "privesc": PrivilegeEscalationTransformer,
    "auth_failure": AuthFailureTransformer,
    "session_duration": SessionDurationTransformer,
    "auth_src_rarity": AuthSourceRarityTransformer,
    "event_count": EventCountTransformer,
    "volume_zscore": VolumeZscoreTransformer,
    "transition_surprise": TransitionSurpriseTransformer,
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
    "BytesRatioTransformer",
    "NewDestTransformer",
    "LoginTimeTransformer",
    "PrivilegeEscalationTransformer",
    "AuthFailureTransformer",
    "SessionDurationTransformer",
    "AuthSourceRarityTransformer",
    "EventCountTransformer",
    "VolumeZscoreTransformer",
    "TransitionSurpriseTransformer",
    "TRANSFORMER_REGISTRY",
]
