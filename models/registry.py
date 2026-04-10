"""
Model registry and per-job model selection.

Maps ML job names to the appropriate model configurations so that
model_manager.py can automatically select the right ensemble for each
detection job.

ATT&CK alignment: each job is mapped to relevant technique IDs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from models.base_model import AnomalyModel
from models.pyod_models import ECODModel, COPODModel, AutoEncoderModel, IForestModel
from models.ensemble import EnsembleModel, DEFAULT_WEIGHTS

logger = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """Configuration for which models to use for a specific job.

    Args:
        model_classes: List of AnomalyModel subclasses to instantiate.
        weights: Per-model weight overrides for this job.
        attack_techniques: MITRE ATT&CK techniques this job targets.
    """

    model_classes: list[type[AnomalyModel]]
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    attack_techniques: list[str] = field(default_factory=list)


# Registry: ML job name -> ModelConfig
MODEL_REGISTRY: dict[str, ModelConfig] = {
    "v3_linux_anomalous_process_all_hosts": ModelConfig(
        model_classes=[IForestModel, ECODModel, COPODModel, AutoEncoderModel],
        weights={"iforest": 0.20, "ecod": 0.30, "copod": 0.20, "autoencoder": 0.30},
        attack_techniques=["T1059", "T1036", "T1055"],
    ),
    "v3_rare_process_by_host_linux": ModelConfig(
        model_classes=[ECODModel, COPODModel],
        weights={"ecod": 0.50, "copod": 0.50},
        attack_techniques=["T1036", "T1078"],
    ),
    "v3_linux_anomalous_network_activity": ModelConfig(
        model_classes=[ECODModel, COPODModel, AutoEncoderModel],
        weights={"ecod": 0.30, "copod": 0.30, "autoencoder": 0.40},
        attack_techniques=["T1071", "T1048", "T1041"],
    ),
    "v3_linux_anomalous_network_port_activity": ModelConfig(
        model_classes=[ECODModel, COPODModel],
        weights={"ecod": 0.45, "copod": 0.55},
        attack_techniques=["T1071", "T1046"],
    ),
    "v3_linux_anomalous_user_name": ModelConfig(
        model_classes=[ECODModel, COPODModel],
        weights={"ecod": 0.50, "copod": 0.50},
        attack_techniques=["T1078", "T1136"],
    ),
    "v3_linux_rare_metadata_process": ModelConfig(
        model_classes=[ECODModel, COPODModel, AutoEncoderModel],
        weights={"ecod": 0.30, "copod": 0.35, "autoencoder": 0.35},
        attack_techniques=["T1059", "T1036"],
    ),
    "v3_linux_rare_metadata_user": ModelConfig(
        model_classes=[ECODModel, COPODModel],
        weights={"ecod": 0.50, "copod": 0.50},
        attack_techniques=["T1078", "T1548"],
    ),
    "v3_linux_rare_sudo_activity": ModelConfig(
        model_classes=[ECODModel, COPODModel, AutoEncoderModel],
        weights={"ecod": 0.25, "copod": 0.25, "autoencoder": 0.50},
        attack_techniques=["T1548", "T1078"],
    ),
    "v3_linux_rare_discovery_activity": ModelConfig(
        model_classes=[ECODModel, COPODModel],
        weights={"ecod": 0.50, "copod": 0.50},
        attack_techniques=["T1082", "T1083", "T1046"],
    ),
}


def get_models_for_job(job_name: str) -> EnsembleModel:
    """Create a configured EnsembleModel for a given ML job.

    Falls back to a default three-model ensemble if the job is not
    in the registry.

    Args:
        job_name: ML job identifier (e.g. 'v3_linux_anomalous_process_all_hosts').

    Returns:
        EnsembleModel with properly weighted constituent models.
    """
    config = MODEL_REGISTRY.get(job_name)
    if config is None:
        logger.warning(
            "No model config for job '%s', using default ensemble", job_name
        )
        config = ModelConfig(
            model_classes=[ECODModel, COPODModel, AutoEncoderModel],
            weights=dict(DEFAULT_WEIGHTS),
            attack_techniques=[],
        )

    models: list[AnomalyModel] = []
    for cls in config.model_classes:
        try:
            models.append(cls())
        except ImportError:
            logger.warning("Could not instantiate %s (missing dependency)", cls.__name__)

    ensemble = EnsembleModel(models=models, weights=config.weights)
    ensemble.attack_techniques = config.attack_techniques
    return ensemble
