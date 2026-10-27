"""
Unified anomaly detection model package.

Provides AnomalyModel ABC, PyOD-backed models (ECOD, COPOD, AutoEncoder),
ensemble scoring, per-job model selection, and model versioning.

All models normalize anomaly scores to [0.0, 1.0].
"""

from models.base_model import AnomalyModel
from models.ensemble import EnsembleModel
from models.pyod_models import AutoEncoderModel, COPODModel, ECODModel, IForestModel
from models.registry import MODEL_REGISTRY, get_models_for_job

__all__ = [
    "AnomalyModel",
    "ECODModel",
    "COPODModel",
    "AutoEncoderModel",
    "IForestModel",
    "EnsembleModel",
    "MODEL_REGISTRY",
    "get_models_for_job",
]
