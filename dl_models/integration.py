"""
Unified interface for deep learning anomaly detection models.

Provides DLModelRegistry that presents DL models with the same API pattern
as Agent 1's statistical model ensemble, allowing interchangeable use in
the detection pipeline.
"""

from __future__ import annotations

import logging
from typing import Any

from dl_models.base import DLAnomalyModel

logger = logging.getLogger(__name__)

# Model name -> (module_path, class_name)
_MODEL_MAP: dict[str, tuple[str, str]] = {
    "temporal_ae": ("dl_models.temporal_ae", "TemporalAutoencoder"),
    "process_graph": ("dl_models.process_graph", "ProcessTreeAnomalyDetector"),
    "contrastive": ("dl_models.contrastive", "ContrastiveEntityLearner"),
}


class DLModelRegistry:
    """Registry that presents DL models with the same API as Agent 1's ensemble.

    Provides lazy-loaded access to all DL anomaly detection models by name.
    """

    def get_model(self, name: str, **config: Any) -> DLAnomalyModel:
        """Instantiate a DL model by name with optional config overrides.

        Args:
            name: Model identifier (one of available_models()).
            **config: Keyword arguments passed to the model constructor.

        Returns:
            Instantiated DLAnomalyModel subclass.

        Raises:
            KeyError: If name is not a registered model.
            ImportError: If PyTorch or model module cannot be imported.
        """
        if name not in _MODEL_MAP:
            raise KeyError(
                f"Unknown DL model: {name!r}. "
                f"Available: {self.available_models()}"
            )

        mod_path, cls_name = _MODEL_MAP[name]
        import importlib

        module = importlib.import_module(mod_path)
        cls = getattr(module, cls_name)
        instance = cls(**config)
        logger.info("Instantiated DL model %s (%s)", name, cls_name)
        return instance

    def available_models(self) -> list[str]:
        """Return list of registered DL model names.

        Returns:
            List of model name strings: ["temporal_ae", "process_graph", "contrastive"].
        """
        return list(_MODEL_MAP.keys())
