"""
Deep learning anomaly detection models for Linux security monitoring.

All models inherit from DLAnomalyModel (base.py) and produce scores
normalized to [0.0, 1.0]. CPU-only, constrained to 3 GB combined memory.

Requires PyTorch. All imports are lazy to avoid hard dependency at package level.
"""

from dl_models.base import DLAnomalyModel


def _lazy_import(name: str):
    """Lazily import torch-dependent classes."""
    import importlib
    _map = {
        "TemporalAutoencoder": ("dl_models.temporal_ae", "TemporalAutoencoder"),
        "ProcessTreeAnomalyDetector": ("dl_models.process_graph", "ProcessTreeAnomalyDetector"),
        "ContrastiveEntityLearner": ("dl_models.contrastive", "ContrastiveEntityLearner"),
        "DLModelRegistry": ("dl_models.integration", "DLModelRegistry"),
        "SequenceDataset": ("dl_models.data_loaders", "SequenceDataset"),
        "TreeFeatureDataset": ("dl_models.data_loaders", "TreeFeatureDataset"),
        "dataframe_to_numpy": ("dl_models.data_loaders", "dataframe_to_numpy"),
        "get_device": ("dl_models.utils", "get_device"),
        "save_checkpoint": ("dl_models.utils", "save_checkpoint"),
        "load_checkpoint": ("dl_models.utils", "load_checkpoint"),
        "EarlyStopping": ("dl_models.utils", "EarlyStopping"),
    }
    if name in _map:
        mod_path, attr = _map[name]
        mod = importlib.import_module(mod_path)
        return getattr(mod, attr)
    raise AttributeError(f"module 'dl_models' has no attribute {name!r}")


def __getattr__(name: str):
    """Module-level __getattr__ for lazy loading of torch-dependent classes."""
    return _lazy_import(name)


__all__ = [
    "DLAnomalyModel",
    "TemporalAutoencoder",
    "ProcessTreeAnomalyDetector",
    "ContrastiveEntityLearner",
    "DLModelRegistry",
    "SequenceDataset",
    "TreeFeatureDataset",
    "dataframe_to_numpy",
    "get_device",
    "save_checkpoint",
    "load_checkpoint",
    "EarlyStopping",
]
