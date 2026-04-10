"""
Model versioning and manifest management.

Tracks model versions, training metadata, and performance metrics
in a manifest.json file alongside saved model artifacts.

ATT&CK alignment: versioning ensures audit trail for detection capability changes.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST_FILENAME: str = "manifest.json"


def create_manifest(
    model_dir: Path,
    job_name: str,
    model_names: list[str],
    training_samples: int,
    training_features: int,
    attack_techniques: list[str],
    metrics: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Create and write a model version manifest.

    Args:
        model_dir: Directory containing saved model files.
        job_name: ML job name this model set serves.
        model_names: Names of models in the ensemble.
        training_samples: Number of training samples used.
        training_features: Number of features in the training matrix.
        attack_techniques: MITRE ATT&CK technique IDs covered.
        metrics: Optional performance metrics dict.

    Returns:
        The manifest dict that was written.
    """
    version = _compute_version(model_dir)
    manifest: dict[str, Any] = {
        "version": version,
        "job_name": job_name,
        "model_names": model_names,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "training_samples": training_samples,
        "training_features": training_features,
        "attack_techniques": attack_techniques,
        "metrics": metrics or {},
    }

    model_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = model_dir / MANIFEST_FILENAME
    manifest_path.write_text(json.dumps(manifest, indent=2))
    logger.info("Model manifest written: %s (version=%s)", manifest_path, version)
    return manifest


def load_manifest(model_dir: Path) -> dict[str, Any] | None:
    """Load an existing model manifest.

    Args:
        model_dir: Directory containing manifest.json.

    Returns:
        Manifest dict or None if not found.
    """
    manifest_path = model_dir / MANIFEST_FILENAME
    if not manifest_path.exists():
        return None
    return json.loads(manifest_path.read_text())


def _compute_version(model_dir: Path) -> str:
    """Compute a content-based version hash from model files.

    Args:
        model_dir: Directory containing model files.

    Returns:
        Short hex hash string identifying this model version.
    """
    hasher = hashlib.sha256()
    if model_dir.exists():
        for fpath in sorted(model_dir.rglob("*")):
            if fpath.is_file() and fpath.name != MANIFEST_FILENAME:
                hasher.update(fpath.read_bytes())
    return hasher.hexdigest()[:12]
