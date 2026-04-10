"""Shared utilities: device selection, checkpointing, early stopping.

All models must call torch.set_num_threads(4) at import time to honour the
4-core CPU constraint.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import numpy as np
import torch

torch.set_num_threads(4)

logger = logging.getLogger(__name__)

CHECKPOINT_META_FILENAME = "meta.json"


def get_device() -> torch.device:
    """Return the best available compute device (CUDA if present, else CPU).

    Returns:
        A torch.device — always falls back to CPU so models work on
        CPU-only machines.
    """
    if torch.cuda.is_available():
        logger.info("CUDA detected — using GPU")
        return torch.device("cuda")
    logger.info("No CUDA found — using CPU")
    return torch.device("cpu")


class EarlyStopping:
    """Monitor validation loss and signal when training should stop.

    Stops training when the loss has not improved by more than ``min_delta``
    for ``patience`` consecutive epochs.
    """

    def __init__(self, patience: int = 3, min_delta: float = 1e-4) -> None:
        """Initialise early-stopping state.

        Args:
            patience: Number of epochs without improvement before stopping.
            min_delta: Minimum change in loss that counts as an improvement.
        """
        self.patience = patience
        self.min_delta = min_delta
        self.best_loss: float = float("inf")
        self.counter: int = 0
        self.should_stop: bool = False

    def step(self, loss: float) -> bool:
        """Record a new epoch loss and decide whether to stop.

        Args:
            loss: Validation (or training) loss for the current epoch.

        Returns:
            True if training should stop, False otherwise.
        """
        if loss < self.best_loss - self.min_delta:
            self.best_loss = loss
            self.counter = 0
        else:
            self.counter += 1
            if self.counter >= self.patience:
                self.should_stop = True
        return self.should_stop


def save_checkpoint(
    state_dict: dict,
    meta: dict,
    directory: Path,
    filename: str = "model.pt",
) -> None:
    """Save a PyTorch state dict and JSON metadata to a directory.

    Args:
        state_dict: PyTorch model state dict to serialise.
        meta: Arbitrary JSON-serialisable metadata (hyperparams, etc.).
        directory: Target directory; created if it does not exist.
        filename: Name of the .pt file inside ``directory``.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    torch.save(state_dict, directory / filename)
    with open(directory / CHECKPOINT_META_FILENAME, "w") as fh:
        json.dump(meta, fh, indent=2)
    logger.debug(f"Checkpoint written to {directory}")


def load_checkpoint(
    directory: Path,
    filename: str = "model.pt",
) -> tuple[dict, dict]:
    """Load a PyTorch state dict and JSON metadata from a directory.

    Args:
        directory: Directory containing ``filename`` and ``meta.json``.
        filename: Name of the .pt file inside ``directory``.

    Returns:
        Tuple of (state_dict, meta).
    """
    directory = Path(directory)
    state_dict = torch.load(directory / filename, map_location="cpu")
    with open(directory / CHECKPOINT_META_FILENAME) as fh:
        meta = json.load(fh)
    return state_dict, meta


def pad_sequence_batch(
    sequences: list[np.ndarray],
    max_len: int,
    pad_value: float = 0.0,
) -> tuple[np.ndarray, np.ndarray]:
    """Pad a list of variable-length 2-D arrays into a uniform 3-D batch.

    Args:
        sequences: List of arrays each shaped (seq_len_i, n_features).
        max_len: Target sequence length; longer sequences are truncated.
        pad_value: Value used for padding shorter sequences.

    Returns:
        Tuple of:
        - padded: ndarray of shape (batch, max_len, n_features).
        - mask: boolean ndarray of shape (batch, max_len) — True where
          the position is real data, False where it is padding.
    """
    if not sequences:
        raise ValueError("sequences list is empty")
    n_features = sequences[0].shape[-1]
    batch_size = len(sequences)
    padded = np.full((batch_size, max_len, n_features), pad_value, dtype=np.float32)
    mask = np.zeros((batch_size, max_len), dtype=bool)
    for i, seq in enumerate(sequences):
        length = min(len(seq), max_len)
        padded[i, :length] = seq[:length]
        mask[i, :length] = True
    return padded, mask


def set_seed(seed: int = 42) -> None:
    """Fix random seeds for reproducibility.

    Args:
        seed: Integer seed value.
    """
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
