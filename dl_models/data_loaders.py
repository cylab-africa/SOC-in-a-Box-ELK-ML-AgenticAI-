"""
DataFrame to PyTorch dataset converters for DL anomaly models.

Converts pandas DataFrames (as produced by the feature engineering pipeline)
into PyTorch-compatible datasets suitable for each DL model architecture.

All converters handle NaN values and return float32 tensors.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset

logger = logging.getLogger(__name__)


class SequenceDataset(Dataset):
    """Sliding-window dataset for temporal models (GRU autoencoder).

    Slices a 2-D feature matrix into overlapping fixed-length windows
    suitable for the TemporalAutoencoder.
    """

    def __init__(
        self, features: np.ndarray, seq_len: int = 32, stride: int | None = None,
    ) -> None:
        """Build sliding windows from a feature matrix.

        Args:
            features: Array of shape (n_samples, n_features).
            seq_len: Number of time steps per window.
            stride: Step size between windows (default: seq_len // 2).
        """
        features = np.nan_to_num(features, nan=0.0).astype(np.float32)
        self.seq_len = seq_len
        self.stride = stride or max(seq_len // 2, 1)

        n_samples, self.n_features = features.shape

        # Pad if fewer samples than seq_len
        if n_samples < seq_len:
            pad = np.zeros((seq_len - n_samples, self.n_features), dtype=np.float32)
            features = np.vstack([features, pad])
            n_samples = seq_len

        self.windows: list[np.ndarray] = []
        for start in range(0, n_samples - seq_len + 1, self.stride):
            self.windows.append(features[start : start + seq_len])

    def __len__(self) -> int:
        """Return number of windows."""
        return len(self.windows)

    def __getitem__(self, idx: int) -> torch.Tensor:
        """Return a single window as a tensor.

        Args:
            idx: Window index.

        Returns:
            Tensor of shape (seq_len, n_features).
        """
        return torch.from_numpy(self.windows[idx])

    @classmethod
    def from_dataframe(
        cls,
        df: pd.DataFrame,
        feature_columns: list[str] | None = None,
        seq_len: int = 32,
        stride: int | None = None,
    ) -> SequenceDataset:
        """Create a SequenceDataset from a pandas DataFrame.

        Args:
            df: Input DataFrame.
            feature_columns: Columns to use as features. If None, uses all
                numeric columns.
            seq_len: Window length.
            stride: Window stride.

        Returns:
            SequenceDataset instance.
        """
        if feature_columns is None:
            feature_columns = df.select_dtypes(include=[np.number]).columns.tolist()

        features = df[feature_columns].values
        return cls(features, seq_len=seq_len, stride=stride)


class TreeFeatureDataset(Dataset):
    """Dataset for process-tree MLP models.

    Each sample is a flat feature vector representing one process event
    or process-tree summary.
    """

    def __init__(self, features: np.ndarray) -> None:
        """Wrap a feature matrix as a PyTorch dataset.

        Args:
            features: Array of shape (n_samples, n_features).
        """
        self.features = np.nan_to_num(features, nan=0.0).astype(np.float32)

    def __len__(self) -> int:
        """Return number of samples."""
        return len(self.features)

    def __getitem__(self, idx: int) -> torch.Tensor:
        """Return a single sample as a tensor.

        Args:
            idx: Sample index.

        Returns:
            Tensor of shape (n_features,).
        """
        return torch.from_numpy(self.features[idx])

    @classmethod
    def from_dataframe(
        cls,
        df: pd.DataFrame,
        feature_columns: list[str] | None = None,
    ) -> TreeFeatureDataset:
        """Create a TreeFeatureDataset from a pandas DataFrame.

        Args:
            df: Input DataFrame.
            feature_columns: Columns to use. If None, uses all numeric columns.

        Returns:
            TreeFeatureDataset instance.
        """
        if feature_columns is None:
            feature_columns = df.select_dtypes(include=[np.number]).columns.tolist()

        features = df[feature_columns].values
        return cls(features)


def dataframe_to_numpy(
    df: pd.DataFrame,
    feature_columns: list[str] | None = None,
) -> np.ndarray:
    """Convert a DataFrame to a clean float32 numpy array.

    Handles NaN, selects numeric columns, and ensures float32 dtype.

    Args:
        df: Input DataFrame.
        feature_columns: Specific columns to extract. If None, uses all
            numeric columns.

    Returns:
        Array of shape (n_samples, n_features) with dtype float32.
    """
    if feature_columns is None:
        feature_columns = df.select_dtypes(include=[np.number]).columns.tolist()

    arr = df[feature_columns].values
    return np.nan_to_num(arr, nan=0.0).astype(np.float32)
