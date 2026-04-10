"""
Abstract base class for all security feature transformers.

Every transformer in the features/ package follows this contract so that
datamanager.py and model_manager.py can use them interchangeably via the
registry in features/__init__.py.
"""

from abc import ABC, abstractmethod

import pandas as pd


class FeatureTransformer(ABC):
    """Abstract base for ATT&CK-aligned feature transformers.

    Subclasses must:
    - Produce only float64 columns (no object/string outputs).
    - Handle NaN / missing source fields gracefully (output 0.0, not NaN).
    - Never drop rows; only append new columns.
    - Be idempotent: calling transform() twice must not duplicate columns.
    """

    def __init__(self) -> None:
        """Initialize transformer in unfitted state."""
        self._is_fitted: bool = False

    @abstractmethod
    def fit(self, df: pd.DataFrame) -> "FeatureTransformer":
        """Learn baselines or statistics from training data.

        Args:
            df: Training DataFrame containing raw Elasticsearch fields.

        Returns:
            self, to allow method chaining.
        """
        ...

    @abstractmethod
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Append feature columns to df and return the result.

        Only adds columns that are not already present (idempotency).
        All new columns are float64; missing source fields produce 0.0.

        Args:
            df: Input DataFrame (may have NaN in source columns).

        Returns:
            DataFrame with new feature columns appended.
        """
        ...

    @abstractmethod
    def get_feature_names(self) -> list[str]:
        """Return the names of all columns this transformer adds.

        Returns:
            List of column name strings.
        """
        ...

    @abstractmethod
    def get_attack_mapping(self) -> dict[str, str]:
        """Return a mapping from feature name to MITRE ATT&CK technique.

        Returns:
            Dict of {column_name: "TXXXX - Technique Name"}.
        """
        ...

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Convenience: fit then transform on the same DataFrame.

        Args:
            df: Training DataFrame.

        Returns:
            DataFrame with new feature columns appended.
        """
        return self.fit(df).transform(df)

    def _skip_existing(self, df: pd.DataFrame) -> list[str]:
        """Return feature names not already present in df.

        Args:
            df: DataFrame to check columns against.

        Returns:
            List of feature names that need to be added.
        """
        return [name for name in self.get_feature_names() if name not in df.columns]
