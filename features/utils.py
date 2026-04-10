"""
Shared utility functions for security feature engineering.

Provides entropy calculation, cyclical encoding, and normalization helpers
used across all feature transformer modules.
"""

import math
import re
from collections import Counter

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG2_E: float = math.log2(math.e)
EPSILON: float = 1e-9  # Prevent log(0)


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy (bits) of a string.

    Returns 0.0 for empty or non-string input.

    Args:
        text: Input string to measure entropy of.

    Returns:
        Shannon entropy in bits, in range [0.0, log2(len(text))].
    """
    if not isinstance(text, str) or not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def normalized_entropy(text: str) -> float:
    """Compute Shannon entropy normalized to [0.0, 1.0].

    Args:
        text: Input string.

    Returns:
        Normalized entropy in [0.0, 1.0]; 0.0 for empty/single-char input.
    """
    if not isinstance(text, str) or len(text) <= 1:
        return 0.0
    raw = shannon_entropy(text)
    max_entropy = math.log2(len(set(text))) if len(set(text)) > 1 else 1.0
    return raw / max_entropy if max_entropy > 0 else 0.0


def domain_entropy(domain: str) -> float:
    """Compute Shannon entropy of the registered domain portion of a FQDN.

    Strips common TLDs and uses the leftmost label for entropy calculation,
    which is where DGA entropy concentrates.

    Args:
        domain: Fully-qualified or registered domain name string.

    Returns:
        Shannon entropy in bits of the domain label characters.
    """
    if not isinstance(domain, str) or not domain:
        return 0.0
    # Use the full domain for entropy (DGA names are unusual throughout)
    clean = domain.lower().strip(".")
    return shannon_entropy(clean)


# ---------------------------------------------------------------------------
# Cyclical (sinusoidal) encoding
# ---------------------------------------------------------------------------


def cyclical_encode(series: pd.Series, period: float) -> tuple[pd.Series, pd.Series]:
    """Encode a periodic numeric series as (sin, cos) pair.

    Args:
        series: Numeric series of raw values (e.g. hour 0-23).
        period: Full cycle length (e.g. 24 for hours, 7 for days).

    Returns:
        Tuple of (sin_series, cos_series), each float64, NaN-free.
    """
    angle = 2 * math.pi * series / period
    sin_vals = np.sin(angle).fillna(0.0).astype(np.float64)
    cos_vals = np.cos(angle).fillna(0.0).astype(np.float64)
    return pd.Series(sin_vals, index=series.index), pd.Series(cos_vals, index=series.index)


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------


def safe_log_frequency(counts: pd.Series, total: int) -> pd.Series:
    """Convert occurrence counts to negative log probability (rarity score).

    Higher values indicate rarer events. All output values are >= 0.

    Args:
        counts: Series of occurrence counts (int).
        total: Total population size used for probability computation.

    Returns:
        Float64 series of -log2(count/total) values, zero for zero counts.
    """
    if total <= 0:
        return pd.Series(0.0, index=counts.index, dtype=np.float64)
    prob = (counts.clip(lower=1) / total).clip(lower=EPSILON)
    return (-np.log2(prob)).astype(np.float64)


def zscore_series(series: pd.Series, mean: float, std: float) -> pd.Series:
    """Compute z-score of a series given pre-computed mean and std.

    Args:
        series: Numeric series to standardize.
        mean: Reference mean (from training baseline).
        std: Reference standard deviation (from training baseline).

    Returns:
        Float64 z-score series; 0.0 where std is zero or input is NaN.
    """
    if std < EPSILON:
        return pd.Series(0.0, index=series.index, dtype=np.float64)
    return ((series - mean) / std).fillna(0.0).astype(np.float64)


def clip_score(series: pd.Series, max_value: float = 10.0) -> pd.Series:
    """Clip and normalize a score series to [0.0, 1.0].

    Args:
        series: Raw numeric score series.
        max_value: Value that maps to 1.0 (hard clip at this point).

    Returns:
        Float64 series in [0.0, 1.0].
    """
    clipped = series.clip(lower=0.0, upper=max_value)
    return (clipped / max_value).fillna(0.0).astype(np.float64)


# ---------------------------------------------------------------------------
# String tokenisation
# ---------------------------------------------------------------------------

# Tokens are non-whitespace, non-punctuation runs from a command line
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_\-\.\/]+")


def tokenize_command(cmd: str) -> list[str]:
    """Tokenize a command-line string into meaningful tokens.

    Args:
        cmd: Raw command-line string (may be None or NaN).

    Returns:
        List of lowercase token strings; empty list for missing input.
    """
    if not isinstance(cmd, str):
        return []
    return _TOKEN_RE.findall(cmd.lower())
