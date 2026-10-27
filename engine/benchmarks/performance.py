"""
Performance benchmarks for the detection pipeline.

Measures training time, inference latency (p50/p95/p99), peak memory usage,
and end-to-end pipeline latency from data load through score to push.

Output: benchmarks/results/{timestamp}_performance.json
"""

from __future__ import annotations

import json
import logging
import time
import tracemalloc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

RESULTS_DIR: Path = Path("benchmarks/results")

DEFAULT_N_SAMPLES: int = 10_000
DEFAULT_N_FEATURES: int = 20
DEFAULT_INFERENCE_ITERATIONS: int = 100


@dataclass
class PerformanceResult:
    """Performance metrics for a single model benchmark."""

    model_name: str
    n_training_samples: int = 0
    n_features: int = 0
    training_time_sec: float = 0.0
    inference_latencies_ms: list[float] = field(default_factory=list)
    memory_peak_mb: float = 0.0

    @property
    def p50_ms(self) -> float:
        """Median inference latency."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 50))

    @property
    def p95_ms(self) -> float:
        """95th percentile inference latency."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 95))

    @property
    def p99_ms(self) -> float:
        """99th percentile inference latency."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 99))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "model_name": self.model_name,
            "n_training_samples": self.n_training_samples,
            "n_features": self.n_features,
            "training_time_sec": round(self.training_time_sec, 4),
            "latency_p50_ms": round(self.p50_ms, 3),
            "latency_p95_ms": round(self.p95_ms, 3),
            "latency_p99_ms": round(self.p99_ms, 3),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
        }


@dataclass
class EndToEndResult:
    """End-to-end pipeline latency from data load to push."""

    data_load_ms: float = 0.0
    feature_extraction_ms: float = 0.0
    scoring_ms: float = 0.0
    push_ms: float = 0.0

    @property
    def total_ms(self) -> float:
        """Total end-to-end latency."""
        return self.data_load_ms + self.feature_extraction_ms + self.scoring_ms + self.push_ms

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "data_load_ms": round(self.data_load_ms, 3),
            "feature_extraction_ms": round(self.feature_extraction_ms, 3),
            "scoring_ms": round(self.scoring_ms, 3),
            "push_ms": round(self.push_ms, 3),
            "total_ms": round(self.total_ms, 3),
        }


def benchmark_model_training(
    model: Any,
    n_samples: int = DEFAULT_N_SAMPLES,
    n_features: int = DEFAULT_N_FEATURES,
    model_name: str = "unknown",
) -> PerformanceResult:
    """Benchmark model training time and memory usage.

    Args:
        model: Model with .fit(X) interface.
        n_samples: Number of synthetic training samples.
        n_features: Number of features per sample.
        model_name: Label for the result.

    Returns:
        PerformanceResult with training metrics.
    """
    rng = np.random.default_rng(42)
    X_train = rng.standard_normal((n_samples, n_features)).astype(np.float32)

    tracemalloc.start()
    start = time.perf_counter()
    model.fit(X_train)
    training_time = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    result = PerformanceResult(
        model_name=model_name,
        n_training_samples=n_samples,
        n_features=n_features,
        training_time_sec=training_time,
        memory_peak_mb=peak / (1024 * 1024),
    )
    logger.info(
        "Training benchmark: %s — %.3fs, %.1f MB peak",
        model_name, training_time, result.memory_peak_mb,
    )
    return result


def benchmark_model_inference(
    model: Any,
    n_samples: int = DEFAULT_N_SAMPLES,
    n_features: int = DEFAULT_N_FEATURES,
    n_iterations: int = DEFAULT_INFERENCE_ITERATIONS,
    model_name: str = "unknown",
) -> PerformanceResult:
    """Benchmark model inference latency over multiple iterations.

    Args:
        model: Model with .decision_function(X) interface (must already be fit).
        n_samples: Number of test samples per iteration.
        n_features: Number of features per sample.
        n_iterations: Number of inference iterations to time.
        model_name: Label for the result.

    Returns:
        PerformanceResult with inference latency metrics.
    """
    rng = np.random.default_rng(99)
    X_test = rng.standard_normal((n_samples, n_features)).astype(np.float32)

    latencies: list[float] = []
    for _ in range(n_iterations):
        start = time.perf_counter()
        model.decision_function(X_test)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

    result = PerformanceResult(
        model_name=model_name,
        n_training_samples=0,
        n_features=n_features,
        inference_latencies_ms=latencies,
    )
    logger.info(
        "Inference benchmark: %s — p50=%.2fms, p95=%.2fms, p99=%.2fms",
        model_name, result.p50_ms, result.p95_ms, result.p99_ms,
    )
    return result


def benchmark_end_to_end(
    data_loader: Any | None = None,
    feature_extractor: Any | None = None,
    scorer: Any | None = None,
    pusher: Any | None = None,
    n_samples: int = DEFAULT_N_SAMPLES,
) -> EndToEndResult:
    """Benchmark end-to-end pipeline latency.

    Each stage is timed independently. Pass None for stages that are
    not available; they will be recorded as 0ms.

    Args:
        data_loader: Callable returning a DataFrame.
        feature_extractor: Callable(DataFrame) -> DataFrame.
        scorer: Callable(DataFrame) -> ndarray.
        pusher: Callable(DataFrame) -> None.
        n_samples: Number of synthetic samples if loader is None.

    Returns:
        EndToEndResult with per-stage timing.
    """
    result = EndToEndResult()
    rng = np.random.default_rng(42)

    # Data load
    start = time.perf_counter()
    if data_loader is not None:
        data = data_loader()
    else:
        import pandas as pd
        data = pd.DataFrame(
            rng.standard_normal((n_samples, DEFAULT_N_FEATURES)),
            columns=[f"feat_{i}" for i in range(DEFAULT_N_FEATURES)],
        )
    result.data_load_ms = (time.perf_counter() - start) * 1000

    # Feature extraction
    start = time.perf_counter()
    if feature_extractor is not None:
        data = feature_extractor(data)
    result.feature_extraction_ms = (time.perf_counter() - start) * 1000

    # Scoring
    start = time.perf_counter()
    if scorer is not None:
        scorer(data)
    result.scoring_ms = (time.perf_counter() - start) * 1000

    # Push
    start = time.perf_counter()
    if pusher is not None:
        pusher(data)
    result.push_ms = (time.perf_counter() - start) * 1000

    logger.info(
        "E2E benchmark: load=%.1fms, features=%.1fms, score=%.1fms, push=%.1fms, total=%.1fms",
        result.data_load_ms, result.feature_extraction_ms,
        result.scoring_ms, result.push_ms, result.total_ms,
    )
    return result


def save_performance_results(
    model_results: list[PerformanceResult],
    e2e_result: EndToEndResult | None = None,
    output_dir: Path | None = None,
) -> Path:
    """Save performance benchmark results to JSON.

    Args:
        model_results: List of per-model performance results.
        e2e_result: Optional end-to-end latency result.
        output_dir: Directory to write to; defaults to RESULTS_DIR.

    Returns:
        Path to the saved file.
    """
    dest = output_dir or RESULTS_DIR
    dest.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = dest / f"{ts}_performance.json"

    data: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model_benchmarks": [r.to_dict() for r in model_results],
    }
    if e2e_result is not None:
        data["end_to_end"] = e2e_result.to_dict()

    path.write_text(json.dumps(data, indent=2))
    logger.info("Performance results saved to %s", path)
    return path
