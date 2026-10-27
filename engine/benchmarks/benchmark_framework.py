"""
Performance and detection benchmark framework.

Measures training time, inference latency (p50/p95/p99), memory usage,
and detection quality (AUC-PR, AUC-ROC) for each model configuration.

Usage:
    python benchmarks/run_benchmarks.py
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

BENCHMARK_RESULTS_DIR: Path = Path("results/benchmarks")


@dataclass
class BenchmarkResult:
    """Container for a single benchmark run's results."""

    model_name: str
    dataset_name: str
    training_time_seconds: float = 0.0
    inference_latencies_ms: list[float] = field(default_factory=list)
    memory_peak_mb: float = 0.0
    n_training_samples: int = 0
    n_test_samples: int = 0
    scores: np.ndarray | None = None
    labels: np.ndarray | None = None

    @property
    def p50_latency_ms(self) -> float:
        """Median inference latency in milliseconds."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 50))

    @property
    def p95_latency_ms(self) -> float:
        """95th percentile inference latency in milliseconds."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 95))

    @property
    def p99_latency_ms(self) -> float:
        """99th percentile inference latency in milliseconds."""
        if not self.inference_latencies_ms:
            return 0.0
        return float(np.percentile(self.inference_latencies_ms, 99))

    def to_dict(self) -> dict[str, Any]:
        """Serialize benchmark result to a dictionary."""
        return {
            "model_name": self.model_name,
            "dataset_name": self.dataset_name,
            "training_time_seconds": round(self.training_time_seconds, 3),
            "latency_p50_ms": round(self.p50_latency_ms, 3),
            "latency_p95_ms": round(self.p95_latency_ms, 3),
            "latency_p99_ms": round(self.p99_latency_ms, 3),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "n_training_samples": self.n_training_samples,
            "n_test_samples": self.n_test_samples,
        }


def benchmark_training(
    model: Any,
    X_train: np.ndarray,
    model_name: str = "unknown",
) -> tuple[float, float]:
    """Benchmark model training time and memory.

    Args:
        model: Model with .fit(X) interface.
        X_train: Training feature matrix.
        model_name: Name for the benchmark record.

    Returns:
        Tuple of (training_time_seconds, peak_memory_mb).
    """
    tracemalloc.start()
    start = time.perf_counter()
    model.fit(X_train)
    elapsed = time.perf_counter() - start
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    peak_mb = peak / (1024 * 1024)
    logger.info(
        "Training benchmark: %s — %.2fs, %.1f MB peak",
        model_name, elapsed, peak_mb,
    )
    return elapsed, peak_mb


def benchmark_inference(
    model: Any,
    X_test: np.ndarray,
    n_iterations: int = 100,
) -> list[float]:
    """Benchmark inference latency over multiple iterations.

    Args:
        model: Model with .decision_function(X) interface.
        X_test: Test feature matrix.
        n_iterations: Number of inference runs to measure.

    Returns:
        List of per-iteration latencies in milliseconds.
    """
    latencies: list[float] = []
    for _ in range(n_iterations):
        start = time.perf_counter()
        model.decision_function(X_test)
        elapsed_ms = (time.perf_counter() - start) * 1000
        latencies.append(elapsed_ms)

    return latencies


def save_benchmark_results(results: list[BenchmarkResult]) -> Path:
    """Save benchmark results to a JSON file.

    Args:
        results: List of BenchmarkResult objects.

    Returns:
        Path to the saved results file.
    """
    BENCHMARK_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = BENCHMARK_RESULTS_DIR / f"benchmark_{timestamp}.json"

    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "results": [r.to_dict() for r in results],
    }
    output_path.write_text(json.dumps(data, indent=2))
    logger.info("Benchmark results saved to %s", output_path)
    return output_path
