"""Benchmarks package for anomaly detection pipeline performance testing."""

from benchmarks.benchmark_framework import (
    BenchmarkResult,
    benchmark_inference,
    benchmark_training,
    save_benchmark_results,
)

__all__ = [
    "BenchmarkResult",
    "benchmark_training",
    "benchmark_inference",
    "save_benchmark_results",
]
