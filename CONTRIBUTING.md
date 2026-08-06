# Contributing to Linux Security Anomaly Detection

Thank you for your interest in contributing! This project uses a multi-agent development architecture where different components are owned by different agents. Understanding this structure will help you contribute effectively.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/your-username/linux-anomaly-detection.git`
3. Install dependencies: `pip install -e ".[dev]"`
4. Run tests: `pytest tests/ -x --tb=short`

## Code Standards

- **Python 3.10+** required
- Type hints on all function signatures
- Docstrings on all public functions
- f-strings over `.format()`
- `pathlib.Path` over `os.path`
- Structured logging (JSON format for production)
- No magic numbers — use named constants or config values
- All ML models implement: `.fit(X)`, `.decision_function(X) -> np.ndarray`
- All anomaly scores normalized to `[0.0, 1.0]`

## ATT&CK Alignment

Every detection capability must map to at least one MITRE ATT&CK technique. Use technique IDs in docstrings, config entries, and alert enrichment.

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes following the code standards above
3. Run the test suite: `pytest tests/ -x --tb=short`
4. Run the linter: `ruff check .`
5. Ensure all validation scripts pass: `python validation/check_all.py`
6. Submit a PR with a clear description of the changes

## Component Ownership

| Component | Description |
|-----------|-------------|
| `model_manager.py`, `detection_methods.py`, `models/` | ML model lifecycle |
| `datamanager.py`, `features/` | Data fetching and feature extraction |
| `dl_models/` | Deep learning models |
| `benign_lists.py`, FP rules in `push_all_anomalies.py` | False-positive tuning |
| `backends/` | SIEM backend abstraction |
| `post_correlation.py`, `realtime_service.py` | Ops and correlation |
| `tests/`, `benchmarks/`, `validation/` | Testing infrastructure |

## Adding a New Backend

See the `backends/` directory. Subclass `SIEMBackend` from `backends/base.py` and implement all abstract methods. See `backends/elasticsearch_backend.py` for a reference implementation.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md).
