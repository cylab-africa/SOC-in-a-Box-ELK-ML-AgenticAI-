# Contributing to SOC-in-a-Box

Thank you for helping. Bug reports, documentation fixes, detection ideas and
code are all welcome. For a large change, open an issue first to discuss it.

## Set up

```bash
git clone https://github.com/<your-username>/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest          # no Elasticsearch needed
ruff check .
```

Project layout: [docs/development.md](docs/development.md).

## Pull requests

1. Branch from `main`.
2. Make your change, with tests where it changes behaviour.
3. Run `pytest` and `ruff check .`.
4. Open a pull request saying what changed and why.

CI runs the tests on Python 3.10–3.12, `ruff`, and a secret scan.

## Code standards

- Python 3.10+, type hints on function signatures, docstrings on public
  functions.
- f-strings, `pathlib.Path`, named constants or config values instead of magic
  numbers.
- ML models implement `.fit(X)` and `.decision_function(X) -> np.ndarray`, and
  anomaly scores are normalized to `[0.0, 1.0]`.
- Every detection maps to at least one MITRE ATT&CK technique. Put the
  technique IDs in docstrings, config entries and alert enrichment.

## Where things live

| Area | Files |
|---|---|
| ML models | `model_manager.py`, `detection_methods.py`, `models/` |
| Data fetching and features | `datamanager.py`, `features/` |
| Deep learning (experimental) | `dl_models/` |
| False-positive tuning | `benign_lists.py`, the filters in `push_all_anomalies.py` |
| Output backends | `engine/backends/` |
| Correlation and the service | `post_correlation.py`, `realtime_service.py` |
| Tests and benchmarks | `engine/tests/`, `engine/benchmarks/` |
| Installer | `deploy.sh` |
| Add-ons | `addons/` |

**New output backend:** subclass `SIEMBackend` in `engine/backends/base.py` and
implement its abstract methods. `engine/backends/elasticsearch_backend.py` is
the reference.

## Never commit

`.env` files, credentials, or hostnames and IP addresses from a real
environment. Security issues: see [SECURITY.md](SECURITY.md).
