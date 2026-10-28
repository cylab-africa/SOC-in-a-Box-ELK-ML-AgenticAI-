# Development

For contributors. To install and use SOC-in-a-Box, see the
[installation guide](installation.md).

## Project structure

```
soc-in-a-box/
├── deploy.sh               # Automated deployment (venv/systemd or Docker)
├── requirements.txt        # Runtime dependencies (read by pyproject.toml)
├── .env.example            # Every setting, with defaults (copy to .env)
├── config/                 # False-positive lists (overrides in config/local/) and SIEM rules
├── engine/                 # The detection engine
│   ├── main.py             # One-shot detection CLI
│   ├── realtime_service.py # Continuous detection service
│   ├── train_models_background.py  # Background training with checkpoints
│   ├── anomaly_detector.py # Core detection engine
│   ├── datamanager.py      # Elasticsearch data fetching
│   ├── detection_methods.py  # Feature extraction and detection jobs
│   ├── model_manager.py    # Model training/loading/versioning
│   ├── push_all_anomalies.py # FP classification, enrichment, push
│   ├── post_correlation.py # Kill-chain correlation
│   ├── benign_lists.py     # Graduated allowlist with dampening
│   ├── config.py           # Configuration from .env
│   ├── backends/           # SIEM backend interface (Elasticsearch)
│   ├── mappings/           # Index templates and ATT&CK mapping
│   ├── scripts/            # Diagnostic and audit scripts
│   ├── tests/              # Pytest test suite
│   ├── features/, models/, dl_models/, adversarial/  # Experimental; not used by the running engine
│   └── benchmarks/         # Attack-scenario benchmarks
├── addons/
│   ├── siem-maintenance/   # Optional SIEM Maintenance Agent
│   ├── alert-triage/       # Optional Alert Triage Agent
│   └── greenbone/          # Optional Greenbone scan results push
├── docker/                 # Dockerfiles and docker-compose
└── docs/                   # Documentation
```

Code lives in `engine/`; everything a deployment creates or edits (`.env`,
`config/`, `results/`, `logs/`) stays at the repo root. Run the engine's scripts
from the repo root, e.g. `python engine/main.py`.

## Commands

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (no Elasticsearch needed)
pytest

# Lint
ruff check .
```

CI runs the tests on Python 3.10–3.12, `ruff`, and a gitleaks secret scan on
every push and pull request.
