# Manual installation

The steps `deploy.sh` runs for the detection engine, for when you want to do
them yourself. Run every command from the repository root. The prerequisites
are the same as in the [installation guide](installation.md#prerequisites).

## 1. Install

```bash
git clone https://github.com/cylab-africa/SOC-in-a-Box-ELK-ML-AgenticAI-.git
cd SOC-in-a-Box-ELK-ML-AgenticAI-
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

## 2. Configure

```bash
cp .env.example .env
```

In `.env`, set `ES_HOST` (e.g. `https://10.0.0.5:9200`), `ES_USERNAME` and
`ES_PASSWORD`. Check that the `ES_*_INDEX` patterns match indices on your
cluster: see [configuration](configuration.md#index-names-and-field-names).

## 3. Train the models

```bash
python engine/train_models_background.py --all
```

This reads up to 7 days of data and takes a while. It worked if
`logs/trainer.log` contains `Successfully trained`.

## 4. Run detection and send the alerts

```bash
python engine/main.py
python engine/push_all_anomalies.py
```

Then add `ml-anomalies-custom-*` as a data view in Kibana.

## 5. Run it as a service

`engine/realtime_service.py` repeats detection every 5 minutes and retrains
every 72 hours. Save this as `/etc/systemd/system/realtime_service.service`,
changing `User` and the paths:

```ini
[Unit]
Description=SOC-in-a-Box detection engine
After=network.target

[Service]
Type=simple
User=YOUR_USER
WorkingDirectory=/opt/SOC-in-a-Box-ELK-ML-AgenticAI-
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/SOC-in-a-Box-ELK-ML-AgenticAI-/.venv/bin/python -u /opt/SOC-in-a-Box-ELK-ML-AgenticAI-/engine/realtime_service.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now realtime_service
```

To add an add-on by hand, see its own README in `addons/`.
