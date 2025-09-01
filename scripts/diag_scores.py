"""Diagnostic: run a single job detection on a small sample and print ml score stats."""
import logging
import pandas as pd
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('linux_anomaly_detection')

from detection_methods import detect_job_anomalies, get_job_for_data_type
import detection_methods as dm

results_dir = os.path.join(os.path.dirname(__file__), '..', '')
results_dir = os.path.abspath(results_dir)

# Find ml_only CSVs
csvs = []
for fname in os.listdir(os.path.join(results_dir, 'results')):
    if fname.startswith('ml_only') and fname.endswith('.csv'):
        csvs.append(os.path.join(results_dir, 'results', fname))

if not csvs:
    print('No ml_only CSV files found in results folder')
    raise SystemExit(0)

sample_csv = csvs[0]
print('Using sample:', sample_csv)
sample = pd.read_csv(sample_csv)

# Take a small head sample
sample = sample.head(200)

# Try to load models via model_manager if available
models = {}
scalers = {}
try:
    from model_manager import load_all_models
    models, scalers = load_all_models()
    print('Loaded models:', len(models), 'scalers:', len(scalers))
except Exception as e:
    print('Could not load models:', e)

job = get_job_for_data_type('process')
print('Running job:', job)
res = detect_job_anomalies(sample, models, scalers, config={}, job_name=job)

if 'ml_anomaly_score' in res.columns:
    print(res['ml_anomaly_score'].describe())
    print('Top rows:')
    print(res[['entity','ml_anomaly_score','confidence']].head(10).to_string(index=False))
else:
    print('No ml_anomaly_score in results')

# Print some scoring-debug messages from entity diagnostics if present
try:
    from detection_methods import pop_job_entity_diagnostics
    diags = pop_job_entity_diagnostics(job)
    print('Entity diagnostics count:', len(diags))
    for k,v in list(diags.items())[:5]:
        print(k, v)
except Exception:
    pass
