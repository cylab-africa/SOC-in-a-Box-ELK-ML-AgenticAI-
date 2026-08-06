from pathlib import Path

import pandas as pd

from detection_methods import detect_job_anomalies
from model_manager import load_all_models

p = Path('results/persisted_results/v3_linux_anomalous_process_all_hosts.parquet')
print('Reading', p)
df = pd.read_parquet(p)
print('Rows', len(df), 'columns', df.columns.tolist()[:20])

models, scalers = load_all_models()
print('Loaded models/scalers counts', len(models), len(scalers))

cfg = {'models': {'storage': {'base_path': '/tmp/linux_anomaly_models'}}}
res = detect_job_anomalies(df.head(500), models, scalers, cfg, 'v3_linux_anomalous_process_all_hosts')
print('Result rows', len(res))
if not res.empty:
    print(res[['entity','ml_anomaly_score','confidence']].head(20))
else:
    print('No results')
