import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from detection_methods import detect_job_anomalies, JOB_CONFIGURATIONS
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

# Build small synthetic dataset for a process job
n = 50
np.random.seed(0)
rows = []
for i in range(n):
    rows.append({
        '@timestamp': pd.Timestamp.now(),
        'process.name': 'procA' if i < 40 else 'procB',
        'cpu_pct': np.random.rand(),
        'mem_pct': np.random.rand(),
        'event_count': 1
    })

df = pd.DataFrame(rows)

# Create a dummy IsolationForest model and scaler for job 'process'
# identify a job name from JOB_CONFIGURATIONS that is process-type; fallback to any
job_name = None
for k,v in JOB_CONFIGURATIONS.items():
    if v.get('data_type') == 'process':
        job_name = k
        break

if job_name is None:
    job_name = list(JOB_CONFIGURATIONS.keys())[0]

# Fit a simple scaler on df numeric
scaler = StandardScaler()
X = df[['cpu_pct','mem_pct','event_count']].values
scaler.fit(X)

# Fit a simple IsolationForest
iso = IsolationForest(random_state=0)
iso.fit(scaler.transform(X))

models = {f"{job_name}:procA": {'isolation_forest': iso}}
scalers = {f"{job_name}:procA": scaler}

# Run detection
results = detect_job_anomalies(df, models, scalers, config={}, job_name=job_name)
print('Done. Results shape:', results.shape)
print(results[['entity','ml_anomaly_score']].head())
