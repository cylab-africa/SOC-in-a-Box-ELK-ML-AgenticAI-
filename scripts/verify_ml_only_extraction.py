import pandas as pd
from pathlib import Path

p = Path('results/persisted_results')
files = list(p.glob('*.parquet')) + list(p.glob('*.csv'))
if not files:
    print('no persisted files found')
    raise SystemExit(0)

for f in files:
    print('='*80)
    print(f'FILE: {f}')
    try:
        if f.suffix == '.parquet':
            df = pd.read_parquet(f)
        else:
            df = pd.read_csv(f)
    except Exception as e:
        print('failed to read', e)
        continue
    cols = list(df.columns)
    print('ROWS:', len(df))
    print('COLUMNS:', cols)

    # canonical anomaly flag
    has_final = 'final_anomaly' in df.columns
    has_is_ml = 'is_ml_anomaly' in df.columns
    has_method = 'detection_method' in df.columns

    if not (has_final or has_is_ml):
        print('no anomaly flags present')
        continue

    cond_final = df['final_anomaly'] if has_final else False
    cond_is_ml = df['is_ml_anomaly'] if has_is_ml else False

    # consider True values
    candidate = pd.Series(False, index=df.index)
    if has_final:
        candidate = candidate | cond_final.fillna(False)
    if has_is_ml:
        candidate = candidate | cond_is_ml.fillna(False)

    if has_method:
        candidate = candidate & (df['detection_method'] == 'machine_learning')

    total = int(candidate.sum())
    print('canonical_ml_anomalies:', total)
    if total > 0:
        sample = df.loc[candidate].head(10).to_dict(orient='records')
        print('SAMPLE flagged rows (up to 10):')
        for r in sample:
            print({k: r.get(k) for k in ['job_name','entity','detection_timestamp','is_ml_anomaly','final_anomaly','ml_anomaly_score','detection_method']})

print('Done')
