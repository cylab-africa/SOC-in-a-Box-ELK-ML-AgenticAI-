import pandas as pd
import os
p_dir = os.path.join('results','persisted_results')
files = [f for f in os.listdir(p_dir) if f.endswith('.parquet') or f.endswith('.csv')]
for f in files:
    path = os.path.join(p_dir, f)
    print('='*80)
    print('FILE:', path)
    try:
        if f.endswith('.parquet'):
            df = pd.read_parquet(path)
        else:
            df = pd.read_csv(path)
        print('ROWS:', len(df))
        print('COLUMNS:', list(df.columns))
        for col in ['final_anomaly','is_ml_anomaly','ml_anomaly_score','detection_method']:
            if col in df.columns:
                try:
                    print(col, ':', int(df[col].sum()))
                except Exception as e:
                    print(col, ': error counting ->', e)
        print('SAMPLE (first 3):')
        print(df.head(3).to_dict(orient='records'))
    except Exception as e:
        print('FAILED to read', path, '->', e)
print('\nDone')
