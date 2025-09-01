"""Audit persisted scaler/model metadata and write concise summaries.

Outputs:
- results/models_audit.json
- results/models_audit.csv

This reads results/persisted_results/scaler_feature_summary.json (created by previous runs)
and summarizes per-job/scaler the feature names, center_/mean_ if available, and any load errors.
"""
import json
import csv
import os
from pathlib import Path

base = Path(__file__).resolve().parent.parent
persisted = base / 'results' / 'persisted_results'
out_dir = base / 'results'

summary_file = persisted / 'scaler_feature_summary.json'
if not summary_file.exists():
    print('No scaler_feature_summary.json found in results/persisted_results')
    raise SystemExit(1)

with open(summary_file, 'r', encoding='utf-8') as fh:
    data = json.load(fh)

# Build rows
rows = []
# scalers section contains many keys (paths -> dict)
scalers = data.get('scalers', {})
for path_key, entries in scalers.items():
    # entries may be error or mapping
    if isinstance(entries, dict):
        for name, info in entries.items():
            if isinstance(info, dict):
                feature_names = info.get('feature_names_in_', []) if isinstance(info.get('feature_names_in_', []), list) else []
                row = {
                    'source_file': path_key,
                    'entry_name': name,
                    'type': info.get('type', ''),
                    'feature_count': len(feature_names),
                    'has_center': 'center_' in info,
                    'has_mean': 'mean_' in info,
                    'load_error': ''
                }
            else:
                row = {'source_file': path_key, 'entry_name': name, 'type': '', 'feature_count': '', 'has_center': False, 'has_mean': False, 'load_error': str(info)}
            rows.append(row)
    else:
        # entry is likely an error string or other scalar
        rows.append({'source_file': path_key, 'entry_name': '', 'type': '', 'feature_count': '', 'has_center': False, 'has_mean': False, 'load_error': str(entries)})

os.makedirs(out_dir, exist_ok=True)
json_out = out_dir / 'models_audit.json'
csv_out = out_dir / 'models_audit.csv'

with open(json_out, 'w', encoding='utf-8') as fh:
    json.dump(rows, fh, indent=2)

with open(csv_out, 'w', newline='', encoding='utf-8') as fh:
    writer = csv.DictWriter(fh, fieldnames=['source_file','entry_name','type','feature_count','has_center','has_mean','load_error'])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

print('Wrote', json_out, csv_out)
