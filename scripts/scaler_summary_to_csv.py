"""Convert scaler_feature_summary.json into a compact CSV summary.
Writes: results/persisted_results/scaler_feature_summary.csv
"""
import json
from pathlib import Path
import csv

ROOT = Path(__file__).resolve().parents[1]
IN_FILE = ROOT / 'results' / 'persisted_results' / 'scaler_feature_summary.json'
OUT_FILE = ROOT / 'results' / 'persisted_results' / 'scaler_feature_summary.csv'

if not IN_FILE.exists():
    print('Input JSON not found:', IN_FILE)
    raise SystemExit(1)

with open(IN_FILE, 'r', encoding='utf-8') as fh:
    data = json.load(fh)

rows = []
for fpath, content in data.get('scalers', {}).items():
    if isinstance(content, dict):
        for entity, info in content.items():
            feature_names = info.get('feature_names_in_', []) if isinstance(info, dict) else []
            n_features = len(feature_names) if feature_names else 0
            has_center = 'center_' in info
            has_mean = 'mean_' in info
            has_median = 'median_' in info
            rows.append({
                'file': fpath,
                'entity': entity,
                'feature_count': n_features,
                'has_center': has_center,
                'has_mean': has_mean,
                'has_median': has_median
            })
    else:
        # scalar info
        info = content
        feature_names = info.get('feature_names_in_', []) if isinstance(info, dict) else []
        rows.append({
            'file': fpath,
            'entity': '<single>',
            'feature_count': len(feature_names),
            'has_center': 'center_' in info,
            'has_mean': 'mean_' in info,
            'has_median': 'median_' in info
        })

OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
with open(OUT_FILE, 'w', newline='', encoding='utf-8') as fh:
    writer = csv.DictWriter(fh, fieldnames=['file', 'entity', 'feature_count', 'has_center', 'has_mean', 'has_median'])
    writer.writeheader()
    for r in rows:
        writer.writerow(r)

print('Wrote CSV summary to:', OUT_FILE)
