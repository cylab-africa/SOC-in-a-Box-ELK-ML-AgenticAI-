"""
Audit saved scalers/models and summarize feature names + per-feature stats.
Saves output to results/persisted_results/scaler_feature_summary.json

Run: python scripts\audit_scalers.py
"""
import json
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / 'results' / 'persisted_results'
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / 'scaler_feature_summary.json'

# Candidate locations to search for model files (ordered - prioritize /tmp/linux_anomaly_models)
candidates_list = []
# First, the known external models dir (prioritized)
candidates_list.append(Path('/tmp/linux_anomaly_models'))
# Then local results/models
candidates_list.append(ROOT / 'results' / 'models')
# Any .joblib files in the repo (parents will be appended later)
repo_joblib_parents = set([p.parent for p in ROOT.rglob('*.joblib')])
# Finally, repo root and results
candidates_list.append(ROOT)
candidates_list.append(ROOT / 'results')

# Build ordered unique candidate list
candidates = []
seen = set()
for c in candidates_list:
    if c.exists() and str(c) not in seen:
        candidates.append(c)
        seen.add(str(c))
for p in sorted(repo_joblib_parents):
    if str(p) not in seen:
        candidates.append(p)
        seen.add(str(p))

found_files = []
for c in list(candidates):
    if not c.exists():
        continue
    # look for *_scalers.joblib and any .joblib files
    for f in c.glob('**/*_scalers.joblib'):
        found_files.append(f)
    for f in c.glob('**/*.joblib'):
        found_files.append(f)

# Deduplicate
found_files = sorted(set(found_files))

summary = {
    'scaler_files_searched': [str(p) for p in found_files],
    'scalers': {}
}

def to_py(x):
    try:
        import numpy as _np
        if isinstance(x, _np.ndarray):
            return x.tolist()
    except Exception:
        pass
    try:
        return json.loads(json.dumps(x, default=str))
    except Exception:
        return str(x)

for f in found_files:
    try:
        obj = joblib.load(f)
    except Exception as e:
        summary['scalers'][str(f)] = {'error': f'load_failed: {e}'}
        continue

    # obj might be dict of scalers or a single scaler
    if isinstance(obj, dict):
        file_entry = {}
        for key, val in obj.items():
            info = {}
            try:
                if hasattr(val, 'feature_names_in_'):
                    info['feature_names_in_'] = to_py(val.feature_names_in_)
                # Common scaler attributes
                for attr in ('mean_', 'scale_', 'center_', 'median_', 'quantile_range_', 'n_samples_seen_'):
                    if hasattr(val, attr):
                        info[attr] = to_py(getattr(val, attr))
                # Basic type
                info['type'] = type(val).__name__
            except Exception as e:
                info['error'] = str(e)
            file_entry[str(key)] = info
        summary['scalers'][str(f)] = file_entry
    else:
        info = {}
        try:
            if hasattr(obj, 'feature_names_in_'):
                info['feature_names_in_'] = to_py(obj.feature_names_in_)
            for attr in ('mean_', 'scale_', 'center_', 'median_', 'quantile_range_', 'n_samples_seen_'):
                if hasattr(obj, attr):
                    info[attr] = to_py(getattr(obj, attr))
            info['type'] = type(obj).__name__
        except Exception as e:
            info['error'] = str(e)
        summary['scalers'][str(f)] = info

# If no files found, try to inspect any in-memory mapped scaler cache file locations
# (legacy: check for '*.scalers' json metadata)
# Save summary
with open(OUT_FILE, 'w', encoding='utf-8') as fh:
    json.dump(summary, fh, indent=2)

print('Audit complete. Summary written to:', OUT_FILE)
