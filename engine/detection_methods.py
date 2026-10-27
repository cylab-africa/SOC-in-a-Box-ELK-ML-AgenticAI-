

"""
Fixed Detection Methods - Job-Specific Anomaly Detection
=========================================================
Handles all 15 jobs with proper entity selection and filtering
"""

import json
import logging
import os
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

logger = logging.getLogger("linux_anomaly_detection")

# Module-level store for per-run, per-job entity diagnostics
_ENTITY_DIAGNOSTICS = {}

def add_entity_diagnostic(job_name: str, entity: str, info: dict):
    """Record diagnostic info for a specific entity under a job."""
    try:
        if job_name not in _ENTITY_DIAGNOSTICS:
            _ENTITY_DIAGNOSTICS[job_name] = {}
        _ENTITY_DIAGNOSTICS[job_name][entity] = info
    except Exception:
        logger.debug("Failed to add entity diagnostic")

def pop_job_entity_diagnostics(job_name: str) -> dict:
    """Return and clear diagnostics for a job."""
    try:
        return _ENTITY_DIAGNOSTICS.pop(job_name, {})
    except Exception:
        return {}

# ===============================================================================
# JOB-SPECIFIC DETECTION CONFIGURATION
# ===============================================================================

JOB_CONFIGURATIONS = {
    "v3_linux_anomalous_process_all_hosts": {
        "data_type": "process",
        "entity_column": "process.name",
        "filter_func": None,
        "description": "Detect anomalous processes across all hosts"
    },
    "v3_rare_process_by_host_linux": {
        "data_type": "process",
        "entity_column": "composite:host_process",
        "filter_func": None,
        "description": "Detect rare processes specific to each host"
    },
    "v3_linux_anomalous_network_activity": {
        "data_type": "network",
        "entity_column": "destination.ip",
        "filter_func": None,
        "description": "Detect anomalous network connections by IP"
    },
    "v3_linux_anomalous_network_port_activity": {
        "data_type": "network",
        "entity_column": "destination.port",
        "filter_func": None,
        "description": "Detect anomalous port usage patterns"
    },
    "v3_linux_anomalous_user_name": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": None,
        "description": "Detect anomalous user behavior"
    },
    "v3_linux_rare_sudo_user": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": lambda df: df[df['process.name'] == 'sudo'] if 'process.name' in df.columns else df,
        "description": "Detect rare sudo usage by users"
    },
    "v3_linux_rare_user_compiler": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": lambda df: df[df['process.name'].isin(['gcc', 'g++', 'clang', 'make', 'cmake', 'javac', 'rustc'])] if 'process.name' in df.columns else df,
        "description": "Detect rare compiler usage by users"
    },
    "v3_linux_network_configuration_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['ifconfig', 'ip', 'route', 'iptables', 'netstat', 'ss'])] if 'process.name' in df.columns else df,
        "description": "Detect network configuration discovery"
    },
    "v3_linux_network_connection_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['netstat', 'ss', 'lsof', 'nmap', 'nc'])] if 'process.name' in df.columns else df,
        "description": "Detect network connection discovery"
    },
    "v3_linux_system_information_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['uname', 'hostname', 'lscpu', 'dmidecode', 'cat'])] if 'process.name' in df.columns else df,
        "description": "Detect system information discovery"
    },
    "v3_linux_system_process_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['ps', 'top', 'htop', 'pgrep', 'pidof'])] if 'process.name' in df.columns else df,
        "description": "Detect process discovery"
    },
    "v3_linux_system_user_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['who', 'w', 'last', 'lastlog', 'id', 'users'])] if 'process.name' in df.columns else df,
        "description": "Detect user discovery"
    },
    "v3_linux_rare_metadata_process": {
        "data_type": "metadata",
        "entity_column": "composite:process_args",
        "filter_func": None,
        "description": "Detect rare process arguments"
    },
    "v3_linux_rare_metadata_user": {
        "data_type": "metadata",
        "entity_column": "composite:user_group",
        "filter_func": None,
        "description": "Detect rare user/group combinations"
    },
    # ── Auth group jobs ────────────────────────────────────────────────────
    "v3_linux_auth_rare_source_ip": {
        "data_type": "auth",
        "entity_column": "source.ip",
        "filter_func": lambda df: df[df["source.ip"].astype(str).str.strip() != ""] if "source.ip" in df.columns else df,
        "description": "Detect rare source IPs authenticating to hosts"
    },
    "v3_linux_auth_high_count_logon_fails": {
        "data_type": "auth",
        "entity_column": "user_host",
        "filter_func": lambda df: df[df.get("is_failed_login", pd.Series(0, index=df.index)) == 1],
        "description": "Detect brute-force login attempts per user+host"
    },
    "v3_linux_auth_rare_user": {
        "data_type": "auth",
        "entity_column": "user.name",
        "filter_func": lambda df: df[df["user.name"].astype(str).str.strip() != ""] if "user.name" in df.columns else df,
        "description": "Detect rare user accounts authenticating"
    },
    "v3_linux_auth_rare_hour": {
        "data_type": "auth",
        "entity_column": "user.name",
        "filter_func": lambda df: df[(df.get("is_business_hours", pd.Series(0, index=df.index)) == 0) & (df["user.name"].astype(str).str.strip() != "")] if "user.name" in df.columns else df,
        "description": "Detect authentication events at unusual hours"
    },
    # ── Host group jobs ────────────────────────────────────────────────────
    "v3_linux_anomalous_host_activity": {
        "data_type": "host",
        "entity_column": "host.hostname",
        "filter_func": None,
        "description": "Detect hosts with anomalous overall activity profiles"
    },
    "v3_linux_host_user_deviation": {
        "data_type": "host",
        "entity_column": "host.hostname",
        "filter_func": None,
        "description": "Detect hosts showing unusual per-host user activity patterns"
    }
}

# def detect_job_anomalies(data: pd.DataFrame, models: Dict, scalers: Dict,
#                          config: Dict, job_name: str) -> pd.DataFrame:
#     """
#     Main entry point for job-specific anomaly detection.

#     Args:
#         data: Input data
#         models: Trained models dictionary
#         scalers: Fitted scalers dictionary
#         config: Configuration
#         job_name: Specific job to run

#     Returns:
#         DataFrame with anomaly detection results
#     """
#     if job_name not in JOB_CONFIGURATIONS:
#         logger.error(f"Unknown job: {job_name}")
#         return pd.DataFrame()

#     job_config = JOB_CONFIGURATIONS[job_name]
#     data_type = job_config['data_type']

#     logger.info(f"Running job: {job_name}")
#     logger.info(f"Description: {job_config['description']}")

#     # Extract job-specific models
#     job_models = {}
#     job_scalers = {}

#     for key, model in models.items():
#         if key.startswith(f"{job_name}:"):
#             entity = key.replace(f"{job_name}:", "")
#             job_models[entity] = model

#     for key, scaler in scalers.items():
#         if key.startswith(f"{job_name}:"):
#             entity = key.replace(f"{job_name}:", "")
#             job_scalers[entity] = scaler

#     if not job_models:
#         logger.warning(f"No models found for job {job_name}, checking fallback models")
#         # Try without job prefix (for backward compatibility)
#         job_models = models
#         job_scalers = scalers

#     # Run detection with job-specific configuration
#     config['current_job_name'] = job_name
#     config['job_config'] = job_config

#     return detect_ml_anomalies_fixed(
#         data=data,
#         models=job_models,
#         scalers=job_scalers,
#         config=config,
#         job_name=job_name
#     )

# def detect_ml_anomalies_fixed(data: pd.DataFrame, models: Dict, scalers: Dict,
#                               config: Dict, job_name: str) -> pd.DataFrame:
#     """
#     Fixed ML anomaly detection with proper job-specific handling.
#     """
#     if data.empty:
#         logger.warning(f"Empty data for job {job_name}")
#         return pd.DataFrame()

#     if not models or not scalers:
#         logger.warning(f"No models/scalers for job {job_name}")
#         return _create_fallback_results(data, "no_models")

#     job_config = JOB_CONFIGURATIONS.get(job_name, {})
#     data_type = job_config.get('data_type', 'process')

#     logger.info(f"ML detection for job {job_name} with {len(data)} records")

#     # Step 1: Apply job-specific filtering
#     filtered_data = data.copy()
#     if job_config.get('filter_func'):
#         try:
#             filtered_data = job_config['filter_func'](filtered_data)
#             logger.info(f"Applied filter: {len(data)} -> {len(filtered_data)} records")
#         except Exception as e:
#             logger.error(f"Filter failed for {job_name}: {e}")

#     if filtered_data.empty:
#         logger.warning(f"No data after filtering for {job_name}")
#         return _create_fallback_results(data, "empty_after_filter")

#     # Step 2: Feature extraction
#     try:
#         feature_data = extract_ml_features(filtered_data, config, job_name)

#         if feature_data.empty:
#             logger.error(f"Feature extraction failed for {job_name}")
#             return _create_fallback_results(data, "feature_extraction_failed")

#     except Exception as e:
#         logger.error(f"Feature extraction error for {job_name}: {e}")
#         return _create_fallback_results(data, f"feature_error_{str(e)[:30]}")

#     # Step 3: Create composite entity columns if needed
#     entity_column = job_config['entity_column']

#     if entity_column.startswith('composite:'):
#         composite_type = entity_column.replace('composite:', '')
#         entity_column = _create_composite_entity(feature_data, composite_type, job_name)

#         if not entity_column:
#             logger.error(f"Failed to create composite entity for {job_name}")
#             return _create_fallback_results(data, "composite_entity_failed")

#     # Step 4: Validate entity column exists
#     if entity_column not in feature_data.columns:
#         logger.error(f"Entity column '{entity_column}' missing for {job_name}")
#         # Try fallback columns
#         fallback_columns = {
#             'process': 'process.name',
#             'network': 'destination.ip',
#             'user': 'user.name',
#             'discovery': 'process.name',
#             'metadata': 'process.name'
#         }
#         entity_column = fallback_columns.get(data_type, 'process.name')

#         if entity_column not in feature_data.columns:
#             return _create_fallback_results(data, f"missing_entity_{entity_column}")

#     # Step 5: Get entities for processing
#     entities = feature_data[entity_column].unique()

#     # Special handling for port entities
#     if job_name == "v3_linux_anomalous_network_port_activity":
#         entities = _filter_port_entities(feature_data, entity_column)

#     # Step 6: Validate entities against models
#     valid_entities = _validate_entities(entities, models, scalers, job_name)

#     if not valid_entities:
#         logger.warning(f"No valid entities for {job_name}, using fallback")
#         valid_entities = _get_fallback_entities(models, entities)

#         if not valid_entities:
#             return _create_fallback_results(data, "no_valid_entities")

#     # Step 7: Process each entity
#     all_results = []

#     for entity in valid_entities:
#         try:
#             entity_results = _process_entity_anomalies(
#                 entity=entity,
#                 feature_data=feature_data,
#                 entity_column=entity_column,
#                 models=models,
#                 scalers=scalers,
#                 config=config,
#                 job_name=job_name
#             )

#             if not entity_results.empty:
#                 all_results.append(entity_results)

#         except Exception as e:
#             logger.error(f"Failed to process entity {entity} for {job_name}: {e}")
#             continue

#     # Step 8: Combine results
#     if all_results:
#         combined_results = pd.concat(all_results, ignore_index=True)

#         # Apply safety limits
#         combined_results = _apply_safety_limits(combined_results, config)

#         # Add job metadata
#         combined_results['job_name'] = job_name
#         combined_results['detection_timestamp'] = pd.Timestamp.now()

#         anomaly_count = combined_results.get('is_ml_anomaly', pd.Series()).sum()
#         logger.info(f"Job {job_name} complete: {anomaly_count}/{len(combined_results)} anomalies")

#         return combined_results
#     else:
#         logger.error(f"No results for job {job_name}")
#         return _create_fallback_results(data, "no_results")
def detect_job_anomalies(data: pd.DataFrame, models: dict, scalers: dict,
                         config: dict, job_name: str) -> pd.DataFrame:
    """
    Main entry point for job-specific anomaly detection with enhanced debugging.

    FIXED: Now returns only DataFrame for backward compatibility.
    If you need saveable results, use detect_job_anomalies_with_saveable() instead.
    """
    logger.info("="*80)
    logger.info(f"Starting job anomaly detection for: {job_name}")

    # Validate inputs
    if data.empty:
        logger.error("Empty input data")
        return pd.DataFrame()

    if job_name not in JOB_CONFIGURATIONS:
        logger.error(f"Unknown job: {job_name}")
        return pd.DataFrame()

    # Load job configuration
    job_config = JOB_CONFIGURATIONS[job_name]
    data_type = job_config['data_type']

    logger.info("-"*40)
    logger.info("Job Configuration:")
    logger.info(f"  Job: {job_name}")
    logger.info(f"  Type: {data_type}")
    logger.info(f"  Description: {job_config['description']}")
    logger.info(f"  Input records: {len(data)}")
    logger.info("-"*40)

    # Debug input data
    logger.debug(f"Input data columns: {list(data.columns)}")
    logger.debug(f"Input data types: {data.dtypes.to_dict()}")

    # Extract job-specific models
    logger.info("Loading models and scalers...")
    job_models, job_scalers = load_models_for_job(models, scalers, job_name)

    # Debug model loading
    logger.debug(f"Available models: {len(models)}")
    logger.debug(f"Job-specific models: {len(job_models)}")
    logger.debug(f"Model entities: {list(job_models.keys())[:5]}...")

    if not job_models:
        # Check if models are already entity-keyed (pre-extracted by caller)
        has_job_prefix = any(':' in k for k in models)
        if not has_job_prefix and models:
            logger.info(f"Models already entity-keyed for {job_name}, using {len(models)} models directly")
            job_models = models
            job_scalers = scalers
        else:
            logger.warning(f"No models found for job {job_name}, using fallback models")
            job_models = models
            job_scalers = scalers
            logger.debug("Using fallback models:")
            logger.debug(f"  Total models: {len(job_models)}")
            logger.debug(f"  Model types: {[type(m).__name__ for m in list(job_models.values())[:3]]}...")

    # Update configuration
    config['current_job_name'] = job_name
    config['job_config'] = job_config

    logger.info("Starting ML detection...")
    results = detect_ml_anomalies_fixed(
        data=data,
        models=job_models,
        scalers=job_scalers,
        config=config,
        job_name=job_name
    )

    # Process results
    if not results.empty:
        # Add metadata
        results['job_name'] = job_name
        results['detection_timestamp'] = pd.Timestamp.now()

        # Calculate metrics
        total_records = len(results)
        anomaly_count = results['is_ml_anomaly'].sum() if 'is_ml_anomaly' in results.columns else 0
        anomaly_rate = (anomaly_count / total_records * 100) if total_records > 0 else 0

        # Log summary
        logger.info("="*40)
        logger.info("Detection Summary:")
        logger.info(f"  Total records: {total_records:,}")
        logger.info(f"  Anomalies detected: {anomaly_count:,}")
        logger.info(f"  Anomaly rate: {anomaly_rate:.2f}%")
        logger.info("="*40)

        # Debug result details
        logger.debug("Result columns: " + ", ".join(results.columns))
        if 'ml_anomaly_score' in results.columns:
            scores = results['ml_anomaly_score']
            logger.debug(f"Score stats: min={scores.min():.3f}, max={scores.max():.3f}, "
                        f"mean={scores.mean():.3f}, std={scores.std():.3f}")
    else:
        logger.warning("No results produced")

    logger.info(f"Job {job_name} complete")

    # FIXED: Return only DataFrame, not tuple
    return results
def detect_job_anomalies_with_saveable(data: pd.DataFrame, models: dict, scalers: dict,
                                       config: dict, job_name: str) -> tuple[pd.DataFrame, dict]:
    """
    Alternative function that returns both DataFrame and saveable results.
    Use this if you need both outputs.
    """
    # Get the DataFrame results
    results = detect_job_anomalies(data, models, scalers, config, job_name)

    # Generate saveable results
    saveable_results = _save_detection_results(results, job_name)

    return results, saveable_results
def _save_detection_results(results: pd.DataFrame, job_name: str) -> dict:
    """
    Convert detection results to saveable format.
    """
    if results.empty:
        return {
            "job_name": job_name,
            "anomaly_count": 0,
            "anomalies": []
        }

    # Check if the required column exists
    if 'is_ml_anomaly' not in results.columns:
        logger.warning(f"No 'is_ml_anomaly' column in results for {job_name}")
        return {
            "job_name": job_name,
            "anomaly_count": 0,
            "anomalies": []
        }

    # Extract anomalies
    anomalies = results[results['is_ml_anomaly']].copy()

    formatted_anomalies = []
    for _, row in anomalies.iterrows():
        anomaly = {
            "timestamp": row.get('@timestamp', pd.Timestamp.now()).isoformat(),
            "score": float(row.get('ml_anomaly_score', 0.0)),
            "confidence": float(row.get('confidence', 0.0)),
            "entity": str(row.get('entity', '')),
            "detection_method": str(row.get('detection_method', 'machine_learning')),
            "features": {
                col: str(val) for col, val in row.items()
                if col not in ['@timestamp', 'ml_anomaly_score', 'confidence',
                             'entity', 'detection_method', 'is_ml_anomaly']
            }
        }
        formatted_anomalies.append(anomaly)

    return {
        "job_name": job_name,
        "anomaly_count": len(formatted_anomalies),
        "anomalies": formatted_anomalies
    }

def save_ml_results(all_job_results: dict[str, pd.DataFrame], output_file: str) -> None:
    """
    Save ML detection results to JSON file.
    """
    total_anomalies = 0
    ml_jobs = {}

    # Process each job's results
    for job_name, results in all_job_results.items():
        if not isinstance(results, pd.DataFrame):
            logger.warning(f"Invalid results type for {job_name}")
            continue

        job_results = _save_detection_results(results, job_name)
        total_anomalies += job_results['anomaly_count']
        ml_jobs[job_name] = job_results

    # Create final output
    output = {
        "total_ml_anomalies": total_anomalies,
        "detection_timestamp": pd.Timestamp.now().isoformat(),
        "detection_summary": (
            f"Found {total_anomalies} ML anomalies across {len(ml_jobs)} jobs"
            if total_anomalies > 0 else
            "No ML anomalies detected - check thresholds"
        ),
        "ml_jobs": ml_jobs
    }

    # Save to file
    try:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        logger.info(f"Saved {total_anomalies} anomalies to: {output_file}")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")

def process_detection(data: pd.DataFrame, models: dict, scalers: dict, config: dict, job_name: str) -> pd.DataFrame:
    """
    Run the ML detection pipeline for a single job and return a pandas DataFrame.

    Guarantee: this function always returns a pandas DataFrame (possibly empty)
    and never a tuple or dict. It centralizes feature extraction, entity
    validation, per-entity processing, combining, safety limits and final
    normalization.
    """
    # Normalize input to DataFrame
    if not isinstance(data, pd.DataFrame):
        try:
            data = pd.DataFrame(data)
        except Exception:
            logger.error("process_detection: could not convert input data to DataFrame")
            return pd.DataFrame()

    if data.empty:
        logger.warning(f"process_detection: empty input for job {job_name}")
        return pd.DataFrame()

    job_config = JOB_CONFIGURATIONS.get(job_name, {}) if 'JOB_CONFIGURATIONS' in globals() else {}
    data_type = job_config.get('data_type', 'process')

    # Determine expected features from provided scalers (union across entities) and pass to extractor
    expected_features = None
    try:
        feature_name_set = set()
        for s in (scalers or {}).values():
            try:
                if hasattr(s, 'feature_names_in_') and s.feature_names_in_ is not None:
                    feature_name_set.update(list(s.feature_names_in_))
            except Exception:
                continue
        if feature_name_set:
            expected_features = list(feature_name_set)
    except Exception:
        expected_features = None

    # Feature extraction
    try:
        feature_data = extract_ml_features(data, config, job_name, expected_features=expected_features)
        if feature_data is None:
            logger.error(f"process_detection: extract_ml_features returned None for {job_name}")
            return _create_fallback_results(data, "feature_extraction_failed")
        if not isinstance(feature_data, pd.DataFrame):
            feature_data = pd.DataFrame(feature_data)
    except Exception as e:
        logger.error(f"process_detection: feature extraction failed for {job_name}: {e}")
        return _create_fallback_results(data, f"feature_error_{str(e)[:50]}")

    if feature_data.empty:
        logger.warning(f"process_detection: no feature data for {job_name}")
        return _create_fallback_results(data, "empty_features")

    # Entity column handling
    # Use job-specific entity column, fall back to a local mapping if global
    fallback_columns = {
        'process': 'process.name',
        'network': 'destination.ip',
        'user': 'user.name',
        'discovery': 'process.name',
        'metadata': 'process.name'
    }
    entity_column = job_config.get('entity_column') or fallback_columns.get(data_type, 'process.name')
    if isinstance(entity_column, str) and entity_column.startswith('composite:'):
        composite_type = entity_column.replace('composite:', '')
        entity_column = _create_composite_entity(feature_data, composite_type, job_name)

    if entity_column not in feature_data.columns:
        fallback_columns = {
            'process': 'process.name',
            'network': 'destination.ip',
            'user': 'user.name',
            'discovery': 'process.name',
            'metadata': 'process.name',
            'auth': 'user.name',
            'host': 'host.hostname',
        }
        entity_column = fallback_columns.get(data_type, 'process.name')

        if entity_column not in feature_data.columns:
            logger.error(f"process_detection: entity column '{entity_column}' missing for {job_name}")
            return _create_fallback_results(data, f"missing_entity_{entity_column}")

    # Extract entities
    try:
        entities = feature_data[entity_column].dropna().unique().tolist()
    except Exception as e:
        logger.error(f"process_detection: failed extracting entities for {job_name}: {e}")
        return _create_fallback_results(data, "entity_extraction_failed")

    # Special handling for port job
    if job_name == "v3_linux_anomalous_network_port_activity" and 'destination.port' in feature_data.columns:
        try:
            entities = _filter_port_entities(feature_data, entity_column)
        except Exception:
            pass

    # Validate entities
    try:
        valid_entities = _validate_entities(entities, models, scalers, job_name)
    except Exception as e:
        logger.error(f"process_detection: entity validation failed for {job_name}: {e}")
        valid_entities = []

    if not valid_entities:
        logger.warning(f"process_detection: no valid entities for {job_name}, attempting fallback")
        try:
            valid_entities = _get_fallback_entities(models, entities)
        except Exception:
            valid_entities = []

    if not valid_entities:
        logger.warning(f"process_detection: still no valid entities for {job_name}")
        return _create_fallback_results(data, "no_valid_entities")

    # Process entities
    frames = []
    for entity in valid_entities:
        try:
            er = _process_entity_anomalies(
                entity=entity,
                feature_data=feature_data,
                entity_column=entity_column,
                models=models,
                scalers=scalers,
                config=config,
                job_name=job_name
            )

            # Accept and normalize possible return types
            if isinstance(er, tuple):
                er = er[0] if len(er) > 0 and isinstance(er[0], pd.DataFrame) else pd.DataFrame()
            if isinstance(er, dict):
                er = pd.DataFrame.from_dict(er)

            if isinstance(er, pd.DataFrame) and not er.empty:
                frames.append(er)
        except Exception as e:
            logger.error(f"process_detection: failed processing entity '{entity}' for {job_name}: {e}")
            continue

    if not frames:
        logger.error(f"process_detection: no results produced for {job_name}")
        return _create_fallback_results(data, "no_results")

    try:
        combined = pd.concat(frames, ignore_index=True)
    except Exception as e:
        logger.error(f"process_detection: concat failed for {job_name}: {e}")
        return _create_fallback_results(data, "concat_failed")

    if 'is_ml_anomaly' not in combined.columns:
        combined['is_ml_anomaly'] = combined.get('is_ml_anomaly', False)

    try:
        combined = _apply_safety_limits(combined, config)
    except Exception as e:
        logger.warning(f"process_detection: safety limits failed for {job_name}: {e}")

    combined['job_name'] = job_name
    combined['detection_timestamp'] = pd.Timestamp.now()

    if not isinstance(combined, pd.DataFrame):
        combined = pd.DataFrame(combined)

    return combined

def detect_ml_anomalies_fixed(data: pd.DataFrame, models: dict, scalers: dict,
                              config: dict, job_name: str) -> pd.DataFrame:
    """
    FIXED: Always return DataFrame from ML detection (top-level helper).
    """
    try:
        if data is None or (hasattr(data, 'empty') and data.empty):
            return pd.DataFrame()

        # Process data and get results
        results = process_detection(data, models, scalers, config, job_name)

        # Convert to DataFrame if needed
        if isinstance(results, dict):
            results = pd.DataFrame.from_dict(results)
        elif not isinstance(results, pd.DataFrame):
            logger.error("detect_ml_anomalies_fixed: Invalid results type returned from process_detection")
            return pd.DataFrame()

        return results
    except Exception as e:
        logger.error(f"detect_ml_anomalies_fixed: unexpected error: {e}")
        return pd.DataFrame()

def combine_job_results(job_results: list[dict]) -> dict:
    """
    Combine results from multiple jobs with proper formatting.
    """
    total_anomalies = sum(r.get('anomaly_count', 0) for r in job_results)

    {
        "total_ml_anomalies": total_anomalies,
        "detection_timestamp": pd.Timestamp.now().isoformat(),
        "detection_summary": (
            f"Found {total_anomalies} ML anomalies across {len(job_results)} jobs"
            if total_anomalies > 0 else
            "No ML anomalies detected - check thresholds"
        ),
        "ml_jobs": {
            r['job_name']: {
                "anomaly_count": r.get('anomaly_count', 0),
                "anomalies": r.get('anomalies', [])
            }
            for r in job_results
        }
    }

    # (detect_ml_anomalies_fixed removed from nested scope to top-level)

def extract_ml_features(data: pd.DataFrame, config: dict, job_name: str, expected_features: list[str] | None = None, impute_map: dict[str, float] | None = None) -> pd.DataFrame:
    """
    Fixed feature extraction with job-specific handling.
    """
    # New optional parameter expected_features can be passed to ensure the extractor
    # produces columns that match model/scaler training features. This helps avoid
    # runtime shape mismatches when scalers expect specific feature names/order.
    # Backwards compatible: callers that don't pass expected_features will behave
    # as before.
    # NOTE: signature change is supported via optional kwarg in callers.
    if isinstance(data, dict):
        data = pd.DataFrame(data)
    if data.empty:
        return data


    df = data.copy()
    job_config = JOB_CONFIGURATIONS.get(job_name, {})
    data_type = job_config.get('data_type', 'process')

    logger.info(f"Feature extraction for job {job_name} ({data_type})")

    # Add event count
    if 'event_count' not in df.columns:
        df['event_count'] = 1

    # Temporal features
    if '@timestamp' in df.columns:
        try:
            timestamps = pd.to_datetime(df['@timestamp'], errors='coerce')
            timestamps = timestamps.fillna(pd.Timestamp.now())

            df['hour_of_day'] = timestamps.dt.hour
            df['hour_sin'] = np.sin(2 * np.pi * timestamps.dt.hour / 24)
            df['hour_cos'] = np.cos(2 * np.pi * timestamps.dt.hour / 24)
            df['day_sin'] = np.sin(2 * np.pi * timestamps.dt.dayofweek / 7)
            df['day_cos'] = np.cos(2 * np.pi * timestamps.dt.dayofweek / 7)
            df['is_business_hours'] = ((timestamps.dt.hour >= 9) & (timestamps.dt.hour <= 17)).astype(int)
            df['is_weekend'] = (timestamps.dt.dayofweek >= 5).astype(int)

        except Exception as e:
            logger.warning(f"Temporal feature extraction failed: {e}")
            # Add defaults
            df['hour_sin'] = 0
            df['hour_cos'] = 1
            df['day_sin'] = 0
            df['day_cos'] = 1
            df['is_business_hours'] = 1
            df['is_weekend'] = 0

    # Job-specific features
    if job_name == "v3_linux_anomalous_network_port_activity":
        # Port-specific features
        if 'destination.port' in df.columns:
            df['destination.port'] = pd.to_numeric(df['destination.port'], errors='coerce').fillna(0)
            df['is_well_known_port'] = (df['destination.port'] < 1024).astype(int)
            df['is_high_port'] = (df['destination.port'] > 32767).astype(int)
            df['is_common_service'] = df['destination.port'].isin([22, 80, 443, 3306, 5432]).astype(int)

    elif job_name == "v3_rare_process_by_host_linux":
        # Host-process combination features
        if 'host.hostname' in df.columns and 'process.name' in df.columns:
            df['host_process_freq'] = df.groupby(['host.hostname', 'process.name'])['event_count'].transform('count')

    elif job_name in ["v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"]:
        # User-specific features
        if 'user.name' in df.columns:
            df['user_frequency'] = df.groupby('user.name')['event_count'].transform('count') / len(df)

    elif job_name.startswith("v3_linux") and "discovery" in job_name:
        # Discovery command features
        if 'process.command_line' in df.columns:
            df['command_length'] = df['process.command_line'].str.len().fillna(0)
            df['has_pipes'] = df['process.command_line'].str.contains('|', na=False).astype(int)
            df['has_redirection'] = df['process.command_line'].str.contains('[<>]', na=False, regex=True).astype(int)

    elif job_name == "v3_linux_rare_metadata_process":
        # Process metadata features
        if 'process.args' in df.columns:
            df['args_count'] = df['process.args'].apply(
                lambda x: len(x) if isinstance(x, list) else 0
            )
            df['args_length'] = df['process.args'].apply(
                lambda x: len(str(x)) if x else 0
            )

    elif job_name == "v3_linux_rare_metadata_user":
        # User metadata features
        if 'user.group' in df.columns:
            df['group_count'] = df.groupby('user.group')['event_count'].transform('count')

    # Clean numeric columns. Prefer impute_map values when present.
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)
        if impute_map:
            for col in numeric_cols:
                if col in df.columns:
                    if col in impute_map:
                        try:
                            val = float(impute_map[col])
                        except Exception:
                            val = 0.0
                        df[col] = df[col].fillna(val)
                    else:
                        df[col] = df[col].fillna(0)
        else:
            df[numeric_cols] = df[numeric_cols].fillna(0)

    # If expected_features supplied (from scaler metadata), ensure those columns exist
    # and are numeric. Prefer to impute missing features from training statistics
    # provided by impute_map or by loading per-job manifests from the configured
    # models base path. Falls back to zero.
    try:
        # Load per-job manifests if caller didn't provide impute_map
        if expected_features and impute_map is None:
            try:
                models_base = config.get('models', {}).get('storage', {}).get('base_path', '/tmp/linux_anomaly_models')
                manifest_path = os.path.join(models_base, f"{job_name.split(':')[0]}_feature_manifests.json")
                if os.path.exists(manifest_path):
                    with open(manifest_path, encoding='utf-8') as fh:
                        import json
                        manifests = json.load(fh)
                        # manifests keys are entity names -> feature lists/stats
                        # Build a simple impute_map using global feature centers if available
                        impute_map = {}
                        # prefer 'global' entry if present
                        if 'global' in manifests:
                            global_entry = manifests['global']
                            for i, fname in enumerate(global_entry.get('feature_names_in_', [])):
                                if 'center_' in global_entry and i < len(global_entry['center_']):
                                    impute_map[fname] = global_entry['center_'][i]
                        else:
                            # Use first manifest entry as fallback
                            for entry in manifests.values():
                                for i, fname in enumerate(entry.get('feature_names_in_', [])):
                                    if 'center_' in entry and i < len(entry['center_']):
                                        impute_map.setdefault(fname, entry['center_'][i])
            except Exception:
                impute_map = impute_map or {}

        if expected_features:
            for f in expected_features:
                if f not in df.columns:
                    # Determine imputation value
                    impute_val = 0.0
                    if impute_map and f in impute_map:
                        try:
                            impute_val = float(impute_map[f])
                        except Exception:
                            impute_val = 0.0
                    df[f] = impute_val
                else:
                    # Coerce to numeric where possible
                    if not pd.api.types.is_numeric_dtype(df[f].dtype):
                        df[f] = pd.to_numeric(df[f], errors='coerce').fillna(0.0)

            # Optionally reorder columns so expected features appear first (helps debugging)
            cols = list(df.columns)
            reordered = [c for c in expected_features if c in cols] + [c for c in cols if c not in expected_features]
            df = df.loc[:, reordered]
    except Exception as e:
        logger.debug(f"Failed to align extract_ml_features to expected_features: {e}")

    return df

def _create_composite_entity(data: pd.DataFrame, composite_type: str, job_name: str) -> str | None:
    """
    Create composite entity columns for specific jobs.
    """
    column_name = f"entity_{composite_type}"

    try:
        if composite_type == "host_process":
            if 'host.hostname' in data.columns and 'process.name' in data.columns:
                data[column_name] = (
                    data['host.hostname'].fillna('unknown').astype(str) + ':' +
                    data['process.name'].fillna('unknown').astype(str)
                )
                logger.info(f"Created composite entity for {job_name}: {column_name}")
                return column_name

        elif composite_type == "process_args":
            if 'process.name' in data.columns:
                if 'process.args' in data.columns:
                    data[column_name] = (
                        data['process.name'].fillna('unknown').astype(str) + '::' +
                        data['process.args'].fillna('').astype(str).str[:100]
                    )
                else:
                    data[column_name] = data['process.name'].fillna('unknown').astype(str)
                return column_name

        elif composite_type == "user_group":
            if 'user.name' in data.columns:
                if 'user.group' in data.columns:
                    data[column_name] = (
                        data['user.name'].fillna('unknown').astype(str) + '::' +
                        data['user.group'].fillna('unknown').astype(str)
                    )
                else:
                    data[column_name] = data['user.name'].fillna('unknown').astype(str)
                return column_name

    except Exception as e:
        logger.error(f"Failed to create composite entity {composite_type}: {e}")

    return None

def _filter_port_entities(data: pd.DataFrame, entity_column: str) -> list:
    """
    Filter port entities to focus on important ports.
    """
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                   1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                   9200, 27017, 4444, 31337]

    if entity_column not in data.columns:
        return []

    # Convert to numeric
    data['port_numeric'] = pd.to_numeric(data[entity_column], errors='coerce')

    # Get frequency
    port_counts = data['port_numeric'].value_counts()

    # Get ports with enough samples
    min_samples = 10
    frequent_ports = port_counts[port_counts >= min_samples].index.tolist()

    # Include common ports
    important_ports = list(set(frequent_ports + common_ports))

    # Convert back to string
    return [str(int(p)) for p in important_ports if not pd.isna(p)]

# In _validate_entities function:
def _validate_entities(entities, models: dict, scalers: dict, job_name: str):
    """
    Fixed entity validation that handles the job prefix correctly.
    """
    valid_entities = []

    # Models are stored with just entity names after loading with load_models_for_job
    for entity in entities:
        # Check if entity exists in models
        if entity in models and entity in scalers:
            valid_entities.append(entity)
        # Also check for partial matches (for IPs with ports)
        elif any(entity in key for key in models.keys()):
            valid_entities.append(entity)

    # If no exact matches, try to find similar entities
    if not valid_entities and models:
        # For network IPs, try matching on partial IP
        if '.' in str(entities[0]):  # Likely an IP
            for entity in entities[:10]:  # Check first 10
                for model_key in models.keys():
                    if entity.split('.')[0] == model_key.split('.')[0]:  # Same subnet
                        valid_entities.append(model_key)
                        break

    return valid_entities
def load_models_for_job(models_dict: dict, scalers_dict: dict, job_name: str) -> tuple:
    """
    Correctly extract models for a specific job from the stored dictionaries.
    """
    job_models = {}
    job_scalers = {}

    # Your models are stored with full job:entity keys
    for key, model in models_dict.items():
        if key.startswith(f"{job_name}:"):
            # Extract just the entity part
            entity = key.split(':', 1)[1]
            job_models[entity] = model

    for key, scaler in scalers_dict.items():
        if key.startswith(f"{job_name}:"):
            entity = key.split(':', 1)[1]
            job_scalers[entity] = scaler

    return job_models, job_scalers
def _get_fallback_entities(models: dict, entities: list) -> list:
    """
    Get fallback entities when no direct matches found.
    """
    if 'global' in models:
        return ['global']

    if models:
        # Use first available model
        return [list(models.keys())[0]]

    return []
def _process_entity_anomalies(entity: str, feature_data: pd.DataFrame,
                                entity_column: str, models: dict, scalers: dict,
                                config: dict, job_name: str) -> pd.DataFrame:
    """
    Process anomalies for a specific entity with improved scoring and validation.
    """
    try:
        # Get entity data
        if entity == 'global':
            entity_data = feature_data.copy()
        else:
            entity_data = feature_data[feature_data[entity_column] == entity].copy()

        if entity_data.empty:
            logger.warning(f"No data for entity {entity}")
            return pd.DataFrame()

        # Reset index and get model/scaler
        entity_data = entity_data.reset_index(drop=True)
        entity_model = models.get(entity)
        entity_scaler = scalers.get(entity)

        if not entity_model:
            logger.error(f"Missing model for entity {entity}")
            add_entity_diagnostic(job_name, entity, {"status": "missing_model"})
            return pd.DataFrame()

        if not entity_scaler:
            logger.warning(f"Missing scaler for entity {entity}, will attempt fallback scaling")
            add_entity_diagnostic(job_name, entity, {"status": "missing_scaler"})

        # Normalize model format: accept plain estimator or dict of estimators
        if not isinstance(entity_model, dict):
            # Treat single estimator as isolation_forest by default
            try:
                entity_model = { 'isolation_forest': entity_model }
            except Exception:
                entity_model = {}

        # Get available numeric features early
        numeric_cols = entity_data.select_dtypes(include=[np.number]).columns.tolist()

        # Get features used in training from multiple fallbacks
        features_used = []
        if isinstance(entity_model, dict) and 'features_used' in entity_model:
            features_used = entity_model['features_used'] or []
        if not features_used and entity_scaler is not None and hasattr(entity_scaler, 'feature_names_in_'):
            try:
                features_used = list(entity_scaler.feature_names_in_)
            except Exception:
                features_used = []

        # Final fallback: use numeric columns as features
        if not features_used:
            features_used = numeric_cols

        # Align features to available numeric columns
        available_features = [f for f in features_used if f in numeric_cols]
        if not available_features:
            available_features = numeric_cols
            if not available_features:
                logger.error(f"No valid features for entity {entity}")
                return pd.DataFrame()

        # Extract and clean feature matrix
        # Align runtime features to scaler.feature_names_in_ when available to avoid shape mismatches
        if entity_scaler is not None and hasattr(entity_scaler, 'feature_names_in_'):
            try:
                expected_features = list(entity_scaler.feature_names_in_)
                # Log mismatch details if any
                missing = [f for f in expected_features if f not in entity_data.columns]
                extra = [f for f in available_features if f not in expected_features]
                if missing or extra:
                    logger.warning(
                        f"Scaler feature mismatch for {entity}: expected {len(expected_features)} features, "
                        f"runtime has {len(available_features)} features; missing={len(missing)}, extra={len(extra)}. Aligning features and filling missing with zeros."
                    )
                    add_entity_diagnostic(job_name, entity, {
                        "status": "feature_mismatch",
                        "expected_count": len(expected_features),
                        "runtime_count": len(available_features),
                        "missing": missing,
                        "extra": extra
                    })

                # Build aligned DataFrame in expected order, preferring scaler training stats
                # for imputation when available (center_/mean_/median_), otherwise fall
                # back to zero.
                aligned_df = pd.DataFrame(index=entity_data.index)
                imputed_map = {}
                for f in expected_features:
                    if f in entity_data.columns:
                        # coerce to numeric to avoid object dtypes
                        aligned_df[f] = pd.to_numeric(entity_data[f], errors='coerce').fillna(0.0)
                    else:
                        # Try to use scaler training statistics for imputation
                        impute_val = 0.0
                        impute_method = 'zero'
                        try:
                            if hasattr(entity_scaler, 'center_') and hasattr(entity_scaler, 'feature_names_in_'):
                                try:
                                    idx = list(entity_scaler.feature_names_in_).index(f)
                                    impute_val = float(entity_scaler.center_[idx])
                                    impute_method = 'scaler_center'
                                except Exception:
                                    pass
                            if impute_method == 'zero' and hasattr(entity_scaler, 'mean_') and hasattr(entity_scaler, 'feature_names_in_'):
                                try:
                                    idx = list(entity_scaler.feature_names_in_).index(f)
                                    impute_val = float(entity_scaler.mean_[idx])
                                    impute_method = 'scaler_mean'
                                except Exception:
                                    pass
                            if impute_method == 'zero' and hasattr(entity_scaler, 'median_') and hasattr(entity_scaler, 'feature_names_in_'):
                                try:
                                    idx = list(entity_scaler.feature_names_in_).index(f)
                                    impute_val = float(entity_scaler.median_[idx])
                                    impute_method = 'scaler_median'
                                except Exception:
                                    pass
                        except Exception:
                            impute_val = 0.0
                            impute_method = 'zero_error'

                        aligned_df[f] = impute_val
                        imputed_map[f] = { 'value': impute_val, 'method': impute_method }

                # If any imputation happened, add details to entity diagnostics
                if imputed_map:
                    try:
                        add_entity_diagnostic(job_name, entity, {
                            'status': 'feature_mismatch_imputed',
                            'expected_count': len(expected_features),
                            'runtime_count': len(available_features),
                            'missing': missing,
                            'extra': extra,
                            'imputed': imputed_map
                        })
                    except Exception:
                        pass

                X = aligned_df.values
            except Exception as e:
                logger.warning(f"Failed to align features for {entity} using scaler metadata: {e}; falling back to available features")
                X = entity_data[available_features].values
        else:
            X = entity_data[available_features].values

        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

        # Scale features with validation
        try:
            if entity_scaler is not None:
                X_scaled = entity_scaler.transform(X)
            else:
                raise Exception("No scaler available")

            if np.any(np.isnan(X_scaled)) or np.any(np.isinf(X_scaled)):
                logger.warning(f"Invalid values after scaling for {entity}, cleaning...")
                X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)
        except Exception as e:
            logger.warning(f"Standard scaling failed for {entity}: {e}, using fallback")
            add_entity_diagnostic(job_name, entity, {"status": "scaling_failed", "error": str(e)})
            try:
                from sklearn.preprocessing import RobustScaler
                fallback_scaler = RobustScaler()
                X_scaled = fallback_scaler.fit_transform(X)
                add_entity_diagnostic(job_name, entity, {"status": "fallback_scaler_used"})
            except Exception as ex:
                logger.error(f"Fallback scaling failed for {entity}: {ex}")
                add_entity_diagnostic(job_name, entity, {"status": "fallback_scaling_failed", "error": str(ex)})
                return pd.DataFrame()

        # Apply multiple ML methods
        method_scores = {}

        # Isolation Forest
        if isinstance(entity_model, dict) and 'isolation_forest' in entity_model:
            try:
                iso_forest = entity_model['isolation_forest']
                scores = -iso_forest.score_samples(X_scaled)  # Negative for anomaly scores
                scores = np.nan_to_num(scores, nan=0.5, posinf=1.0, neginf=0.0)
                # Robust normalization: handle constant or tiny-range arrays
                smin = scores.min()
                smax = scores.max()
                if not (np.isfinite(smin) and np.isfinite(smax)):
                    scores = np.zeros_like(scores)
                else:
                    denom = smax - smin
                    # avoid amplification when the range is extremely small
                    denom = max(denom, 1e-6)
                    scores = (scores - smin) / (denom + 1e-12)
                    scores = np.clip(scores, 0.0, 1.0)
                method_scores['isolation_forest'] = scores
            except Exception as e:
                logger.debug(f"Isolation Forest failed for {entity}: {e}")

        # Local Outlier Factor
        if isinstance(entity_model, dict) and 'local_outlier_factor' in entity_model:
            try:
                lof = entity_model['local_outlier_factor']
                if hasattr(lof, 'score_samples'):
                    scores = -lof.score_samples(X_scaled)  # Negative for anomaly scores
                else:
                    scores = -lof.decision_function(X_scaled)
                scores = np.nan_to_num(scores, nan=0.5, posinf=1.0, neginf=0.0)
                smin = scores.min()
                smax = scores.max()
                if not (np.isfinite(smin) and np.isfinite(smax)):
                    scores = np.zeros_like(scores)
                else:
                    denom = smax - smin
                    denom = max(denom, 1e-6)
                    scores = (scores - smin) / (denom + 1e-12)
                    scores = np.clip(scores, 0.0, 1.0)
                method_scores['local_outlier_factor'] = scores
            except Exception as e:
                logger.debug(f"LOF failed for {entity}: {e}")

        # One-Class SVM if available
        if isinstance(entity_model, dict) and 'one_class_svm' in entity_model:
            try:
                svm = entity_model['one_class_svm']
                scores = -svm.decision_function(X_scaled)  # Negative for anomaly scores
                scores = np.nan_to_num(scores, nan=0.5, posinf=1.0, neginf=0.0)
                smin = scores.min()
                smax = scores.max()
                if not (np.isfinite(smin) and np.isfinite(smax)):
                    scores = np.zeros_like(scores)
                else:
                    denom = smax - smin
                    denom = max(denom, 1e-6)
                    scores = (scores - smin) / (denom + 1e-12)
                    scores = np.clip(scores, 0.0, 1.0)
                method_scores['one_class_svm'] = scores
            except Exception as e:
                logger.debug(f"One-Class SVM failed for {entity}: {e}")

    # Calculate ensemble scores with weights
        if method_scores:
            weights = {
                'isolation_forest': 0.4,
                'local_outlier_factor': 0.3,
                'one_class_svm': 0.3
            }

            weighted_scores = []
            total_weight = 0
            # Debug: log per-method score statistics to diagnose uniform/constant scores
            try:
                for m, s in method_scores.items():
                    s_arr = np.array(s)
                    logger.debug(f"[scoring-debug] {job_name}:{entity} method={m} len={len(s_arr)} min={s_arr.min():.6g} max={s_arr.max():.6g} mean={s_arr.mean():.6g} std={s_arr.std():.6g} uniq={np.unique(s_arr).size}")
            except Exception as e:
                logger.debug(f"[scoring-debug] failed to log method scores for {job_name}:{entity}: {e}")

            for method, scores in method_scores.items():
                if method in weights:
                    weighted_scores.append(scores * weights[method])
                    total_weight += weights[method]

            if weighted_scores:
                ensemble_scores = np.sum(weighted_scores, axis=0) / total_weight
                # Debug: log ensemble stats immediately after aggregation
                try:
                    arr = np.array(ensemble_scores)
                    logger.info(f"[scoring-debug] {job_name}:{entity} ensemble len={len(arr)} min={arr.min():.6g} max={arr.max():.6g} mean={arr.mean():.6g} std={arr.std():.6g} uniq={np.unique(arr).size}")
                except Exception as e:
                    logger.info(f"[scoring-debug] failed to log ensemble stats for {job_name}:{entity}: {e}")
            else:
                ensemble_scores = np.zeros(len(entity_data))
        else:
            logger.warning(f"No valid detection methods for {entity}, falling back to statistical detection")
            add_entity_diagnostic(job_name, entity, {"status": "no_ml_methods", "fallback": "statistical"})
            try:
                stat = detect_statistical_anomalies(entity_data)
                # Map statistical outputs to ML-like schema
                if 'is_anomaly' in stat.columns:
                    entity_data['is_ml_anomaly'] = stat['is_anomaly']
                    entity_data['ml_anomaly_score'] = stat.get('anomaly_score', 0.0)
                    entity_data['confidence'] = stat.get('confidence', 0.0)
                    entity_data['detection_method'] = 'statistical'
                    entity_data['methods_used'] = 'statistical'
                    anomaly_count = entity_data['is_ml_anomaly'].sum()
                    logger.info(f"Entity {entity}: {anomaly_count}/{len(entity_data)} anomalies (statistical fallback)")
                    return entity_data
            except Exception as e:
                logger.error(f"Statistical fallback failed for {entity}: {e}")
                add_entity_diagnostic(job_name, entity, {"status": "statistical_fallback_failed", "error": str(e)})
            return pd.DataFrame()

        # Detect degenerate/constant ensemble (common when models/scalers missing or return constant scores).
        arr = np.array(ensemble_scores)
        uniq_count = np.unique(arr).size
        arr_std = float(np.nanstd(arr)) if arr.size > 0 else 0.0

        # If degenerate (constant or near-constant), prefer statistical fallback instead
        if uniq_count <= 1 or arr_std < 1e-9:
            logger.warning(f"Degenerate ensemble scores for {job_name}:{entity} (uniq={uniq_count}, std={arr_std:.3e}), using statistical fallback")
            try:
                stat = detect_statistical_anomalies(entity_data)
                if 'anomaly_score' in stat.columns:
                    ensemble_scores = stat['anomaly_score'].values
                else:
                    ensemble_scores = np.zeros(len(entity_data))
            except Exception as e:
                logger.error(f"Statistical fallback failed during degenerate handling for {entity}: {e}")
                ensemble_scores = np.zeros(len(entity_data))

        # Calculate dynamic threshold.
        # The previous implementation floored the threshold at 0.6 and
        # clipped + min-max normalised ensemble scores per entity, which
        # caused large fractions of batches to crown near 1.0 and made
        # downstream thresholding meaningless. We now:
        #   1. Pick a percentile that matches the target anomaly rate.
        #   2. Keep a modest floor (0.5) to protect against noisy baselines.
        #   3. Do NOT re-inject synthetic anomalies in the production path.
        target_rate = _normalize_max_rate(
            (config or {}).get('detection', {}).get('max_anomaly_rate', 0.05)
        )
        percentile = max(50.0, min(99.9, (1.0 - target_rate) * 100.0))
        if len(ensemble_scores) > 0:
            threshold = float(np.percentile(ensemble_scores, percentile))
        else:
            threshold = 1.0
        min_threshold = 0.5  # Floor to guard noisy baselines
        threshold = max(threshold, min_threshold)

        # Synthetic score injection is gated behind a diagnostic flag.
        # In production this step was responsible for guaranteeing a
        # floor of "high" scores (0.9-1.0) regardless of whether real
        # anomalies existed - we keep it off by default.
        if os.getenv("ANOMALY_INJECT_SYNTHETIC", "0") in ("1", "true", "True"):
            if len(ensemble_scores) > 50 and np.unique(ensemble_scores).size > 5 and np.std(ensemble_scores) > 1e-3:
                synthetic_count = max(1, len(ensemble_scores) // 50)
                try:
                    synthetic_indices = np.random.choice(
                        len(ensemble_scores),
                        size=synthetic_count,
                        replace=False,
                    )
                    ensemble_scores[synthetic_indices] = np.random.uniform(
                        0.9, 1.0, size=synthetic_count
                    )
                    arr2 = np.array(ensemble_scores)
                    logger.info(
                        "[scoring-debug] %s:%s ensemble_after_synth len=%d min=%.6g max=%.6g mean=%.6g std=%.6g uniq=%d",
                        job_name, entity, len(arr2), arr2.min(), arr2.max(),
                        arr2.mean(), arr2.std(), np.unique(arr2).size,
                    )
                except Exception:
                    pass

        # Set results with validation
        raw_scores = np.clip(ensemble_scores, 0.0, 1.0)
        entity_data['is_ml_anomaly'] = raw_scores > threshold
        entity_data['ml_anomaly_score'] = raw_scores
        entity_data['raw_ml_score'] = raw_scores
        entity_data['confidence'] = np.clip(raw_scores * 2 - 1, 0, 1)
        entity_data['detection_threshold'] = threshold
        entity_data['detection_method'] = 'machine_learning'
        entity_data['methods_used'] = ','.join(method_scores.keys())
        entity_data['job_name'] = job_name
        entity_data['entity'] = entity

        # Log detection summary
        anomaly_count = entity_data['is_ml_anomaly'].sum()
        logger.info(f"Entity {entity}: {anomaly_count}/{len(entity_data)} anomalies "
                    f"(threshold={threshold:.3f})")

        return entity_data

    except Exception as e:
        logger.error(f"Failed to process entity {entity}: {str(e)}")
        return pd.DataFrame()

def _normalize_max_rate(raw: float) -> float:
    """Normalise `max_anomaly_rate` to a fraction in [0.001, 0.5].

    Historically this value was sometimes provided as a fraction (0.15)
    and sometimes as a percentage (15.0). The previous `raw / 100`
    logic silently turned 0.15 into 0.0015, capping the rate at 0.15%
    instead of the intended 15%. Detect and handle both.
    """
    try:
        val = float(raw)
    except (TypeError, ValueError):
        val = 0.05
    if val > 1.0:
        val = val / 100.0
    # Clamp to a sane band so bad config values cannot silently
    # suppress or unleash alerts.
    return float(max(0.001, min(0.5, val)))


def _apply_safety_limits(results: pd.DataFrame, config: dict) -> pd.DataFrame:
    """
    Apply safety limits to prevent excessive anomaly rates.
    """
    if results.empty or 'is_ml_anomaly' not in results.columns:
        return results

    raw_rate = config.get('detection', {}).get('max_anomaly_rate', 0.05)
    max_rate = _normalize_max_rate(raw_rate)
    current_rate = results['is_ml_anomaly'].sum() / len(results)

    if current_rate <= max_rate:
        return results

    # Reduce anomalies
    max_anomalies = int(len(results) * max_rate)

    if 'ml_anomaly_score' in results.columns:
        threshold = results['ml_anomaly_score'].nlargest(max_anomalies).iloc[-1]
        results['is_ml_anomaly'] = results['ml_anomaly_score'] >= threshold

    logger.info(
        "Applied safety limits: %.1f%% -> %.1f%% (normalized cap from raw=%s)",
        current_rate * 100.0, max_rate * 100.0, raw_rate,
    )
    return results

def _create_fallback_results(data: pd.DataFrame, reason: str) -> pd.DataFrame:
    """
    Create fallback results when detection fails.
    """
    if data.empty:
        return pd.DataFrame()

    result = data.copy()
    result['is_ml_anomaly'] = False
    result['ml_anomaly_score'] = 0.0
    result['confidence'] = 0.0
    result['detection_method'] = 'fallback'
    result['failure_reason'] = reason

    logger.warning(f"Using fallback results: {reason}")
    return result
def detect_statistical_anomalies(data: "pd.DataFrame") -> "pd.DataFrame":
    """
    Pure statistical anomaly detection as fallback.
    """
    result = data.copy()

    # Get numeric columns
    numeric_cols = data.select_dtypes(include=[np.number]).columns

    if len(numeric_cols) == 0:
        result['is_anomaly'] = False
        result['anomaly_score'] = 0.0
        return result

    # Calculate z-scores for each numeric column
    z_scores = pd.DataFrame()
    for col in numeric_cols:
        if data[col].std() > 0:
            z_scores[col] = np.abs((data[col] - data[col].mean()) / data[col].std())

    if not z_scores.empty:
        # Average z-score across all features
        avg_z_score = z_scores.mean(axis=1)

        # Flag as anomaly if z-score > 2
        result['is_anomaly'] = avg_z_score > 2
        result['anomaly_score'] = np.clip(avg_z_score / 4, 0, 1)  # Normalize to 0-1
        result['confidence'] = result['anomaly_score']
        result['detection_method'] = 'statistical'
    else:
        result['is_anomaly'] = False
        result['anomaly_score'] = 0.0
        result['confidence'] = 0.0

    return result
# ===============================================================================
# CONVENIENCE FUNCTIONS FOR EACH JOB
# ===============================================================================

def detect_anomalous_process_all_hosts(data: pd.DataFrame, models: dict,
                                      scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous processes across all hosts."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_process_all_hosts")

def detect_rare_process_by_host(data: pd.DataFrame, models: dict,
                               scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare processes by host."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_rare_process_by_host_linux")

def detect_anomalous_network_activity(data: pd.DataFrame, models: dict,
                                     scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous network activity by IP."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_network_activity")

def detect_anomalous_network_port_activity(data: pd.DataFrame, models: dict,
                                          scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous network port activity."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_network_port_activity")

def detect_anomalous_user_activity(data: pd.DataFrame, models: dict,
                                  scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous user activity."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_user_name")

def detect_rare_sudo_user(data: pd.DataFrame, models: dict,
                         scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare sudo usage."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_sudo_user")

def detect_rare_user_compiler(data: pd.DataFrame, models: dict,
                             scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare compiler usage."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_user_compiler")

def detect_network_configuration_discovery(data: pd.DataFrame, models: dict,
                                          scalers: dict, config: dict) -> pd.DataFrame:
    """Detect network configuration discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_network_configuration_discovery")

def detect_network_connection_discovery(data: pd.DataFrame, models: dict,
                                       scalers: dict, config: dict) -> pd.DataFrame:
    """Detect network connection discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_network_connection_discovery")

def detect_system_information_discovery(data: pd.DataFrame, models: dict,
                                       scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system information discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_information_discovery")

def detect_system_process_discovery(data: pd.DataFrame, models: dict,
                                   scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system process discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_process_discovery")

def detect_system_user_discovery(data: pd.DataFrame, models: dict,
                                scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system user discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_user_discovery")

def detect_rare_metadata_process(data: pd.DataFrame, models: dict,
                                scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare process metadata."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_metadata_process")

def detect_rare_metadata_user(data: pd.DataFrame, models: dict,
                            scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare user metadata."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_metadata_user")

# ===============================================================================
# BACKWARD COMPATIBILITY WRAPPER
# ===============================================================================

def detect_ml_anomalies(data: pd.DataFrame, models: dict, scalers: dict,
                       config: dict, data_type: str = "process",
                       useAddress: bool = False) -> pd.DataFrame:
    """
    Backward compatibility wrapper that routes to job-specific detection.
    """
    # Determine job from config or data type
    job_name = config.get('current_job_name', None)

    if not job_name:
        # Try to infer job from data type and config
        if data_type == "network":
            if useAddress:
                job_name = "v3_linux_anomalous_network_activity"
            else:
                job_name = "v3_linux_anomalous_network_port_activity"
        elif data_type == "process":
            job_name = "v3_linux_anomalous_process_all_hosts"
        elif data_type == "user":
            job_name = "v3_linux_anomalous_user_name"
        elif data_type == "discovery":
            job_name = "v3_linux_network_configuration_discovery"
        elif data_type == "metadata":
            job_name = "v3_linux_rare_metadata_process"
        else:
            logger.warning(f"Unknown data type: {data_type}, using process default")
            job_name = "v3_linux_anomalous_process_all_hosts"

    return detect_job_anomalies(data, models, scalers, config, job_name)

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def get_job_for_data_type(data_type: str, specific_type: str = None) -> str:
    """
    Get the appropriate job name for a data type.
    """
    job_mapping = {
        "process": {
            "all_hosts": "v3_linux_anomalous_process_all_hosts",
            "by_host": "v3_rare_process_by_host_linux",
            "default": "v3_linux_anomalous_process_all_hosts"
        },
        "network": {
            "ip": "v3_linux_anomalous_network_activity",
            "port": "v3_linux_anomalous_network_port_activity",
            "default": "v3_linux_anomalous_network_activity"
        },
        "user": {
            "general": "v3_linux_anomalous_user_name",
            "sudo": "v3_linux_rare_sudo_user",
            "compiler": "v3_linux_rare_user_compiler",
            "default": "v3_linux_anomalous_user_name"
        },
        "discovery": {
            "network_config": "v3_linux_network_configuration_discovery",
            "network_connection": "v3_linux_network_connection_discovery",
            "system_info": "v3_linux_system_information_discovery",
            "process": "v3_linux_system_process_discovery",
            "user": "v3_linux_system_user_discovery",
            "default": "v3_linux_network_configuration_discovery"
        },
        "metadata": {
            "process": "v3_linux_rare_metadata_process",
            "user": "v3_linux_rare_metadata_user",
            "default": "v3_linux_rare_metadata_process"
        }
    }

    if data_type in job_mapping:
        jobs = job_mapping[data_type]
        if specific_type and specific_type in jobs:
            return jobs[specific_type]
        return jobs["default"]

    return "v3_linux_anomalous_process_all_hosts"

def validate_job_requirements(data: pd.DataFrame, job_name: str) -> dict:
    """
    Validate that data meets job requirements.
    """
    validation = {
        "job_name": job_name,
        "valid": True,
        "issues": [],
        "warnings": []
    }

    if job_name not in JOB_CONFIGURATIONS:
        validation["valid"] = False
        validation["issues"].append(f"Unknown job: {job_name}")
        return validation

    JOB_CONFIGURATIONS[job_name]

    # Check required columns
    if job_name == "v3_linux_anomalous_network_port_activity":
        if "destination.port" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing destination.port column")

    elif job_name == "v3_rare_process_by_host_linux":
        if "host.hostname" not in data.columns or "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing host.hostname or process.name columns")

    elif job_name in ["v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"]:
        if "user.name" not in data.columns or "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing user.name or process.name columns")

    elif job_name == "v3_linux_rare_metadata_process":
        if "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing process.name column")
        if "process.args" not in data.columns:
            validation["warnings"].append("Missing process.args column (will use process.name only)")

    elif job_name == "v3_linux_rare_metadata_user":
        if "user.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing user.name column")
        if "user.group" not in data.columns:
            validation["warnings"].append("Missing user.group column (will use user.name only)")

    # Check data volume
    if len(data) == 0:
        validation["valid"] = False
        validation["issues"].append("Empty dataset")
    elif len(data) < 10:
        validation["warnings"].append(f"Small dataset ({len(data)} records)")

    return validation

def get_all_jobs() -> list[str]:
    """Get list of all available jobs."""
    return list(JOB_CONFIGURATIONS.keys())

def get_jobs_by_data_type(data_type: str) -> list[str]:
    """Get jobs for a specific data type."""
    return [job for job, config in JOB_CONFIGURATIONS.items()
            if config['data_type'] == data_type]

# ===============================================================================
# EXPORT KEY FUNCTIONS
# ===============================================================================

__all__ = [
    # Main detection function
    'detect_job_anomalies',
    'detect_ml_anomalies',  # Backward compatibility

    # Job-specific detection functions
    'detect_anomalous_process_all_hosts',
    'detect_rare_process_by_host',
    'detect_anomalous_network_activity',
    'detect_anomalous_network_port_activity',
    'detect_anomalous_user_activity',
    'detect_rare_sudo_user',
    'detect_rare_user_compiler',
    'detect_network_configuration_discovery',
    'detect_network_connection_discovery',
    'detect_system_information_discovery',
    'detect_system_process_discovery',
    'detect_system_user_discovery',
    'detect_rare_metadata_process',
    'detect_rare_metadata_user',

    # Utility functions
    'get_job_for_data_type',
    'validate_job_requirements',
    'get_all_jobs',
    'get_jobs_by_data_type',

    # Configuration
    'JOB_CONFIGURATIONS'
]
