import pandas as pd
import numpy as np
import logging
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from statsmodels.tsa.seasonal import seasonal_decompose
from scipy import stats
from scipy.spatial.distance import mahalanobis
from scipy.stats import chi2
from collections import defaultdict
import warnings

logger = logging.getLogger("linux_anomaly_detection")
def analyze_feature_availability(data, data_type="process"):
    """
    Analyze which features are available in the dataset and determine feature strategy.
    
    Args:
        data (pd.DataFrame): Input data
        data_type (str): Type of data (process, network, user, discovery, metadata)
        
    Returns:
        dict: Feature availability analysis with strategy recommendations
    """
    logger.info(f"Analyzing feature availability for {data_type} data")
    
    if data.empty:
        logger.warning("Empty dataset provided for feature analysis")
        return {"strategy": "fallback", "available_features": [], "missing_features": []}
    
    # Define expected features by data type
    feature_definitions = {
        "process": {
            "required": ["event_count", "@timestamp"],
            "domain_specific": [
                "args_count", "command_length", "has_suspicious_chars",
                "has_encoded_content", "is_system_path", "is_tmp_execution",
                "is_root_user", "has_hash", "env_vars_count", "process.name"
            ],
            "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
            "entity_col": "process.name"
        },
        "network": {
            "required": ["event_count", "@timestamp"],
            "domain_specific": [
                "destination_port", "is_well_known_port", "is_ephemeral_port",
                "bytes_per_packet", "is_large_transfer", "is_outbound",
                "is_browser_traffic", "destination.geo.country_name"
            ],
            "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
            "entity_col": "destination.geo.country_name"
        },
        "user": {
            "required": ["event_count", "@timestamp"],
            "domain_specific": [
                "is_sudo_command", "is_su_command", "is_compiler_activity",
                "is_dev_tool", "is_root_user", "is_service_user", "user.name"
            ],
            "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
            "entity_col": "user.name"
        },
        "discovery": {
            "required": ["event_count", "@timestamp"],
            "domain_specific": [
                "command_length", "has_pipes", "has_redirection",
                "args_count", "is_root_discovery", "is_regular_user_discovery",
                "process.name", "user.name"
            ],
            "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
            "entity_col": "process.name"
        },
        "metadata": {
            "required": ["event_count", "@timestamp"],
            "domain_specific": [
                "is_root_access", "is_service_account", "potential_cred_harvest",
                "user_data_access", "process.name"
            ],
            "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
            "entity_col": "process.name"
        }
    }
    
    expected_features = feature_definitions.get(data_type, feature_definitions["process"])
    available_columns = set(data.columns)
    
    # Check feature availability
    analysis = {
        "data_type": data_type,
        "total_columns": len(available_columns),
        "available_features": {},
        "missing_features": {},
        "feature_coverage": {},
        "strategy": "unknown",
        "entity_col": expected_features["entity_col"]
    }
    
    # Analyze each feature category
    for category, features in expected_features.items():
        if category == "entity_col":
            continue
            
        available = [f for f in features if f in available_columns]
        missing = [f for f in features if f not in available_columns]
        coverage = len(available) / len(features) if features else 0
        
        analysis["available_features"][category] = available
        analysis["missing_features"][category] = missing
        analysis["feature_coverage"][category] = coverage
        
        logger.info(f"{category.upper()} features - Available: {len(available)}/{len(features)} ({coverage:.1%})")
        if available:
            logger.info(f"  Found: {available}")
        if missing:
            logger.info(f"  Missing: {missing}")
    
    # Determine strategy based on feature availability
    required_coverage = analysis["feature_coverage"].get("required", 0)
    domain_coverage = analysis["feature_coverage"].get("domain_specific", 0)
    temporal_coverage = analysis["feature_coverage"].get("temporal", 0)
    
    if required_coverage < 1.0:
        analysis["strategy"] = "insufficient_data"
        logger.error(f"Insufficient data: Missing required features {analysis['missing_features']['required']}")
    elif domain_coverage >= 0.7:
        analysis["strategy"] = "full_features"
        logger.info(f"Full feature strategy: High domain coverage ({domain_coverage:.1%})")
    elif domain_coverage >= 0.3:
        analysis["strategy"] = "hybrid"
        logger.info(f"Hybrid strategy: Partial domain coverage ({domain_coverage:.1%})")
    else:
        analysis["strategy"] = "time_based_only"
        logger.info(f"Time-based strategy: Low domain coverage ({domain_coverage:.1%})")
    
    # Check entity column availability
    if expected_features["entity_col"] not in available_columns:
        logger.warning(f"Entity column '{expected_features['entity_col']}' not found. Available alternatives:")
        alternatives = ["host.hostname", "process.name", "user.name", "destination.geo.country_name"]
        for alt in alternatives:
            if alt in available_columns:
                logger.info(f"  Found alternative entity column: {alt}")
                analysis["entity_col"] = alt
                break
    
    return analysis
# Import and reuse core functions from network detection methods
def extract_ml_features(aggregated_data, config):
    """
    Enhanced feature extraction with automatic fallback based on feature availability.
    """
    if aggregated_data.empty:
        logger.warning("Empty dataframe received for feature extraction")
        return aggregated_data
    
    df = aggregated_data.copy()
    
    try:
        # Determine data type from config or infer from columns
        data_type = config.get('data_type', 'process')
        
        # Analyze feature availability
        feature_analysis = analyze_feature_availability(df, data_type)
        
        if feature_analysis["strategy"] == "insufficient_data":
            logger.error("Cannot proceed with feature extraction due to missing required features")
            return df
        
        # Ensure timestamp is datetime and has consistent timezone
        if '@timestamp' in df.columns:
            if not pd.api.types.is_datetime64_any_dtype(df['@timestamp']):
                df['@timestamp'] = pd.to_datetime(df['@timestamp'])
            df['@timestamp'] = pd.to_datetime(df['@timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S'))
        
        # Create base time features (always available)
        logger.info("Creating base temporal features")
        df['hour_of_day'] = df['@timestamp'].dt.hour
        df['day_of_week'] = df['@timestamp'].dt.dayofweek
        df['is_business_hours'] = ((df['hour_of_day'] >= 8) & (df['hour_of_day'] <= 18) & 
                                (df['day_of_week'] <= 4)).astype(int)
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        
        # Add sine and cosine transformations for cyclical time features
        df['hour_sin'] = np.sin(2 * np.pi * df['hour_of_day'] / 24)
        df['hour_cos'] = np.cos(2 * np.pi * df['hour_of_day'] / 24)
        df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
        df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)
        
        logger.info("Created temporal features: hour_sin, hour_cos, day_sin, day_cos, is_business_hours, is_weekend")
        
        # Sort by timestamp and entity
        entity_col = feature_analysis["entity_col"]
        sort_cols = ['@timestamp']
        if entity_col in df.columns:
            sort_cols.append(entity_col)
        df.sort_values(sort_cols, inplace=True)
        
        # Process each entity group separately
        result_frames = []
        entities = df[entity_col].unique() if entity_col in df.columns else ['global']
        
        logger.info(f"Processing {len(entities)} entities using column: {entity_col}")
        
        # Loop through each entity
        for entity in entities:
            if entity == 'global':
                entity_df = df.copy()
            else:
                entity_df = df[df[entity_col] == entity].copy()
            
            entity_df['row_id'] = range(len(entity_df))
            
            # Process time series features if we have enough data
            if len(entity_df) > 1:
                ts_df = entity_df.set_index('@timestamp')
                
                # Determine rolling windows based on data availability
                if len(entity_df) >= 24:
                    rolling_windows = [3, 6, 12, 24]
                elif len(entity_df) >= 12:
                    rolling_windows = [3, 6, 12]
                elif len(entity_df) >= 6:
                    rolling_windows = [3, 6]
                else:
                    rolling_windows = [3]
                
                logger.debug(f"Entity {entity}: Using rolling windows {rolling_windows} for {len(entity_df)} samples")
                
                # Calculate rolling statistics for event counts
                if 'event_count' in ts_df.columns:
                    for window in rolling_windows:
                        min_periods = max(1, window // 2)
                        ts_df[f'rolling_mean_{window}h'] = ts_df['event_count'].rolling(
                            window=window, min_periods=min_periods).mean()
                        ts_df[f'rolling_std_{window}h'] = ts_df['event_count'].rolling(
                            window=window, min_periods=min_periods).std().fillna(0)
                        ts_df[f'rolling_max_{window}h'] = ts_df['event_count'].rolling(
                            window=window, min_periods=min_periods).max().fillna(0)
                
                # Lag features (adaptive based on data size)
                max_lag = min(24, len(entity_df) // 2)
                if max_lag >= 1:
                    lag_periods = [lag for lag in [1, 3, 6, 12, 24] if lag <= max_lag]
                    logger.debug(f"Entity {entity}: Using lag periods {lag_periods}")
                    
                    for lag in lag_periods:
                        if 'event_count' in ts_df.columns:
                            ts_df[f'event_count_lag_{lag}'] = ts_df['event_count'].shift(lag).fillna(
                                ts_df['event_count'].mean())
                
                # Rate of change
                if 'event_count' in ts_df.columns:
                    ts_df['event_count_roc'] = ts_df['event_count'].pct_change().fillna(0)
                    
                    if len(ts_df) >= 24:
                        ts_df['event_count_day_roc'] = (ts_df['event_count'] / 
                                                      ts_df['event_count'].shift(24)).fillna(1) - 1
                
                # Calculate deviation from typical pattern
                if 'is_business_hours' in ts_df.columns and 'event_count' in ts_df.columns:
                    biz_hours = ts_df[ts_df['is_business_hours'] == 1]
                    non_biz_hours = ts_df[ts_df['is_business_hours'] == 0]
                    
                    biz_mean = biz_hours['event_count'].mean() if len(biz_hours) > 0 else 0
                    non_biz_mean = non_biz_hours['event_count'].mean() if len(non_biz_hours) > 0 else 0
                    
                    ts_df['expected_count'] = ts_df['is_business_hours'].map({1: biz_mean, 0: non_biz_mean})
                    ts_df['pattern_deviation'] = (ts_df['event_count'] - ts_df['expected_count']).abs()
                    
                    with np.errstate(divide='ignore', invalid='ignore'):
                        ts_df['relative_deviation'] = np.where(
                            ts_df['expected_count'] > 0,
                            ts_df['pattern_deviation'] / ts_df['expected_count'],
                            0
                        )
                
                ts_df = ts_df.reset_index()
                
                # Merge features back
                new_columns = [col for col in ts_df.columns if col not in entity_df.columns]
                logger.debug(f"Entity {entity}: Created {len(new_columns)} new time series features")
                
                if new_columns:
                    merge_columns = ['row_id'] + new_columns
                    ts_features = ts_df[merge_columns]
                    entity_df = pd.merge(entity_df, ts_features, on='row_id', how='left')
            
            result_frames.append(entity_df)
        
        # Combine all results
        if result_frames:
            result_df = pd.concat(result_frames, ignore_index=True)
            
            if 'row_id' in result_df.columns:
                result_df = result_df.drop(columns=['row_id'])
            
            # Log final feature summary
            feature_cols = [col for col in result_df.columns if col not in aggregated_data.columns]
            logger.info(f"Successfully extracted {len(feature_cols)} new features for {len(result_df)} records")
            logger.info(f"New features created: {feature_cols}")
            
            # Store feature analysis in config for downstream use
            config['feature_analysis'] = feature_analysis
            
            return result_df
        else:
            logger.warning("No results from feature extraction")
            return df
        
    except Exception as e:
        logger.error(f"Error in feature extraction: {str(e)}")
        logger.info("Falling back to minimal time-based features only")
        
        # Emergency fallback - create minimal features
        try:
            df['hour_of_day'] = df['@timestamp'].dt.hour
            df['day_of_week'] = df['@timestamp'].dt.dayofweek
            df['hour_sin'] = np.sin(2 * np.pi * df['hour_of_day'] / 24)
            df['hour_cos'] = np.cos(2 * np.pi * df['hour_of_day'] / 24)
            logger.info("Created emergency fallback features: hour_sin, hour_cos")
        except:
            logger.error("Even fallback feature creation failed")
        
        return df

def select_ml_features(data, config, data_type="process", expected_feature_count=None):
    """
    Enhanced feature selection with fixed feature count support for model compatibility.
    
    Args:
        data: DataFrame with features
        config: Configuration dictionary
        data_type: Type of data (process, network, user, etc.)
        expected_feature_count: If provided, ensures output has exactly this many features
        
    Returns:
        tuple: (list of feature names, feature matrix)
    """
    if data.empty:
        logger.warning("Empty dataframe for feature selection")
        return [], np.array([])
    
    logger.info(f"Starting feature selection for {data_type} data")
    
    # Get feature analysis from config if available
    feature_analysis = config.get('feature_analysis', {})
    strategy = feature_analysis.get('strategy', 'time_based_only')
    
    logger.info(f"Using feature selection strategy: {strategy}")
    
    # Complete list of all possible features (in priority order)
    all_possible_features = [
        # Base features (highest priority)
        'event_count',
        'hour_sin', 'hour_cos', 
        'day_sin', 'day_cos',
        'is_business_hours', 'is_weekend',
        
        # Domain-specific features by data type
        # Process
        'args_count', 'command_length', 'has_suspicious_chars',
        'has_encoded_content', 'is_system_path', 'is_tmp_execution',
        'is_root_user', 'has_hash', 'env_vars_count',
        
        # Network
        'destination_port', 'is_well_known_port', 'is_ephemeral_port',
        'bytes_per_packet', 'is_large_transfer', 'is_outbound',
        'is_browser_traffic',
        
        # User
        'is_sudo_command', 'is_su_command', 'is_compiler_activity',
        'is_dev_tool', 'is_service_user',
        
        # Discovery
        'has_pipes', 'has_redirection',
        'is_root_discovery', 'is_regular_user_discovery',
        
        # Metadata
        'is_root_access', 'is_service_account', 'potential_cred_harvest',
        'user_data_access',
        
        # Time series features (rolling windows)
        'rolling_mean_3h', 'rolling_std_3h', 'rolling_max_3h',
        'rolling_mean_6h', 'rolling_std_6h', 'rolling_max_6h',
        'rolling_mean_12h', 'rolling_std_12h', 'rolling_max_12h',
        'rolling_mean_24h', 'rolling_std_24h', 'rolling_max_24h',
        
        # Lag features
        'event_count_lag_1', 'event_count_lag_3', 'event_count_lag_6',
        'event_count_lag_12', 'event_count_lag_24',
        
        # Rate of change features
        'event_count_roc', 'event_count_day_roc',
        
        # Pattern features
        'expected_count', 'pattern_deviation', 'relative_deviation'
    ]
    
    # Additional generic features if needed to reach expected count
    if expected_feature_count is not None:
        while len(all_possible_features) < expected_feature_count:
            all_possible_features.append(f"generic_feature_{len(all_possible_features)}")
    
    # Filter to only include features that exist in the data
    available_features = [feat for feat in all_possible_features if feat in data.columns]
    missing_features = [feat for feat in all_possible_features if feat not in data.columns]
    
    logger.info(f"Feature availability check:")
    logger.info(f"  Total potential features: {len(all_possible_features)}")
    logger.info(f"  Available features: {len(available_features)}")
    logger.info(f"  Missing features: {len(missing_features)}")
    
    # Feature selection based on strategy
    if strategy == "full_features":
        # Use all features relevant to this data type
        selected_features = available_features
        logger.info("Full feature strategy: using all available features")
    elif strategy == "time_based_only":
        # Use only time-based features
        time_based_features = [
            'event_count', 'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
            'is_business_hours', 'is_weekend', 'rolling_mean_3h',
            'rolling_std_3h', 'rolling_max_3h', 'event_count_lag_1',
            'event_count_roc', 'pattern_deviation', 'relative_deviation'
        ]
        selected_features = [f for f in time_based_features if f in available_features]
        logger.info("Time-based strategy: using only time-based features")
    elif strategy == "hybrid":
        # Use time-based features plus domain features if available
        domain_coverage = len([f for f in missing_features if 'is_' in f or '_count' in f]) / len([f for f in all_possible_features if 'is_' in f or '_count' in f])
        if domain_coverage >= 0.5:
            logger.info(f"High domain coverage ({domain_coverage:.1%})")
            selected_features = available_features
        else:
            logger.info(f"Low domain coverage ({domain_coverage:.1%})")
            # Fallback to time-based features
            time_features = [f for f in available_features if 'hour' in f or 'day' in f or 'rolling' in f or 'lag' in f or 'roc' in f]
            selected_features = time_features
    else:
        # Default to all available
        selected_features = available_features
        logger.info("Using all available features")
    
    # CRITICAL: Handle expected feature count
    if expected_feature_count is not None:
        logger.info(f"Adjusting feature count to match expected {expected_feature_count} features")
        
        if len(selected_features) < expected_feature_count:
            # Need to add missing features
            missing_count = expected_feature_count - len(selected_features)
            logger.info(f"Adding {missing_count} missing features to match expected count")
            
            # First try to add features from all_possible_features that aren't in selected_features
            candidates = [f for f in all_possible_features if f not in selected_features]
            
            # Add missing features to data and selected_features
            for feature in candidates:
                if len(selected_features) >= expected_feature_count:
                    break
                    
                # Add feature to dataframe with appropriate default value
                if feature not in data.columns:
                    if 'sin' in feature or 'cos' in feature:
                        data[feature] = 0.0
                    elif 'std' in feature:
                        data[feature] = 0.1
                    elif 'rolling_' in feature or 'lag' in feature:
                        data[feature] = 1.0
                    elif feature == 'event_count':
                        data[feature] = 1.0
                    else:
                        data[feature] = 0
                
                # Add to selected features
                selected_features.append(feature)
            
            # If still not enough, add generic features
            while len(selected_features) < expected_feature_count:
                feature_name = f"generic_feature_{len(selected_features)}"
                data[feature_name] = 0
                selected_features.append(feature_name)
                
        elif len(selected_features) > expected_feature_count:
            # Need to trim features - keep higher priority ones
            logger.info(f"Trimming feature list from {len(selected_features)} to {expected_feature_count}")
            
            # Sort selected features by their position in all_possible_features (priority order)
            def get_priority(feature):
                try:
                    return all_possible_features.index(feature)
                except ValueError:
                    return 999999  # Put unknown features at the end
                    
            selected_features = sorted(selected_features, key=get_priority)
            selected_features = selected_features[:expected_feature_count]
    
    logger.info(f"Final feature selection: {len(selected_features)} features for {data_type} ML")
    if len(selected_features) <= 20:  # Only log full list if not too long
        logger.info(f"Selected features: {selected_features}")
    else:
        logger.info(f"Selected {len(selected_features)} features (too many to list)")
    
    if not selected_features:
        logger.error("No suitable features found for ML")
        return [], np.array([])
    
    try:
        # Create DataFrame with selected features
        X_df = data[selected_features].copy()
        
        # Clean data - replace infinities and NaNs
        X_df = X_df.replace([np.inf, -np.inf], np.nan)
        X_df = X_df.fillna(0)
        
        # Remove extreme outliers
        for col in X_df.columns:
            if pd.api.types.is_numeric_dtype(X_df[col]):
                q1 = X_df[col].quantile(0.01)
                q3 = X_df[col].quantile(0.99)
                iqr = q3 - q1
                
                if iqr > 0:
                    lower_bound = q1 - (iqr * 1.5)
                    upper_bound = q3 + (iqr * 1.5)
                    X_df[col] = X_df[col].clip(lower=lower_bound, upper=upper_bound)
        
        # Add small noise to zero-variance columns
        for col in X_df.columns:
            if X_df[col].nunique() <= 1:
                X_df[col] = X_df[col] + np.random.normal(0, 0.0001, size=len(X_df))
                logger.debug(f"Added noise to zero-variance feature: {col}")
        
        feature_matrix = X_df.values
        logger.info(f"Feature matrix shape: {feature_matrix.shape}")
        
        return selected_features, feature_matrix
        
    except Exception as e:
        logger.error(f"Error processing features: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return [], np.array([])

def train_ml_models(historical_data, config, data_type="process"):
    """
    Enhanced model training with feature availability awareness.
    """
    if historical_data.empty:
        logger.warning("No historical data available for model training")
        return {}, {}
    
    logger.info(f"Starting ML model training for {data_type} data")
    
    # Set data type in config for feature extraction
    config['data_type'] = data_type
    
    # Extract and engineer features
    feature_data = extract_ml_features(historical_data, config)
    
    if feature_data.empty:
        logger.error("Feature extraction failed, cannot train models")
        return {}, {}
    
    models = {}
    scalers = {}
    
    # Configure model parameters from config with better defaults
    ml_config = config.get("ml", {})
    min_samples = ml_config.get("min_samples", 50)  # Increased from 10
    
    isolation_forest_params = ml_config.get("isolation_forest", {
        "n_estimators": 100,
        "contamination": 0.05,
        "random_state": 42
    })
    
    lof_params = ml_config.get("lof", {
        "n_neighbors": 20,
        "contamination": 0.05
    })
    
    ocsvm_params = ml_config.get("ocsvm", {
        "nu": 0.05,
        "kernel": "rbf",
        "gamma": "scale"
    })
    
    # Get feature analysis to determine entity column
    feature_analysis = config.get('feature_analysis', {})
    entity_col = feature_analysis.get('entity_col', 'host.hostname')
    
    logger.info(f"Training models using entity column: {entity_col}")
    
    # Train models for each entity
    if entity_col in feature_data.columns:
        entities = feature_data[entity_col].unique()
        logger.info(f"Found {len(entities)} unique entities")
    else:
        entities = ['global']  # Train single global model
        logger.info("Training single global model (no entity column available)")
    
    successful_entities = 0
    
    for entity in entities:
        if entity == 'global':
            entity_data = feature_data
        else:
            entity_data = feature_data[feature_data[entity_col] == entity]
        
        # Select features for this entity
        selected_features, X = select_ml_features(entity_data, config, data_type)
        
        # Check data sufficiency with more stringent requirements
        if len(X) < min_samples:
            logger.warning(f"Insufficient data for {entity}: {len(X)} samples (need {min_samples})")
            continue
        
        if len(selected_features) < 1:
            logger.warning(f"No features available for {entity}")
            continue
        
        try:
            logger.info(f"Training models for {entity} with {len(X)} samples and {len(selected_features)} features")
            
            # Scale the data
            scaler = RobustScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Store the scaler
            scalers[entity] = scaler
            
            # Initialize models dict for this entity
            models[entity] = {"features_used": selected_features}
            
            # Train Isolation Forest
            try:
                iso_forest = IsolationForest(
                    n_estimators=isolation_forest_params.get("n_estimators", 100),
                    contamination=isolation_forest_params.get("contamination", 0.05),
                    random_state=isolation_forest_params.get("random_state", 42)
                )
                iso_forest.fit(X_scaled)
                models[entity]["isolation_forest"] = iso_forest
                logger.debug(f"Trained Isolation Forest for {entity}")
            except Exception as e:
                logger.warning(f"Failed to train Isolation Forest for {entity}: {e}")
            
            # Train Local Outlier Factor (only if we have enough samples)
            if len(X_scaled) > lof_params.get("n_neighbors", 20):
                try:
                    lof = LocalOutlierFactor(
                        n_neighbors=min(lof_params.get("n_neighbors", 20), len(X_scaled)-1),
                        contamination=lof_params.get("contamination", 0.05),
                        novelty=True
                    )
                    lof.fit(X_scaled)
                    models[entity]["lof"] = lof
                    logger.debug(f"Trained LOF for {entity}")
                except Exception as e:
                    logger.warning(f"Failed to train LOF for {entity}: {e}")
            
            # Train One-Class SVM (may be slow for large datasets)
            if len(X_scaled) <= 1000:  # Limit OCSVM to smaller datasets
                try:
                    ocsvm = OneClassSVM(
                        nu=ocsvm_params.get("nu", 0.05),
                        kernel=ocsvm_params.get("kernel", "rbf"),
                        gamma=ocsvm_params.get("gamma", "scale")
                    )
                    ocsvm.fit(X_scaled)
                    models[entity]["ocsvm"] = ocsvm
                    logger.debug(f"Trained OCSVM for {entity}")
                except Exception as e:
                    logger.warning(f"Failed to train OCSVM for {entity}: {e}")
            
            # Calculate PCA for reconstruction error
            try:
                n_components = min(int(0.95 * X_scaled.shape[1]), X_scaled.shape[1]-1, 10)
                if n_components > 0:
                    pca = PCA(n_components=n_components)
                    pca.fit(X_scaled)
                    models[entity]["pca"] = pca
                    logger.debug(f"Trained PCA for {entity} with {n_components} components")
            except Exception as e:
                logger.warning(f"Failed to train PCA for {entity}: {e}")
            
            successful_entities += 1
            logger.info(f"Successfully trained models for {entity}")
            
        except Exception as e:
            logger.error(f"Error training models for {entity}: {e}")
    
    logger.info(f"Model training completed: {successful_entities}/{len(entities)} entities successful")
    
    if successful_entities == 0:
        logger.error("No models were successfully trained")
    
    return models, scalers

def detect_statistical_anomalies(aggregated_data, baselines, config, data_type="process"):
    """
    Detect anomalies using statistical methods adapted for Linux data.
    Reuses proven statistical detection from network methods.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated Linux event data
        baselines (dict): Baseline statistics
        config (dict): Configuration dictionary
        data_type (str): Type of data being processed
        
    Returns:
        pd.DataFrame: Results with anomaly flags and scores
    """
    if aggregated_data.empty:
        return pd.DataFrame()
    
    detection_config = config["detection"]
    window = detection_config.get("time_window", 24)
    threshold_multiplier = detection_config.get("threshold_multiplier", 3.0)
    
    results = []
    
    # Determine entity column based on data type
    if data_type == "process":
        entity_col = 'process.name'
    elif data_type == "network":
        entity_col = 'destination.geo.country_name'
    elif data_type == "user":
        entity_col = 'user.name'
    elif data_type == "discovery":
        entity_col = 'process.name'
    elif data_type == "metadata":
        entity_col = 'process.name'
    else:
        entity_col = 'host.hostname'
    
    if entity_col not in aggregated_data.columns:
        logger.warning(f"Entity column {entity_col} not found in data")
        return pd.DataFrame()
    
    for entity in aggregated_data[entity_col].unique():
        entity_data = aggregated_data[
            aggregated_data[entity_col] == entity
        ].copy()
        
        # Check baseline stats
        baseline = baselines.get(entity, {})
        baseline_mean = baseline.get("mean", entity_data["event_count"].mean())
        baseline_std = baseline.get("std", entity_data["event_count"].std())
        
        # Handle very small standard deviations
        if baseline_std < 0.1:
            baseline_std = max(0.1, baseline_mean * 0.1)
        
        # Calculate z-scores
        z_scores = (entity_data["event_count"] - baseline_mean) / baseline_std
        entity_data["z_score"] = z_scores
        
        # Calculate rolling statistics
        entity_data = entity_data.sort_values("@timestamp")
        entity_data["rolling_mean"] = entity_data["event_count"].rolling(
            window=window, min_periods=1
        ).mean()
        
        entity_data["rolling_std"] = entity_data["event_count"].rolling(
            window=window, min_periods=1
        ).std().fillna(baseline_std)
        
        # Set dynamic thresholds
        entity_data["threshold"] = entity_data["rolling_mean"] + (
            threshold_multiplier * entity_data["rolling_std"]
        )
        
        # Use percentile threshold from baseline
        if "percentiles" in baseline:
            entity_data["percentile_threshold"] = baseline["percentiles"]["p99"]
        else:
            entity_data["percentile_threshold"] = entity_data["event_count"].quantile(0.99)
        
        # Mark anomalies - require multiple conditions
        entity_data["is_anomaly"] = (
            ((entity_data["event_count"] > entity_data["threshold"]) & 
            (entity_data["event_count"] > entity_data["percentile_threshold"])) |
            ((entity_data["event_count"] > entity_data["threshold"]) & 
            (entity_data["z_score"] > 3.0)) |
            ((entity_data["event_count"] > entity_data["percentile_threshold"]) & 
            (entity_data["z_score"] > 3.0))
        )
        
        # Calculate anomaly score
        entity_data["anomaly_score"] = (
            0.4 * (entity_data["event_count"] / entity_data["threshold"].clip(lower=1)) +
            0.3 * (entity_data["event_count"] / entity_data["percentile_threshold"].clip(lower=1)) +
            0.3 * (entity_data["z_score"] / 5.0)
        ).clip(0, 10)
        
        entity_data["detection_method"] = "statistical"
        results.append(entity_data)
    
    if results:
        return pd.concat(results, ignore_index=True)
    return pd.DataFrame()



# def detect_ml_anomalies(aggregated_data, models, scalers, config, data_type="process"):
#     """
#     Detect anomalies using trained ML models for Linux data.
#     Ensures feature compatibility with model scalers.
#     """
#     if aggregated_data.empty or not models:
#         logger.warning("No data or models available for ML anomaly detection")
#         return pd.DataFrame()
    
#     # Extract features
#     try:
#         feature_data = extract_ml_features(aggregated_data, config)
#         logger.info("Successfully extracted features for ML detection")
#     except Exception as e:
#         logger.error(f"Error in feature extraction for ML detection: {e}")
#         return pd.DataFrame()
    
#     results = []
    
#     # Determine entity column
#     if data_type == "process":
#         entity_col = 'process.name'
#     elif data_type == "network":
#         entity_col = 'destination.geo.country_name'
#     elif data_type == "user":
#         entity_col = 'user.name'
#     elif data_type == "discovery":
#         entity_col = 'process.name'
#     elif data_type == "metadata":
#         entity_col = 'process.name'
#     else:
#         entity_col = 'host.hostname'
    
#     # Process each entity
#     if entity_col in feature_data.columns:
#         entities = feature_data[entity_col].unique()
#     else:
#         entities = ['global']
    
#     for entity in entities:
#         if entity not in models or entity not in scalers:
#             logger.warning(f"No models or scalers found for entity: {entity}")
#             continue
        
#         if entity == 'global':
#             entity_data = feature_data.copy()
#         else:
#             entity_data = feature_data[feature_data[entity_col] == entity].copy()
        
#         try:
#             if len(entity_data) == 0:
#                 continue
                
#             # CRITICAL FIX: Get the exact number of features the scaler expects
#             expected_feature_count = None
#             try:
#                 # Try to infer from the scaler's n_features_in_ attribute
#                 if hasattr(scalers[entity], 'n_features_in_'):
#                     expected_feature_count = scalers[entity].n_features_in_
#                     logger.info(f"Scaler for {entity} expects {expected_feature_count} features")
                
#                 else:
#                     dummy_array = np.zeros((1, 32))  # Try with 32 features
#                     try:
#                         scalers[entity].transform(dummy_array)
#                         expected_feature_count = 32
#                     except:
#                         # Try with different counts until one works
#                         for count in [14, 24, 28, 30, 36]:
#                             try:
#                                 dummy_array = np.zeros((1, count))
#                                 scalers[entity].transform(dummy_array)
#                                 expected_feature_count = count
#                                 break
#                             except:
#                                 continue
#             except Exception as e:
#                 logger.error(f"Error determining feature count for {entity}: {e}")
#                 expected_feature_count = 32  # Default to 32 if we can't determine
            
#             # Define a complete list of features the model might expect
#             all_possible_features = [
#                 # Basic features
#                 'event_count', 'process.name',
                
#                 # Domain-specific features
#                 'args_count', 'command_length', 'has_suspicious_chars', 
#                 'has_encoded_content', 'is_system_path', 'is_tmp_execution', 
#                 'is_root_user', 'has_hash', 'env_vars_count',
                
#                 # Time-based features
#                 'hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend',
#                 'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
                
#                 # Time-series features
#                 'rolling_mean_3h', 'rolling_std_3h', 'rolling_max_3h',
#                 'rolling_mean_6h', 'rolling_std_6h', 'rolling_max_6h',
#                 'rolling_mean_12h', 'rolling_std_12h', 'rolling_max_12h',
#                 'rolling_mean_24h', 'rolling_std_24h', 'rolling_max_24h',
#                 'event_count_lag_1', 'event_count_lag_3', 'event_count_lag_6',
#                 'event_count_lag_12', 'event_count_lag_24',
#                 'event_count_roc', 'event_count_day_roc',
#                 'expected_count', 'pattern_deviation', 'relative_deviation'
#             ]
            
#             # Make sure we have enough features in our list
#             while len(all_possible_features) < expected_feature_count:
#                 all_possible_features.append(f"feature_{len(all_possible_features)}")
            
#             # Take exactly the number of features we need
#             expected_features = all_possible_features[:expected_feature_count]
            
#             # Add missing features with default values
#             for feature in expected_features:
#                 if feature not in entity_data.columns:
#                     # Default value based on feature type
#                     if 'sin' in feature or 'cos' in feature:
#                         entity_data[feature] = 0.0  # Trigonometric features
#                     elif 'std' in feature:
#                         entity_data[feature] = 0.1  # Standard deviations are positive
#                     elif 'rolling_' in feature or 'lag' in feature:
#                         entity_data[feature] = 1.0  # Rolling and lag features
#                     elif feature == 'event_count':
#                         entity_data[feature] = 1.0  # Event count defaults to 1
#                     else:
#                         entity_data[feature] = 0    # Most features default to 0
            
#             # Select exactly the expected features in the right order
#             X = entity_data[expected_features].copy()
            
#             # CRITICAL FIX: Convert string columns to numeric safely before scaling
#             for col in X.columns:
#                 if X[col].dtype == 'object':
#                     # For entity columns (like process.name), use a binary indicator
#                     if col == entity_col:
#                         X[col] = 1  # Just mark with 1 since all are the same entity
#                     else:
#                         # Try to convert to numeric, replace with 0 if fails
#                         X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
            
#             # Handle NaN values - replace with 0 for simplicity
#             if X.isna().any().any():
#                 logger.error(f"NaN values found in features for {entity}, replacing with 0")
#                 X = X.fillna(0)
            
#             # Convert to numpy array
#             X_values = X.values
            
#             # Check final shape
#             logger.info(f"Feature matrix for {entity} has shape {X_values.shape}, expected {expected_feature_count} features")
            
#             # Apply scaler
#             try:
#                 X_scaled = scalers[entity].transform(X_values)
#             except Exception as e:
#                 logger.error(f"Scaling error for {entity}: {e}")
#                 logger.error(f"X shape: {X_values.shape}, expected {expected_feature_count} features")
#                 continue
            
#             # Initialize anomaly flags and scores
#             entity_data["is_ml_anomaly"] = False
#             entity_data["ml_anomaly_score"] = 0.0
            
#             # Apply models
#             anomaly_votes = np.zeros(len(entity_data))
#             anomaly_scores = []
            
#             # Isolation Forest
#             if "isolation_forest" in models[entity]:
#                 try:
#                     iso_forest = models[entity]["isolation_forest"]
#                     if_scores = iso_forest.decision_function(X_scaled)
#                     if_predictions = iso_forest.predict(X_scaled)
                    
#                     anomaly_votes += (if_predictions == -1).astype(int)
#                     normalized_scores = (1 - (if_scores + 1) / 2).clip(0, 1)
#                     anomaly_scores.append(normalized_scores)
                    
#                 except Exception as e:
#                     logger.error(f"Isolation Forest error for {entity}: {e}")
            
#             # Local Outlier Factor
#             if "lof" in models[entity]:
#                 try:
#                     lof = models[entity]["lof"]
#                     lof_scores = lof.decision_function(X_scaled)
#                     lof_predictions = lof.predict(X_scaled)
                    
#                     anomaly_votes += (lof_predictions == -1).astype(int)
                    
#                     min_score = lof_scores.min()
#                     max_score = lof_scores.max()
#                     if min_score < max_score:
#                         normalized_scores = ((max_score - lof_scores) / (max_score - min_score)).clip(0, 1)
#                     else:
#                         normalized_scores = np.zeros_like(lof_scores)
#                     anomaly_scores.append(normalized_scores)
                    
#                 except Exception as e:
#                     logger.error(f"LOF error for {entity}: {e}")
            
#             # One-Class SVM
#             if "ocsvm" in models[entity]:
#                 try:
#                     ocsvm = models[entity]["ocsvm"]
#                     ocsvm_scores = ocsvm.decision_function(X_scaled)
#                     ocsvm_predictions = ocsvm.predict(X_scaled)
                    
#                     anomaly_votes += (ocsvm_predictions == -1).astype(int)
                    
#                     min_score = ocsvm_scores.min()
#                     max_score = ocsvm_scores.max()
#                     if min_score < max_score:
#                         normalized_scores = ((max_score - ocsvm_scores) / (max_score - min_score)).clip(0, 1)
#                     else:
#                         normalized_scores = np.zeros_like(ocsvm_scores)
#                     anomaly_scores.append(normalized_scores)
                    
#                 except Exception as e:
#                     logger.error(f"OCSVM error for {entity}: {e}")
            
#             # PCA reconstruction error
#             if "pca" in models[entity]:
#                 try:
#                     pca = models[entity]["pca"]
#                     X_pca = pca.transform(X_scaled)
#                     X_reconstructed = pca.inverse_transform(X_pca)
                    
#                     reconstruction_errors = np.sum(np.square(X_scaled - X_reconstructed), axis=1)
#                     error_threshold = np.percentile(reconstruction_errors, 95)
                    
#                     anomaly_votes += (reconstruction_errors > error_threshold).astype(int)
                    
#                     max_error = reconstruction_errors.max()
#                     if max_error > 0:
#                         normalized_scores = (reconstruction_errors / max_error).clip(0, 1)
#                     else:
#                         normalized_scores = np.zeros_like(reconstruction_errors)
#                     anomaly_scores.append(normalized_scores)
                    
#                 except Exception as e:
#                     logger.error(f"PCA error for {entity}: {e}")
            
#             # DBSCAN clustering
#             if "dbscan" in models[entity]:
#                 try:
#                     dbscan = models[entity]["dbscan"]
#                     labels = dbscan.fit_predict(X_scaled)
                    
#                     dbscan_anomalies = (labels == -1).astype(int)
#                     anomaly_votes += dbscan_anomalies
#                     anomaly_scores.append(dbscan_anomalies.astype(float))
                    
#                 except Exception as e:
#                     logger.error(f"DBSCAN error for {entity}: {e}")
            
#             # Combine results using consensus voting
#             num_methods = len(anomaly_scores)
#             if num_methods > 0:
#                 # Require at least 60% of methods to agree
#                 consensus_threshold = max(2, int(0.6 * num_methods))
#                 entity_data["is_ml_anomaly"] = anomaly_votes >= consensus_threshold
                
#                 # Calculate weighted average of scores
#                 combined_scores = np.mean(anomaly_scores, axis=0)
#                 entity_data["ml_anomaly_score"] = combined_scores
                
#                 logger.info(f"ML detection found {entity_data['is_ml_anomaly'].sum()} anomalies for {entity}")
            
#             entity_data["detection_method"] = "machine_learning"
#             results.append(entity_data)
            
#         except Exception as e:
#             logger.error(f"Error processing {entity} in ML detection: {e}")
#             import traceback
#             logger.error(traceback.format_exc())
    
#     if results:
#         try:
#             return pd.concat(results, ignore_index=True)
#         except Exception as e:
#             logger.error(f"Error concatenating ML results: {e}")
#             return results[0] if results else pd.DataFrame()
    
#     return pd.DataFrame()

def detect_ml_anomalies(aggregated_data, models, scalers, config, data_type="process"):
    """
    Detect anomalies using trained ML models for Linux data.
    Ensures feature compatibility with model scalers.
    """
    if aggregated_data.empty or not models:
        logger.warning("No data or models available for ML anomaly detection")
        return pd.DataFrame()
    
    # Extract features
    try:
        feature_data = extract_ml_features(aggregated_data, config)
        logger.info("Successfully extracted features for ML detection")
    except Exception as e:
        logger.error(f"Error in feature extraction for ML detection: {e}")
        return pd.DataFrame()
    
    results = []
    
    # Determine entity column
    if data_type == "process":
        entity_col = 'process.name'
    elif data_type == "network":
        entity_col = 'destination.geo.country_name'
    elif data_type == "user":
        entity_col = 'user.name'
    elif data_type == "discovery":
        entity_col = 'process.name'
    elif data_type == "metadata":
        entity_col = 'process.name'
    else:
        entity_col = 'host.hostname'
    
    # FIXED: Better entity column handling
    if entity_col in feature_data.columns:
        entities = feature_data[entity_col].unique()
    else:
        # If the entity column is missing, add it with a default value
        logger.warning(f"Entity column '{entity_col}' not found. Available alternatives:")
        for col in feature_data.columns:
            if 'name' in col or 'hostname' in col:
                logger.info(f"  Found alternative entity column: {col}")
                entity_col = col
                entities = feature_data[entity_col].unique()
                break
        else:
            logger.warning("No suitable entity column found, using 'global' entity")
            feature_data['global_entity'] = 'global'
            entity_col = 'global_entity'
            entities = ['global']
    
    # FIXED: Add fallback model creation for unknown entities
    available_entities = set(models.keys())
    missing_entities = set(entities) - available_entities
    
    if missing_entities and 'global' in models:
        logger.info(f"Creating fallback models for {len(missing_entities)} unknown entities using 'global' model")
        for entity in missing_entities:
            if entity is not None and str(entity) != 'nan':
                models[entity] = models['global']
                scalers[entity] = scalers['global']
    
    # Process each entity
    for entity in entities:
        # FIXED: Handle None/NaN entities
        if entity is None or (isinstance(entity, float) and np.isnan(entity)):
            continue
            
        entity = str(entity)  # Convert to string for consistency
        
        if entity not in models or entity not in scalers:
            logger.warning(f"No models or scalers found for entity: {entity}")
            continue
        
        if entity == 'global':
            entity_data = feature_data.copy()
        else:
            entity_data = feature_data[feature_data[entity_col] == entity].copy()
        
        try:
            if len(entity_data) == 0:
                continue
                
            # FIXED: Get the exact number of features the scaler expects
            expected_feature_count = None
            try:
                # Try to infer from the scaler's n_features_in_ attribute
                if hasattr(scalers[entity], 'n_features_in_'):
                    expected_feature_count = scalers[entity].n_features_in_
                    logger.info(f"Scaler for {entity} expects {expected_feature_count} features")
                
                else:
                    # Extract feature count from scaler attributes or dimensions
                    for attr in ['n_features_', 'n_features_in_', 'feature_names_in_', 'mean_']:
                        if hasattr(scalers[entity], attr):
                            val = getattr(scalers[entity], attr)
                            if isinstance(val, (list, np.ndarray)):
                                expected_feature_count = len(val)
                                break
                    
                    # If still not found, try with common feature counts
                    if expected_feature_count is None:
                        for count in [35, 32, 30, 28, 24, 16]:  # Common feature counts
                            try:
                                dummy_array = np.zeros((1, count))
                                scalers[entity].transform(dummy_array)
                                expected_feature_count = count
                                break
                            except:
                                continue
            except Exception as e:
                logger.error(f"Error determining feature count for {entity}: {e}")
                
            # Use default count if still not determined
            if expected_feature_count is None:
                expected_feature_count = 35  # Most common feature count based on logs
                logger.info(f"Using default feature count of {expected_feature_count} for {entity}")
            
            # Define a complete list of features the model might expect
            all_possible_features = [
                # Basic features
                'event_count', 
                
                # Domain-specific features
                'args_count', 'command_length', 'has_suspicious_chars', 
                'has_encoded_content', 'is_system_path', 'is_tmp_execution', 
                'is_root_user', 'has_hash', 'env_vars_count',
                
                # Time-based features
                'hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend',
                'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
                
                # Time-series features
                'rolling_mean_3h', 'rolling_std_3h', 'rolling_max_3h',
                'rolling_mean_6h', 'rolling_std_6h', 'rolling_max_6h',
                'rolling_mean_12h', 'rolling_std_12h', 'rolling_max_12h',
                'rolling_mean_24h', 'rolling_std_24h', 'rolling_max_24h',
                'event_count_lag_1', 'event_count_lag_3', 'event_count_lag_6',
                'event_count_lag_12', 'event_count_lag_24',
                'event_count_roc', 'event_count_day_roc',
                'expected_count', 'pattern_deviation', 'relative_deviation'
            ]
            
            # Make sure we have enough features in our list
            while len(all_possible_features) < expected_feature_count:
                all_possible_features.append(f"feature_{len(all_possible_features)}")
            
            # Take exactly the number of features we need
            expected_features = all_possible_features[:expected_feature_count]
            
            # FIXED: Better feature handling with more descriptive warnings
            missing_features = [f for f in expected_features if f not in entity_data.columns]
            if missing_features:
                logger.warning(f"Missing {len(missing_features)} features for {entity}: {missing_features[:5]}...")
            
            # Add missing features with default values
            for feature in expected_features:
                if feature not in entity_data.columns:
                    # Default value based on feature type
                    if 'sin' in feature or 'cos' in feature:
                        entity_data[feature] = 0.0  # Trigonometric features
                    elif 'std' in feature:
                        entity_data[feature] = 0.1  # Standard deviations are positive
                    elif 'rolling_' in feature or 'lag' in feature:
                        entity_data[feature] = 1.0  # Rolling and lag features
                    elif feature == 'event_count':
                        entity_data[feature] = 1.0  # Event count defaults to 1
                    else:
                        entity_data[feature] = 0    # Most features default to 0
            
            # Select exactly the expected features in the right order
            X = entity_data[expected_features].copy()
            
            # FIXED: Better handling of string columns
            for col in X.columns:
                if X[col].dtype == 'object':
                    # For entity columns (like process.name), use a binary indicator
                    if col == entity_col:
                        X[col] = 1  # Just mark with 1 since all are the same entity
                    else:
                        # Try to convert to numeric, replace with 0 if fails
                        try:
                            X[col] = pd.to_numeric(X[col], errors='coerce').fillna(0)
                        except:
                            X[col] = 0  # Last resort - use zero for non-convertible columns
            
            # FIXED: Better NaN handling with a warning about which columns had NaNs
            nan_cols = X.columns[X.isna().any()].tolist()
            if nan_cols:
                logger.warning(f"NaN values found in {len(nan_cols)} columns for {entity}: {nan_cols[:5]}...")
                # Use more appropriate imputation based on column type
                for col in nan_cols:
                    if 'sin' in col or 'cos' in col:
                        X[col] = X[col].fillna(0.0)  # Trig features default to 0
                    elif 'std' in col or 'deviation' in col:
                        X[col] = X[col].fillna(0.1)  # Small positive value for variance features
                    elif 'mean' in col or 'expected' in col:
                        X[col] = X[col].fillna(X[col].mean() if not pd.isna(X[col].mean()) else 1.0)
                    else:
                        X[col] = X[col].fillna(0)  # General case
            
            # Convert to numpy array
            X_values = X.values
            
            # Check final shape
            logger.info(f"Feature matrix for {entity} has shape {X_values.shape}, expected {expected_feature_count} features")
            
            # Apply scaler
            try:
                X_scaled = scalers[entity].transform(X_values)
            except Exception as e:
                logger.error(f"Scaling error for {entity}: {e}")
                logger.error(f"X shape: {X_values.shape}, expected {expected_feature_count} features")
                # Try a fallback approach - create a new array with the right shape
                try:
                    if hasattr(scalers[entity], 'mean_') and hasattr(scalers[entity], 'scale_'):
                        # For StandardScaler, we can manually apply the transformation
                        X_scaled = (X_values - scalers[entity].mean_) / scalers[entity].scale_
                    else:
                        # Last resort - skip scaling and use raw features
                        logger.warning(f"Using unscaled features for {entity} due to scaling error")
                        X_scaled = X_values
                except:
                    logger.error(f"Fallback scaling also failed for {entity}, skipping")
                    continue
            
            # Initialize anomaly flags and scores
            entity_data["is_ml_anomaly"] = False
            entity_data["ml_anomaly_score"] = 0.0
            
            # Apply models
            anomaly_votes = np.zeros(len(entity_data))
            anomaly_scores = []
            
            # Isolation Forest
            if "isolation_forest" in models[entity]:
                try:
                    iso_forest = models[entity]["isolation_forest"]
                    if_scores = iso_forest.decision_function(X_scaled)
                    if_predictions = iso_forest.predict(X_scaled)
                    
                    anomaly_votes += (if_predictions == -1).astype(int)
                    normalized_scores = (1 - (if_scores + 1) / 2).clip(0, 1)
                    anomaly_scores.append(normalized_scores)
                    
                except Exception as e:
                    logger.error(f"Isolation Forest error for {entity}: {e}")
            
            # Local Outlier Factor
            if "lof" in models[entity]:
                try:
                    lof = models[entity]["lof"]
                    lof_scores = lof.decision_function(X_scaled)
                    lof_predictions = lof.predict(X_scaled)
                    
                    anomaly_votes += (lof_predictions == -1).astype(int)
                    
                    min_score = lof_scores.min()
                    max_score = lof_scores.max()
                    if min_score < max_score:
                        normalized_scores = ((max_score - lof_scores) / (max_score - min_score)).clip(0, 1)
                    else:
                        normalized_scores = np.zeros_like(lof_scores)
                    anomaly_scores.append(normalized_scores)
                    
                except Exception as e:
                    logger.error(f"LOF error for {entity}: {e}")
            
            # One-Class SVM
            if "ocsvm" in models[entity]:
                try:
                    ocsvm = models[entity]["ocsvm"]
                    ocsvm_scores = ocsvm.decision_function(X_scaled)
                    ocsvm_predictions = ocsvm.predict(X_scaled)
                    
                    anomaly_votes += (ocsvm_predictions == -1).astype(int)
                    
                    min_score = ocsvm_scores.min()
                    max_score = ocsvm_scores.max()
                    if min_score < max_score:
                        normalized_scores = ((max_score - ocsvm_scores) / (max_score - min_score)).clip(0, 1)
                    else:
                        normalized_scores = np.zeros_like(ocsvm_scores)
                    anomaly_scores.append(normalized_scores)
                    
                except Exception as e:
                    logger.error(f"OCSVM error for {entity}: {e}")
            
            # PCA reconstruction error
            if "pca" in models[entity]:
                try:
                    pca = models[entity]["pca"]
                    X_pca = pca.transform(X_scaled)
                    X_reconstructed = pca.inverse_transform(X_pca)
                    
                    reconstruction_errors = np.sum(np.square(X_scaled - X_reconstructed), axis=1)
                    error_threshold = np.percentile(reconstruction_errors, 95)
                    
                    anomaly_votes += (reconstruction_errors > error_threshold).astype(int)
                    
                    max_error = reconstruction_errors.max()
                    if max_error > 0:
                        normalized_scores = (reconstruction_errors / max_error).clip(0, 1)
                    else:
                        normalized_scores = np.zeros_like(reconstruction_errors)
                    anomaly_scores.append(normalized_scores)
                    
                except Exception as e:
                    logger.error(f"PCA error for {entity}: {e}")
            
            # DBSCAN clustering
            if "dbscan" in models[entity]:
                try:
                    dbscan = models[entity]["dbscan"]
                    labels = dbscan.fit_predict(X_scaled)
                    
                    dbscan_anomalies = (labels == -1).astype(int)
                    anomaly_votes += dbscan_anomalies
                    anomaly_scores.append(dbscan_anomalies.astype(float))
                    
                except Exception as e:
                    logger.error(f"DBSCAN error for {entity}: {e}")
            
            # Combine results using consensus voting
            num_methods = len(anomaly_scores)
            if num_methods > 0:
                # Require at least 60% of methods to agree
                consensus_threshold = max(1, int(0.6 * num_methods))
                entity_data["is_ml_anomaly"] = anomaly_votes >= consensus_threshold
                
                # Calculate weighted average of scores
                combined_scores = np.mean(anomaly_scores, axis=0)
                entity_data["ml_anomaly_score"] = combined_scores
                
                logger.info(f"ML detection found {entity_data['is_ml_anomaly'].sum()} anomalies for {entity}")
            
            entity_data["detection_method"] = "machine_learning"
            results.append(entity_data)
            
        except Exception as e:
            logger.error(f"Error processing {entity} in ML detection: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    # FIXED: Better handling of results combining
    if results:
        try:
            final_results = pd.concat(results, ignore_index=True)
            
            # Make sure anomaly_score exists
            if "ml_anomaly_score" in final_results.columns and "anomaly_score" not in final_results.columns:
                final_results["anomaly_score"] = final_results["ml_anomaly_score"]
                
            return final_results
            
        except Exception as e:
            logger.error(f"Error concatenating ML results: {e}")
            # Fall back to returning a single result if concatenation fails
            if len(results) > 0:
                return results[0]
            else:
                return pd.DataFrame()
    
    return pd.DataFrame()

def calculate_baselines(historical_data, config, data_type="process"):
    """
    Calculate baseline statistics for Linux entities.
    Adapted from network detection methods.
    
    Args:
        historical_data (pd.DataFrame): Historical data
        config (dict): Configuration dictionary
        data_type (str): Type of data being processed
        
    Returns:
        dict: Baseline statistics by entity
    """
    if historical_data.empty:
        return {}
    
    baselines = {}
    
    # Determine entity column
    if data_type == "process":
        entity_col = 'process.name'
    elif data_type == "network":
        entity_col = 'destination.geo.country_name'
    elif data_type == "user":
        entity_col = 'user.name'
    elif data_type == "discovery":
        entity_col = 'process.name'
    elif data_type == "metadata":
        entity_col = 'process.name'
    else:
        entity_col = 'host.hostname'
    
    if entity_col not in historical_data.columns:
        return {}
    
    # Group data by entity
    entity_groups = historical_data.groupby(entity_col)
    
    for entity, group in entity_groups:
        # Basic statistics
        stats = {
            "mean": group["event_count"].mean(),
            "std": group["event_count"].std(),
            "median": group["event_count"].median(),
            "max": group["event_count"].max(),
            "min": group["event_count"].min()
        }
        
        # Handle very small standard deviations
        if stats["std"] < 0.1:
            stats["std"] = max(0.1, stats["mean"] * 0.1)
        
        # Calculate percentiles
        percentiles = {
            "p50": group["event_count"].quantile(0.5),
            "p75": group["event_count"].quantile(0.75),
            "p90": group["event_count"].quantile(0.9),
            "p95": group["event_count"].quantile(0.95),
            "p99": group["event_count"].quantile(0.99)
        }
        stats["percentiles"] = percentiles
        
        # Time-based patterns
        if "hour_of_day" in group.columns:
            hour_patterns = group.groupby("hour_of_day")["event_count"].mean().to_dict()
            stats["hourly_patterns"] = hour_patterns
        
        if "day_of_week" in group.columns:
            day_patterns = group.groupby("day_of_week")["event_count"].mean().to_dict()
            stats["daily_patterns"] = day_patterns
        
        baselines[entity] = stats
    
    return baselines

# Linux-specific detection functions

def detect_rare_processes_all_hosts(aggregated_data, config):
    """
    Detect processes that are unusual across all Linux hosts.
    Implements v3_linux_anomalous_process_all_hosts detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated process data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with rare process detection
    """
    logger.info("Running rare processes (all hosts) detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    # Calculate process frequency across all hosts
    process_totals = aggregated_data.groupby('process.name')['event_count'].sum()
    total_events = process_totals.sum()
    
    # Calculate percentage for each process
    process_percentages = (process_totals / total_events) * 100
    
    # Get threshold from config
    rare_threshold = config.get('detection', {}).get('rare_process_threshold', 0.1)
    
    # Identify rare processes
    rare_processes = process_percentages[process_percentages < rare_threshold].index.tolist()
    
    # Mark rare processes in the data
    results = aggregated_data.copy()
    results['is_rare_process'] = results['process.name'].isin(rare_processes)
    results['process_percentage'] = results['process.name'].map(process_percentages)
    
    # Flag anomalies for rare processes
    results['rare_process_anomaly'] = results['is_rare_process'] & (results['event_count'] > 0)
    
    # Calculate anomaly score
    results['rare_process_score'] = 0.0
    rare_mask = results['is_rare_process']
    results.loc[rare_mask, 'rare_process_score'] = 1.0 - (results.loc[rare_mask, 'process_percentage'] / rare_threshold)
    
    logger.info(f"Identified {len(rare_processes)} rare processes across all hosts")
    return results

def detect_rare_processes_by_host(aggregated_data, config):
    """
    Detect processes that are unusual to a particular Linux host.
    Implements v3_rare_process_by_host_linux detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated process data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with host-specific rare process detection
    """
    logger.info("Running rare processes (by host) detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    results = aggregated_data.copy()
    results['is_rare_process_host'] = False
    results['rare_process_host_score'] = 0.0
    
    # Get threshold from config
    rare_threshold = config.get('detection', {}).get('rare_process_host_threshold', 0.05)
    
    # Process each host separately
    for hostname in aggregated_data['host.hostname'].unique():
        host_data = aggregated_data[aggregated_data['host.hostname'] == hostname]
        
        # Calculate process frequency for this host
        host_process_totals = host_data.groupby('process.name')['event_count'].sum()
        host_total_events = host_process_totals.sum()
        
        if host_total_events == 0:
            continue
        
        # Calculate percentage for each process on this host
        host_process_percentages = (host_process_totals / host_total_events) * 100
        
        # Identify rare processes for this host
        rare_processes_host = host_process_percentages[host_process_percentages < rare_threshold].index.tolist()
        
        # Update results for this host
        host_mask = results['host.hostname'] == hostname
        results.loc[host_mask, 'is_rare_process_host'] = results.loc[host_mask, 'process.name'].isin(rare_processes_host)
        
        # Calculate scores for rare processes on this host
        for process in rare_processes_host:
            process_mask = host_mask & (results['process.name'] == process)
            if process_mask.any():
                process_pct = host_process_percentages[process]
                score = 1.0 - (process_pct / rare_threshold)
                results.loc[process_mask, 'rare_process_host_score'] = score
    
    # Flag anomalies
    results['rare_process_host_anomaly'] = results['is_rare_process_host'] & (results['event_count'] > 0)
    
    logger.info(f"Completed rare process detection for {len(aggregated_data['host.hostname'].unique())} hosts")
    return results

def detect_anomalous_user_activity(aggregated_data, config):
    """
    Detect rare and unusual users that may indicate unauthorized activity.
    Implements v3_linux_anomalous_user_name detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated user activity data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with anomalous user detection
    """
    logger.info("Running anomalous user activity detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    # Calculate user activity frequency
    user_totals = aggregated_data.groupby('user.name')['event_count'].sum()
    total_events = user_totals.sum()
    
    # Calculate percentage for each user
    user_percentages = (user_totals / total_events) * 100
    
    # Get threshold from config
    rare_user_threshold = config.get('detection', {}).get('rare_user_threshold', 0.5)
    
    # Identify rare users
    rare_users = user_percentages[user_percentages < rare_user_threshold].index.tolist()
    
    # Mark rare users in the data
    results = aggregated_data.copy()
    results['is_rare_user'] = results['user.name'].isin(rare_users)
    results['user_percentage'] = results['user.name'].map(user_percentages)
    
    # Flag anomalies for rare users
    results['rare_user_anomaly'] = results['is_rare_user'] & (results['event_count'] > 0)
    
    # Calculate anomaly score
    results['rare_user_score'] = 0.0
    rare_mask = results['is_rare_user']
    results.loc[rare_mask, 'rare_user_score'] = 1.0 - (results.loc[rare_mask, 'user_percentage'] / rare_user_threshold)
    
    # Additional checks for privileged users
    if 'is_root_user' in results.columns:
        # Root activity outside business hours is more suspicious
        root_after_hours = (
            (results['is_root_user'] == 1) & 
            (results['is_business_hours'] == 0) & 
            (results['event_count'] > 0)
        )
        results.loc[root_after_hours, 'rare_user_score'] *= 1.5
        results.loc[root_after_hours, 'rare_user_anomaly'] = True
    
    logger.info(f"Identified {len(rare_users)} rare users")
    return results

def detect_sudo_anomalies(aggregated_data, config):
    """
    Detect sudo activity from unusual user contexts.
    Implements v3_linux_rare_sudo_user detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated sudo activity data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with sudo anomaly detection
    """
    logger.info("Running sudo anomaly detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    # Filter for sudo activities
    sudo_data = aggregated_data[
        aggregated_data.get('is_sudo_command', False) == True
    ].copy()
    
    if sudo_data.empty:
        return pd.DataFrame()
    
    # Calculate sudo frequency by user
    sudo_user_totals = sudo_data.groupby('user.name')['event_count'].sum()
    total_sudo_events = sudo_user_totals.sum()
    
    # Calculate percentage for each user
    sudo_user_percentages = (sudo_user_totals / total_sudo_events) * 100
    
    # Get threshold from config
    rare_sudo_threshold = config.get('detection', {}).get('rare_sudo_threshold', 1.0)
    
    # Identify rare sudo users
    rare_sudo_users = sudo_user_percentages[sudo_user_percentages < rare_sudo_threshold].index.tolist()
    
    # Mark results
    results = aggregated_data.copy()
    results['is_rare_sudo_user'] = (
        (results['user.name'].isin(rare_sudo_users)) & 
        (results.get('is_sudo_command', False) == True)
    )
    
    # Calculate anomaly score
    results['rare_sudo_score'] = 0.0
    rare_sudo_mask = results['is_rare_sudo_user']
    
    for user in rare_sudo_users:
        user_mask = (results['user.name'] == user) & results.get('is_sudo_command', False)
        if user_mask.any():
            user_pct = sudo_user_percentages[user]
            score = 1.0 - (user_pct / rare_sudo_threshold)
            results.loc[user_mask, 'rare_sudo_score'] = score
    
    # Flag anomalies
    results['sudo_anomaly'] = results['is_rare_sudo_user'] & (results['event_count'] > 0)
    
    logger.info(f"Identified {len(rare_sudo_users)} rare sudo users")
    return results

def detect_compiler_anomalies(aggregated_data, config):
    """
    Detect compiler activity by users who don't normally compile code.
    Implements v3_linux_rare_user_compiler detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated compiler activity data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with compiler anomaly detection
    """
    logger.info("Running compiler anomaly detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    # Filter for compiler activities
    compiler_data = aggregated_data[
        aggregated_data.get('is_compiler_activity', False) == True
    ].copy()
    
    if compiler_data.empty:
        return pd.DataFrame()
    
    # Calculate compiler usage frequency by user
    compiler_user_totals = compiler_data.groupby('user.name')['event_count'].sum()
    total_compiler_events = compiler_user_totals.sum()
    
    # Calculate percentage for each user
    compiler_user_percentages = (compiler_user_totals / total_compiler_events) * 100
    
    # Get threshold from config
    rare_compiler_threshold = config.get('detection', {}).get('rare_compiler_threshold', 2.0)
    
    # Identify rare compiler users
    rare_compiler_users = compiler_user_percentages[compiler_user_percentages < rare_compiler_threshold].index.tolist()
    
    # Mark results
    results = aggregated_data.copy()
    results['is_rare_compiler_user'] = (
        (results['user.name'].isin(rare_compiler_users)) & 
        (results.get('is_compiler_activity', False) == True)
    )
    
    # Calculate anomaly score
    results['rare_compiler_score'] = 0.0
    
    for user in rare_compiler_users:
        user_mask = (results['user.name'] == user) & results.get('is_compiler_activity', False)
        if user_mask.any():
            user_pct = compiler_user_percentages[user]
            score = 1.0 - (user_pct / rare_compiler_threshold)
            results.loc[user_mask, 'rare_compiler_score'] = score
    
    # Flag anomalies
    results['compiler_anomaly'] = results['is_rare_compiler_user'] & (results['event_count'] > 0)
    
    logger.info(f"Identified {len(rare_compiler_users)} rare compiler users")
    return results

def detect_discovery_command_anomalies(aggregated_data, config):
    """
    Detect unusual system discovery commands from unexpected user contexts.
    Implements all v3_linux_*_discovery detection jobs.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated discovery command data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with discovery command anomaly detection
    """
    logger.info("Running discovery command anomaly detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    results = aggregated_data.copy()
    results['discovery_anomaly'] = False
    results['discovery_anomaly_score'] = 0.0
    results['discovery_anomaly_reason'] = ""
    
    # Discovery command categories
    discovery_categories = {
        "network": ["netstat", "ss", "lsof", "nmap", "arp", "route", "ip", "ifconfig"],
        "process": ["ps", "top", "htop", "pgrep", "pidof"],
        "user": ["who", "w", "users", "last", "lastlog", "id", "groups"],
        "system": ["uname", "hostname", "uptime", "lscpu", "df", "mount"]
    }
    
    # For each category, detect unusual usage patterns
    for category, commands in discovery_categories.items():
        category_data = results[
            results['process.name'].isin(commands)
        ].copy()
        
        if category_data.empty:
            continue
        
        # Calculate usage frequency by user for this category
        user_category_totals = category_data.groupby('user.name')['event_count'].sum()
        total_category_events = user_category_totals.sum()
        
        if total_category_events == 0:
            continue
        
        # Calculate percentage for each user
        user_category_percentages = (user_category_totals / total_category_events) * 100
        
        # Get threshold from config
        discovery_threshold = config.get('detection', {}).get('discovery_threshold', 5.0)
        
        # Identify rare discovery users for this category
        rare_discovery_users = user_category_percentages[
            user_category_percentages < discovery_threshold
        ].index.tolist()
        
        # Mark anomalies for this category
        for user in rare_discovery_users:
            user_mask = (
                (results['user.name'] == user) & 
                (results['process.name'].isin(commands))
            )
            
            if user_mask.any():
                user_pct = user_category_percentages[user]
                score = 1.0 - (user_pct / discovery_threshold)
                
                results.loc[user_mask, 'discovery_anomaly'] = True
                results.loc[user_mask, 'discovery_anomaly_score'] = np.maximum(
                    results.loc[user_mask, 'discovery_anomaly_score'], score
                )
                
                # Add reason
                for idx in results[user_mask].index:
                    current_reason = results.loc[idx, 'discovery_anomaly_reason']
                    new_reason = f"{category}_discovery"
                    if current_reason:
                        results.loc[idx, 'discovery_anomaly_reason'] = f"{current_reason},{new_reason}"
                    else:
                        results.loc[idx, 'discovery_anomaly_reason'] = new_reason
    
    # Additional checks for suspicious patterns
    if 'is_business_hours' in results.columns:
        # Discovery commands outside business hours are more suspicious
        after_hours_discovery = (
            (results['discovery_anomaly'] == True) & 
            (results['is_business_hours'] == 0)
        )
        results.loc[after_hours_discovery, 'discovery_anomaly_score'] *= 1.5
    
    logger.info(f"Detected {results['discovery_anomaly'].sum()} discovery command anomalies")
    return results

def detect_metadata_access_anomalies(aggregated_data, config):
    """
    Detect unusual access to metadata services.
    Implements v3_linux_rare_metadata_process and v3_linux_rare_metadata_user detection.
    
    Args:
        aggregated_data (pd.DataFrame): Aggregated metadata access data
        config (dict): Configuration dictionary
        
    Returns:
        pd.DataFrame: Results with metadata access anomaly detection
    """
    logger.info("Running metadata access anomaly detection")
    
    if aggregated_data.empty:
        return pd.DataFrame()
    
    results = aggregated_data.copy()
    results['metadata_anomaly'] = False
    results['metadata_anomaly_score'] = 0.0
    results['metadata_anomaly_type'] = ""
    
    # Process-based metadata access anomalies
    if 'process.name' in results.columns:
        process_totals = results.groupby('process.name')['event_count'].sum()
        total_events = process_totals.sum()
        
        if total_events > 0:
            process_percentages = (process_totals / total_events) * 100
            rare_threshold = config.get('detection', {}).get('rare_metadata_process_threshold', 1.0)
            
            rare_processes = process_percentages[process_percentages < rare_threshold].index.tolist()
            
            process_mask = results['process.name'].isin(rare_processes)
            results.loc[process_mask, 'metadata_anomaly'] = True
            results.loc[process_mask, 'metadata_anomaly_type'] = "rare_process"
            
            for process in rare_processes:
                proc_mask = results['process.name'] == process
                if proc_mask.any():
                    proc_pct = process_percentages[process]
                    score = 1.0 - (proc_pct / rare_threshold)
                    results.loc[proc_mask, 'metadata_anomaly_score'] = score
    
    # User-based metadata access anomalies
    if 'user.name' in results.columns:
        user_totals = results.groupby('user.name')['event_count'].sum()
        total_user_events = user_totals.sum()
        
        if total_user_events > 0:
            user_percentages = (user_totals / total_user_events) * 100
            rare_user_threshold = config.get('detection', {}).get('rare_metadata_user_threshold', 2.0)
            
            rare_users = user_percentages[user_percentages < rare_user_threshold].index.tolist()
            
            for user in rare_users:
                user_mask = results['user.name'] == user
                if user_mask.any():
                    user_pct = user_percentages[user]
                    score = 1.0 - (user_pct / rare_user_threshold)
                    
                    # Update anomaly flags
                    current_anomaly = results.loc[user_mask, 'metadata_anomaly']
                    results.loc[user_mask, 'metadata_anomaly'] = True
                    
                    # Update scores (take maximum)
                    current_scores = results.loc[user_mask, 'metadata_anomaly_score']
                    results.loc[user_mask, 'metadata_anomaly_score'] = np.maximum(current_scores, score)
                    
                    # Update type
                    current_type = results.loc[user_mask, 'metadata_anomaly_type']
                    new_type = current_type.apply(
                        lambda x: "rare_user" if x == "" else f"{x},rare_user"
                    )
                    results.loc[user_mask, 'metadata_anomaly_type'] = new_type
    
    # Additional checks for credential harvesting indicators
    if 'potential_cred_harvest' in results.columns:
        cred_harvest_mask = results['potential_cred_harvest'] == 1
        results.loc[cred_harvest_mask, 'metadata_anomaly'] = True
        results.loc[cred_harvest_mask, 'metadata_anomaly_score'] *= 2.0
        results.loc[cred_harvest_mask, 'metadata_anomaly_score'] = results.loc[cred_harvest_mask, 'metadata_anomaly_score'].clip(0, 10)
    
    logger.info(f"Detected {results['metadata_anomaly'].sum()} metadata access anomalies")
    return results

def combine_detection_results(statistical_results, ml_results, config, data_type="process"):
    """
    Combine results from different detection methods for Linux anomaly detection.
    Adapted from network detection methods.
    
    Args:
        statistical_results (pd.DataFrame): Results from statistical detection
        ml_results (pd.DataFrame): Results from ML detection
        config (dict): Configuration dictionary
        data_type (str): Type of data being processed
        
    Returns:
        pd.DataFrame: Combined results with final anomaly flags
    """
    logger.info(f"Combining detection results for {data_type}")
    
    all_results = []
    
    # Standardize timestamps
    for df in [statistical_results, ml_results]:
        if not isinstance(df, pd.DataFrame) or df.empty:
            continue
        
        if "@timestamp" in df.columns:
            try:
                if not pd.api.types.is_datetime64_any_dtype(df["@timestamp"]):
                    df["@timestamp"] = pd.to_datetime(df["@timestamp"])
                df["@timestamp"] = df["@timestamp"].dt.tz_localize(None)
            except Exception as e:
                logger.warning(f"Error standardizing timestamps: {e}")
    
    # Add results if available
    if not statistical_results.empty:
        all_results.append(statistical_results)
    if not ml_results.empty:
        all_results.append(ml_results)
    
    if not all_results:
        return pd.DataFrame()
    
    try:
        combined = pd.concat(all_results, ignore_index=True)
        
        # Determine grouping columns based on data type
        if data_type == "process":
            group_cols = ["@timestamp", "host.hostname", "process.name"]
        elif data_type == "network":
            group_cols = ["@timestamp", "destination.geo.country_name"]
        elif data_type == "user":
            group_cols = ["@timestamp", "host.hostname", "user.name"]
        elif data_type == "discovery":
            group_cols = ["@timestamp", "host.hostname", "process.name", "user.name"]
        elif data_type == "metadata":
            group_cols = ["@timestamp", "host.hostname", "process.name"]
        else:
            group_cols = ["@timestamp", "host.hostname"]
        
        # Filter to existing columns
        group_cols = [col for col in group_cols if col in combined.columns]
        
        if not group_cols:
            group_cols = ["@timestamp"]
        
        # Group and aggregate
        grouped = combined.groupby(group_cols)
        
        agg_dict = {
            "event_count": "first",
            "is_anomaly": "any",
        }
        
        # Add optional columns
        if "anomaly_score" in combined.columns:
            agg_dict["anomaly_score"] = "mean"
        if "ml_anomaly_score" in combined.columns:
            agg_dict["ml_anomaly_score"] = "mean"
        if "is_ml_anomaly" in combined.columns:
            agg_dict["is_ml_anomaly"] = "any"
        
        agg_dict["detection_method"] = lambda x: ",".join(set(x))
        
        aggregated_results = grouped.agg(agg_dict).reset_index()
        
        # Calculate combined score
        aggregated_results["combined_score"] = 0
        
        if "anomaly_score" in aggregated_results.columns:
            aggregated_results["combined_score"] += 0.6 * aggregated_results["anomaly_score"].fillna(0)
        
        if "ml_anomaly_score" in aggregated_results.columns:
            aggregated_results["combined_score"] += 0.4 * aggregated_results["ml_anomaly_score"].fillna(0)
        
        # Apply sensitivity threshold
        sensitivity = config["detection"]["sensitivity"]
        aggregated_results["final_anomaly"] = (
            aggregated_results["combined_score"] > (1 - sensitivity)
        )
        
        # Ensure any individual method anomalies are preserved
        if "is_anomaly" in aggregated_results.columns:
            aggregated_results["final_anomaly"] |= aggregated_results["is_anomaly"]
        if "is_ml_anomaly" in aggregated_results.columns:
            aggregated_results["final_anomaly"] |= aggregated_results["is_ml_anomaly"]
        
        logger.info(f"Combined results: {len(aggregated_results)} records, {aggregated_results['final_anomaly'].sum()} anomalies")
        return aggregated_results
        
    except Exception as e:
        logger.error(f"Error combining results: {e}")
        return pd.DataFrame()