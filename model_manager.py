import numpy as np
import pandas as pd
import os
import logging
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN, KMeans
from sklearn.svm import OneClassSVM
from sklearn.neighbors import NearestNeighbors
import warnings

# Import detection methods for feature extraction
try:
    from detection_methods import extract_ml_features
except ImportError:
    # Fallback if not available
    extract_ml_features = None

logger = logging.getLogger("linux_anomaly_detection")

class LinuxModelManager:
    """
    Comprehensive model manager for Linux anomaly detection across all 14 detection jobs.
    Handles training, saving, loading, and baseline establishment for 5 data groups.
    """
    
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.scalers = {}
        self.baselines = {}
        self.data_groups = {
            "process": ["v3_linux_anomalous_process_all_hosts", "v3_rare_process_by_host_linux"],
            "network": ["v3_linux_anomalous_network_activity", "v3_linux_anomalous_network_port_activity"],
            "user": ["v3_linux_anomalous_user_name", "v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"],
            "discovery": ["v3_linux_network_configuration_discovery", "v3_linux_network_connection_discovery",
                         "v3_linux_system_information_discovery", "v3_linux_system_process_discovery",
                         "v3_linux_system_user_discovery"],
            "metadata": ["v3_linux_rare_metadata_process", "v3_linux_rare_metadata_user"]
        }
    
    def establish_baselines(self, historical_data, data_type="process"):
        """
        Establish baseline patterns for Linux entities based on data type.
        
        Args:
            historical_data (pd.DataFrame): Historical Linux event data
            data_type (str): Type of data (process, network, user, discovery, metadata)
            
        Returns:
            dict: Baseline statistics for entities
        """
        logger.info(f"Establishing {data_type} baselines")
        
        if historical_data.empty:
            logger.warning(f"No historical data for establishing {data_type} baselines")
            return {}
        
        baselines = {}
        
        # Determine entity column based on data type
        entity_columns = {
            "process": ["process.name", "host.hostname"],
            "network": ["destination.geo.country_name", "destination.port"],
            "user": ["user.name", "host.hostname"],
            "discovery": ["process.name", "user.name"],
            "metadata": ["process.name", "user.name"]
        }
        
        primary_entity = entity_columns[data_type][0]
        secondary_entity = entity_columns[data_type][1] if len(entity_columns[data_type]) > 1 else None
        
        if primary_entity not in historical_data.columns:
            logger.warning(f"Primary entity column {primary_entity} not found in data")
            return {}
        
        # Group by primary entity
        entity_groups = historical_data.groupby(primary_entity)
        
        for entity, group in entity_groups:
            # Skip empty entities
            if pd.isna(entity) or entity == "":
                continue
            
            # Skip if insufficient data
            if len(group) < 5:
                continue
            
            # Calculate basic statistics
            stats = {
                "mean": float(group["event_count"].mean()),
                "std": float(group["event_count"].std()),
                "median": float(group["event_count"].median()),
                "max": float(group["event_count"].max()),
                "min": float(group["event_count"].min()),
                "count": int(len(group))
            }
            
            # Handle very small standard deviations
            if stats["std"] < stats["mean"] * 0.1:
                stats["std"] = max(0.1, stats["mean"] * 0.1)
            
            # Calculate percentiles
            stats["percentiles"] = {
                "p50": float(group["event_count"].quantile(0.5)),
                "p75": float(group["event_count"].quantile(0.75)),
                "p90": float(group["event_count"].quantile(0.9)),
                "p95": float(group["event_count"].quantile(0.95)),
                "p99": float(group["event_count"].quantile(0.99)),
                "p999": float(group["event_count"].quantile(0.999))
            }
            
            # Add time-based patterns if available
            if "hour_of_day" in group.columns:
                hour_patterns = group.groupby("hour_of_day")["event_count"].mean().to_dict()
                stats["hourly_patterns"] = {str(k): float(v) for k, v in hour_patterns.items()}
            
            if "day_of_week" in group.columns:
                day_patterns = group.groupby("day_of_week")["event_count"].mean().to_dict()
                stats["daily_patterns"] = {str(k): float(v) for k, v in day_patterns.items()}
            
            # Add business hours pattern
            if "is_business_hours" in group.columns:
                biz_hours = group[group["is_business_hours"] == 1]["event_count"].mean()
                non_biz_hours = group[group["is_business_hours"] == 0]["event_count"].mean()
                stats["business_hours_pattern"] = {
                    "business_hours_mean": float(biz_hours) if not pd.isna(biz_hours) else 0.0,
                    "non_business_hours_mean": float(non_biz_hours) if not pd.isna(non_biz_hours) else 0.0
                }
            
            # Data type specific metrics
            if data_type == "process":
                # Process-specific metrics
                if "args_count" in group.columns:
                    stats["avg_args_count"] = float(group["args_count"].mean())
                if "command_length" in group.columns:
                    stats["avg_command_length"] = float(group["command_length"].mean())
                if "is_system_path" in group.columns:
                    stats["system_path_ratio"] = float(group["is_system_path"].mean())
            
            elif data_type == "network":
                # Network-specific metrics
                if "destination.port" in group.columns:
                    port_distribution = group["destination.port"].value_counts().head(10).to_dict()
                    stats["top_ports"] = {str(k): int(v) for k, v in port_distribution.items()}
                if "bytes_per_packet" in group.columns:
                    stats["avg_bytes_per_packet"] = float(group["bytes_per_packet"].mean())
            
            elif data_type == "user":
                # User-specific metrics
                if "is_sudo_command" in group.columns:
                    stats["sudo_ratio"] = float(group["is_sudo_command"].mean())
                if "is_compiler_activity" in group.columns:
                    stats["compiler_ratio"] = float(group["is_compiler_activity"].mean())
            
            elif data_type == "discovery":
                # Discovery-specific metrics
                if "discovery_category" in group.columns:
                    category_distribution = group["discovery_category"].value_counts().to_dict()
                    stats["discovery_categories"] = {str(k): int(v) for k, v in category_distribution.items()}
            
            elif data_type == "metadata":
                # Metadata-specific metrics
                if "metadata_service_type" in group.columns:
                    service_distribution = group["metadata_service_type"].value_counts().to_dict()
                    stats["service_types"] = {str(k): int(v) for k, v in service_distribution.items()}
            
            baselines[entity] = stats
        
        # Secondary entity baselines (e.g., per-host patterns)
        if secondary_entity and secondary_entity in historical_data.columns:
            baselines[f"{secondary_entity}_patterns"] = {}
            
            for sec_entity, sec_group in historical_data.groupby(secondary_entity):
                if pd.isna(sec_entity) or sec_entity == "" or len(sec_group) < 3:
                    continue
                
                # Entity frequency on this secondary entity (e.g., processes per host)
                entity_counts = sec_group[primary_entity].value_counts()
                total_events = entity_counts.sum()
                
                if total_events > 0:
                    entity_percentages = (entity_counts / total_events * 100).to_dict()
                    baselines[f"{secondary_entity}_patterns"][sec_entity] = {
                        "entity_distribution": {str(k): float(v) for k, v in entity_percentages.items()},
                        "total_events": int(total_events),
                        "unique_entities": int(len(entity_counts))
                    }
        
        logger.info(f"Established baselines for {len(baselines)} {data_type} entities")
        return baselines
    
    def train_models(self, historical_data, data_type="process"):
        """
        Train machine learning models for Linux anomaly detection.
        
        Args:
            historical_data (pd.DataFrame): Historical data for training
            data_type (str): Type of data being processed
            
        Returns:
            tuple: (models dict, scalers dict)
        """
        logger.info(f"Training {data_type} anomaly detection models")
        
        if historical_data.empty:
            logger.warning(f"No historical data for training {data_type} models")
            return {}, {}
        
        # Extract and engineer features
        try:
            if extract_ml_features:
                feature_data = extract_ml_features(historical_data, self.config)
                logger.info("Used enhanced feature extraction")
            else:
                feature_data = self._add_basic_features(historical_data)
                logger.info("Used basic feature extraction")
        except Exception as e:
            logger.error(f"Error in feature extraction: {e}")
            feature_data = self._add_basic_features(historical_data)
        
        models = {}
        scalers = {}
        
        # Configure model parameters
        ml_config = self.config.get("ml", {})
        contamination = ml_config.get("contamination", 0.05)
        
        # Determine entity column based on data type
        entity_columns = {
            "process": "process.name",
            "network": "destination.geo.country_name", 
            "user": "user.name",
            "discovery": "process.name",
            "metadata": "process.name"
        }
        
        entity_col = entity_columns.get(data_type, "host.hostname")
        
        if entity_col not in feature_data.columns:
            logger.warning(f"Entity column {entity_col} not found, using global model")
            entities = ["global"]
        else:
            entities = feature_data[entity_col].dropna().unique()
            
            # Limit entities if too many
            if len(entities) > 50:
                entity_counts = feature_data[entity_col].value_counts()
                top_entities = entity_counts.head(50).index.tolist()
                entities = [e for e in entities if e in top_entities]
        
        # Train models for each entity
        for entity in entities:
            if entity == "global":
                entity_data = feature_data.copy()
            else:
                entity_data = feature_data[feature_data[entity_col] == entity].copy()
            
            # Skip if insufficient data
            if len(entity_data) < 10:
                logger.warning(f"Insufficient data for {entity} ({len(entity_data)} records)")
                continue
            
            # Select features based on data type
            features = self._select_features_by_type(entity_data, data_type)
            
            if not features:
                logger.warning(f"No valid features for {entity}")
                continue
            
            try:
                # Create feature matrix
                X = entity_data[features].values
                
                # Handle any remaining NaN or infinite values
                X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
                
                # Scale the data
                scaler = RobustScaler()  # More robust to outliers than StandardScaler
                X_scaled = scaler.fit_transform(X)
                
                # Store the scaler
                scalers[entity] = scaler
                
                # Initialize models dict for this entity
                models[entity] = {"features_used": features}
                
                # Train Isolation Forest
                iso_forest = IsolationForest(
                    n_estimators=ml_config.get("n_estimators", 100),
                    contamination=contamination,
                    random_state=42,
                    n_jobs=-1
                )
                iso_forest.fit(X_scaled)
                models[entity]["isolation_forest"] = iso_forest
                
                # Train Local Outlier Factor
                n_neighbors = min(ml_config.get("lof_neighbors", 20), len(X_scaled) - 1)
                if n_neighbors >= 1:
                    lof = LocalOutlierFactor(
                        n_neighbors=n_neighbors,
                        contamination=contamination,
                        novelty=True
                    )
                    lof.fit(X_scaled)
                    models[entity]["lof"] = lof
                
                # Train One-Class SVM
                try:
                    nu = min(contamination * 2, 0.5)  # nu should be in (0, 0.5]
                    ocsvm = OneClassSVM(
                        nu=nu,
                        kernel=ml_config.get("svm_kernel", "rbf"),
                        gamma="scale"
                    )
                    ocsvm.fit(X_scaled)
                    models[entity]["ocsvm"] = ocsvm
                except Exception as e:
                    logger.warning(f"OneClassSVM training failed for {entity}: {e}")
                
                # Train PCA for reconstruction error
                n_components = min(ml_config.get("pca_components", 0.95), X_scaled.shape[1] - 1)
                if isinstance(n_components, float):
                    pca = PCA(n_components=n_components)
                else:
                    pca = PCA(n_components=min(n_components, X_scaled.shape[1] - 1))
                
                pca.fit(X_scaled)
                models[entity]["pca"] = pca
                
                # Train DBSCAN
                try:
                    # Estimate eps parameter using k-distance
                    k = min(5, len(X_scaled) - 1)
                    if k >= 1:
                        nn = NearestNeighbors(n_neighbors=k)
                        nn.fit(X_scaled)
                        distances, _ = nn.kneighbors(X_scaled)
                        
                        # Use knee point as eps
                        sorted_distances = np.sort(distances[:, -1])
                        eps = np.percentile(sorted_distances, 90)
                        eps = max(0.1, min(eps, 2.0))  # Reasonable bounds
                        
                        dbscan = DBSCAN(
                            eps=eps,
                            min_samples=max(3, int(len(X_scaled) * 0.05))
                        )
                        models[entity]["dbscan"] = dbscan
                except Exception as e:
                    logger.warning(f"DBSCAN configuration failed for {entity}: {e}")
                
                logger.info(f"Trained models for {entity} using {len(features)} features on {len(X_scaled)} samples")
                
            except Exception as e:
                logger.error(f"Error training models for {entity}: {e}")
        
        logger.info(f"Successfully trained models for {len(models)} entities in {data_type} group")
        return models, scalers
    
    def _select_features_by_type(self, data, data_type):
        """
        Select appropriate features based on data type.
        
        Args:
            data (pd.DataFrame): Data with features
            data_type (str): Type of data
            
        Returns:
            list: Selected feature names
        """
        # Basic features for all types
        basic_features = [
            'event_count', 'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
            'is_business_hours', 'is_weekend'
        ]
        
        # Type-specific features
        type_features = {
            "process": [
                'args_count', 'command_length', 'has_suspicious_chars',
                'has_encoded_content', 'is_system_path', 'is_tmp_execution',
                'is_root_user', 'has_hash', 'env_vars_count'
            ],
            "network": [
                'destination_port', 'is_well_known_port', 'is_ephemeral_port',
                'bytes_per_packet', 'is_large_transfer', 'is_outbound'
            ],
            "user": [
                'is_sudo_command', 'is_su_command', 'is_compiler_activity',
                'is_dev_tool', 'is_root_user', 'is_service_user'
            ],
            "discovery": [
                'command_length', 'has_pipes', 'has_redirection',
                'args_count', 'is_root_discovery'
            ],
            "metadata": [
                'is_root_access', 'is_service_account', 'potential_cred_harvest',
                'user_data_access'
            ]
        }
        
        # Rolling and lag features
        rolling_features = [col for col in data.columns if 'rolling_' in col]
        lag_features = [col for col in data.columns if '_lag_' in col]
        roc_features = [col for col in data.columns if '_roc' in col]
        
        # Combine features
        all_features = (
            basic_features + 
            type_features.get(data_type, []) + 
            rolling_features + 
            lag_features + 
            roc_features
        )
        
        # Filter to existing features
        selected_features = [feat for feat in all_features if feat in data.columns]
        
        # Ensure we have at least event_count
        if not selected_features and 'event_count' in data.columns:
            selected_features = ['event_count']
        
        return selected_features
    
    def _add_basic_features(self, data):
        """
        Add basic time features if enhanced feature extraction is not available.
        
        Args:
            data (pd.DataFrame): Input data
            
        Returns:
            pd.DataFrame: Data with basic features added
        """
        feature_data = data.copy()
        
        if "@timestamp" in feature_data.columns:
            # Add time features
            feature_data["hour_of_day"] = feature_data["@timestamp"].dt.hour
            feature_data["day_of_week"] = feature_data["@timestamp"].dt.dayofweek
            feature_data["is_business_hours"] = (
                (feature_data["hour_of_day"] >= 8) & 
                (feature_data["hour_of_day"] <= 18) & 
                (feature_data["day_of_week"] <= 4)
            ).astype(int)
            feature_data["is_weekend"] = (feature_data["day_of_week"] >= 5).astype(int)
            
            # Add cyclical time features
            feature_data["hour_sin"] = np.sin(2 * np.pi * feature_data["hour_of_day"] / 24)
            feature_data["hour_cos"] = np.cos(2 * np.pi * feature_data["hour_of_day"] / 24)
            feature_data["day_sin"] = np.sin(2 * np.pi * feature_data["day_of_week"] / 7)
            feature_data["day_cos"] = np.cos(2 * np.pi * feature_data["day_of_week"] / 7)
        
        return feature_data
    
    def save_models(self, data_type="process"):
        """
        Save trained models and baselines for a specific data type.
        
        Args:
            data_type (str): Type of data (process, network, user, discovery, metadata)
        """
        if data_type not in self.models or not self.models[data_type]:
            logger.warning(f"No models to save for {data_type}")
            return
        
        models_dir = os.path.join(self.config["output"]["results_dir"], "models", data_type)
        os.makedirs(models_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save models for each entity
        for entity, entity_models in self.models[data_type].items():
            entity_dir = os.path.join(models_dir, str(entity).replace(" ", "_").replace("/", "_"))
            os.makedirs(entity_dir, exist_ok=True)
            
            for model_name, model in entity_models.items():
                if model_name != "features_used":  # Skip metadata
                    model_file = os.path.join(entity_dir, f"{model_name}_{timestamp}.joblib")
                    try:
                        joblib.dump(model, model_file)
                    except Exception as e:
                        logger.error(f"Error saving {model_name} for {entity}: {e}")
            
            # Save features metadata
            if "features_used" in entity_models:
                features_file = os.path.join(entity_dir, f"features_used_{timestamp}.joblib")
                joblib.dump(entity_models["features_used"], features_file)
        
        # Save scalers
        if data_type in self.scalers and self.scalers[data_type]:
            scalers_dir = os.path.join(models_dir, "scalers")
            os.makedirs(scalers_dir, exist_ok=True)
            
            for entity, scaler in self.scalers[data_type].items():
                scaler_file = os.path.join(scalers_dir, f"{str(entity).replace(' ', '_')}_{timestamp}.joblib")
                try:
                    joblib.dump(scaler, scaler_file)
                except Exception as e:
                    logger.error(f"Error saving scaler for {entity}: {e}")
        
        # Save baselines
        if data_type in self.baselines and self.baselines[data_type]:
            baseline_file = os.path.join(models_dir, f"baselines_{timestamp}.joblib")
            try:
                joblib.dump(self.baselines[data_type], baseline_file)
            except Exception as e:
                logger.error(f"Error saving baselines for {data_type}: {e}")
        
        logger.info(f"Models saved for {data_type} to {models_dir}")
    
    def load_models(self, data_type="process"):
        """
        Load previously trained models for a specific data type.
        
        Args:
            data_type (str): Type of data to load models for
            
        Returns:
            bool: Success status
        """
        models_dir = os.path.join(self.config["output"]["results_dir"], "models", data_type)
        
        if not os.path.exists(models_dir):
            logger.warning(f"Models directory {models_dir} does not exist")
            return False
        
        try:
            # Initialize data type dictionaries
            if data_type not in self.models:
                self.models[data_type] = {}
            if data_type not in self.scalers:
                self.scalers[data_type] = {}
            if data_type not in self.baselines:
                self.baselines[data_type] = {}
            
            # Load models for each entity
            entity_dirs = [d for d in os.listdir(models_dir) 
                          if os.path.isdir(os.path.join(models_dir, d)) and d != "scalers"]
            
            for entity_dir in entity_dirs:
                entity = entity_dir.replace("_", " ")
                entity_path = os.path.join(models_dir, entity_dir)
                
                # Load models for this entity
                model_files = [f for f in os.listdir(entity_path) if f.endswith(".joblib")]
                
                self.models[data_type][entity] = {}
                
                for model_file in model_files:
                    model_name = model_file.split("_")[0]  # Extract model name
                    model_path = os.path.join(entity_path, model_file)
                    
                    try:
                        loaded_model = joblib.load(model_path)
                        self.models[data_type][entity][model_name] = loaded_model
                    except Exception as e:
                        logger.error(f"Error loading {model_file}: {e}")
            
            # Load scalers
            scalers_dir = os.path.join(models_dir, "scalers")
            if os.path.exists(scalers_dir):
                scaler_files = [f for f in os.listdir(scalers_dir) if f.endswith(".joblib")]
                
                for scaler_file in scaler_files:
                    entity = scaler_file.split("_")[0].replace("_", " ")
                    scaler_path = os.path.join(scalers_dir, scaler_file)
                    
                    try:
                        self.scalers[data_type][entity] = joblib.load(scaler_path)
                    except Exception as e:
                        logger.error(f"Error loading scaler {scaler_file}: {e}")
            
            # Load baselines
            baseline_files = [f for f in os.listdir(models_dir) 
                             if f.startswith("baselines_") and f.endswith(".joblib")]
            
            if baseline_files:
                # Get the most recent baseline file
                latest_baseline = sorted(baseline_files)[-1]
                baseline_path = os.path.join(models_dir, latest_baseline)
                
                try:
                    self.baselines[data_type] = joblib.load(baseline_path)
                except Exception as e:
                    logger.error(f"Error loading baselines: {e}")
            
            logger.info(f"Loaded models for {len(self.models[data_type])} entities in {data_type}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading models for {data_type}: {e}")
            return False
    
    def train_all_groups(self, data_dict):
        """
        Train models for all data groups using provided data.
        
        Args:
            data_dict (dict): Dictionary with data for each group
                             {"process": df, "network": df, "user": df, "discovery": df, "metadata": df}
        """
        logger.info("Training models for all Linux anomaly detection groups")
        
        for data_type, data in data_dict.items():
            if data.empty:
                logger.warning(f"No data provided for {data_type} group")
                continue
            
            logger.info(f"Training {data_type} group models...")
            
            # Establish baselines
            baselines = self.establish_baselines(data, data_type)
            if data_type not in self.baselines:
                self.baselines[data_type] = {}
            self.baselines[data_type].update(baselines)
            
            # Train models
            models, scalers = self.train_models(data, data_type)
            if data_type not in self.models:
                self.models[data_type] = {}
            if data_type not in self.scalers:
                self.scalers[data_type] = {}
            
            self.models[data_type].update(models)
            self.scalers[data_type].update(scalers)
            
            # Save models for this group
            self.save_models(data_type)
            
            logger.info(f"Completed training for {data_type} group")
        
        logger.info("Completed training for all groups")
    
    def get_models_for_group(self, data_type):
        """
        Get models and related objects for a specific data group.
        
        Args:
            data_type (str): Type of data group
            
        Returns:
            tuple: (models, scalers, baselines)
        """
        models = self.models.get(data_type, {})
        scalers = self.scalers.get(data_type, {})
        baselines = self.baselines.get(data_type, {})
        
        return models, scalers, baselines
    
    def get_supported_jobs(self):
        """
        Get list of supported Linux anomaly detection jobs by group.
        
        Returns:
            dict: Jobs organized by data group
        """
        return self.data_groups.copy()

# Convenience functions for backward compatibility

def establish_linux_baselines(historical_data, config, data_type="process"):
    """
    Convenience function to establish baselines for Linux data.
    
    Args:
        historical_data (pd.DataFrame): Historical data
        config (dict): Configuration dictionary
        data_type (str): Type of data
        
    Returns:
        dict: Baseline statistics
    """
    manager = LinuxModelManager(config)
    return manager.establish_baselines(historical_data, data_type)

def train_linux_models(historical_data, config, data_type="process"):
    """
    Convenience function to train Linux anomaly detection models.
    
    Args:
        historical_data (pd.DataFrame): Historical data for training
        config (dict): Configuration dictionary
        data_type (str): Type of data
        
    Returns:
        tuple: (models dict, scalers dict)
    """
    manager = LinuxModelManager(config)
    return manager.train_models(historical_data, data_type)

def save_linux_models(models, scalers, baselines, config, data_type="process"):
    """
    Convenience function to save Linux models.
    
    Args:
        models (dict): Trained models
        scalers (dict): Fitted scalers
        baselines (dict): Baseline statistics
        config (dict): Configuration dictionary
        data_type (str): Type of data
    """
    manager = LinuxModelManager(config)
    manager.models[data_type] = models
    manager.scalers[data_type] = scalers
    manager.baselines[data_type] = baselines
    manager.save_models(data_type)

def load_linux_models(config, data_type="process"):
    """
    Convenience function to load Linux models.
    
    Args:
        config (dict): Configuration dictionary
        data_type (str): Type of data
        
    Returns:
        tuple: (models dict, scalers dict, baselines dict, success bool)
    """
    manager = LinuxModelManager(config)
    success = manager.load_models(data_type)
    
    if success:
        models = manager.models.get(data_type, {})
        scalers = manager.scalers.get(data_type, {})
        baselines = manager.baselines.get(data_type, {})
        return models, scalers, baselines, True
    else:
        return {}, {}, {}, False

# Advanced model management functions

def train_process_anomaly_models(historical_data, config):
    """
    Train specialized models for process anomaly detection.
    Supports: v3_linux_anomalous_process_all_hosts, v3_rare_process_by_host_linux
    
    Args:
        historical_data (pd.DataFrame): Historical process data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized process anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish baselines for both global and per-host process patterns
    baselines = {}
    
    # Global process baselines (for v3_linux_anomalous_process_all_hosts)
    global_baselines = manager.establish_baselines(historical_data, "process")
    baselines["global"] = global_baselines
    
    # Per-host process baselines (for v3_rare_process_by_host_linux)
    if "host.hostname" in historical_data.columns:
        host_baselines = {}
        for hostname in historical_data["host.hostname"].unique():
            if pd.isna(hostname) or hostname == "":
                continue
            
            host_data = historical_data[historical_data["host.hostname"] == hostname]
            if len(host_data) >= 10:
                host_process_baselines = manager.establish_baselines(host_data, "process")
                host_baselines[hostname] = host_process_baselines
        
        baselines["per_host"] = host_baselines
        logger.info(f"Established per-host baselines for {len(host_baselines)} hosts")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "process")
    
    # Save everything
    manager.baselines["process"] = baselines
    manager.models["process"] = models
    manager.scalers["process"] = scalers
    manager.save_models("process")
    
    return models, scalers, baselines

def train_network_activity_models(historical_data, config):
    """
    Train specialized models for network activity anomaly detection.
    Supports: v3_linux_anomalous_network_activity, v3_linux_anomalous_network_port_activity
    
    Args:
        historical_data (pd.DataFrame): Historical network data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized network activity anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish baselines for network patterns
    baselines = {}
    
    # Country-based baselines
    country_baselines = manager.establish_baselines(historical_data, "network")
    baselines["countries"] = country_baselines
    
    # Port-based baselines
    if "destination.port" in historical_data.columns:
        port_baselines = {}
        
        # Group by port for common ports
        port_groups = historical_data.groupby("destination.port")
        for port, port_data in port_groups:
            if len(port_data) >= 20:  # Only for ports with significant traffic
                port_stats = {
                    "mean": float(port_data["event_count"].mean()),
                    "std": float(port_data["event_count"].std()),
                    "percentiles": {
                        "p95": float(port_data["event_count"].quantile(0.95)),
                        "p99": float(port_data["event_count"].quantile(0.99))
                    }
                }
                
                # Add process associations for this port
                if "process.name" in port_data.columns:
                    process_dist = port_data["process.name"].value_counts().head(10).to_dict()
                    port_stats["common_processes"] = {str(k): int(v) for k, v in process_dist.items()}
                
                port_baselines[int(port)] = port_stats
        
        baselines["ports"] = port_baselines
        logger.info(f"Established baselines for {len(port_baselines)} network ports")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "network")
    
    # Train additional port-specific models
    if "destination.port" in historical_data.columns:
        port_models = {}
        port_scalers = {}
        
        # Train models for high-traffic ports
        common_ports = historical_data["destination.port"].value_counts().head(20)
        
        for port, count in common_ports.items():
            port_data = historical_data[historical_data["destination.port"] == port]
            
            if len(port_data) >= 50:  # Sufficient data for modeling
                try:
                    port_features = manager._select_features_by_type(port_data, "network")
                    if port_features and len(port_data) >= 10:
                        
                        X = port_data[port_features].values
                        X = np.nan_to_num(X, nan=0.0)
                        
                        # Scale data
                        scaler = RobustScaler()
                        X_scaled = scaler.fit_transform(X)
                        
                        # Train Isolation Forest for this port
                        iso_forest = IsolationForest(
                            n_estimators=100,
                            contamination=0.05,
                            random_state=42
                        )
                        iso_forest.fit(X_scaled)
                        
                        port_models[f"port_{port}"] = {
                            "isolation_forest": iso_forest,
                            "features_used": port_features
                        }
                        port_scalers[f"port_{port}"] = scaler
                        
                        logger.info(f"Trained model for port {port} with {len(port_data)} samples")
                        
                except Exception as e:
                    logger.error(f"Error training model for port {port}: {e}")
        
        models.update(port_models)
        scalers.update(port_scalers)
    
    # Save everything
    manager.baselines["network"] = baselines
    manager.models["network"] = models
    manager.scalers["network"] = scalers
    manager.save_models("network")
    
    return models, scalers, baselines

def train_user_behavior_models(historical_data, config):
    """
    Train specialized models for user behavior anomaly detection.
    Supports: v3_linux_anomalous_user_name, v3_linux_rare_sudo_user, v3_linux_rare_user_compiler
    
    Args:
        historical_data (pd.DataFrame): Historical user activity data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized user behavior anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish comprehensive user baselines
    baselines = {}
    
    # General user activity baselines
    user_baselines = manager.establish_baselines(historical_data, "user")
    baselines["users"] = user_baselines
    
    # Sudo activity baselines
    if "is_sudo_command" in historical_data.columns:
        sudo_data = historical_data[historical_data["is_sudo_command"] == True]
        if not sudo_data.empty:
            sudo_baselines = {}
            sudo_user_groups = sudo_data.groupby("user.name")
            
            for user, user_sudo_data in sudo_user_groups:
                if len(user_sudo_data) >= 5:
                    sudo_stats = {
                        "sudo_frequency": float(len(user_sudo_data)),
                        "avg_sudo_per_day": float(len(user_sudo_data) / max(1, len(user_sudo_data["@timestamp"].dt.date.unique()))),
                        "business_hours_ratio": float(user_sudo_data["is_business_hours"].mean()) if "is_business_hours" in user_sudo_data.columns else 0.0
                    }
                    
                    # Add command patterns
                    if "process.command_line" in user_sudo_data.columns:
                        command_patterns = user_sudo_data["process.command_line"].apply(
                            lambda x: x.split()[1] if len(str(x).split()) > 1 else "unknown"
                        ).value_counts().head(10).to_dict()
                        sudo_stats["common_sudo_commands"] = {str(k): int(v) for k, v in command_patterns.items()}
                    
                    sudo_baselines[user] = sudo_stats
            
            baselines["sudo_patterns"] = sudo_baselines
            logger.info(f"Established sudo baselines for {len(sudo_baselines)} users")
    
    # Compiler activity baselines
    if "is_compiler_activity" in historical_data.columns:
        compiler_data = historical_data[historical_data["is_compiler_activity"] == True]
        if not compiler_data.empty:
            compiler_baselines = {}
            compiler_user_groups = compiler_data.groupby("user.name")
            
            for user, user_compiler_data in compiler_user_groups:
                if len(user_compiler_data) >= 3:
                    compiler_stats = {
                        "compiler_frequency": float(len(user_compiler_data)),
                        "avg_compile_sessions": float(len(user_compiler_data) / max(1, len(user_compiler_data["@timestamp"].dt.date.unique()))),
                        "business_hours_ratio": float(user_compiler_data["is_business_hours"].mean()) if "is_business_hours" in user_compiler_data.columns else 0.0
                    }
                    
                    # Add compiler tool patterns
                    if "process.name" in user_compiler_data.columns:
                        tool_patterns = user_compiler_data["process.name"].value_counts().to_dict()
                        compiler_stats["compiler_tools"] = {str(k): int(v) for k, v in tool_patterns.items()}
                    
                    compiler_baselines[user] = compiler_stats
            
            baselines["compiler_patterns"] = compiler_baselines
            logger.info(f"Established compiler baselines for {len(compiler_baselines)} users")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "user")
    
    # Train specialized models for privilege escalation detection
    if "is_sudo_command" in historical_data.columns:
        sudo_models = {}
        sudo_scalers = {}
        
        # Train per-user sudo behavior models
        frequent_sudo_users = historical_data[historical_data["is_sudo_command"] == True]["user.name"].value_counts()
        
        for user, count in frequent_sudo_users.head(20).items():
            user_sudo_data = historical_data[
                (historical_data["user.name"] == user) & 
                (historical_data["is_sudo_command"] == True)
            ]
            
            if len(user_sudo_data) >= 20:
                try:
                    # Create features specific to sudo behavior
                    sudo_features = ["event_count", "hour_sin", "hour_cos", "day_sin", "day_cos"]
                    if "command_length" in user_sudo_data.columns:
                        sudo_features.append("command_length")
                    
                    sudo_features = [f for f in sudo_features if f in user_sudo_data.columns]
                    
                    if sudo_features:
                        X = user_sudo_data[sudo_features].values
                        X = np.nan_to_num(X, nan=0.0)
                        
                        scaler = RobustScaler()
                        X_scaled = scaler.fit_transform(X)
                        
                        # Train Isolation Forest for sudo behavior
                        iso_forest = IsolationForest(
                            n_estimators=50,
                            contamination=0.1,
                            random_state=42
                        )
                        iso_forest.fit(X_scaled)
                        
                        sudo_models[f"sudo_{user}"] = {
                            "isolation_forest": iso_forest,
                            "features_used": sudo_features
                        }
                        sudo_scalers[f"sudo_{user}"] = scaler
                        
                        logger.info(f"Trained sudo model for user {user}")
                        
                except Exception as e:
                    logger.error(f"Error training sudo model for user {user}: {e}")
        
        models.update(sudo_models)
        scalers.update(sudo_scalers)
    
    # Save everything
    manager.baselines["user"] = baselines
    manager.models["user"] = models
    manager.scalers["user"] = scalers
    manager.save_models("user")
    
    return models, scalers, baselines

def train_discovery_command_models(historical_data, config):
    """
    Train specialized models for discovery command anomaly detection.
    Supports all v3_linux_*_discovery detection jobs.
    
    Args:
        historical_data (pd.DataFrame): Historical discovery command data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized discovery command anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish discovery command baselines
    baselines = {}
    
    # General discovery command baselines
    discovery_baselines = manager.establish_baselines(historical_data, "discovery")
    baselines["commands"] = discovery_baselines
    
    # Category-specific baselines
    if "discovery_category" in historical_data.columns:
        category_baselines = {}
        
        for category in historical_data["discovery_category"].unique():
            if pd.isna(category) or category == "":
                continue
            
            category_data = historical_data[historical_data["discovery_category"] == category]
            if len(category_data) >= 10:
                category_stats = {
                    "frequency": float(len(category_data)),
                    "unique_users": int(category_data["user.name"].nunique()) if "user.name" in category_data.columns else 0,
                    "business_hours_ratio": float(category_data["is_business_hours"].mean()) if "is_business_hours" in category_data.columns else 0.0
                }
                
                # Add user patterns for this category
                if "user.name" in category_data.columns:
                    user_dist = category_data["user.name"].value_counts().head(10).to_dict()
                    category_stats["common_users"] = {str(k): int(v) for k, v in user_dist.items()}
                
                category_baselines[category] = category_stats
        
        baselines["categories"] = category_baselines
        logger.info(f"Established baselines for {len(category_baselines)} discovery categories")
    
    # User-command combination baselines
    if "user.name" in historical_data.columns and "process.name" in historical_data.columns:
        user_command_baselines = {}
        
        # Analyze which users typically run which discovery commands
        user_command_combinations = historical_data.groupby(["user.name", "process.name"]).size().reset_index(name="frequency")
        
        for user in historical_data["user.name"].unique():
            if pd.isna(user) or user == "":
                continue
            
            user_commands = user_command_combinations[user_command_combinations["user.name"] == user]
            if len(user_commands) >= 3:
                command_patterns = user_commands.set_index("process.name")["frequency"].to_dict()
                user_command_baselines[user] = {
                    "command_patterns": {str(k): int(v) for k, v in command_patterns.items()},
                    "total_discovery_commands": int(user_commands["frequency"].sum()),
                    "unique_commands": int(len(user_commands))
                }
        
        baselines["user_command_patterns"] = user_command_baselines
        logger.info(f"Established user-command baselines for {len(user_command_baselines)} users")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "discovery")
    
    # Train category-specific models
    if "discovery_category" in historical_data.columns:
        category_models = {}
        category_scalers = {}
        
        for category in historical_data["discovery_category"].unique():
            if pd.isna(category) or category == "":
                continue
            
            category_data = historical_data[historical_data["discovery_category"] == category]
            
            if len(category_data) >= 30:
                try:
                    category_features = manager._select_features_by_type(category_data, "discovery")
                    
                    if category_features:
                        X = category_data[category_features].values
                        X = np.nan_to_num(X, nan=0.0)
                        
                        scaler = RobustScaler()
                        X_scaled = scaler.fit_transform(X)
                        
                        # Train Isolation Forest for this category
                        iso_forest = IsolationForest(
                            n_estimators=100,
                            contamination=0.1,
                            random_state=42
                        )
                        iso_forest.fit(X_scaled)
                        
                        category_models[f"category_{category}"] = {
                            "isolation_forest": iso_forest,
                            "features_used": category_features
                        }
                        category_scalers[f"category_{category}"] = scaler
                        
                        logger.info(f"Trained model for discovery category: {category}")
                        
                except Exception as e:
                    logger.error(f"Error training model for category {category}: {e}")
        
        models.update(category_models)
        scalers.update(category_scalers)
    
    # Save everything
    manager.baselines["discovery"] = baselines
    manager.models["discovery"] = models
    manager.scalers["discovery"] = scalers
    manager.save_models("discovery")
    
    return models, scalers, baselines

def train_metadata_access_models(historical_data, config):
    """
    Train specialized models for metadata access anomaly detection.
    Supports: v3_linux_rare_metadata_process, v3_linux_rare_metadata_user
    
    Args:
        historical_data (pd.DataFrame): Historical metadata access data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized metadata access anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish metadata access baselines
    baselines = {}
    
    # General metadata access baselines
    metadata_baselines = manager.establish_baselines(historical_data, "metadata")
    baselines["general"] = metadata_baselines
    
    # Process-specific metadata access patterns
    if "process.name" in historical_data.columns:
        process_baselines = {}
        
        process_groups = historical_data.groupby("process.name")
        for process, process_data in process_groups:
            if len(process_data) >= 5:
                process_stats = {
                    "access_frequency": float(len(process_data)),
                    "unique_users": int(process_data["user.name"].nunique()) if "user.name" in process_data.columns else 0,
                    "business_hours_ratio": float(process_data["is_business_hours"].mean()) if "is_business_hours" in process_data.columns else 0.0
                }
                
                # Add service type patterns
                if "metadata_service_type" in process_data.columns:
                    service_dist = process_data["metadata_service_type"].value_counts().to_dict()
                    process_stats["service_types"] = {str(k): int(v) for k, v in service_dist.items()}
                
                process_baselines[process] = process_stats
        
        baselines["processes"] = process_baselines
        logger.info(f"Established metadata access baselines for {len(process_baselines)} processes")
    
    # User-specific metadata access patterns
    if "user.name" in historical_data.columns:
        user_baselines = {}
        
        user_groups = historical_data.groupby("user.name")
        for user, user_data in user_groups:
            if len(user_data) >= 3:
                user_stats = {
                    "access_frequency": float(len(user_data)),
                    "avg_daily_access": float(len(user_data) / max(1, len(user_data["@timestamp"].dt.date.unique()))),
                    "business_hours_ratio": float(user_data["is_business_hours"].mean()) if "is_business_hours" in user_data.columns else 0.0
                }
                
                # Add credential harvesting indicators
                if "potential_cred_harvest" in user_data.columns:
                    user_stats["cred_harvest_ratio"] = float(user_data["potential_cred_harvest"].mean())
                
                user_baselines[user] = user_stats
        
        baselines["users"] = user_baselines
        logger.info(f"Established metadata access baselines for {len(user_baselines)} users")
    
    # Cloud service type baselines
    if "metadata_service_type" in historical_data.columns:
        service_baselines = {}
        
        for service_type in historical_data["metadata_service_type"].unique():
            if pd.isna(service_type) or service_type == "":
                continue
            
            service_data = historical_data[historical_data["metadata_service_type"] == service_type]
            if len(service_data) >= 5:
                service_stats = {
                    "access_frequency": float(len(service_data)),
                    "unique_processes": int(service_data["process.name"].nunique()) if "process.name" in service_data.columns else 0,
                    "unique_users": int(service_data["user.name"].nunique()) if "user.name" in service_data.columns else 0
                }
                
                service_baselines[service_type] = service_stats
        
        baselines["service_types"] = service_baselines
        logger.info(f"Established baselines for {len(service_baselines)} metadata service types")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "metadata")
    
    # Train high-risk behavior models (credential harvesting)
    if "potential_cred_harvest" in historical_data.columns:
        cred_harvest_data = historical_data[historical_data["potential_cred_harvest"] == 1]
        
        if len(cred_harvest_data) >= 10:
            try:
                cred_features = manager._select_features_by_type(cred_harvest_data, "metadata")
                
                if cred_features:
                    X = cred_harvest_data[cred_features].values
                    X = np.nan_to_num(X, nan=0.0)
                    
                    scaler = RobustScaler()
                    X_scaled = scaler.fit_transform(X)
                    
                    # Train model specifically for credential harvesting patterns
                    iso_forest = IsolationForest(
                        n_estimators=100,
                        contamination=0.2,  # Higher contamination for this high-risk activity
                        random_state=42
                    )
                    iso_forest.fit(X_scaled)
                    
                    models["credential_harvesting"] = {
                        "isolation_forest": iso_forest,
                        "features_used": cred_features
                    }
                    scalers["credential_harvesting"] = scaler
                    
                    logger.info("Trained specialized credential harvesting detection model")
                    
            except Exception as e:
                logger.error(f"Error training credential harvesting model: {e}")
    
    # Save everything
    manager.baselines["metadata"] = baselines
    manager.models["metadata"] = models
    manager.scalers["metadata"] = scalers
    manager.save_models("metadata")
    
    return models, scalers, baselines