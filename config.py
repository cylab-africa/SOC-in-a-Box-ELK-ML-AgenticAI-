# config.py - Configuration loader for Linux Anomaly Detection System

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger("linux_anomaly_detection")

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load configuration from file or environment variables.
    
    Args:
        config_path (str, optional): Path to configuration file
        
    Returns:
        dict: Complete configuration dictionary
    """
    # Default configuration
    default_config = {
        "dagshub": {
            "repo_name": "Anomaly-Detection-ML--SOC",
            "username": "masterlion-hash", 
            "token": "***REMOVED_DAGSHUB_TOKEN***"
        },
        "elasticsearch": {
            "host": "https://***REMOVED_INTERNAL_IP***:9200",
            "username": "***REMOVED_EMAIL***",
            "password": "***REMOVED_PASSWORD***",
            "verify_certs": False,
            "ssl_show_warn": False,
            "timeout": 60,
            "scroll_size": 5000,
            "scroll_timeout": "2m",
            "indices": {
                "process": "logs-endpoint.events.process-*",
                "network": "logs-endpoint.events.network-*,logs-suricata.eve-*",
                "user": "logs-endpoint.events.process-*,logs-system.auth-*",
                "discovery": "logs-endpoint.events.process-*",
                "metadata": "logs-endpoint.events.process-*,logs-endpoint.events.network-*",
                "alerts": ".internal.alerts-security.alerts-default-*"
            }
        },
        "detection": {
            "time_window": 24,
            "threshold_multiplier": 3.0,
            "min_baseline_period_days": 30,
            "aggregation_interval": "15min",
            "bucket_span": "15m",
            "anomaly_methods": ["statistical", "isolation_forest", "lof", "ocsvm", "pca"],
            "sensitivity": 0.7,
            "data_groups": {
                "process": {
                    "enabled": True,
                    "bucket_span": "15m",
                    "threshold_multiplier": 3.0,
                    "rare_process_threshold": 0.1,
                    "rare_process_host_threshold": 0.05
                },
                "network": {
                    "enabled": True,
                    "bucket_span": "15m", 
                    "threshold_multiplier": 2.5,
                    "rare_country_threshold": 0.1,
                    "spike_threshold": 3.0
                },
                "user": {
                    "enabled": True,
                    "bucket_span": "30m",
                    "threshold_multiplier": 2.0,
                    "rare_user_threshold": 0.5,
                    "rare_sudo_threshold": 1.0,
                    "rare_compiler_threshold": 2.0
                },
                "discovery": {
                    "enabled": True,
                    "bucket_span": "60m",
                    "threshold_multiplier": 2.0,
                    "discovery_threshold": 5.0
                },
                "metadata": {
                    "enabled": True,
                    "bucket_span": "15m",
                    "threshold_multiplier": 1.5,
                    "rare_metadata_process_threshold": 1.0,
                    "rare_metadata_user_threshold": 2.0
                }
            }
        },
        "ml": {
            "feature_selection": "enhanced",
            "contamination": 0.05,
            "n_estimators": 100,
            "lof_neighbors": 20,
            "svm_kernel": "rbf",
            "pca_components": 0.95,
            "isolation_forest": {
                "n_estimators": 100,
                "contamination": 0.05,
                "random_state": 42,
                "n_jobs": -1
            },
            "lof": {
                "n_neighbors": 20,
                "contamination": 0.05,
                "novelty": True
            },
            "ocsvm": {
                "nu": 0.05,
                "kernel": "rbf",
                "gamma": "scale"
            },
            "dbscan": {
                "eps": 0.5,
                "min_samples": 5
            },
            "pca": {
                "n_components": 0.95
            }
        },
        "output": {
            "save_results": True,
            "visualization": True,
            "generate_reports": True,
            "results_dir": "./results",
            "models_dir": "./results/models",
            "reports_dir": "./results/reports",
            "visualizations_dir": "./results/visualizations"
        },
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            "file": "./logs/linux_anomaly_detection.log"
        }
    }
    
    config = default_config.copy()
    
    # Load from file if specified
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                    file_config = yaml.safe_load(f)
                else:
                    file_config = json.load(f)
            
            # Deep merge file config
            config = deep_merge(config, file_config)
            logger.info(f"Loaded configuration from {config_path}")
            
        except Exception as e:
            logger.warning(f"Error loading config file {config_path}: {e}")
            logger.info("Using default configuration")
    
    # Override with environment variables
    config = load_env_overrides(config)
    
    # Validate and create directories
    validate_config(config)
    
    return config

def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.
    
    Args:
        base (dict): Base dictionary
        override (dict): Override dictionary
        
    Returns:
        dict: Merged dictionary
    """
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result

def load_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Override configuration with environment variables.
    
    Args:
        config (dict): Base configuration
        
    Returns:
        dict: Configuration with environment overrides
    """
    # DAGsHub configuration
    if os.getenv("DAGSHUB_REPO_NAME"):
        config["dagshub"]["repo_name"] = os.getenv("DAGSHUB_REPO_NAME")
    if os.getenv("DAGSHUB_USERNAME"):
        config["dagshub"]["username"] = os.getenv("DAGSHUB_USERNAME")
    if os.getenv("DAGSHUB_TOKEN"):
        config["dagshub"]["token"] = os.getenv("DAGSHUB_TOKEN")
    
    # Elasticsearch configuration
    if os.getenv("ES_HOST"):
        config["elasticsearch"]["host"] = os.getenv("ES_HOST")
    if os.getenv("ES_USERNAME"):
        config["elasticsearch"]["username"] = os.getenv("ES_USERNAME")
    if os.getenv("ES_PASSWORD"):
        config["elasticsearch"]["password"] = os.getenv("ES_PASSWORD")
    if os.getenv("ES_SCROLL_SIZE"):
        config["elasticsearch"]["scroll_size"] = int(os.getenv("ES_SCROLL_SIZE"))
    if os.getenv("ES_SCROLL_TIMEOUT"):
        config["elasticsearch"]["scroll_timeout"] = os.getenv("ES_SCROLL_TIMEOUT")
    
    # Index overrides for different data types
    if os.getenv("ES_PROCESS_INDEX"):
        config["elasticsearch"]["indices"]["process"] = os.getenv("ES_PROCESS_INDEX")
    if os.getenv("ES_NETWORK_INDEX"):
        config["elasticsearch"]["indices"]["network"] = os.getenv("ES_NETWORK_INDEX")
    if os.getenv("ES_USER_INDEX"):
        config["elasticsearch"]["indices"]["user"] = os.getenv("ES_USER_INDEX")
    if os.getenv("ES_DISCOVERY_INDEX"):
        config["elasticsearch"]["indices"]["discovery"] = os.getenv("ES_DISCOVERY_INDEX")
    if os.getenv("ES_METADATA_INDEX"):
        config["elasticsearch"]["indices"]["metadata"] = os.getenv("ES_METADATA_INDEX")
    
    # Detection configuration
    if os.getenv("TIME_WINDOW"):
        config["detection"]["time_window"] = int(os.getenv("TIME_WINDOW"))
    if os.getenv("THRESHOLD_MULTIPLIER"):
        config["detection"]["threshold_multiplier"] = float(os.getenv("THRESHOLD_MULTIPLIER"))
    if os.getenv("MIN_BASELINE_PERIOD"):
        config["detection"]["min_baseline_period_days"] = int(os.getenv("MIN_BASELINE_PERIOD"))
    if os.getenv("AGGREGATION_INTERVAL"):
        config["detection"]["aggregation_interval"] = os.getenv("AGGREGATION_INTERVAL")
    if os.getenv("BUCKET_SPAN"):
        config["detection"]["bucket_span"] = os.getenv("BUCKET_SPAN")
    if os.getenv("ANOMALY_METHODS"):
        methods = os.getenv("ANOMALY_METHODS").split(",")
        config["detection"]["anomaly_methods"] = [m.strip() for m in methods]
    if os.getenv("SENSITIVITY"):
        config["detection"]["sensitivity"] = float(os.getenv("SENSITIVITY"))
    
    # ML configuration
    if os.getenv("ML_CONTAMINATION"):
        config["ml"]["contamination"] = float(os.getenv("ML_CONTAMINATION"))
    if os.getenv("ML_N_ESTIMATORS"):
        config["ml"]["n_estimators"] = int(os.getenv("ML_N_ESTIMATORS"))
    if os.getenv("ML_FEATURE_SELECTION"):
        config["ml"]["feature_selection"] = os.getenv("ML_FEATURE_SELECTION")
    
    # Output configuration
    if os.getenv("SAVE_RESULTS"):
        config["output"]["save_results"] = os.getenv("SAVE_RESULTS").lower() == "true"
    if os.getenv("VISUALIZATION"):
        config["output"]["visualization"] = os.getenv("VISUALIZATION").lower() == "true"
    if os.getenv("RESULTS_DIR"):
        config["output"]["results_dir"] = os.getenv("RESULTS_DIR")
    
    # Logging configuration
    if os.getenv("LOG_LEVEL"):
        config["logging"]["level"] = os.getenv("LOG_LEVEL")
    if os.getenv("LOG_FILE"):
        config["logging"]["file"] = os.getenv("LOG_FILE")
    
    return config

def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate configuration and create necessary directories.
    
    Args:
        config (dict): Configuration to validate
    """
    # Create output directories
    for dir_key in ["results_dir", "models_dir", "reports_dir", "visualizations_dir"]:
        if dir_key in config["output"]:
            dir_path = config["output"][dir_key]
            Path(dir_path).mkdir(parents=True, exist_ok=True)
    
    # Create logs directory
    if "file" in config["logging"]:
        log_file = config["logging"]["file"]
        log_dir = os.path.dirname(log_file)
        if log_dir:
            Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Validate required fields
    required_fields = [
        ("elasticsearch", "host"),
        ("elasticsearch", "username"), 
        ("elasticsearch", "password"),
        ("detection", "sensitivity"),
        ("output", "results_dir")
    ]
    
    for section, field in required_fields:
        if section not in config or field not in config[section]:
            raise ValueError(f"Missing required configuration: {section}.{field}")
    
    # Validate sensitivity range
    sensitivity = config["detection"]["sensitivity"]
    if not 0 <= sensitivity <= 1:
        raise ValueError(f"Sensitivity must be between 0 and 1, got {sensitivity}")
    
    # Validate ML contamination
    contamination = config["ml"]["contamination"]
    if not 0 < contamination <= 0.5:
        raise ValueError(f"ML contamination must be between 0 and 0.5, got {contamination}")

def get_elasticsearch_index(config: Dict[str, Any], data_type: str) -> str:
    """
    Get the appropriate Elasticsearch index for a data type.
    
    Args:
        config (dict): Configuration dictionary
        data_type (str): Type of data (process, network, user, discovery, metadata)
        
    Returns:
        str: Elasticsearch index pattern
    """
    indices = config.get("elasticsearch", {}).get("indices", {})
    return indices.get(data_type, "logs-endpoint.events.*-*")

def get_data_group_config(config: Dict[str, Any], data_type: str) -> Dict[str, Any]:
    """
    Get configuration specific to a data group.
    
    Args:
        config (dict): Configuration dictionary
        data_type (str): Type of data group
        
    Returns:
        dict: Data group specific configuration
    """
    data_groups = config.get("detection", {}).get("data_groups", {})
    return data_groups.get(data_type, {})

def is_data_group_enabled(config: Dict[str, Any], data_type: str) -> bool:
    """
    Check if a data group is enabled.
    
    Args:
        config (dict): Configuration dictionary
        data_type (str): Type of data group
        
    Returns:
        bool: True if enabled
    """
    group_config = get_data_group_config(config, data_type)
    return group_config.get("enabled", True)