# """
# Enhanced Configuration Manager for Linux Anomaly Detection System
# Handles all configuration loading, validation, and environment setup
# """

# import os
# import logging
# from typing import Dict, Any, List, Optional, Union, Tuple
# from dataclasses import dataclass, field
# from pathlib import Path
# import json
# from dotenv import load_dotenv
# from datetime import datetime, timedelta


# @dataclass
# class DagshubConfig:
#     """DagsHub MLflow configuration"""
#     repo_name: str = ""
#     username: str = ""
#     token: str = ""

#     @property
#     def mlflow_uri(self) -> str:
#         return f"https://dagshub.com/{self.username}/{self.repo_name}.mlflow"


# @dataclass
# class ElasticsearchConfig:
#     """Elasticsearch configuration"""
#     host: str = "https://localhost:9200"
#     username: str = ""
#     password: str = ""

#     # Index patterns
#     process_index: str = ".ds-logs-endpoint.events.process-default-*"
#     network_index: str = ".ds-logs-endpoint.events.network-default-*"
#     discovery_index: str = "logs-endpoint.events.process-*"
#     metadata_index: str = "logs-endpoint.events.process-*,logs-endpoint.events.network-*"
#     alerts_index: str = ".internal.alerts-security.alerts-default-*"

#     # Performance settings
#     scroll_size: int = 5000
#     scroll_timeout: str = "2m"
#     timeout: int = 60


# @dataclass
# class DetectionConfig:
#     """Anomaly detection configuration"""
#     time_window: int = 24
#     threshold_multiplier: float = 3.0
#     min_baseline_period: int = 30
#     aggregation_interval: str = "15min"
#     bucket_span: str = "15m"
#     sensitivity: float = 0.3

#     # Anomaly detection methods
#     anomaly_methods: List[str] = field(default_factory=lambda: ["statistical", "isolation_forest", "lof"])

#     # Thresholds for different data groups
#     rare_process_threshold: float = 0.1
#     rare_process_host_threshold: float = 0.05
#     rare_user_threshold: float = 0.5
#     rare_sudo_threshold: float = 1.0
#     rare_compiler_threshold: float = 2.0
#     discovery_threshold: float = 5.0
#     rare_metadata_process_threshold: float = 1.0
#     rare_metadata_user_threshold: float = 2.0


# @dataclass
# class MLConfig:
#     """Machine Learning configuration"""
#     feature_selection: str = "enhanced"
#     contamination: float = 0.05
#     n_estimators: int = 100
#     lof_neighbors: int = 20
#     svm_kernel: str = "rbf"
#     pca_components: float = 0.95


# @dataclass
# class OutputConfig:
#     """Output configuration"""
#     save_results: bool = True
#     visualization: bool = True
#     generate_reports: bool = True
#     save_models: bool = True

#     # Directory structure
#     results_dir: str = "./results"
#     models_dir: str = "./results/models"
#     reports_dir: str = "./results/reports"
#     visualizations_dir: str = "./results/visualizations"
#     logs_dir: str = "./logs"


# @dataclass
# class LoggingConfig:
#     """Logging configuration"""
#     log_level: str = "INFO"
#     log_file: str = "./logs/linux_anomaly_detection.log"
#     console_output: bool = True


# @dataclass
# class PerformanceConfig:
#     """Performance configuration"""
#     max_workers: int = 4
#     chunk_size: int = 1000
#     memory_limit: str = "4GB"
#     enable_parallel_processing: bool = True
#     cache_enabled: bool = True


# @dataclass
# class AlertConfig:
#     """Alert configuration"""
#     alerts_enabled: bool = False
#     critical_threshold: float = 0.9
#     high_threshold: float = 0.7
#     medium_threshold: float = 0.5
#     low_threshold: float = 0.2

#     # Email settings
#     email_enabled: bool = False
#     smtp_server: str = ""
#     smtp_port: int = 587
#     email_username: str = ""
#     email_password: str = ""
#     email_recipients: List[str] = field(default_factory=list)

#     # Slack settings
#     slack_enabled: bool = False
#     slack_webhook_url: str = ""
#     slack_channel: str = "#security-alerts"


# @dataclass
# class SchedulerConfig:
#     """Job scheduler configuration"""
#     scheduler_enabled: bool = False
#     scheduler_timezone: str = "UTC"


# @dataclass
# class DataQualityConfig:
#     """Data quality settings"""
#     min_event_threshold: int = 10
#     max_anomaly_rate: float = 0.4
#     outlier_removal: bool = True
#     null_value_handling: str = "fill_zero"


# @dataclass
# class TrainingConfig:
#     """Training configuration"""
#     auto_retrain: bool = True
#     retrain_interval_days: int = 7
#     min_training_samples: int = 1000
#     validation_split: float = 0.2

#     # Training data period configuration

#     training_period_days: int = 30  # How many days of historical data to use for training
#     baseline_query_size: int = 500000  # Default query size for baseline data
#     training_start_offset_days: int = 1  # Days to skip from current time (exclude recent data)
#     training_end_offset_days: int = 0  # Additional days to exclude from end

#     # Specific time periods for different data types
#     process_training_period_days: int = 30
#     network_training_period_days: int = 14
#     discovery_training_period_days: int = 60  # Longer for rare events
#     metadata_training_period_days: int = 21
#     alerts_training_period_days: int = 90

#     # Time-based training filters
#     include_weekends: bool = True
#     include_business_hours_only: bool = False
#     business_hours_start: int = 8
#     business_hours_end: int = 18
#     exclude_holidays: bool = False

#     # Rolling training window configuration
#     use_rolling_window: bool = False
#     rolling_window_size_days: int = 30
#     rolling_window_step_days: int = 7

#     # Seasonal training adjustments
#     seasonal_adjustment: bool = False
#     seasonal_period_days: int = 7  # Weekly seasonality
#     include_multiple_seasons: bool = True
#     num_seasons_to_include: int = 4

#     # Training data quality filters
#     min_events_per_day: int = 10
#     max_gap_days: int = 3  # Maximum allowed gap in training data
#     exclude_anomalous_training_days: bool = True
#     anomalous_day_threshold: float = 0.1  # Days with >10% anomalies excluded

#     # Custom training periods (ISO format dates)
#     custom_training_start: Optional[str] = None  # "2024-01-01T00:00:00Z"
#     custom_training_end: Optional[str] = None    # "2024-12-31T23:59:59Z"
#     use_custom_period: bool = False


# @dataclass
# class FeatureEngineeringConfig:
#     """Feature engineering configuration"""
#     time_features_enabled: bool = True
#     include_cyclical_features: bool = True
#     business_hours_start: int = 8
#     business_hours_end: int = 18
#     rolling_features_enabled: bool = True
#     lag_features_enabled: bool = True
#     pattern_features_enabled: bool = True


# @dataclass
# class DebugConfig:
#     """Development and debug settings"""
#     debug_mode: bool = False
#     verbose_logging: bool = False
#     profile_performance: bool = False
#     enable_testing_mode: bool = False


# class ConfigManager:
#     """Enhanced Configuration Manager"""

#     def __init__(self, env_file: str = ".env"):
#         """Initialize configuration manager"""
#         self.env_file = env_file
#         self.load_environment()
#         self.config = self._build_config()
#         self._setup_directories()
#         self._setup_logging()

#     def load_environment(self):
#         """Load environment variables from .env file"""
#         if os.path.exists(self.env_file):
#             load_dotenv(self.env_file)
#             # print(f"Loaded environment from {self.env_file}")
#         else:
#             print(f"Warning: {self.env_file} not found, using default values")

#     def _get_env(self, key: str, default: Any = None, cast_type: type = str) -> Any:
#         """Get environment variable with type casting"""
#         value = os.getenv(key, default)

#         if value is None:
#             return default

#         if cast_type == bool:
#             return str(value).lower() in ('true', '1', 'yes', 'on')
#         elif cast_type == list:
#             return [item.strip() for item in str(value).split(',') if item.strip()]
#         elif cast_type in (int, float):
#             try:
#                 return cast_type(value)
#             except (ValueError, TypeError):
#                 return default
#         else:
#             return cast_type(value)

#     def _build_config(self) -> Dict[str, Any]:
#         """Build complete configuration from environment variables"""
#         return {
#             'dagshub': DagshubConfig(
#                 repo_name=self._get_env('DAGSHUB_REPO_NAME'),
#                 username=self._get_env('DAGSHUB_USERNAME'),
#                 token=self._get_env('DAGSHUB_TOKEN')
#             ),

#             'elasticsearch': ElasticsearchConfig(
#                 host=self._get_env('ES_HOST'),
#                 username=self._get_env('ES_USERNAME'),
#                 password=self._get_env('ES_PASSWORD'),
#                 process_index=self._get_env('ES_PROCESS_INDEX'),
#                 network_index=self._get_env('ES_NETWORK_INDEX'),
#                 discovery_index=self._get_env('ES_DISCOVERY_INDEX'),
#                 metadata_index=self._get_env('ES_METADATA_INDEX'),
#                 alerts_index=self._get_env('ES_ALERTS_INDEX'),
#                 scroll_size=self._get_env('ES_SCROLL_SIZE', 5000, int),
#                 scroll_timeout=self._get_env('ES_SCROLL_TIMEOUT', '2m'),
#                 timeout=self._get_env('ES_TIMEOUT', 60, int)
#             ),

#             'detection': DetectionConfig(
#                 time_window=self._get_env('TIME_WINDOW', 24, int),
#                 threshold_multiplier=self._get_env('THRESHOLD_MULTIPLIER', 3.0, float),
#                 min_baseline_period=self._get_env('MIN_BASELINE_PERIOD', 30, int),
#                 aggregation_interval=self._get_env('AGGREGATION_INTERVAL', '15min'),
#                 bucket_span=self._get_env('BUCKET_SPAN', '15m'),
#                 sensitivity=self._get_env('SENSITIVITY', 0.3, float),
#                 anomaly_methods=self._get_env('ANOMALY_METHODS',
#                                             ['statistical', 'isolation_forest', 'lof'], list),
#                 rare_process_threshold=self._get_env('RARE_PROCESS_THRESHOLD', 0.1, float),
#                 rare_process_host_threshold=self._get_env('RARE_PROCESS_HOST_THRESHOLD', 0.05, float),
#                 rare_user_threshold=self._get_env('RARE_USER_THRESHOLD', 0.5, float),
#                 rare_sudo_threshold=self._get_env('RARE_SUDO_THRESHOLD', 1.0, float),
#                 rare_compiler_threshold=self._get_env('RARE_COMPILER_THRESHOLD', 2.0, float),
#                 discovery_threshold=self._get_env('DISCOVERY_THRESHOLD', 5.0, float),
#                 rare_metadata_process_threshold=self._get_env('RARE_METADATA_PROCESS_THRESHOLD', 1.0, float),
#                 rare_metadata_user_threshold=self._get_env('RARE_METADATA_USER_THRESHOLD', 2.0, float)
#             ),

#             'ml': MLConfig(
#                 feature_selection=self._get_env('ML_FEATURE_SELECTION', 'enhanced'),
#                 contamination=self._get_env('ML_CONTAMINATION', 0.05, float),
#                 n_estimators=self._get_env('ML_N_ESTIMATORS', 100, int),
#                 lof_neighbors=self._get_env('ML_LOF_NEIGHBORS', 20, int),
#                 svm_kernel=self._get_env('ML_SVM_KERNEL', 'rbf'),
#                 pca_components=self._get_env('ML_PCA_COMPONENTS', 0.95, float)
#             ),

#             'output': OutputConfig(
#                 save_results=self._get_env('SAVE_RESULTS', True, bool),
#                 visualization=self._get_env('VISUALIZATION', True, bool),
#                 generate_reports=self._get_env('GENERATE_REPORTS', True, bool),
#                 save_models=self._get_env('SAVE_MODELS', True, bool),
#                 results_dir=self._get_env('RESULTS_DIR', './results'),
#                 models_dir=self._get_env('MODELS_DIR', './results/models'),
#                 reports_dir=self._get_env('REPORTS_DIR', './results/reports'),
#                 visualizations_dir=self._get_env('VISUALIZATIONS_DIR', './results/visualizations'),
#                 logs_dir=self._get_env('LOGS_DIR', './logs')
#             ),

#             'logging': LoggingConfig(
#                 log_level=self._get_env('LOG_LEVEL', 'INFO'),
#                 log_file=self._get_env('LOG_FILE', './logs/linux_anomaly_detection.log'),
#                 console_output=self._get_env('CONSOLE_OUTPUT', True, bool)
#             ),

#             'performance': PerformanceConfig(
#                 max_workers=self._get_env('MAX_WORKERS', 4, int),
#                 chunk_size=self._get_env('CHUNK_SIZE', 1000, int),
#                 memory_limit=self._get_env('MEMORY_LIMIT', '4GB'),
#                 enable_parallel_processing=self._get_env('ENABLE_PARALLEL_PROCESSING', True, bool),
#                 cache_enabled=self._get_env('CACHE_ENABLED', True, bool)
#             ),

#             'alerts': AlertConfig(
#                 alerts_enabled=self._get_env('ALERTS_ENABLED', False, bool),
#                 critical_threshold=self._get_env('CRITICAL_THRESHOLD', 0.9, float),
#                 high_threshold=self._get_env('HIGH_THRESHOLD', 0.7, float),
#                 medium_threshold=self._get_env('MEDIUM_THRESHOLD', 0.5, float),
#                 low_threshold=self._get_env('LOW_THRESHOLD', 0.2, float),
#                 email_enabled=self._get_env('EMAIL_ENABLED', False, bool),
#                 smtp_server=self._get_env('SMTP_SERVER', ''),
#                 smtp_port=self._get_env('SMTP_PORT', 587, int),
#                 email_username=self._get_env('EMAIL_USERNAME', ''),
#                 email_password=self._get_env('EMAIL_PASSWORD', ''),
#                 email_recipients=self._get_env('EMAIL_RECIPIENTS', [], list),
#                 slack_enabled=self._get_env('SLACK_ENABLED', False, bool),
#                 slack_webhook_url=self._get_env('SLACK_WEBHOOK_URL', ''),
#                 slack_channel=self._get_env('SLACK_CHANNEL', '#security-alerts')
#             ),

#             'scheduler': SchedulerConfig(
#                 scheduler_enabled=self._get_env('SCHEDULER_ENABLED', False, bool),
#                 scheduler_timezone=self._get_env('SCHEDULER_TIMEZONE', 'UTC')
#             ),

#             'data_quality': DataQualityConfig(
#                 min_event_threshold=self._get_env('MIN_EVENT_THRESHOLD', 10, int),
#                 max_anomaly_rate=self._get_env('MAX_ANOMALY_RATE', 0.4, float),
#                 outlier_removal=self._get_env('OUTLIER_REMOVAL', True, bool),
#                 null_value_handling=self._get_env('NULL_VALUE_HANDLING', 'fill_zero')
#             ),

#             'training': TrainingConfig(
#                 auto_retrain=self._get_env('AUTO_RETRAIN', True, bool),
#                 retrain_interval_days=self._get_env('RETRAIN_INTERVAL_DAYS', 7, int),
#                 min_training_samples=self._get_env('MIN_TRAINING_SAMPLES', 1000, int),
#                 validation_split=self._get_env('VALIDATION_SPLIT', 0.2, float),

#                 # Training period configuration
#                 training_period_days=self._get_env('TRAINING_PERIOD_DAYS', 30, int),
#                 baseline_query_size=self._get_env('BASELINE_QUERY_SIZE', 40000, int),
#                 training_start_offset_days=self._get_env('TRAINING_START_OFFSET_DAYS', 1, int),
#                 training_end_offset_days=self._get_env('TRAINING_END_OFFSET_DAYS', 0, int),

#                 # Data type specific periods
#                 process_training_period_days=self._get_env('PROCESS_TRAINING_PERIOD_DAYS', 30, int),
#                 network_training_period_days=self._get_env('NETWORK_TRAINING_PERIOD_DAYS', 14, int),
#                 discovery_training_period_days=self._get_env('DISCOVERY_TRAINING_PERIOD_DAYS', 60, int),
#                 metadata_training_period_days=self._get_env('METADATA_TRAINING_PERIOD_DAYS', 21, int),
#                 alerts_training_period_days=self._get_env('ALERTS_TRAINING_PERIOD_DAYS', 90, int),

#                 # Time filters
#                 include_weekends=self._get_env('TRAINING_INCLUDE_WEEKENDS', True, bool),
#                 include_business_hours_only=self._get_env('TRAINING_BUSINESS_HOURS_ONLY', False, bool),
#                 business_hours_start=self._get_env('TRAINING_BUSINESS_HOURS_START', 8, int),
#                 business_hours_end=self._get_env('TRAINING_BUSINESS_HOURS_END', 18, int),
#                 exclude_holidays=self._get_env('TRAINING_EXCLUDE_HOLIDAYS', False, bool),

#                 # Rolling window
#                 use_rolling_window=self._get_env('USE_ROLLING_TRAINING_WINDOW', False, bool),
#                 rolling_window_size_days=self._get_env('ROLLING_WINDOW_SIZE_DAYS', 30, int),
#                 rolling_window_step_days=self._get_env('ROLLING_WINDOW_STEP_DAYS', 7, int),

#                 # Seasonal adjustments
#                 seasonal_adjustment=self._get_env('TRAINING_SEASONAL_ADJUSTMENT', False, bool),
#                 seasonal_period_days=self._get_env('SEASONAL_PERIOD_DAYS', 7, int),
#                 include_multiple_seasons=self._get_env('INCLUDE_MULTIPLE_SEASONS', True, bool),
#                 num_seasons_to_include=self._get_env('NUM_SEASONS_TO_INCLUDE', 4, int),

#                 # Data quality filters
#                 min_events_per_day=self._get_env('MIN_EVENTS_PER_DAY', 10, int),
#                 max_gap_days=self._get_env('MAX_GAP_DAYS', 3, int),
#                 exclude_anomalous_training_days=self._get_env('EXCLUDE_ANOMALOUS_TRAINING_DAYS', True, bool),
#                 anomalous_day_threshold=self._get_env('ANOMALOUS_DAY_THRESHOLD', 0.1, float),

#                 # Custom periods
#                 custom_training_start=self._get_env('CUSTOM_TRAINING_START'),
#                 custom_training_end=self._get_env('CUSTOM_TRAINING_END'),
#                 use_custom_period=self._get_env('USE_CUSTOM_TRAINING_PERIOD', False, bool)
#             ),

#             'feature_engineering': FeatureEngineeringConfig(
#                 time_features_enabled=self._get_env('TIME_FEATURES_ENABLED', True, bool),
#                 include_cyclical_features=self._get_env('INCLUDE_CYCLICAL_FEATURES', True, bool),
#                 business_hours_start=self._get_env('BUSINESS_HOURS_START', 8, int),
#                 business_hours_end=self._get_env('BUSINESS_HOURS_END', 18, int),
#                 rolling_features_enabled=self._get_env('ROLLING_FEATURES_ENABLED', True, bool),
#                 lag_features_enabled=self._get_env('LAG_FEATURES_ENABLED', True, bool),
#                 pattern_features_enabled=self._get_env('PATTERN_FEATURES_ENABLED', True, bool)
#             ),

#             'debug': DebugConfig(
#                 debug_mode=self._get_env('DEBUG_MODE', False, bool),
#                 verbose_logging=self._get_env('VERBOSE_LOGGING', False, bool),
#                 profile_performance=self._get_env('PROFILE_PERFORMANCE', False, bool),
#                 enable_testing_mode=self._get_env('ENABLE_TESTING_MODE', False, bool)
#             )
#         }

#     def _setup_directories(self):
#         """Create necessary directories"""
#         output_config = self.config['output']
#         directories = [
#             output_config.results_dir,
#             output_config.models_dir,
#             output_config.reports_dir,
#             output_config.visualizations_dir,
#             output_config.logs_dir
#         ]

#         for directory in directories:
#             Path(directory).mkdir(parents=True, exist_ok=True)

#     def _setup_logging(self):
#         """Setup logging configuration"""
#         logging_config = self.config['logging']
#         debug_config = self.config['debug']

#         # Determine log level
#         log_level = getattr(logging, logging_config.log_level.upper(), logging.INFO)
#         if debug_config.debug_mode:
#             log_level = logging.DEBUG

#         # Configure logging
#         handlers = []

#         # File handler
#         if logging_config.log_file:
#             handlers.append(logging.FileHandler(logging_config.log_file))

#         # Console handler
#         if logging_config.console_output:
#             handlers.append(logging.StreamHandler())

#         logging.basicConfig(
#             level=log_level,
#             format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#             handlers=handlers
#         )

#     def get(self, section: str, key: Optional[str] = None) -> Any:
#         """Get configuration value"""
#         if key is None:
#             return self.config.get(section)
#         return getattr(self.config.get(section), key, None)

#     def get_elasticsearch_indices(self) -> Dict[str, str]:
#         """Get all Elasticsearch indices"""
#         es_config = self.config['elasticsearch']
#         return {
#             'process': es_config.process_index,
#             'network': es_config.network_index,
#             'discovery': es_config.discovery_index,
#             'metadata': es_config.metadata_index,
#             'alerts': es_config.alerts_index
#         }

#     def get_mlflow_uri(self) -> str:
#         """Get MLflow tracking URI"""
#         return self.config['dagshub'].mlflow_uri

#     def is_debug_mode(self) -> bool:
#         """Check if debug mode is enabled"""
#         return self.config['debug'].debug_mode

#     def print_config(self):
#         """Print current configuration (excluding sensitive data)"""
#         print("\n=== Configuration Summary ===")
#         for section_name, section_config in self.config.items():
#             print(f"\n[{section_name.upper()}]")
#             for attr_name in dir(section_config):
#                 if not attr_name.startswith('_'):
#                     value = getattr(section_config, attr_name)
#                     # Hide sensitive information
#                     if any(sensitive in attr_name.lower() for sensitive in ['password', 'token', 'key']):
#                         value = '*' * len(str(value)) if value else ''
#                     print(f"  {attr_name}: {value}")

#     def get_training_period(self, data_type: Optional[str] = None) -> Tuple[datetime, datetime]:
#         """Get training period dates for specified data type"""
#         training_config = self.config['training']

#         # Use custom period if specified
#         if training_config.use_custom_period:
#             if training_config.custom_training_start and training_config.custom_training_end:
#                 start_date = datetime.fromisoformat(training_config.custom_training_start.replace('Z', '+00:00'))
#                 end_date = datetime.fromisoformat(training_config.custom_training_end.replace('Z', '+00:00'))
#                 return start_date, end_date

#         # Get data type specific period
#         if data_type:
#             period_map = {
#                 'process': training_config.process_training_period_days,
#                 'network': training_config.network_training_period_days,
#                 'discovery': training_config.discovery_training_period_days,
#                 'metadata': training_config.metadata_training_period_days,
#                 'alerts': training_config.alerts_training_period_days
#             }
#             period_days = period_map.get(data_type.lower(), training_config.training_period_days)
#         else:
#             period_days = training_config.training_period_days

#         # Calculate dates
#         end_date = datetime.now() - timedelta(days=training_config.training_start_offset_days)
#         start_date = end_date - timedelta(days=period_days)

#         # Apply additional end offset
#         if training_config.training_end_offset_days > 0:
#             end_date = end_date - timedelta(days=training_config.training_end_offset_days)

#         return start_date, end_date


#     def get_rolling_training_windows(self, data_type: Optional[str] = None) -> List[Tuple[datetime, datetime]]:
#         """Get multiple training windows for rolling training"""
#         training_config = self.config['training']

#         if not training_config.use_rolling_window:
#             return [self.get_training_period(data_type)]

#         windows = []
#         base_start, base_end = self.get_training_period(data_type)

#         window_size = timedelta(days=training_config.rolling_window_size_days)
#         step_size = timedelta(days=training_config.rolling_window_step_days)

#         current_end = base_end
#         while current_end > base_start:
#             current_start = current_end - window_size
#             if current_start < base_start:
#                 current_start = base_start

#             windows.append((current_start, current_end))
#             current_end = current_end - step_size

#         return windows

#     def should_include_time_period(self, timestamp: datetime) -> bool:
#         """Check if a timestamp should be included in training based on time filters"""
#         training_config = self.config['training']

#         # Weekend filter
#         if not training_config.include_weekends and timestamp.weekday() >= 5:
#             return False

#         # Business hours filter
#         if training_config.include_business_hours_only:
#             hour = timestamp.hour
#             if hour < training_config.business_hours_start or hour >= training_config.business_hours_end:
#                 return False

#         # Holiday filter (basic implementation - can be extended)
#         if training_config.exclude_holidays:
#             # Add your holiday logic here
#             # For now, just exclude major holidays (extend as needed)
#             holiday_dates = [
#                 # Add holiday dates in format: (month, day)
#                 (1, 1),   # New Year's Day
#                 (7, 4),   # Independence Day
#                 (12, 25), # Christmas
#             ]
#             if (timestamp.month, timestamp.day) in holiday_dates:
#                 return False

#         return True


# # Global config instance
# config = None

# def get_config(env_file: str = ".env") -> ConfigManager:
#     """Get global configuration instance"""
#     global config
#     if config is None:
#         config = ConfigManager(env_file)
#     return config


# def reload_config(env_file: str = ".env") -> ConfigManager:
#     """Reload configuration"""
#     global config
#     config = ConfigManager(env_file)
#     return config


# def load_config(config_file: str = "config.json", env_file: str = ".env") -> Dict[str, Any]:
#     """
#     Load configuration for backward compatibility.
#     Returns configuration in the old dictionary format.
#     """
#     # Get the new configuration
#     config_manager = get_config(env_file)

#     # Convert to old format for backward compatibility
#     legacy_config = {
#         "elasticsearch": {
#             "host": config_manager.get('elasticsearch').host,
#             "username": config_manager.get('elasticsearch').username,
#             "password": config_manager.get('elasticsearch').password,
#             "scroll_size": config_manager.get('elasticsearch').scroll_size,
#             "scroll_timeout": config_manager.get('elasticsearch').scroll_timeout,
#             "timeout": config_manager.get('elasticsearch').timeout
#         },
#         "detection": {
#             "time_window": config_manager.get('detection').time_window,
#             "threshold_multiplier": config_manager.get('detection').threshold_multiplier,
#             "min_baseline_period": config_manager.get('detection').min_baseline_period,
#             "sensitivity": config_manager.get('detection').sensitivity,
#             "anomaly_methods": config_manager.get('detection').anomaly_methods

#         },
#         "output": {
#             "save_results": config_manager.get('output').save_results,
#             "visualization": config_manager.get('output').visualization,
#             "generate_reports": config_manager.get('output').generate_reports,
#             "results_dir": config_manager.get('output').results_dir,
#             "models_dir": config_manager.get('output').models_dir,
#             "visualizations_dir": config_manager.get('output').visualizations_dir

#         },
#         "performance": {
#             "max_workers": config_manager.get('performance').max_workers,
#             "chunk_size": config_manager.get('performance').chunk_size,
#             "enable_parallel_processing": config_manager.get('performance').enable_parallel_processing
#         },
#         "training": {
#             "baseline_query_size": config_manager.get('training').baseline_query_size,
#             "training_period_days": config_manager.get('training').training_period_days,
#             "training_start_offset_days": config_manager.get('training').training_start_offset_days,
#             "include_weekends": config_manager.get('training').include_weekends,
#             "include_business_hours_only": config_manager.get('training').include_business_hours_only,
#             "business_hours_start": config_manager.get('training').business_hours_start,
#             "business_hours_end": config_manager.get('training').business_hours_end
#         },
#         "debug_mode": config_manager.get('debug').debug_mode,
#         "batch_size": config_manager.get('performance').chunk_size
#     }

#     return legacy_config


# def save_config(config_dict: Dict[str, Any], config_file: str = "config.json"):
#     """
#     Save configuration to file for backward compatibility.
#     """
#     try:
#         with open(config_file, 'w') as f:
#             json.dump(config_dict, f, indent=2, default=str)
#         print(f"Configuration saved to {config_file}")
#     except Exception as e:
#         print(f"Error saving configuration: {e}")


# def validate_config(config_dict: Dict[str, Any]) -> bool:
#     """
#     Validate configuration dictionary for backward compatibility.
#     """
#     required_sections = ['elasticsearch', 'detection', 'output']

#     for section in required_sections:
#         if section not in config_dict:
#             print(f"Missing required configuration section: {section}")
#             return False

#     # Validate Elasticsearch config
#     es_config = config_dict.get('elasticsearch', {})
#     required_es_fields = ['host', 'username', 'password']

#     for field in required_es_fields:
#         if not es_config.get(field):
#             print(f"Missing required Elasticsearch field: {field}")
#             return False

#     return True


# def get_elasticsearch_config() -> Dict[str, Any]:
#     """
#     Get Elasticsearch configuration for backward compatibility.
#     """
#     config_manager = get_config()
#     es_config = config_manager.get('elasticsearch')

#     return {
#         "host": es_config.host,
#         "username": es_config.username,
#         "password": es_config.password,
#         "scroll_size": es_config.scroll_size,
#         "scroll_timeout": es_config.scroll_timeout,
#         "timeout": es_config.timeout
#     }


# def get_detection_config() -> Dict[str, Any]:
#     """
#     Get detection configuration for backward compatibility.
#     """
#     config_manager = get_config()
#     detection_config = config_manager.get('detection')

#     return {
#         "time_window": detection_config.time_window,
#         "threshold_multiplier": detection_config.threshold_multiplier,
#         "min_baseline_period": detection_config.min_baseline_period,
#         "sensitivity": detection_config.sensitivity,
#         "anomaly_methods": detection_config.anomaly_methods
#     }


# if __name__ == "__main__":
#     # Test configuration
#     config_manager = get_config()
#     config_manager.print_config()
#     config_manager.save_config_to_file()

"""
Enhanced Configuration Manager for Linux Anomaly Detection System
Handles all configuration loading, validation, and environment setup
UPDATED: Fixed dictionary conversion and backward compatibility
"""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dotenv import load_dotenv


@dataclass
class DagshubConfig:
    """DagsHub MLflow configuration"""
    repo_name: str = ""
    username: str = ""
    token: str = ""

    @property
    def mlflow_uri(self) -> str:
        """Build the MLflow tracking URI from DagsHub coordinates."""
        return f"https://dagshub.com/{self.username}/{self.repo_name}.mlflow"


@dataclass
class ElasticsearchConfig:
    """Elasticsearch configuration"""
    host: str = "https://localhost:9200"
    username: str = ""
    password: str = ""

    # Index patterns
    process_index: str = ".ds-logs-endpoint.events.process-default-*"
    network_index: str = ".ds-logs-endpoint.events.network-default-*"
    discovery_index: str = "logs-endpoint.events.process-*"
    metadata_index: str = "logs-endpoint.events.process-*,logs-endpoint.events.network-*"
    alerts_index: str = ".internal.alerts-security.alerts-default-*"

    # Performance settings
    scroll_size: int = 5000
    scroll_timeout: str = "2m"
    timeout: int = 60

    # TLS (see es_tls.py): verification stays on unless explicitly disabled
    verify_certs: bool = True
    ca_certs: str = ""


@dataclass
class DetectionConfig:
    """Anomaly detection configuration"""
    time_window: int = 24
    threshold_multiplier: float = 3.0
    min_baseline_period: int = 30
    aggregation_interval: str = "15min"
    bucket_span: str = "15m"
    sensitivity: float = 0.3

    # CRITICAL: Lower thresholds for better detection
    max_anomaly_rate: float = 0.15  # Allow up to 15% anomalies
    percentile_threshold: int = 85   # Use 85th percentile instead of 95th

    # Anomaly detection methods
    anomaly_methods: list[str] = field(default_factory=lambda: ["statistical", "isolation_forest", "lof"])

    # Thresholds for different data groups - LOWERED FOR BETTER DETECTION
    rare_process_threshold: float = 0.1
    rare_process_host_threshold: float = 0.05
    rare_user_threshold: float = 0.5
    rare_sudo_threshold: float = 1.0
    rare_compiler_threshold: float = 2.0
    discovery_threshold: float = 5.0
    rare_metadata_process_threshold: float = 1.0
    rare_metadata_user_threshold: float = 2.0

    # Safety override settings
    safety_override: dict[str, Any] = field(default_factory=lambda: {
        "max_anomaly_percentage": 20,  # 20% max
        "critical_threshold": 50,      # 50% critical (was 90%)
        "adjustment_threshold": 15     # 15% adjustment threshold
    })


@dataclass
class MLConfig:
    """Machine Learning configuration"""
    feature_selection: str = "enhanced"
    contamination: float = 0.05
    n_estimators: int = 100
    lof_neighbors: int = 20
    svm_kernel: str = "rbf"
    pca_components: float = 0.95

    # CRITICAL: Lowered thresholds for better detection
    percentile_threshold: int = 75  # Use 75th percentile instead of 95th
    score_threshold_min: float = 0.3  # Minimum threshold
    score_threshold_max: float = 0.7  # Maximum threshold


@dataclass
class OutputConfig:
    """Output configuration"""
    save_results: bool = True
    visualization: bool = False
    generate_reports: bool = True
    save_models: bool = True

    # Directory structure - FIXED: Ensure all are strings
    results_dir: str = "./results"
    models_dir: str = "./results/models"
    reports_dir: str = "./results/reports"
    visualizations_dir: str = "./results/visualizations"
    visualization_dir: str = "./results/visualizations"  # Alternative name
    logs_dir: str = "./logs"


@dataclass
class LoggingConfig:
    """Logging configuration"""
    log_level: str = "INFO"
    log_file: str = "./logs/linux_anomaly_detection.log"
    console_output: bool = True


@dataclass
class PerformanceConfig:
    """Performance configuration"""
    max_workers: int = 4
    chunk_size: int = 1000
    memory_limit: str = "4GB"
    enable_parallel_processing: bool = True
    cache_enabled: bool = True


@dataclass
class AlertConfig:
    """Alert configuration"""
    alerts_enabled: bool = False
    critical_threshold: float = 0.9
    high_threshold: float = 0.7
    medium_threshold: float = 0.5
    low_threshold: float = 0.2

    # Email settings
    email_enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    email_username: str = ""
    email_password: str = ""
    email_recipients: list[str] = field(default_factory=list)

    # Slack settings
    slack_enabled: bool = False
    slack_webhook_url: str = ""
    slack_channel: str = "#security-alerts"


@dataclass
class SchedulerConfig:
    """Job scheduler configuration"""
    scheduler_enabled: bool = False
    scheduler_timezone: str = "UTC"


@dataclass
class DataQualityConfig:
    """Data quality settings"""
    min_event_threshold: int = 10
    max_anomaly_rate: float = 0.15  # Reduced from 0.4 to 0.15
    outlier_removal: bool = True
    null_value_handling: str = "fill_zero"


@dataclass
class TrainingConfig:
    """Training configuration"""
    auto_retrain: bool = True
    retrain_interval_days: int = 7
    min_training_samples: int = 1000
    validation_split: float = 0.2

    # Training data period configuration
    training_period_days: int = 30
    baseline_query_size: int = 40000  # Reduced from 500000
    training_start_offset_days: int = 1
    training_end_offset_days: int = 0

    # Specific time periods for different data types
    process_training_period_days: int = 5   # Reduced for faster testing
    network_training_period_days: int = 5   # Reduced for faster testing
    discovery_training_period_days: int = 4 # Reduced for faster testing
    metadata_training_period_days: int = 1  # Reduced for faster testing
    alerts_training_period_days: int = 7

    # Time-based training filters
    include_weekends: bool = True
    include_business_hours_only: bool = False
    business_hours_start: int = 8
    business_hours_end: int = 18
    exclude_holidays: bool = False

    # Rolling training window configuration
    use_rolling_window: bool = False
    rolling_window_size_days: int = 30
    rolling_window_step_days: int = 7

    # Seasonal training adjustments
    seasonal_adjustment: bool = False
    seasonal_period_days: int = 7
    include_multiple_seasons: bool = True
    num_seasons_to_include: int = 4

    # Training data quality filters
    min_events_per_day: int = 10
    max_gap_days: int = 3
    exclude_anomalous_training_days: bool = True
    anomalous_day_threshold: float = 0.1

    # Custom training periods
    custom_training_start: str | None = None
    custom_training_end: str | None = None
    use_custom_period: bool = False


@dataclass
class FeatureEngineeringConfig:
    """Feature engineering configuration"""
    time_features_enabled: bool = True
    include_cyclical_features: bool = True
    business_hours_start: int = 8
    business_hours_end: int = 18
    rolling_features_enabled: bool = True
    lag_features_enabled: bool = True
    pattern_features_enabled: bool = True


@dataclass
class DebugConfig:
    """Development and debug settings"""
    debug_mode: bool = False
    verbose_logging: bool = False
    profile_performance: bool = False
    enable_testing_mode: bool = False


# ---------------------------------------------------------------------------
# Agent 4 — Adaptive Threshold Configuration
# Replaces static MIN_PUSH_ML_SCORE with per-job, time-aware thresholds.
#
# ATT&CK alignment: threshold tuning reduces FN for T1059, T1046, T1548.
# ---------------------------------------------------------------------------

@dataclass
class AdaptiveThreshold:
    """Per-job and context-aware push threshold for anomaly scoring.

    The effective threshold for a given alert is:
        effective = base_score
                    * off_hours_multiplier   (if outside 06:00-18:00 local)
                    * high_value_host_multiplier (if host in high_value_hosts)
        Then optionally overridden by per_job_overrides.

    All multipliers < 1.0 lower the threshold (make detection more sensitive).
    """

    base_score: float = 0.65
    per_job_overrides: dict[str, float] = field(default_factory=lambda: {
        # Network anomalies benefit from a lower bar — attackers move laterally fast
        "v3_linux_anomalous_network_activity": 0.55,
        # Sudo events produce many FPs — require higher confidence
        "v3_linux_rare_sudo_activity": 0.70,
        # Rare process on a single host — moderate sensitivity
        "v3_linux_anomalous_process_all_hosts": 0.65,
        # Discovery commands are high-signal for recon
        "v3_linux_rare_discovery_activity": 0.60,
    })
    # Outside 06:00–18:00 attackers are more likely to be active
    off_hours_multiplier: float = 0.85
    # Critical / high-value hosts warrant lower thresholds
    high_value_host_multiplier: float = 0.80
    high_value_hosts: list[str] = field(default_factory=list)
    # Hour boundaries for off-hours detection (24-h clock, local time)
    business_hours_start: int = 6
    business_hours_end: int = 18


class ConfigManager:
    """Enhanced Configuration Manager with Dictionary Conversion"""

    def __init__(self, env_file: str = ".env"):
        """Initialize configuration manager"""
        self.env_file = env_file
        self.load_environment()
        self.config = self._build_config()
        self._setup_directories()
        self._setup_logging()

    def load_environment(self):
        """Load environment variables from .env file"""
        if os.path.exists(self.env_file):
            load_dotenv(self.env_file)
        else:
            print(f"Warning: {self.env_file} not found, using default values")

    def _get_env(self, key: str, default: Any = None, cast_type: type = str) -> Any:
        """Get environment variable with type casting"""
        value = os.getenv(key, default)

        if value is None:
            return default

        if cast_type == bool:
            return str(value).lower() in ('true', '1', 'yes', 'on')
        elif cast_type == list:
            return [item.strip() for item in str(value).split(',') if item.strip()]
        elif cast_type in (int, float):
            try:
                return cast_type(value)
            except (ValueError, TypeError):
                return default
        else:
            return cast_type(value)

    def _build_config(self) -> dict[str, Any]:
        """Build complete configuration from environment variables"""
        return {
            'dagshub': DagshubConfig(
                repo_name=self._get_env('DAGSHUB_REPO_NAME', ''),
                username=self._get_env('DAGSHUB_USERNAME', ''),
                token=self._get_env('DAGSHUB_TOKEN', '')
            ),

            'elasticsearch': ElasticsearchConfig(
                host=self._get_env('ES_HOST', ''),
                username=self._get_env('ES_USERNAME', ''),
                password=self._get_env('ES_PASSWORD', ''),
                process_index=self._get_env('ES_PROCESS_INDEX', '.ds-logs-endpoint.events.process-default-*'),
                network_index=self._get_env('ES_NETWORK_INDEX', '.ds-logs-endpoint.events.network-default-*'),
                discovery_index=self._get_env('ES_DISCOVERY_INDEX', 'logs-endpoint.events.process-*'),
                metadata_index=self._get_env('ES_METADATA_INDEX', 'logs-endpoint.events.process-*,logs-endpoint.events.network-*'),
                alerts_index=self._get_env('ES_ALERTS_INDEX', '.internal.alerts-security.alerts-default-*'),
                scroll_size=self._get_env('ES_SCROLL_SIZE', 5000, int),
                scroll_timeout=self._get_env('ES_SCROLL_TIMEOUT', '2m'),
                timeout=self._get_env('ES_TIMEOUT', 60, int),
                verify_certs=self._get_env('ES_VERIFY_CERTS', True, bool),
                ca_certs=self._get_env('ES_CA_CERT', '')
            ),

            'detection': DetectionConfig(
                time_window=self._get_env('TIME_WINDOW', 24, int),
                threshold_multiplier=self._get_env('THRESHOLD_MULTIPLIER', 2.0, float),  # Reduced from 3.0
                min_baseline_period=self._get_env('MIN_BASELINE_PERIOD', 30, int),
                aggregation_interval=self._get_env('AGGREGATION_INTERVAL', '15min'),
                bucket_span=self._get_env('BUCKET_SPAN', '15m'),
                sensitivity=self._get_env('SENSITIVITY', 0.5, float),  # Increased from 0.3
                max_anomaly_rate=self._get_env('MAX_ANOMALY_RATE', 0.15, float),
                percentile_threshold=self._get_env('PERCENTILE_THRESHOLD', 85, int),
                anomaly_methods=self._get_env('ANOMALY_METHODS', ['statistical', 'isolation_forest', 'lof'], list),
                rare_process_threshold=self._get_env('RARE_PROCESS_THRESHOLD', 0.1, float),
                rare_process_host_threshold=self._get_env('RARE_PROCESS_HOST_THRESHOLD', 0.05, float),
                rare_user_threshold=self._get_env('RARE_USER_THRESHOLD', 0.5, float),
                rare_sudo_threshold=self._get_env('RARE_SUDO_THRESHOLD', 1.0, float),
                rare_compiler_threshold=self._get_env('RARE_COMPILER_THRESHOLD', 2.0, float),
                discovery_threshold=self._get_env('DISCOVERY_THRESHOLD', 5.0, float),
                rare_metadata_process_threshold=self._get_env('RARE_METADATA_PROCESS_THRESHOLD', 1.0, float),
                rare_metadata_user_threshold=self._get_env('RARE_METADATA_USER_THRESHOLD', 2.0, float)
            ),

            'ml': MLConfig(
                feature_selection=self._get_env('ML_FEATURE_SELECTION', 'enhanced'),
                contamination=self._get_env('ML_CONTAMINATION', 0.05, float),
                n_estimators=self._get_env('ML_N_ESTIMATORS', 100, int),
                lof_neighbors=self._get_env('ML_LOF_NEIGHBORS', 20, int),
                svm_kernel=self._get_env('ML_SVM_KERNEL', 'rbf'),
                pca_components=self._get_env('ML_PCA_COMPONENTS', 0.95, float),
                percentile_threshold=self._get_env('ML_PERCENTILE_THRESHOLD', 75, int),
                score_threshold_min=self._get_env('ML_SCORE_THRESHOLD_MIN', 0.3, float),
                score_threshold_max=self._get_env('ML_SCORE_THRESHOLD_MAX', 0.7, float)
            ),

            'output': OutputConfig(
                save_results=self._get_env('SAVE_RESULTS', True, bool),
                visualization=self._get_env('VISUALIZATION', False, bool),
                generate_reports=self._get_env('GENERATE_REPORTS', True, bool),
                save_models=self._get_env('SAVE_MODELS', True, bool),
                results_dir=self._get_env('RESULTS_DIR', './results'),
                models_dir=self._get_env('MODELS_DIR', './results/models'),
                reports_dir=self._get_env('REPORTS_DIR', './results/reports'),
                visualizations_dir=self._get_env('VISUALIZATIONS_DIR', './results/visualizations'),
                visualization_dir=self._get_env('VISUALIZATION_DIR', './results/visualizations'),
                logs_dir=self._get_env('LOGS_DIR', './logs')
            ),

            'logging': LoggingConfig(
                log_level=self._get_env('LOG_LEVEL', 'INFO'),
                log_file=self._get_env('LOG_FILE', './logs/linux_anomaly_detection.log'),
                console_output=self._get_env('CONSOLE_OUTPUT', True, bool)
            ),

            'performance': PerformanceConfig(
                max_workers=self._get_env('MAX_WORKERS', 4, int),
                chunk_size=self._get_env('CHUNK_SIZE', 1000, int),
                memory_limit=self._get_env('MEMORY_LIMIT', '4GB'),
                enable_parallel_processing=self._get_env('ENABLE_PARALLEL_PROCESSING', True, bool),
                cache_enabled=self._get_env('CACHE_ENABLED', True, bool)
            ),

            'alerts': AlertConfig(
                alerts_enabled=self._get_env('ALERTS_ENABLED', False, bool),
                critical_threshold=self._get_env('CRITICAL_THRESHOLD', 0.7, float),  # Reduced from 0.9
                high_threshold=self._get_env('HIGH_THRESHOLD', 0.6, float),         # Reduced from 0.7
                medium_threshold=self._get_env('MEDIUM_THRESHOLD', 0.4, float),     # Reduced from 0.5
                low_threshold=self._get_env('LOW_THRESHOLD', 0.2, float),
                email_enabled=self._get_env('EMAIL_ENABLED', False, bool),
                smtp_server=self._get_env('SMTP_SERVER', ''),
                smtp_port=self._get_env('SMTP_PORT', 587, int),
                email_username=self._get_env('EMAIL_USERNAME', ''),
                email_password=self._get_env('EMAIL_PASSWORD', ''),
                email_recipients=self._get_env('EMAIL_RECIPIENTS', [], list),
                slack_enabled=self._get_env('SLACK_ENABLED', False, bool),
                slack_webhook_url=self._get_env('SLACK_WEBHOOK_URL', ''),
                slack_channel=self._get_env('SLACK_CHANNEL', '#security-alerts')
            ),

            'scheduler': SchedulerConfig(
                scheduler_enabled=self._get_env('SCHEDULER_ENABLED', False, bool),
                scheduler_timezone=self._get_env('SCHEDULER_TIMEZONE', 'UTC')
            ),

            'data_quality': DataQualityConfig(
                min_event_threshold=self._get_env('MIN_EVENT_THRESHOLD', 10, int),
                max_anomaly_rate=self._get_env('DATA_QUALITY_MAX_ANOMALY_RATE', 0.15, float),
                outlier_removal=self._get_env('OUTLIER_REMOVAL', True, bool),
                null_value_handling=self._get_env('NULL_VALUE_HANDLING', 'fill_zero')
            ),

            'training': TrainingConfig(
                auto_retrain=self._get_env('AUTO_RETRAIN', True, bool),
                retrain_interval_days=self._get_env('RETRAIN_INTERVAL_DAYS', 7, int),
                min_training_samples=self._get_env('MIN_TRAINING_SAMPLES', 1000, int),
                validation_split=self._get_env('VALIDATION_SPLIT', 0.2, float),
                training_period_days=self._get_env('TRAINING_PERIOD_DAYS', 30, int),
                baseline_query_size=self._get_env('BASELINE_QUERY_SIZE', 40000, int),
                training_start_offset_days=self._get_env('TRAINING_START_OFFSET_DAYS', 1, int),
                training_end_offset_days=self._get_env('TRAINING_END_OFFSET_DAYS', 0, int),
                process_training_period_days=self._get_env('PROCESS_TRAINING_PERIOD_DAYS', 5, int),
                network_training_period_days=self._get_env('NETWORK_TRAINING_PERIOD_DAYS', 5, int),
                discovery_training_period_days=self._get_env('DISCOVERY_TRAINING_PERIOD_DAYS', 4, int),
                metadata_training_period_days=self._get_env('METADATA_TRAINING_PERIOD_DAYS', 1, int),
                alerts_training_period_days=self._get_env('ALERTS_TRAINING_PERIOD_DAYS', 7, int),
                include_weekends=self._get_env('TRAINING_INCLUDE_WEEKENDS', True, bool),
                include_business_hours_only=self._get_env('TRAINING_BUSINESS_HOURS_ONLY', False, bool),
                business_hours_start=self._get_env('TRAINING_BUSINESS_HOURS_START', 8, int),
                business_hours_end=self._get_env('TRAINING_BUSINESS_HOURS_END', 18, int),
                exclude_holidays=self._get_env('TRAINING_EXCLUDE_HOLIDAYS', False, bool),
                use_rolling_window=self._get_env('USE_ROLLING_TRAINING_WINDOW', False, bool),
                rolling_window_size_days=self._get_env('ROLLING_WINDOW_SIZE_DAYS', 30, int),
                rolling_window_step_days=self._get_env('ROLLING_WINDOW_STEP_DAYS', 7, int),
                seasonal_adjustment=self._get_env('TRAINING_SEASONAL_ADJUSTMENT', False, bool),
                seasonal_period_days=self._get_env('SEASONAL_PERIOD_DAYS', 7, int),
                include_multiple_seasons=self._get_env('INCLUDE_MULTIPLE_SEASONS', True, bool),
                num_seasons_to_include=self._get_env('NUM_SEASONS_TO_INCLUDE', 4, int),
                min_events_per_day=self._get_env('MIN_EVENTS_PER_DAY', 10, int),
                max_gap_days=self._get_env('MAX_GAP_DAYS', 3, int),
                exclude_anomalous_training_days=self._get_env('EXCLUDE_ANOMALOUS_TRAINING_DAYS', True, bool),
                anomalous_day_threshold=self._get_env('ANOMALOUS_DAY_THRESHOLD', 0.1, float),
                custom_training_start=self._get_env('CUSTOM_TRAINING_START'),
                custom_training_end=self._get_env('CUSTOM_TRAINING_END'),
                use_custom_period=self._get_env('USE_CUSTOM_TRAINING_PERIOD', False, bool)
            ),

            'feature_engineering': FeatureEngineeringConfig(
                time_features_enabled=self._get_env('TIME_FEATURES_ENABLED', True, bool),
                include_cyclical_features=self._get_env('INCLUDE_CYCLICAL_FEATURES', True, bool),
                business_hours_start=self._get_env('BUSINESS_HOURS_START', 8, int),
                business_hours_end=self._get_env('BUSINESS_HOURS_END', 18, int),
                rolling_features_enabled=self._get_env('ROLLING_FEATURES_ENABLED', True, bool),
                lag_features_enabled=self._get_env('LAG_FEATURES_ENABLED', True, bool),
                pattern_features_enabled=self._get_env('PATTERN_FEATURES_ENABLED', True, bool)
            ),

            'debug': DebugConfig(
                debug_mode=self._get_env('DEBUG_MODE', False, bool),
                verbose_logging=self._get_env('VERBOSE_LOGGING', False, bool),
                profile_performance=self._get_env('PROFILE_PERFORMANCE', False, bool),
                enable_testing_mode=self._get_env('ENABLE_TESTING_MODE', False, bool)
            )
        }

    def _setup_directories(self):
        """Create necessary directories"""
        output_config = self.config['output']
        directories = [
            output_config.results_dir,
            output_config.models_dir,
            output_config.reports_dir,
            output_config.visualizations_dir,
            output_config.logs_dir
        ]

        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)

    def _setup_logging(self):
        """Setup logging configuration"""
        logging_config = self.config['logging']
        debug_config = self.config['debug']

        # Determine log level
        log_level = getattr(logging, logging_config.log_level.upper(), logging.INFO)
        if debug_config.debug_mode:
            log_level = logging.DEBUG

        # Configure logging
        handlers = []

        # File handler
        if logging_config.log_file:
            handlers.append(logging.FileHandler(logging_config.log_file))

        # Console handler
        if logging_config.console_output:
            handlers.append(logging.StreamHandler())

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=handlers
        )

    # CRITICAL: New method for dictionary conversion
    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary format for backward compatibility"""
        result = {}
        for section_name, section_config in self.config.items():
            if hasattr(section_config, '__dict__'):
                # Convert dataclass to dict
                result[section_name] = asdict(section_config)
            else:
                # Handle regular objects
                result[section_name] = {}
                for attr_name in dir(section_config):
                    if not attr_name.startswith('_') and not callable(getattr(section_config, attr_name)):
                        result[section_name][attr_name] = getattr(section_config, attr_name)
        return result

    def get(self, section: str, key: str | None = None) -> Any:
        """Get configuration value - supports both object and dict access"""
        if key is None:
            return self.config.get(section)

        section_config = self.config.get(section)
        if section_config:
            return getattr(section_config, key, None)
        return None

    def get_dict(self, section: str, key: str | None = None) -> Any:
        """Get configuration as dictionary - for backward compatibility"""
        config_dict = self.to_dict()
        if key is None:
            return config_dict.get(section, {})
        return config_dict.get(section, {}).get(key)

    def get_elasticsearch_indices(self) -> dict[str, str]:
        """Get all Elasticsearch indices"""
        es_config = self.config['elasticsearch']
        return {
            'process': es_config.process_index,
            'network': es_config.network_index,
            'discovery': es_config.discovery_index,
            'metadata': es_config.metadata_index,
            'alerts': es_config.alerts_index
        }

    def get_mlflow_uri(self) -> str:
        """Get MLflow tracking URI"""
        return self.config['dagshub'].mlflow_uri

    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return self.config['debug'].debug_mode

    def print_config(self):
        """Print current configuration (excluding sensitive data)"""
        print("\n=== Configuration Summary ===")
        for section_name, section_config in self.config.items():
            print(f"\n[{section_name.upper()}]")
            for attr_name in dir(section_config):
                if not attr_name.startswith('_'):
                    value = getattr(section_config, attr_name)
                    # Hide sensitive information
                    if any(sensitive in attr_name.lower() for sensitive in ['password', 'token', 'key']):
                        value = '*' * len(str(value)) if value else ''
                    print(f"  {attr_name}: {value}")

    def get_training_period(self, data_type: str | None = None) -> tuple[datetime, datetime]:
        """Get training period dates for specified data type"""
        training_config = self.config['training']

        # Use custom period if specified
        if training_config.use_custom_period:
            if training_config.custom_training_start and training_config.custom_training_end:
                start_date = datetime.fromisoformat(training_config.custom_training_start.replace('Z', '+00:00'))
                end_date = datetime.fromisoformat(training_config.custom_training_end.replace('Z', '+00:00'))
                return start_date, end_date

        # Get data type specific period
        if data_type:
            period_map = {
                'process': training_config.process_training_period_days,
                'network': training_config.network_training_period_days,
                'discovery': training_config.discovery_training_period_days,
                'metadata': training_config.metadata_training_period_days,
                'alerts': training_config.alerts_training_period_days
            }
            period_days = period_map.get(data_type.lower(), training_config.training_period_days)
        else:
            period_days = training_config.training_period_days

        # Calculate dates
        end_date = datetime.now() - timedelta(days=training_config.training_start_offset_days)
        start_date = end_date - timedelta(days=period_days)

        # Apply additional end offset
        if training_config.training_end_offset_days > 0:
            end_date = end_date - timedelta(days=training_config.training_end_offset_days)

        return start_date, end_date

    def save_config_to_file(self, filename: str = "current_config.json"):
        """Save current configuration to JSON file"""
        try:
            config_dict = self.to_dict()
            with open(filename, 'w') as f:
                json.dump(config_dict, f, indent=2, default=str)
            print(f"Configuration saved to {filename}")
        except Exception as e:
            print(f"Error saving configuration: {e}")


# Global config instance
config = None

def get_config(env_file: str = ".env") -> ConfigManager:
    """Get global configuration instance"""
    global config
    if config is None:
        config = ConfigManager(env_file)
    return config


def reload_config(env_file: str = ".env") -> ConfigManager:
    """Reload configuration"""
    global config
    config = ConfigManager(env_file)
    return config


def load_config(config_file: str = "config.json", env_file: str = ".env") -> dict[str, Any]:
    """
    UPDATED: Load configuration for backward compatibility.
    Returns configuration in the old dictionary format.
    """
    # Get the new configuration manager
    config_manager = get_config(env_file)

    # Convert to dictionary format
    config_dict = config_manager.to_dict()

    # Return in expected format for backward compatibility
    return config_dict


def save_config(config_dict: dict[str, Any], config_file: str = "config.json"):
    """Save configuration to file for backward compatibility"""
    try:
        with open(config_file, 'w') as f:
            json.dump(config_dict, f, indent=2, default=str)
        print(f"Configuration saved to {config_file}")
    except Exception as e:
        print(f"Error saving configuration: {e}")


        def validate_config(config_dict: dict[str, Any]) -> bool:
            """
            Validate configuration dictionary for backward compatibility.
            """
            required_sections = ['elasticsearch', 'detection', 'output', 'training', 'performance']

            for section in required_sections:
                if section not in config_dict:
                    print(f"Missing required configuration section: {section}")
                    return False

            # Validate Elasticsearch config
            es_config = config_dict.get('elasticsearch', {})
            required_es_fields = ['host', 'username', 'password']

            for field in required_es_fields:
                if not es_config.get(field):
                    print(f"Missing required Elasticsearch field: {field}")
                    return False

            return True


def get_elasticsearch_config() -> dict[str, Any]:
    """
    Get Elasticsearch configuration for backward compatibility.
    """
    config_manager = get_config()
    es_config = config_manager.get('elasticsearch')

    return {
        "host": es_config.host,
        "username": es_config.username,
        "password": es_config.password,
        "scroll_size": es_config.scroll_size,
        "scroll_timeout": es_config.scroll_timeout,
        "timeout": es_config.timeout
    }


def get_detection_config() -> dict[str, Any]:
    """
    Get detection configuration for backward compatibility.
    """
    config_manager = get_config()
    detection_config = config_manager.get('detection')

    return {
        "time_window": detection_config.time_window,
        "threshold_multiplier": detection_config.threshold_multiplier,
        "min_baseline_period": detection_config.min_baseline_period,
        "sensitivity": detection_config.sensitivity,
        "anomaly_methods": detection_config.anomaly_methods
    }
