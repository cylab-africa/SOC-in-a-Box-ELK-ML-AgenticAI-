# import pandas as pd
# import numpy as np
# import os
# import json
# from datetime import datetime, timedelta
# from typing import Dict, List, Optional, Tuple, Any
# import logging
# import time
# from entity_alignment import apply_immediate_fixes
# def ensure_event_category(df):
#     """
#     Ensure the event.category column exists in the dataframe.
#     """
#     if 'event.category' not in df.columns:
#         # Determine appropriate category based on data content
#         if 'process.name' in df.columns:
#             default_category = 'process'
#         elif 'destination.ip' or 'destination.port' in df.columns:
#             default_category = 'network'
#         elif 'user.name' in df.columns and 'is_sudo_command' in df.columns:
#             default_category = 'user'
#         else:
#             default_category = 'unknown'

#         df['event.category'] = default_category
#         logger.debug(f"Added missing 'event.category' column with default value '{default_category}'")

#     return df
# def validate_training_detection_compatibility(training_data: pd.DataFrame,
#                                             detection_data: pd.DataFrame,
#                                             data_type: str) -> Dict:
#     """
#     CRITICAL FIX: Validate compatibility between training and detection phases.
#     """
#     validation_report = {
#         'compatible': True,
#         'issues': [],
#         'warnings': [],
#         'training_features': set(),
#         'detection_features': set(),
#         'missing_in_detection': [],
#         'feature_distribution_match': {},
#         'recommendation': 'proceed'
#     }

#     if training_data.empty or detection_data.empty:
#         validation_report['compatible'] = False
#         validation_report['issues'].append("Empty training or detection data")
#         validation_report['recommendation'] = 'retrain_models'
#         return validation_report

#     # Extract numeric features from both datasets
#     training_numeric = training_data.select_dtypes(include=[np.number]).columns
#     detection_numeric = detection_data.select_dtypes(include=[np.number]).columns

#     validation_report['training_features'] = set(training_numeric)
#     validation_report['detection_features'] = set(detection_numeric)
#     validation_report['missing_in_detection'] = list(set(training_numeric) - set(detection_numeric))

#     # Check for missing features
#     if validation_report['missing_in_detection']:
#         validation_report['compatible'] = False
#         validation_report['issues'].append(f"Features missing in detection: {validation_report['missing_in_detection']}")

#     # Check feature distributions for common features
#     common_features = set(training_numeric) & set(detection_numeric)
#     for feature in common_features:
#         try:
#             # Compare basic statistics
#             train_stats = training_data[feature].describe()
#             detect_stats = detection_data[feature].describe()

#             # Check if distributions are reasonably similar (within 50% variance)
#             mean_diff = abs(train_stats['mean'] - detect_stats['mean']) / max(abs(train_stats['mean']), 1e-6)
#             std_diff = abs(train_stats['std'] - detect_stats['std']) / max(abs(train_stats['std']), 1e-6)

#             if mean_diff > 0.5 or std_diff > 0.5:
#                 validation_report['warnings'].append(f"Feature {feature} has different distribution in detection vs training")
#                 validation_report['feature_distribution_match'][feature] = False
#             else:
#                 validation_report['feature_distribution_match'][feature] = True

#         except Exception as e:
#             validation_report['warnings'].append(f"Could not compare feature {feature}: {e}")

#     # Determine recommendation
#     if len(validation_report['issues']) > 0:
#         validation_report['recommendation'] = 'fix_features'
#     elif len(validation_report['warnings']) > len(common_features) * 0.3:  # >30% features have issues
#         validation_report['recommendation'] = 'review_data'
#     else:
#         validation_report['recommendation'] = 'proceed'

#     return validation_report

# def create_feature_registry(data_type: str) -> Dict:
#     """
#     CRITICAL FIX: Create a comprehensive feature registry for validation.
#     """
#     registry = {
#         'data_type': data_type,
#         'last_updated': pd.Timestamp.now().isoformat(),
#         'features': {}
#     }

#     # Define feature metadata for validation
#     FEATURE_REGISTRY = {
#         'process': {
#             'command_length': {
#                 'source': 'process.command_line',
#                 'calculation': 'len(command_line)',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             },
#             'command_word_count': {
#                 'source': 'process.command_line',
#                 'calculation': 'len(command_line.split())',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             },
#             'pid_difference': {
#                 'source': ['process.pid', 'process.parent.pid'],
#                 'calculation': 'abs(pid - parent_pid)',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             },
#             'has_pipe': {
#                 'source': 'process.command_line',
#                 'calculation': 'contains_pipe_char',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             },
#             'hour_sin': {
#                 'source': '@timestamp',
#                 'calculation': 'sin(2*pi*hour/24)',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             }
#         },
#         'network': {
#             'destination.port': {
#                 'source': 'destination.port',
#                 'calculation': 'direct_field',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             },
#             'network.bytes': {
#                 'source': 'network.bytes',
#                 'calculation': 'direct_field',
#                 'real_time_available': True,
#                 'latency_ms': 1,
#                 'fallback_value': 0
#             }
#         }
#     }

#     registry['features'] = FEATURE_REGISTRY.get(data_type, {})
#     return registry

# def monitor_detection_performance(results: pd.DataFrame,
#                                 data_type: str,
#                                 processing_time_ms: float) -> Dict:
#     """
#     CRITICAL FIX: Monitor detection performance and alert on issues.
#     """
#     metrics = {
#         'data_type': data_type,
#         'timestamp': pd.Timestamp.now().isoformat(),
#         'processing_time_ms': processing_time_ms,
#         'records_processed': len(results),
#         'anomalies_detected': 0,
#         'anomaly_rate': 0.0,
#         'performance_issues': [],
#         'data_quality_issues': [],
#         'status': 'healthy'
#     }

#     if not results.empty:
#         if 'final_anomaly' in results.columns:
#             metrics['anomalies_detected'] = results['final_anomaly'].sum()
#             metrics['anomaly_rate'] = metrics['anomalies_detected'] / len(results)

#     # Check for performance issues
#     max_processing_time = 500  # 500ms threshold
#     if processing_time_ms > max_processing_time:
#         metrics['performance_issues'].append(f"Processing time {processing_time_ms}ms exceeds {max_processing_time}ms threshold")
#         metrics['status'] = 'degraded'

#     # Check for data quality issues
#     if len(results) == 0:
#         metrics['data_quality_issues'].append("No data returned from detection")
#         metrics['status'] = 'error'

#     # Check for anomaly rate issues
#     if metrics['anomaly_rate'] > 0.1:  # >10% anomaly rate is suspicious
#         metrics['data_quality_issues'].append(f"High anomaly rate: {metrics['anomaly_rate']:.1%}")
#         metrics['status'] = 'warning'

#     return metrics


# # Import project modules for Linux anomaly detection
# from config import load_config
# from datamanager import (
#     connect_to_elasticsearch,
#     fetch_process_data,
#     fetch_network_activity_data,
#     fetch_user_activity_data,
#     fetch_discovery_commands_data,
#     fetch_metadata_access_data,
#     fetch_baseline_data,
#     preprocess_process_data,
#     preprocess_network_data,
#     preprocess_user_data,
#     preprocess_discovery_data,
#     preprocess_metadata_data,
#     get_training_configuration,
#     aggregate_data_by_group,
#     create_time_buckets
# )
# from model_manager import (
#     LinuxModelManager,
#     establish_linux_baselines,
#     train_linux_models,
#     save_linux_models,
#     load_linux_models,
#     train_process_anomaly_models,
#     train_network_activity_models,
#     train_user_behavior_models,
#     train_discovery_command_models,
#     train_metadata_access_models
# )
# from detection_methods import (
#     detect_statistical_anomalies,
#     detect_ml_anomalies,
#     combine_detection_results,
#     analyze_feature_availability,
#     detect_rare_processes_all_hosts,
#     detect_rare_processes_by_host,
#     detect_anomalous_user_activity,
#     detect_sudo_anomalies,
#     detect_compiler_anomalies,
#     detect_discovery_command_anomalies,
#     detect_metadata_access_anomalies,
#     calculate_baselines
# )
# from visualizer import LinuxAnomalyVisualizer
# # from fixedLDS import apply_all_fixes, FixedDetectionPipeline
# from fixedLDS import apply_all_fixes, EntityValidator,FeatureEngineer,ConfigManager
# logger = logging.getLogger("linux_anomaly_detection")


# def safe_string_join(items, separator=', '):
#     """Safely join items into a string, handling mixed types."""
#     try:
#         str_items = []
#         for item in items:
#             if pd.isna(item) or item is None:
#                 str_items.append('Unknown')
#             else:
#                 str_items.append(str(item))
#         return separator.join(str_items)
#     except Exception as e:
#         logger.warning(f"Error in safe_string_join: {e}")
#         return "Unknown"


# def safe_column_check(df: pd.DataFrame, required_columns: List[str], operation_name: str) -> bool:
#     """Check if required columns exist in DataFrame."""
#     missing_columns = [col for col in required_columns if col not in df.columns]
#     if missing_columns:
#         logger.error(f"Missing required columns for {operation_name}: {missing_columns}")
#         logger.info(f"Available columns: {list(df.columns)}")
#         return False
#     return True


# def add_default_columns(df: pd.DataFrame, default_columns: Dict[str, Any]) -> pd.DataFrame:
#     """Add default columns if they don't exist."""
#     for col_name, default_value in default_columns.items():
#         if col_name not in df.columns:
#             df[col_name] = default_value
#             logger.info(f"Added default column {col_name} with value {default_value}")
#     return df


# class LinuxAnomalyDetector:
#     """
#     Comprehensive Linux anomaly detection system supporting all 14 detection jobs
#     across 5 data groups: process, network, user, discovery, and metadata.
#     """

#     def __init__(self, config_path=None):
#         """Initialize the Linux anomaly detector with configuration."""
#         self.es = None
#         self.model_manager = None
#         self.visualizer = None
#         self.config = load_config(config_path)
#         self.connect_to_elasticsearch()

#         # Initialize managers
#         self.model_manager = LinuxModelManager(self.config)
#         self.visualizer = LinuxAnomalyVisualizer(self.config)
#         from fixedLDS import ConfigManager
#         from fixedLDS import ConfigManager

#         self.config = ConfigManager.fix_config(self.config)

#         # Supported detection jobs organized by data group
#         self.detection_jobs = {
#             "process": {
#                 "v3_linux_anomalous_process_all_hosts": {
#                     "description": "Processes unusual to all Linux hosts",
#                     "method": self._detect_anomalous_process_all_hosts
#                 },
#                 "v3_rare_process_by_host_linux": {
#                     "description": "Processes unusual to particular Linux hosts",
#                     "method": self._detect_rare_process_by_host
#                 }
#             },
#             "network": {
#                 "v3_linux_anomalous_network_activity": {
#                     "description": "Unusual network activity from processes",
#                     "method": self._detect_anomalous_network_activity
#                 },
#                 "v3_linux_anomalous_network_port_activity": {
#                     "description": "Unusual destination port activity",
#                     "method": self._detect_anomalous_network_port_activity
#                 }
#             },
#             "user": {
#                 "v3_linux_anomalous_user_name": {
#                     "description": "Rare and unusual user activity",
#                     "method": self._detect_anomalous_user_name
#                 },
#                 "v3_linux_rare_sudo_user": {
#                     "description": "Sudo activity from unusual users",
#                     "method": self._detect_rare_sudo_user
#                 },
#                 "v3_linux_rare_user_compiler": {
#                     "description": "Compiler activity from unusual users",
#                     "method": self._detect_rare_user_compiler
#                 }
#             },
#             "discovery": {
#                 "v3_linux_network_configuration_discovery": {
#                     "description": "Network configuration discovery commands",
#                     "method": self._detect_network_configuration_discovery
#                 },
#                 "v3_linux_network_connection_discovery": {
#                     "description": "Network connection discovery commands",
#                     "method": self._detect_network_connection_discovery
#                 },
#                 "v3_linux_system_information_discovery": {
#                     "description": "System information discovery commands",
#                     "method": self._detect_system_information_discovery
#                 },
#                 "v3_linux_system_process_discovery": {
#                     "description": "System process discovery commands",
#                     "method": self._detect_system_process_discovery
#                 },
#                 "v3_linux_system_user_discovery": {
#                     "description": "System user discovery commands",
#                     "method": self._detect_system_user_discovery
#                 }
#             },
#             "metadata": {
#                 "v3_linux_rare_metadata_process": {
#                     "description": "Unusual processes accessing metadata services",
#                     "method": self._detect_rare_metadata_process
#                 },
#                 "v3_linux_rare_metadata_user": {
#                     "description": "Unusual users accessing metadata services",
#                     "method": self._detect_rare_metadata_user
#                 }
#             }
#         }

#     def _generate_summary_report(self, results: Dict[str, Dict[str, pd.DataFrame]]):
#         """
#         Generate a summary report across all data groups.

#         Args:
#             results: Results from comprehensive detection
#         """
#         try:
#             # Count total anomalies across all data groups
#             total_anomalies = 0
#             anomalies_by_group = {}

#             for data_type, group_results in results.items():
#                 group_anomalies = 0
#                 for job_name, job_results in group_results.items():
#                     if not job_results.empty and 'final_anomaly' in job_results.columns:
#                         job_anomalies = job_results['final_anomaly'].sum()
#                         group_anomalies += job_anomalies

#                 anomalies_by_group[data_type] = group_anomalies
#                 total_anomalies += group_anomalies

#             # Create a simple summary report
#             timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#             output_dir = self.config.get("output", {}).get("results_dir", "results")
#             report_file = os.path.join(output_dir, f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")

#             with open(report_file, "w") as f:
#                 f.write(f"# Linux Anomaly Detection Summary Report\n\n")
#                 f.write(f"Generated: {timestamp_str}\n\n")

#                 f.write(f"## Overview\n\n")
#                 f.write(f"Total anomalies detected: **{total_anomalies}**\n\n")

#                 f.write("### Anomalies by Data Group\n\n")
#                 for group, count in anomalies_by_group.items():
#                     f.write(f"- **{group.title()}**: {count} anomalies\n")

#                 f.write("\n## Group Summaries\n\n")
#                 for data_type, group_results in results.items():
#                     f.write(f"### {data_type.title()} Group\n\n")

#                     if not group_results:
#                         f.write("No data available for this group.\n\n")
#                         continue

#                     for job_name, job_results in group_results.items():
#                         if job_results.empty:
#                             f.write(f"- {job_name}: No results\n")
#                             continue

#                         job_anomalies = 0
#                         if 'final_anomaly' in job_results.columns:
#                             job_anomalies = job_results['final_anomaly'].sum()

#                         job_description = self.detection_jobs.get(data_type, {}).get(job_name, {}).get("description", "")
#                         f.write(f"- **{job_name}**: {job_anomalies} anomalies")

#                         if job_description:
#                             f.write(f" - {job_description}")

#                         f.write("\n")

#                     f.write("\n")

#                 f.write("\n## Next Steps\n\n")
#                 f.write("1. Review detailed reports for each data group\n")
#                 f.write("2. Investigate high-priority anomalies\n")
#                 f.write("3. Consider adjusting detection thresholds if needed\n")

#                 f.write("\n---\n\n")
#                 f.write("*Report generated by Linux Anomaly Detection System*\n")

#             logger.info(f"Generated summary report: {report_file}")
#             return report_file

#         except Exception as e:
#             logger.error(f"Error generating summary report: {e}")
#             return None

#     def _generate_comprehensive_outputs(self, results: Dict[str, Dict[str, pd.DataFrame]]):
#         """Generate comprehensive reports, visualizations, and individual anomaly data."""
#         try:
#             logger.info("Generating comprehensive outputs")

#             # Generate reports and visualizations for each data group
#             for data_type, group_results in results.items():
#                 if not group_results:
#                     continue

#                 try:
#                     # Generate group report
#                     report_file, csv_file = self.visualizer.generate_comprehensive_report(
#                         group_results, data_type
#                     )

#                     if report_file:
#                         logger.info(f"Generated {data_type} report: {report_file}")

#                     # Generate visualizations
#                     viz_paths = self.visualizer.create_data_type_visualizations(
#                         group_results, data_type
#                     )

#                     if viz_paths:
#                         logger.info(f"Generated {len(viz_paths)} visualizations for {data_type}")

#                 except Exception as e:
#                     logger.error(f"Error generating outputs for {data_type}: {e}")

#             # Generate overall summary report
#             self._generate_summary_report(results)

#             # NEW: Extract and save individual anomalies to JSON
#             anomalies_file = self.extract_and_save_anomalies(results)

#             # NEW: Generate a separate index of anomalies by severity
#             self._generate_anomaly_index(results, anomalies_file)

#         except Exception as e:
#             logger.error(f"Error generating comprehensive outputs: {e}")

#     def train_models_for_group(self, data_type: str, retrain: bool = False) -> bool:
#         """
#         Train machine learning models for a specific data group.

#         Args:
#             data_type: Data group to train models for
#             retrain: Whether to retrain even if models exist

#         Returns:
#             bool: Success status
#         """
#         logger.info(f"Training models for {data_type} group")

#         if data_type not in self.detection_jobs:
#             raise ValueError(f"Unknown data type: {data_type}")

#         try:
#             # Check if models already exist
#             if not retrain:
#                 success = self.model_manager.load_models(data_type)
#                 if success:
#                     logger.info(f"Models already exist for {data_type}, skipping training")
#                     return True

#             # Fetch baseline data for training
#             baseline_data = self._fetch_baseline_data_with_scroll(data_type)
#             if baseline_data.empty:
#                 logger.error(f"No baseline data available for training {data_type} models")
#                 return False

#             # Use specialized training functions from model_manager
#             if data_type == "process":
#                 models, scalers, baselines = train_process_anomaly_models(baseline_data, self.config)
#             elif data_type == "network":
#                 models, scalers, baselines = train_network_activity_models(baseline_data, self.config)
#             elif data_type == "user":
#                 models, scalers, baselines = train_user_behavior_models(baseline_data, self.config)
#             elif data_type == "discovery":
#                 models, scalers, baselines = train_discovery_command_models(baseline_data, self.config)
#             elif data_type == "metadata":
#                 models, scalers, baselines = train_metadata_access_models(baseline_data, self.config)
#             else:
#                 # Fallback to general training
#                 models, scalers = self.model_manager.train_models(baseline_data, data_type)
#                 baselines = self.model_manager.establish_baselines(baseline_data, data_type)

#             if models or baselines:
#                 # Store in model manager
#                 if models:
#                     self.model_manager.models[data_type] = models
#                 if scalers:
#                     self.model_manager.scalers[data_type] = scalers
#                 if baselines:
#                     self.model_manager.baselines[data_type] = baselines

#                 logger.info(f"Successfully trained and saved models for {data_type}")
#                 return True
#             else:
#                 logger.error(f"Failed to train models for {data_type}")
#                 return False

#         except Exception as e:
#             logger.error(f"Error training models for {data_type}: {e}")
#             return False

#     def _detect_rare_metadata_user(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect unusual users accessing metadata services."""
#         return self._detect_metadata_anomalies(data, focus="user")
#     def _detect_rare_sudo_user(self, data: pd.DataFrame) -> pd.DataFrame:
#             """Detect sudo activity from unusual users."""
#             return self._detect_user_anomalies(data, detect_sudo_anomalies)
#     def _detect_anomalous_user_name(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect rare and unusual user activity."""
#         return self._detect_user_anomalies(data, detect_anomalous_user_activity)
#     def _detect_rare_user_compiler(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect compiler activity from unusual users."""
#         return self._detect_user_anomalies(data, detect_compiler_anomalies)
#     def _detect_anomalous_network_activity(self, data: pd.DataFrame) -> pd.DataFrame:
#             data, self.config = apply_all_fixes(data, self.config, 'network')
#             if data.empty:
#                 return pd.DataFrame()

#             try:
#                 # Add missing network fields with defaults
#                 required_fields = {
#                     'destination.ip': 'Unknown',
#                     'network.bytes': 0,
#                     'network.packets': 0
#                 }

#                 for field, default_value in required_fields.items():
#                     if field not in data.columns:
#                         data[field] = default_value
#                         logger.info(f"Added missing field '{field}' with default value")


#                 bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15s"))
#                 # bucketed_data = ensure_event_category(bucketed_data, 'process')
#                 if bucketed_data.empty:
#                     return pd.DataFrame()

#                 # Safe aggregation for network data
#                 try:
#                     agg_dict = {
#                         'event.category': 'count',
#                         'network.bytes': 'sum',
#                         'network.packets': 'sum'
#                     }

#                     group_cols = ['time_bucket', 'process.name', 'destination.ip']
#                     bucketed_data = ensure_event_category(bucketed_data)
#                     aggregated = bucketed_data.groupby(group_cols).agg(agg_dict).reset_index()
#                     aggregated = aggregated.rename(columns={'event.category': 'event_count'})
#                     aggregated['@timestamp'] = aggregated['time_bucket']

#                     # Run detection
#                     models, scalers, baselines = self.model_manager.get_models_for_group("network")
#                     results_list = []

#                     try:
#                         stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "network")
#                         if not stat_results.empty:
#                             results_list.append(stat_results)
#                     except Exception as e:
#                         logger.warning(f"Network statistical detection failed: {e}")

#                     if models:
#                         try:
#                             ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "network", useAddress=True)
#                             if not ml_results.empty:
#                                 results_list.append(ml_results)
#                         except Exception as e:
#                             logger.warning(f"Network ML detection failed: {e}")

#                     # Combine results
#                     if results_list:
#                         final_results = results_list[0]
#                         for additional_result in results_list[1:]:
#                             final_results = self._safe_combine_results(final_results, additional_result)

#                         if 'final_anomaly' not in final_results.columns:
#                             final_results['final_anomaly'] = False

#                         return final_results
#                     else:
#                         aggregated['anomaly_score'] = 0.0
#                         aggregated['final_anomaly'] = False
#                         aggregated['detection_method'] = 'baseline_aggregation'
#                         return aggregated

#                 except Exception as agg_error:
#                     logger.error(f"Error in network activity aggregation: {agg_error}")
#                     return pd.DataFrame()

#             except Exception as e:
#                 logger.error(f"Error in _detect_anomalous_network_activity: {e}")
#                 return pd.DataFrame()
#     def _detect_user_anomalies(self, data: pd.DataFrame, specific_detector) -> pd.DataFrame:
#         """Common user anomaly detection logic with enhanced error handling."""
#         data, self.config = apply_all_fixes(data, self.config, 'user')
#         if data.empty:
#             return pd.DataFrame()

#         try:
#             data = ensure_event_category(data)
#             bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "5m"))

#             if bucketed_data.empty:
#                 return pd.DataFrame()

#             # Ensure user column exists
#             if 'user.name' not in bucketed_data.columns:
#                 logger.error("Missing user.name column for user detection")
#                 return pd.DataFrame()

#             # Ensure required feature columns exist
#             required_fields = {
#                 'is_sudo_command': 0,
#                 'is_compiler_activity': 0
#             }

#             for field, default_value in required_fields.items():
#                 if field not in bucketed_data.columns:
#                     bucketed_data[field] = default_value

#             # Aggregate by user
#             agg_dict = {
#                 'event.category': 'count',
#                 'is_sudo_command': 'sum',
#                 'is_compiler_activity': 'sum'
#             }

#             aggregated = bucketed_data.groupby(['time_bucket', 'user.name']).agg(agg_dict).reset_index()
#             aggregated = aggregated.rename(columns={'event.category': 'event_count'})
#             aggregated['@timestamp'] = aggregated['time_bucket']

#             # Run detection
#             models, scalers, baselines = self.model_manager.get_models_for_group("user")
#             results_list = []

#             try:
#                 stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "user")
#                 if not stat_results.empty:
#                     results_list.append(stat_results)
#             except Exception as e:
#                 logger.warning(f"User statistical detection failed: {e}")

#             if models:
#                 try:
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "user")
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                 except Exception as e:
#                     logger.warning(f"User ML detection failed: {e}")

#             # Run specific user detection
#             try:
#                 specific_results = specific_detector(aggregated, self.config)
#                 if not specific_results.empty:
#                     results_list.append(specific_results)
#             except Exception as e:
#                 logger.warning(f"User specific detection failed: {e}")

#             # Combine results
#             if results_list:
#                 combined = results_list[0]
#                 for additional_result in results_list[1:]:
#                     combined = self._safe_combine_results(combined, additional_result)

#                 if 'final_anomaly' not in combined.columns:
#                     combined['final_anomaly'] = False

#                 return combined
#             else:
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Error in _detect_user_anomalies: {e}")
#             return pd.DataFrame()


#     def _detect_metadata_anomalies(self, data: pd.DataFrame, focus: str) -> pd.DataFrame:
#         """Common metadata access anomaly detection logic."""
#         data, self.config = apply_all_fixes(data, self.config, 'metadata')
#         if data.empty:
#             return pd.DataFrame()

#         try:
#             bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))

#             if bucketed_data.empty:
#                 return pd.DataFrame()

#             # Ensure required fields exist
#             required_fields = {
#                 'metadata_service_type': 'unknown',
#                 'potential_cred_harvest': 0,
#                 'user_data_access': 0,

#             }

#             for field, default_value in required_fields.items():
#                 if field not in bucketed_data.columns:
#                     bucketed_data[field] = default_value

#                 if 'process.name' in bucketed_data.columns:
#                     # Filter out rows with null process names first
#                     non_null_mask = bucketed_data['process.name'].notna()
#                     if non_null_mask.sum() > 0:
#                         bucketed_data = bucketed_data[non_null_mask].copy()
#                         logger.info(f"Filtered out {len(bucketed_data) - non_null_mask.sum()} null process names")
#                     else:
#                         # If all are null, keep them but fill
#                         bucketed_data['process.name'] = bucketed_data['process.name'].fillna('unknown')
#                 else:
#                     bucketed_data['process.name'] = 'unknown'

#             if 'user.name' in bucketed_data.columns:
#                 bucketed_data['user.name'] = bucketed_data['user.name'].fillna('unknown')
#             else:
#                 bucketed_data['user.name'] = 'unknown'

#             # Aggregate based on focus
#             if focus == "process":
#                 group_cols = ['time_bucket', 'process.name', 'metadata_service_type']
#             else:  # user
#                 group_cols = ['time_bucket', 'user.name', 'metadata_service_type']
#             bucketed_data['_record_count'] = 1
#             agg_dict = {
#                 '_record_count': 'sum',
#                 'potential_cred_harvest': 'sum',
#                 'user_data_access': 'sum'
#             }

#             aggregated = bucketed_data.groupby(group_cols).agg(agg_dict).reset_index()
#             aggregated = aggregated.rename(columns={'_record_count': 'event_count'})
#             aggregated['@timestamp'] = aggregated['time_bucket']

#             # Run detection
#             models, scalers, baselines = self.model_manager.get_models_for_group("metadata")
#             results_list = []


#             if models:
#                 try:
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "metadata")
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                 except Exception as e:
#                     logger.warning(f"Metadata ML detection failed: {e}")

#             # Run metadata-specific detection
#             try:
#                 metadata_results = detect_metadata_access_anomalies(aggregated, self.config)
#                 if not metadata_results.empty:
#                     results_list.append(metadata_results)
#             except Exception as e:
#                 logger.warning(f"Metadata specific detection failed: {e}")

#             # Combine results
#             if results_list:
#                 combined = results_list[0]
#                 for additional_result in results_list[1:]:
#                     combined = self._safe_combine_results(combined, additional_result)

#                 if 'final_anomaly' not in combined.columns:
#                     combined['final_anomaly'] = False

#                 return combined
#             else:
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Error in _detect_metadata_anomalies: {e}")
#             return pd.DataFrame()

#     def _detect_rare_metadata_process(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect unusual processes accessing metadata services."""
#         return self._detect_metadata_anomalies(data, focus="process")
#     def _detect_anomalous_network_port_activity(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect unusual destination port activity."""
#         if data.empty:
#             return pd.DataFrame()

#         try:
#             # Ensure port column exists
#             if 'destination.port' not in data.columns:
#                 logger.warning("Missing destination.port column, adding default")
#                 data['destination.port'] = 80
#                 logger.info("Added default destination.port column")

#             # Filter for data with meaningful port information
#             port_data = data[data['destination.port'].notna() & (data['destination.port'] > 0)].copy()
#             port_data = ensure_event_category(port_data)
#             if port_data.empty:
#                 logger.warning("No meaningful port data available")
#                 # Create minimal result
#                 result = pd.DataFrame({
#                     '@timestamp': [datetime.utcnow()],
#                     'destination.port': [0],
#                     # 'event_count': [0],
#                     'anomaly_score': [0.0],
#                     'final_anomaly': [False],
#                     'detection_method': ['no_data']
#                 })
#                 return result

#             bucketed_data = self._create_time_buckets_safe(port_data, self.config.get("detection", {}).get("bucket_span", "15m"))

#             if bucketed_data.empty:
#                 return pd.DataFrame()

#             # Aggregate by port
#             agg_dict = {
#                 'event.category': 'count',
#                 'process.name': 'nunique'
#             }

#             aggregated = bucketed_data.groupby(['time_bucket', 'destination.port']).agg(agg_dict).reset_index()
#             aggregated = aggregated.rename(columns={
#                 'event.category': 'event_count',
#                 'process.name': 'process_count'
#             })
#             aggregated['@timestamp'] = aggregated['time_bucket']

#             # Run detection
#             models, scalers, baselines = self.model_manager.get_models_for_group("network")
#             results_list = []

#             try:
#                 stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "network")
#                 if not stat_results.empty:
#                     results_list.append(stat_results)
#             except Exception as e:
#                 logger.warning(f"Port statistical detection failed: {e}")

#             if models:
#                 try:
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "network", useAddress=False)
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                 except Exception as e:
#                     logger.warning(f"Port ML detection failed: {e}")

#             # Combine results
#             if results_list:
#                 final_results = results_list[0]
#                 for additional_result in results_list[1:]:
#                     final_results = self._safe_combine_results(final_results, additional_result)

#                 if 'final_anomaly' not in final_results.columns:
#                     final_results['final_anomaly'] = False

#                 return final_results
#             else:
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Error in _detect_anomalous_network_port_activity: {e}")
#             return pd.DataFrame()

#     def connect_to_elasticsearch(self):
#         """Establish connection to Elasticsearch."""
#         self.es = connect_to_elasticsearch(self.config)

#     def train_models_before_detection(self, data_groups: List[str] = None, force_retrain: bool = False) -> bool:
#         """
#         Train models before detection using the scroll API for 30+ day baselines.

#         Args:
#             data_groups: List of data groups to train models for
#             force_retrain: Whether to retrain even if models exist

#         Returns:
#             bool: Success status
#         """
#         logger.info("Training models before detection")

#         groups_to_train = data_groups if data_groups else list(self.detection_jobs.keys())
#         overall_success = True

#         for data_type in groups_to_train:
#             try:
#                 # Check if models already exist
#                 models_exist = self.model_manager.load_models(data_type)

#                 if models_exist and not force_retrain:
#                     logger.info(f"Models already exist for {data_type}, skipping training")
#                     continue

#                 logger.info(f"Training models for {data_type} group")

#                 # Fetch comprehensive baseline data using scroll API
#                 baseline_data = self._fetch_baseline_data_with_scroll(data_type)

#                 if baseline_data.empty:
#                     logger.error(f"No baseline data available for training {data_type} models")
#                     overall_success = False
#                     continue

#                 # Use specialized training functions from model_manager
#                 if data_type == "process":
#                     models, scalers, baselines = train_process_anomaly_models(baseline_data, self.config)
#                 elif data_type == "network":
#                     models, scalers, baselines = train_network_activity_models(baseline_data, self.config)
#                 elif data_type == "user":
#                     models, scalers, baselines = train_user_behavior_models(baseline_data, self.config)
#                 elif data_type == "discovery":
#                     models, scalers, baselines = train_discovery_command_models(baseline_data, self.config)
#                 elif data_type == "metadata":
#                     models, scalers, baselines = train_metadata_access_models(baseline_data, self.config)
#                 else:
#                     # Fallback to general training
#                     models, scalers = self.model_manager.train_models(baseline_data, data_type)
#                     baselines = self.model_manager.establish_baselines(baseline_data, data_type)

#                 if models or baselines:
#                     # Store in model manager
#                     if models:
#                         self.model_manager.models[data_type] = models
#                     if scalers:
#                         self.model_manager.scalers[data_type] = scalers
#                     if baselines:
#                         self.model_manager.baselines[data_type] = baselines

#                     # Save models to disk - they're already saved by specialized functions
#                     logger.info(f"Successfully trained and saved models for {data_type}")
#                 else:
#                     logger.error(f"Failed to train models for {data_type}")
#                     overall_success = False

#             except Exception as e:
#                 logger.error(f"Error training models for {data_type}: {e}")
#                 import traceback
#                 logger.error(f"Traceback: {traceback.format_exc()}")
#                 overall_success = False

#         return overall_success

#     def _fetch_baseline_data_with_scroll(self, data_type: str) -> pd.DataFrame:
#         """
#         Fetch comprehensive baseline data using scroll API for 30+ days.

#         Args:
#             data_type: Type of data to fetch

#         Returns:
#             pd.DataFrame: Baseline data
#         """
#         if not self.es:
#             logger.error("No Elasticsearch connection available")
#             return pd.DataFrame()

#         try:
#             # Use the fetch_baseline_data function from datamanager
#             baseline_data = fetch_baseline_data(self.es, self.config, data_type)

#             if not baseline_data.empty:
#                 logger.info(f"Retrieved {len(baseline_data)} baseline records for {data_type}")

#                 # Apply preprocessing specific to data type
#                 if data_type == "process":
#                     baseline_data = preprocess_process_data(baseline_data)
#                 elif data_type == "network":
#                     baseline_data = preprocess_network_data(baseline_data)
#                 elif data_type == "user":
#                     baseline_data = preprocess_user_data(baseline_data)
#                 elif data_type == "discovery":
#                     baseline_data = preprocess_discovery_data(baseline_data)
#                 elif data_type == "metadata":
#                     baseline_data = preprocess_metadata_data(baseline_data)

#                 logger.info(f"Preprocessed baseline data shape: {baseline_data.shape}")
#                 return baseline_data
#             else:
#                 logger.warning(f"No baseline data retrieved for {data_type}")
#                 return pd.DataFrame()

#         except Exception as e:
#             logger.error(f"Error fetching baseline data for {data_type}: {e}")
#             import traceback
#             logger.error(f"Traceback: {traceback.format_exc()}")
#             return pd.DataFrame()

#     def run_comprehensive_detection(self, data_groups: List[str] = None,
#                                   use_baseline: bool = True,
#                                   train_models: bool = True,
#                                   force_retrain: bool = False) -> Dict[str, Dict[str, pd.DataFrame]]:
#         """
#         Run comprehensive Linux anomaly detection with improved model training.

#         Args:
#             data_groups: Data groups to process (default: all)
#             use_baseline: Whether to use baseline data
#             train_models: Whether to train models if needed
#             force_retrain: Whether to force retrain existing models

#         Returns:
#             dict: Results organized by data group and job
#         """
#         logger.info("Running comprehensive Linux anomaly detection")

#         # Determine which data groups to process
#         available_groups = list(self.detection_jobs.keys())
#         groups_to_process = data_groups if data_groups else available_groups

#         # Validate groups
#         invalid_groups = [group for group in groups_to_process if group not in available_groups]
#         if invalid_groups:
#             raise ValueError(f"Invalid data groups: {invalid_groups}")

#         # Train models before detection if requested
#         if train_models:
#             logger.info("Training models before detection")
#             training_success = self.train_models_before_detection(groups_to_process, force_retrain)
#             if not training_success:
#                 logger.warning("Some models failed to train, continuing with available models")

#         comprehensive_results = {}

#         # Process each data group
#         for data_type in groups_to_process:
#             logger.info(f"Processing {data_type} data group")

#             try:
#                 group_results = self.run_data_group_detection(
#                     data_type=data_type,
#                     use_baseline=use_baseline,
#                     load_existing_models=True
#                 )

#                 comprehensive_results[data_type] = group_results

#                 # Log summary for this group
#                 total_anomalies = 0
#                 for job_name, results in group_results.items():
#                     if not results.empty and 'final_anomaly' in results.columns:
#                         anomalies = results[results['final_anomaly'] == True]
#                         total_anomalies += len(anomalies)

#                 logger.info(f"Completed {data_type} group: {total_anomalies} total anomalies detected")

#             except Exception as e:
#                 logger.error(f"Error processing {data_type} group: {e}")
#                 comprehensive_results[data_type] = {}

#         # Generate comprehensive report and visualizations
#         if self.config.get("output", {}).get("save_results", True):
#             self._generate_comprehensive_outputs(comprehensive_results)

#         logger.info("Comprehensive Linux anomaly detection completed")
#         return comprehensive_results

#     def validate_real_time_data_quality(data: pd.DataFrame, data_type: str) -> Dict:
#         """
#         CRITICAL FIX: Validate data quality for real-time detection.
#         """
#         validation = {
#             'is_valid': True,
#             'issues': [],
#             'warnings': [],
#             'record_count': len(data),
#             'freshness_ok': False,
#             'required_fields_present': False,
#             'recommendation': 'proceed'
#         }

#         if data.empty:
#             validation['is_valid'] = False
#             validation['issues'].append("No data returned")
#             validation['recommendation'] = 'retry_fetch'
#             return validation

#         # Check data freshness (should be recent for real-time detection)
#         if '@timestamp' in data.columns:
#             try:
#                 timestamps = pd.to_datetime(data['@timestamp'])
#                 latest_timestamp = timestamps.max()
#                 now = pd.Timestamp.now(tz='UTC')

#                 # Data should be no older than 1 hour for real-time detection
#                 max_age_hours = 1
#                 if (now - latest_timestamp).total_seconds() / 3600 > max_age_hours:
#                     validation['warnings'].append(f"Data is older than {max_age_hours} hours")
#                 else:
#                     validation['freshness_ok'] = True
#             except Exception as e:
#                 validation['warnings'].append(f"Could not validate timestamp freshness: {e}")

#         # Check required fields based on data type
#         REQUIRED_FIELDS = {
#             'process': ['process.name', 'host.hostname', '@timestamp'],
#             'network': ['destination.ip', 'destination.port', '@timestamp'],
#             'user': ['user.name', '@timestamp'],
#             'discovery': ['process.name', '@timestamp'],
#             'metadata': ['destination.ip', '@timestamp']
#         }

#         required_fields = REQUIRED_FIELDS.get(data_type, [])
#         missing_fields = [field for field in required_fields if field not in data.columns]

#         if missing_fields:
#             validation['is_valid'] = False
#             validation['issues'].append(f"Missing required fields: {missing_fields}")
#         else:
#             validation['required_fields_present'] = True

#         # Check for reasonable record count
#         min_records = 1
#         max_records = 10000  # Too many records might indicate a query issue

#         if len(data) < min_records:
#             validation['is_valid'] = False
#             validation['issues'].append(f"Too few records: {len(data)} < {min_records}")
#         elif len(data) > max_records:
#             validation['warnings'].append(f"Very large dataset: {len(data)} records")

#         # Determine overall recommendation
#         if not validation['is_valid']:
#             validation['recommendation'] = 'fix_data_source'
#         elif len(validation['warnings']) > 2:
#             validation['recommendation'] = 'review_warnings'
#         else:
#             validation['recommendation'] = 'proceed'

#         return validation
#     def validate_training_detection_compatibility(training_data: pd.DataFrame,
#                                             detection_data: pd.DataFrame,
#                                             data_type: str) -> Dict:
#         """
#         CRITICAL FIX: Validate compatibility between training and detection phases.
#         """
#         validation_report = {
#             'compatible': True,
#             'issues': [],
#             'warnings': [],
#             'training_features': set(),
#             'detection_features': set(),
#             'missing_in_detection': [],
#             'feature_distribution_match': {},
#             'recommendation': 'proceed'
#         }

#         if training_data.empty or detection_data.empty:
#             validation_report['compatible'] = False
#             validation_report['issues'].append("Empty training or detection data")
#             validation_report['recommendation'] = 'retrain_models'
#             return validation_report

#         # Extract numeric features from both datasets
#         training_numeric = training_data.select_dtypes(include=[np.number]).columns
#         detection_numeric = detection_data.select_dtypes(include=[np.number]).columns

#         validation_report['training_features'] = set(training_numeric)
#         validation_report['detection_features'] = set(detection_numeric)
#         validation_report['missing_in_detection'] = list(set(training_numeric) - set(detection_numeric))

#         # Check for missing features
#         if validation_report['missing_in_detection']:
#             validation_report['compatible'] = False
#             validation_report['issues'].append(f"Features missing in detection: {validation_report['missing_in_detection']}")

#         # Check feature distributions for common features
#         common_features = set(training_numeric) & set(detection_numeric)
#         for feature in common_features:
#             try:
#                 # Compare basic statistics
#                 train_stats = training_data[feature].describe()
#                 detect_stats = detection_data[feature].describe()

#                 # Check if distributions are reasonably similar (within 50% variance)
#                 mean_diff = abs(train_stats['mean'] - detect_stats['mean']) / max(abs(train_stats['mean']), 1e-6)
#                 std_diff = abs(train_stats['std'] - detect_stats['std']) / max(abs(train_stats['std']), 1e-6)

#                 if mean_diff > 0.5 or std_diff > 0.5:
#                     validation_report['warnings'].append(f"Feature {feature} has different distribution in detection vs training")
#                     validation_report['feature_distribution_match'][feature] = False
#                 else:
#                     validation_report['feature_distribution_match'][feature] = True

#             except Exception as e:
#                 validation_report['warnings'].append(f"Could not compare feature {feature}: {e}")

#         # Determine recommendation
#         if len(validation_report['issues']) > 0:
#             validation_report['recommendation'] = 'fix_features'
#         elif len(validation_report['warnings']) > len(common_features) * 0.3:  # >30% features have issues
#             validation_report['recommendation'] = 'review_data'
#         else:
#             validation_report['recommendation'] = 'proceed'

#         return validation_report

#     def create_feature_registry(data_type: str) -> Dict:
#         """
#         CRITICAL FIX: Create a comprehensive feature registry for validation.
#         """
#         registry = {
#             'data_type': data_type,
#             'last_updated': pd.Timestamp.now().isoformat(),
#             'features': {}
#         }

#         # Define feature metadata for validation
#         FEATURE_REGISTRY = {
#             'process': {
#                 'command_length': {
#                     'source': 'process.command_line',
#                     'calculation': 'len(command_line)',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 },
#                 'command_word_count': {
#                     'source': 'process.command_line',
#                     'calculation': 'len(command_line.split())',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 },
#                 'pid_difference': {
#                     'source': ['process.pid', 'process.parent.pid'],
#                     'calculation': 'abs(pid - parent_pid)',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 },
#                 'has_pipe': {
#                     'source': 'process.command_line',
#                     'calculation': 'contains_pipe_char',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 },
#                 'hour_sin': {
#                     'source': '@timestamp',
#                     'calculation': 'sin(2*pi*hour/24)',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 }
#             },
#             'network': {
#                 'destination.port': {
#                     'source': 'destination.port',
#                     'calculation': 'direct_field',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 },
#                 'network.bytes': {
#                     'source': 'network.bytes',
#                     'calculation': 'direct_field',
#                     'real_time_available': True,
#                     'latency_ms': 1,
#                     'fallback_value': 0
#                 }
#             }
#         }

#         registry['features'] = FEATURE_REGISTRY.get(data_type, {})
#         return registry

#     def monitor_detection_performance(results: pd.DataFrame,
#                                     data_type: str,
#                                     processing_time_ms: float) -> Dict:
#         """
#         CRITICAL FIX: Monitor detection performance and alert on issues.
#         """
#         metrics = {
#             'data_type': data_type,
#             'timestamp': pd.Timestamp.now().isoformat(),
#             'processing_time_ms': processing_time_ms,
#             'records_processed': len(results),
#             'anomalies_detected': 0,
#             'anomaly_rate': 0.0,
#             'performance_issues': [],
#             'data_quality_issues': [],
#             'status': 'healthy'
#         }

#         if not results.empty:
#             if 'final_anomaly' in results.columns:
#                 metrics['anomalies_detected'] = results['final_anomaly'].sum()
#                 metrics['anomaly_rate'] = metrics['anomalies_detected'] / len(results)

#         # Check for performance issues
#         max_processing_time = 500  # 500ms threshold
#         if processing_time_ms > max_processing_time:
#             metrics['performance_issues'].append(f"Processing time {processing_time_ms}ms exceeds {max_processing_time}ms threshold")
#             metrics['status'] = 'degraded'

#         # Check for data quality issues
#         if len(results) == 0:
#             metrics['data_quality_issues'].append("No data returned from detection")
#             metrics['status'] = 'error'

#         # Check for anomaly rate issues
#         if metrics['anomaly_rate'] > 0.1:  # >10% anomaly rate is suspicious
#             metrics['data_quality_issues'].append(f"High anomaly rate: {metrics['anomaly_rate']:.1%}")
#             metrics['status'] = 'warning'

#         return metrics
#     def run_data_group_detection(self, data_type: str, jobs: List[str] = None,
#                                 use_baseline: bool = True, load_existing_models: bool = True) -> Dict[str, pd.DataFrame]:
#         """Enhanced detection with proper error handling."""
#         logger.info(f"Running {data_type} group detection")

#         if data_type not in self.detection_jobs:
#             raise ValueError(f"Unknown data type: {data_type}")

#         # Load models if requested
#         if load_existing_models:
#             try:
#                 models_loaded = self.model_manager.load_models(data_type)
#                 if models_loaded:
#                     logger.info(f"Loaded existing models for {data_type}")
#                 else:
#                     logger.warning(f"No existing models found for {data_type}")
#             except Exception as e:
#                 logger.error(f"Error loading models for {data_type}: {e}")

#         # Fetch and preprocess data
#         try:
#             data = self._fetch_data_for_type(data_type)
#             if data.empty:
#                 logger.warning(f"No data available for {data_type} group")
#                 return {}

#             # Import and analyze feature availability
#             from detection_methods import analyze_feature_availability
#             logger.info(f"Analyzing feature availability for {data_type} data")
#             feature_analysis = analyze_feature_availability(data, data_type)

#             if not feature_analysis.get('real_time_compatible', False):
#                 logger.warning(f"Data quality issues for {data_type}: {feature_analysis.get('fallback_strategy', 'unknown')}")
#                 # Continue with reduced functionality rather than failing completely

#             # Determine which jobs to run
#             available_jobs = list(self.detection_jobs[data_type].keys())
#             jobs_to_run = jobs if jobs else available_jobs

#             # Validate jobs
#             invalid_jobs = [job for job in jobs_to_run if job not in available_jobs]
#             if invalid_jobs:
#                 raise ValueError(f"Invalid jobs for {data_type}: {invalid_jobs}")

#             # Run each job with error handling
#             results = {}
#             baselines_established = False

#             for job_name in jobs_to_run:
#                 try:
#                     job_method = self.detection_jobs[data_type][job_name]["method"]

#                     # Handle feature analysis in job execution
#                     if not feature_analysis.get('real_time_compatible', False):
#                         logger.warning(f"Skipping ML-heavy job {job_name} due to feature incompatibility")
#                         results[job_name] = pd.DataFrame()
#                         continue

#                     job_results = job_method(data)

#                     # Establish baselines once on the first successful result
#                     if (use_baseline and not baselines_established and
#                         not job_results.empty and hasattr(job_results, 'columns') and 'event_count' in job_results.columns):
#                         try:
#                             self._establish_baselines_for_aggregated_data(data_type, job_results)
#                             baselines_established = True
#                         except Exception as baseline_error:
#                             logger.warning(f"Could not establish baselines for {data_type}: {baseline_error}")

#                     results[job_name] = job_results
#                     logger.info(f"Completed {job_name}: {len(job_results)} records processed")

#                 except Exception as e:
#                     logger.error(f"Error in {job_name}: {e}")
#                     results[job_name] = pd.DataFrame()

#             return results

#         except Exception as e:
#             logger.error(f"Error processing {data_type} group: {e}")
#             return {}
#     def _fetch_data_for_type(self, data_type: str, timeframe: Dict[str, str] = None) -> pd.DataFrame:
#         """Fetch data for a specific data type with improved error handling."""

#         # CRITICAL FIX: Use same time range logic as training
#         if timeframe is None:
#             try:
#                 # Use training configuration for consistency
#                 training_config = get_training_configuration(data_type)
#                 detection_days = training_config.get("detection_period_days", 1)

#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(days=detection_days)
#                 timeframe = {
#                     "gte": start_time.isoformat(),
#                     "lte": end_time.isoformat()
#                 }
#                 logger.info(f"Using detection period: {detection_days} days for {data_type}")
#             except Exception as e:
#                 logger.warning(f"Could not get detection time range, using defaults: {e}")
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=1)
#                 timeframe = {
#                     "gte": start_time.isoformat(),
#                     "lte": end_time.isoformat()
#                 }

#         # Fetch data using same functions as training but with detection time range
#         if data_type == "process":
#             return fetch_process_data(self.es, self.config, timeframe, query_size=10000)
#         elif data_type == "network":
#             return fetch_network_activity_data(self.es, self.config, timeframe, query_size=10000)
#         elif data_type == "user":
#             return fetch_user_activity_data(self.es, self.config, timeframe, query_size=10000)
#         elif data_type == "discovery":
#             return fetch_discovery_commands_data(self.es, self.config, timeframe, query_size=10000)
#         elif data_type == "metadata":
#             return fetch_metadata_access_data(self.es, self.config, timeframe, query_size=10000)
#         else:
#             logger.error(f"Unknown data type: {data_type}")
#             return pd.DataFrame()
#     def _establish_baselines_for_aggregated_data(self, data_type: str, aggregated_data: pd.DataFrame):
#         """Establish baselines for aggregated data with event_count column."""
#         try:
#             if 'event_count' not in aggregated_data.columns:
#                 logger.warning(f"No event_count column in aggregated data for {data_type}")
#                 return

#             if aggregated_data.empty:
#                 logger.warning(f"Empty aggregated data for {data_type} baseline establishment")
#                 return

#             # Use the model manager's establish_baselines method
#             baselines = self.model_manager.establish_baselines(aggregated_data, data_type)

#             # Store baselines
#             if data_type not in self.model_manager.baselines:
#                 self.model_manager.baselines[data_type] = {}

#             self.model_manager.baselines[data_type].update(baselines)

#             logger.info(f"Established baselines for {data_type} on aggregated data with {len(aggregated_data)} records")

#         except Exception as e:
#             logger.error(f"Error establishing baselines for {data_type}: {e}")


#     def _create_time_buckets_safe(self, data: pd.DataFrame, bucket_span: str) -> pd.DataFrame:
#         """Create time buckets with dynamic adjustment for temporal variation."""
#         try:
#             if data.empty or '@timestamp' not in data.columns:
#                 return pd.DataFrame()

#             # Calculate data time span
#             timestamps = pd.to_datetime(data['@timestamp'])
#             time_span_seconds = (timestamps.max() - timestamps.min()).total_seconds()
#             time_span_hours = time_span_seconds / 3600
#             record_count = len(data)

#             # Determine minimum buckets needed for meaningful analysis
#             min_buckets = max(10, int(record_count / 100))  # At least 10 buckets or 1% of records
#             min_buckets = min(min_buckets, 50)  # Cap at 50 buckets

#             # Calculate ideal bucket size based on time span and desired buckets
#             if time_span_seconds > 0:
#                 ideal_bucket_seconds = time_span_seconds / min_buckets

#                 # Enhanced bucket size options with proper pandas format
#                 bucket_options = [
#                     (1, "1S"),       # 1 second
#                     (5, "5S"),       # 5 seconds
#                     (10, "10S"),     # 10 seconds
#                     (30, "30S"),     # 30 seconds
#                     (60, "1min"),    # 1 minute
#                     (120, "2min"),   # 2 minutes
#                     (300, "5min"),   # 5 minutes
#                     (600, "10min"),  # 10 minutes
#                     (900, "15min"),  # 15 minutes
#                     (1800, "30min"), # 30 minutes
#                     (3600, "1H"),    # 1 hour
#                 ]

#                 # Select optimal bucket size
#                 adjusted_bucket_span = bucket_span  # Default
#                 for seconds, span_str in bucket_options:
#                     expected_buckets = time_span_seconds / seconds
#                     if expected_buckets >= min_buckets:
#                         adjusted_bucket_span = span_str
#                         break

#                 # If still using default, force smaller buckets for short time spans
#                 if adjusted_bucket_span == bucket_span and time_span_hours < 2:
#                     # For your 1.1 hour data, this would select 10s or 30s buckets
#                     if time_span_seconds < 300:  # Less than 5 minutes
#                         adjusted_bucket_span = "5S"
#                     elif time_span_seconds < 1800:  # Less than 30 minutes
#                         adjusted_bucket_span = "30S"
#                     elif time_span_seconds < 3600:  # Less than 1 hour
#                         adjusted_bucket_span = "1min"
#                     else:  # 1-2 hours
#                         adjusted_bucket_span = "2min"
#             else:
#                 adjusted_bucket_span = "1S"
#                 logger.warning("No time span detected, using 1-second buckets")

#             if adjusted_bucket_span != bucket_span:
#                 logger.info(f"Adjusted bucket size from {bucket_span} to {adjusted_bucket_span} for {time_span_hours:.1f}h data span")
#                 logger.info(f"Target: {min_buckets} buckets for {record_count} records")

#             # Import and use the bucket creation function
#             from datamanager import create_time_buckets
#             # Pass min_buckets as integer, not string
#             result = create_time_buckets(data, "@timestamp", adjusted_bucket_span, min_buckets=int(min_buckets))

#             # Validate bucket creation
#             if 'time_bucket' in result.columns:
#                 unique_buckets = result['time_bucket'].nunique()

#                 # If still too few buckets, add warning and create synthetic buckets
#                 if unique_buckets < min_buckets / 2:
#                     logger.warning(f"Only {unique_buckets} time buckets created (target: {min_buckets})")

#                     # Add micro-buckets for better granularity
#                     if unique_buckets > 0 and record_count > min_buckets:
#                         result = result.sort_values('@timestamp')
#                         # Create sub-buckets within each time bucket
#                         result['micro_bucket_id'] = result.groupby('time_bucket').cumcount()
#                         sub_buckets_per_main = max(2, int(min_buckets / unique_buckets))
#                         result['micro_bucket'] = result['micro_bucket_id'] % sub_buckets_per_main
#                         result['enhanced_bucket'] = (
#                             result['time_bucket'].astype(str) + '_' +
#                             result['micro_bucket'].astype(str)
#                         )
#                         enhanced_buckets = result['enhanced_bucket'].nunique()
#                         logger.info(f"Created {enhanced_buckets} enhanced buckets using micro-bucketing")
#                 else:
#                     logger.info(f"Successfully created {unique_buckets} time buckets")
#             else:
#                 logger.error("time_bucket column not created")

#             return result

#         except Exception as e:
#             logger.error(f"Error creating time buckets: {e}")
#             import traceback
#             logger.error(traceback.format_exc())
#             return pd.DataFrame()
#     # def _create_time_buckets_safe(self, data: pd.DataFrame, bucket_span: str) -> pd.DataFrame:
#     #     """Create time buckets with dynamic adjustment for temporal variation."""
#     #     try:
#     #         if data.empty or '@timestamp' not in data.columns:
#     #             return pd.DataFrame()

#     #         # Calculate data time span
#     #         timestamps = pd.to_datetime(data['@timestamp'])
#     #         time_span_hours = (timestamps.max() - timestamps.min()).total_seconds() / 3600

#     #         # Adjust bucket size based on data span
#     #         if time_span_hours < 0.5:  # Less than 30 minutes
#     #             adjusted_bucket_span = "5min"
#     #         elif time_span_hours < 2:  # Less than 2 hours
#     #             adjusted_bucket_span = "15min"
#     #         elif time_span_hours < 8:  # Less than 8 hours
#     #             adjusted_bucket_span = "30min"
#     #         else:
#     #             adjusted_bucket_span = bucket_span  # Use original

#     #         if adjusted_bucket_span != bucket_span:
#     #             logger.info(f"Adjusted bucket size from {bucket_span} to {adjusted_bucket_span} for {time_span_hours:.1f}h data span")
#     #             bucket_span = adjusted_bucket_span

#     #         # Continue with existing bucket creation logic...
#     #         from datamanager import create_time_buckets
#     #         result = create_time_buckets(data, "@timestamp", bucket_span)

#     #         # Check if adjustment helped
#     #         unique_buckets = result['time_bucket'].nunique()
#     #         if unique_buckets == 1 and len(result) > 100:
#     #             logger.warning(f"Only 1 unique time bucket for {len(result)} records even after adjustment - data may lack temporal variation")

#     #         return result

#     #     except Exception as e:
#     #         logger.error(f"Error creating time buckets: {e}")
#     #         return pd.DataFrame()
#     def _safe_combine_results(self, result1: pd.DataFrame, result2: pd.DataFrame) -> pd.DataFrame:
#         """Safely combine detection results with improved anomaly flag handling."""
#         try:
#             if result1.empty:
#                 return result2.copy()
#             if result2.empty:
#                 return result1.copy()

#             common_columns = list(set(result1.columns) & set(result2.columns))
#             if not common_columns:
#                 # If no common columns, concatenate with all columns
#                 combined = pd.concat([result1, result2], ignore_index=True, sort=False)
#             else:
#                 # Align data types for common columns
#                 for col in common_columns:
#                     if result1[col].dtype != result2[col].dtype:
#                         # Convert both to string to avoid type conflicts
#                         result1[col] = result1[col].astype(str)
#                         result2[col] = result2[col].astype(str)

#                 # Concatenate the DataFrames
#                 combined = pd.concat([result1, result2], ignore_index=True, sort=False)

#             # Handle anomaly flags - CRITICAL FIX
#             anomaly_columns = [col for col in combined.columns if 'anomaly' in col.lower()]

#             # Initialize final_anomaly column if it doesn't exist
#             if 'final_anomaly' not in combined.columns:
#                 combined['final_anomaly'] = False

#             # Set final_anomaly to True if any anomaly flag is True
#             for col in anomaly_columns:
#                 if col != 'final_anomaly':  # Skip the final_anomaly column itself
#                     # Convert column to boolean safely
#                     if combined[col].dtype != bool:
#                         try:
#                             combined[col] = combined[col].astype(bool)
#                         except:
#                             combined[col] = combined[col].astype(str).str.lower() == 'true'

#                     # Update final_anomaly flag
#                     combined['final_anomaly'] = combined['final_anomaly'] | combined[col]

#             # Update anomaly score if needed
#             if 'anomaly_score' not in combined.columns and any(col for col in combined.columns if 'score' in col.lower()):
#                 score_columns = [col for col in combined.columns if 'score' in col.lower() and col != 'anomaly_score']
#                 if score_columns:
#                     # Use the first available score column
#                     combined['anomaly_score'] = combined[score_columns[0]]

#             # Remove duplicates if possible
#             if '@timestamp' in combined.columns:
#                 duplicate_cols = ['@timestamp']
#                 if 'process.name' in combined.columns:
#                     duplicate_cols.append('process.name')
#                 elif 'user.name' in combined.columns:
#                     duplicate_cols.append('user.name')

#                 before_count = len(combined)
#                 combined = combined.drop_duplicates(subset=duplicate_cols, keep='first')
#                 after_count = len(combined)

#                 if before_count != after_count:
#                     logger.info(f"Removed {before_count - after_count} duplicate records")

#             return combined

#         except Exception as e:
#             logger.error(f"Error in safe combine results: {e}")
#             return result1.copy() if not result1.empty else result2.copy()
#     def _extract_entity_from_row(self, row, data_type):
#         """
#         Extract the primary entity identifier from an anomaly row based on data type.

#         Args:
#             row (pd.Series): A single anomaly record
#             data_type (str): Type of data the anomaly belongs to

#         Returns:
#             str: Entity identifier (process name, user name, etc.)
#         """
#         try:
#             if data_type == 'process':
#                 if 'process.name' in row:
#                     return str(row['process.name'])
#                 elif 'process.executable' in row:
#                     # Extract basename from executable path
#                     executable = str(row['process.executable'])
#                     return os.path.basename(executable) if executable else "unknown_process"

#             elif data_type == 'network':
#                 if 'destination.ip' in row:
#                     dest_ip = str(row['destination.ip'])
#                     dest_port = str(row.get('destination.port', ''))
#                     if dest_port:
#                         return f"{dest_ip}:{dest_port}"
#                     return dest_ip
#                 elif 'destination.ip' in row:
#                     return str(row['destination.ip'])

#             elif data_type == 'user':
#                 if 'user.name' in row:
#                     return str(row['user.name'])

#             elif data_type == 'discovery':
#                 if 'process.name' in row:
#                     return str(row['process.name'])
#                 elif 'discovery_category' in row:
#                     return f"{row['discovery_category']} discovery"

#             elif data_type == 'metadata':
#                 if 'process.name' in row and 'metadata_service_type' in row:
#                     return f"{row['process.name']} → {row['metadata_service_type']}"
#                 elif 'metadata_service_type' in row:
#                     return str(row['metadata_service_type'])
#                 elif 'process.name' in row:
#                     return str(row['process.name'])

#             # Default fallbacks
#             for key in ['process.name', 'user.name', 'destination.ip', 'host.hostname']:
#                 if key in row and not pd.isna(row[key]):
#                     return str(row[key])

#             return "unknown_entity"

#         except Exception as e:
#             self.logger.warning(f"Error extracting entity from row: {e}")
#             return "unknown_entity"


#     def _generate_anomaly_description(self, anomaly, data_type=None):
#         """
#         Generate a detailed description for a detected anomaly with improved handling
#         of missing data, job-specific information, and optional LLM enhancement.

#         Args:
#             anomaly (pd.Series): A single anomaly record
#             data_type (str, optional): Type of data the anomaly belongs to

#         Returns:
#             str: Human-readable description of the anomaly
#         """
#         description = []

#         try:
#             # Get basic anomaly information
#             timestamp = anomaly.get('@timestamp', 'Unknown time')
#             if isinstance(timestamp, pd.Timestamp):
#                 timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
#             else:
#                 timestamp_str = str(timestamp)

#             # Better handling of detection job name
#             job_name = anomaly.get('detection_job', '')
#             if not job_name and 'job_id' in anomaly:
#                 job_name = anomaly['job_id']

#             # Format the job name nicely
#             if job_name:
#                 job_display = job_name.replace('v3_linux_', '').replace('_', ' ').title()
#             else:
#                 job_display = "Unknown Detection"

#             # Get score with better handling
#             score = 0.0
#             if 'combined_score' in anomaly and not pd.isna(anomaly['combined_score']):
#                 score = float(anomaly['combined_score'])
#             elif 'anomaly_score' in anomaly and not pd.isna(anomaly['anomaly_score']):
#                 score = float(anomaly['anomaly_score'])

#             description.append(f"[{timestamp_str}] {job_display} (Score: {score:.2f})")

#             # Add entity information based on data type
#             if data_type is None:
#                 if 'data_type' in anomaly:
#                     data_type = anomaly['data_type']
#                 else:
#                     # Try to infer data type from detection job
#                     if 'process' in job_name:
#                         data_type = 'process'
#                     elif 'network' in job_name:
#                         data_type = 'network'
#                     elif 'user' in job_name:
#                         data_type = 'user'
#                     elif 'discovery' in job_name:
#                         data_type = 'discovery'
#                     elif 'metadata' in job_name:
#                         data_type = 'metadata'
#                     else:
#                         data_type = 'unknown'

#             # Add job-specific context
#             if 'user' in job_name.lower():
#                 if job_name == 'v3_linux_anomalous_user_name':
#                     description.append("Unusual user activity detected")
#                 elif job_name == 'v3_linux_rare_sudo_user':
#                     description.append("Unusual sudo privileges detected")
#                 elif job_name == 'v3_linux_rare_user_compiler':
#                     description.append("Unusual compiler activity detected")

#             # Add entity-specific details with better NaN handling
#             if data_type == 'process':
#                 process_name = None

#                 # Try different ways to extract process name
#                 if 'process.name' in anomaly and not pd.isna(anomaly['process.name']):
#                     process_name = anomaly['process.name']
#                 elif isinstance(anomaly.get('process'), dict) and 'name' in anomaly['process']:
#                     if not pd.isna(anomaly['process']['name']) and anomaly['process']['name'] != 0.0:
#                         process_name = anomaly['process']['name']

#                 if process_name:
#                     description.append(f"Process: {process_name}")

#                 if 'process.command_line' in anomaly and not pd.isna(anomaly['process.command_line']):
#                     cmd = anomaly['process.command_line']
#                     # Truncate long command lines
#                     if len(cmd) > 100:
#                         cmd = cmd[:97] + '...'
#                     description.append(f"Command: {cmd}")

#             elif data_type == 'user':
#                 user_name = None

#                 # Try different ways to extract user name
#                 if 'user.name' in anomaly and not pd.isna(anomaly['user.name']):
#                     user_name = anomaly['user.name']
#                 elif isinstance(anomaly.get('user'), dict) and 'name' in anomaly['user']:
#                     if not pd.isna(anomaly['user']['name']):
#                         user_name = anomaly['user']['name']

#                 if user_name:
#                     description.append(f"User: {user_name}")

#                 # Add context about user activity
#                 is_root = False
#                 if 'is_root_user' in anomaly and anomaly['is_root_user']:
#                     is_root = True
#                 elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_root_user'):
#                     is_root = True
#                 elif user_name == 'root':
#                     is_root = True

#                 if is_root:
#                     description.append("Root privileges used")

#                 is_sudo = False
#                 if 'is_sudo_command' in anomaly and anomaly['is_sudo_command']:
#                     is_sudo = True
#                 elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_sudo_command'):
#                     is_sudo = True

#                 if is_sudo:
#                     description.append("Sudo command execution")

#                 is_compiler = False
#                 if 'is_compiler_activity' in anomaly and anomaly['is_compiler_activity']:
#                     is_compiler = True
#                 elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_compiler_activity'):
#                     is_compiler = True

#                 if is_compiler:
#                     description.append("Compiler activity detected")

#             # Add host information
#             host_name = None
#             if 'host.hostname' in anomaly and not pd.isna(anomaly['host.hostname']):
#                 host_name = anomaly['host.hostname']
#             elif isinstance(anomaly.get('host'), dict) and 'name' in anomaly['host']:
#                 if not pd.isna(anomaly['host']['name']):
#                     host_name = anomaly['host']['name']

#             if host_name:
#                 description.append(f"Host: {host_name}")

#             # Add detection method info if available
#             methods = []

#             # Check direct attributes
#             if 'ml_detection' in anomaly and anomaly['ml_detection']:
#                 methods.append("Machine Learning")
#             if 'stat_detection' in anomaly and anomaly['stat_detection']:
#                 methods.append("Statistical")
#             if 'ts_detection' in anomaly and anomaly['ts_detection']:
#                 methods.append("Time Series")

#             # Check context dictionary
#             if isinstance(anomaly.get('context'), dict):
#                 method = anomaly['context'].get('detection_method', '')
#                 if method and method not in methods:
#                     if method == 'machine_learning':
#                         methods.append("Machine Learning")
#                     elif method == 'statistical':
#                         methods.append("Statistical")
#                     elif method == 'time_series':
#                         methods.append("Time Series")
#                     else:
#                         methods.append(method.replace('_', ' ').title())

#             if methods:
#                 description.append(f"Detection Methods: {', '.join(methods)}")

#             # Add reason if available
#             if 'anomaly_reason' in anomaly and anomaly['anomaly_reason']:
#                 description.append(f"Reason: {anomaly['anomaly_reason']}")

#             # Add features with high contribution to anomaly
#             high_deviation_features = []

#             # Check for deviation in direct attributes
#             for col in anomaly.index if hasattr(anomaly, 'index') else []:
#                 if col.endswith('_deviation') and not pd.isna(anomaly[col]) and float(anomaly[col]) > 2.0:
#                     feature_name = col.replace('_deviation', '')
#                     high_deviation_features.append(f"{feature_name} ({float(anomaly[col]):.2f}x)")

#             # Check features that might be in context
#             if isinstance(anomaly.get('features'), dict):
#                 for feature, value in anomaly['features'].items():
#                     if feature.endswith('_deviation') and float(value) > 2.0:
#                         feature_name = feature.replace('_deviation', '')
#                         high_deviation_features.append(f"{feature_name} ({float(value):.2f}x)")

#             if high_deviation_features:
#                 description.append(f"Anomalous Features: {', '.join(high_deviation_features[:3])}")

#             # Add event count information if available
#             if 'event_count' in anomaly and not pd.isna(anomaly['event_count']):
#                 event_count = int(anomaly['event_count'])
#                 if event_count > 0:
#                     description.append(f"Event Count: {event_count}")

#             # Add temporal context if available
#             is_business_hours = False
#             if 'is_business_hours' in anomaly:
#                 is_business_hours = bool(anomaly['is_business_hours'])
#             elif isinstance(anomaly.get('context'), dict) and 'is_business_hours' in anomaly['context']:
#                 is_business_hours = bool(anomaly['context']['is_business_hours'])

#             if not is_business_hours:
#                 description.append("Activity occurred outside business hours")

#             # Add job-specific summary based on data
#             if data_type == 'user':
#                 event_count = int(anomaly.get('event_count', 0))
#                 if job_name == 'v3_linux_anomalous_user_name' and event_count > 200:
#                     description.append(f"Unusually high volume of user activity ({event_count} events)")
#                 elif job_name == 'v3_linux_rare_sudo_user':
#                     description.append("Potential privilege escalation attempt")
#                 elif job_name == 'v3_linux_rare_user_compiler':
#                     description.append("Potential unauthorized code compilation")

#             # Compile the basic description
#             basic_description = "\n".join(description)

#             # If Ollama is available, enhance the description with LLM
#             global OLLAMA_AVAILABLE, ollama_client
#             if 'OLLAMA_AVAILABLE' in globals() and OLLAMA_AVAILABLE and self.config.get("llm", {}).get("enhance_descriptions", False):
#                 try:
#                     # Extract key information as context for the LLM
#                     entity = "unknown"
#                     if data_type == 'process' and process_name:
#                         entity = process_name
#                     elif data_type == 'user' and user_name:
#                         entity = user_name
#                     elif data_type == 'network' and 'destination.ip' in anomaly:
#                         entity = anomaly['destination.ip']

#                     # Create a condensed description of the anomaly for the prompt
#                     anomaly_summary = f"{job_display} - {entity} - Score: {score:.2f}"
#                     if methods:
#                         anomaly_summary += f" - Methods: {', '.join(methods)}"

#                     # Create prompt for the LLM
#                     prompt = f"""
#                     You are a cybersecurity analyst describing a detected Linux anomaly.
#                     Here is the technical information about the anomaly:

#                     Timestamp: {timestamp_str}
#                     Type: {data_type} anomaly ({job_display})
#                     Entity: {entity}
#                     Score: {score:.2f}

#                     Technical details:
#                     {basic_description}

#                     Please provide a natural language description of this anomaly that:
#                     1. Explains what was detected in simple terms
#                     2. Indicates the potential security implications
#                     3. Suggests possible next steps for investigation
#                     4. Keeps the length under 200 words
#                     5. Uses a professional but accessible tone

#                     Description:
#                     """

#                     # Call Ollama
#                     response = ollama_client.generate(
#                         model=self.config.get("llm", {}).get("model", "llama3"),
#                         prompt=prompt,
#                         max_tokens=300,
#                         temperature=0.2
#                     )

#                     # If we got a valid response, return the enhanced description
#                     if response and hasattr(response, 'get') and response.get('response'):
#                         # Combine the basic and enhanced descriptions
#                         return basic_description + "\n\n### LLM Analysis ###\n" + response['response'].strip()

#                 except Exception as llm_error:
#                     self.logger.warning(f"LLM enhancement failed: {llm_error}")
#                     # Fall back to basic description if LLM fails

#             # Return the basic description if LLM is not available or fails
#             return basic_description

#         except Exception as e:
#             self.logger.warning(f"Error generating anomaly description: {e}")
#             return f"Anomaly detected at {timestamp_str if 'timestamp_str' in locals() else 'unknown time'}"

#     def _detect_anomalous_process_all_hosts(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect processes unusual to all Linux hosts with enhanced processing."""
#         if data.empty:
#             logger.info("Empty data provided to _detect_anomalous_process_all_hosts")
#             return pd.DataFrame()

#         try:
#             logger.debug(f"Starting anomaly detection for {len(data)} records")

#             # Create time buckets for analysis with safe wrapper
#             bucketed_data = self._create_time_buckets_safe(
#                 data,
#                 self.config.get("detection", {}).get("bucket_span", "15m")
#             )

#             # Enhanced empty check with type validation
#             if isinstance(bucketed_data, dict):
#                 if not bucketed_data:
#                     logger.warning("Time bucketing returned empty dictionary")
#                     return pd.DataFrame()
#                 # Convert dict to DataFrame if needed
#                 try:
#                     bucketed_data = pd.DataFrame.from_dict(bucketed_data, orient='index')
#                 except Exception as e:
#                     logger.error(f"Failed to convert dict to DataFrame: {e}")
#                     return pd.DataFrame()

#             if bucketed_data.empty:
#                 logger.warning("No data after time bucketing for anomalous_process_all_hosts")
#                 return pd.DataFrame()

#             logger.debug(f"After time bucketing: {len(bucketed_data)} records")

#             # Ensure required columns exist with fallbacks
#             required_columns = ['process.name', 'host.hostname', '@timestamp']
#             for col in required_columns:
#                 if col not in bucketed_data.columns:
#                     if col == 'process.name':
#                         logger.error("Missing critical process.name column for process detection")
#                         return pd.DataFrame()
#                     elif col == 'host.hostname':
#                         logger.warning("Missing host.hostname column, adding default")
#                         bucketed_data['host.hostname'] = 'unknown_host'
#                     elif col == '@timestamp':
#                         if 'time_bucket' in bucketed_data.columns:
#                             bucketed_data['@timestamp'] = bucketed_data['time_bucket']
#                         else:
#                             logger.warning("Missing timestamp column, using current time")
#                             bucketed_data['@timestamp'] = pd.Timestamp.now(tz='UTC')

#             # Ensure event_count column exists
#             if 'event_count' not in bucketed_data.columns:
#                 logger.debug("Adding default event_count column")
#                 bucketed_data['event_count'] = 1

#             # Ensure time_bucket column exists for grouping
#             if 'time_bucket' not in bucketed_data.columns:
#                 if '@timestamp' in bucketed_data.columns:
#                     # Create time buckets from timestamp
#                     bucket_span = self.config.get("detection", {}).get("bucket_span", "15m")
#                     freq_map = {
#                         "1m": "1T", "5m": "5T", "15m": "15T", "30m": "30T",
#                         "1h": "1H", "2h": "2H", "6h": "6H", "12h": "12H",
#                         "1d": "1D", "1w": "1W"
#                     }
#                     freq = freq_map.get(bucket_span, "15T")
#                     bucketed_data['time_bucket'] = pd.to_datetime(bucketed_data['@timestamp']).dt.floor(freq)
#                 else:
#                     logger.warning("No timestamp available, using single time bucket")
#                     bucketed_data['time_bucket'] = pd.Timestamp.now(tz='UTC').floor('15T')

#             # Validate data types
#             try:
#                 bucketed_data['event_count'] = pd.to_numeric(bucketed_data['event_count'], errors='coerce').fillna(1)
#                 bucketed_data['process.name'] = bucketed_data['process.name'].astype(str)
#                 bucketed_data['host.hostname'] = bucketed_data['host.hostname'].astype(str)
#             except Exception as e:
#                 logger.warning(f"Data type conversion warning: {e}")

#             # Safe aggregation with proper error handling
#             try:
#                 # Define aggregation dictionary
#                 agg_dict = {
#                     'event_count': 'sum',
#                     'host.hostname': 'nunique',  # Count unique hosts
#                     '@timestamp': 'first'  # Keep first timestamp per bucket
#                 }

#                 # Add any additional numeric columns that exist
#                 numeric_cols = bucketed_data.select_dtypes(include=[np.number]).columns
#                 for col in numeric_cols:
#                     if col not in ['event_count'] and col in bucketed_data.columns:
#                         agg_dict[col] = 'mean'

#                 # Perform grouped aggregation
#                 logger.debug("Performing aggregation by time bucket and process name")
#                 aggregated = bucketed_data.groupby(['time_bucket', 'process.name']).agg(agg_dict).reset_index()

#                 # Rename host.hostname column to host_count for clarity
#                 aggregated = aggregated.rename(columns={'host.hostname': 'host_count'})

#                 # Ensure @timestamp exists in aggregated data
#                 if '@timestamp' not in aggregated.columns:
#                     aggregated['@timestamp'] = aggregated['time_bucket']

#                 logger.debug(f"Aggregation complete: {len(aggregated)} aggregated records")

#             except Exception as e:
#                 logger.error(f"Aggregation failed: {e}")
#                 # Fallback: use original data with minimal processing
#                 aggregated = bucketed_data.copy()
#                 if 'host_count' not in aggregated.columns:
#                     aggregated['host_count'] = 1

#             # Validate aggregated data
#             if aggregated.empty:
#                 logger.warning("Aggregation resulted in empty DataFrame")
#                 return pd.DataFrame()

#             # Get models and baselines with error handling
#             try:
#                 models, scalers, baselines = self.model_manager.get_models_for_group("process")
#                 logger.debug(f"Retrieved {len(models) if models else 0} models and {len(baselines) if baselines else 0} baselines")
#             except Exception as e:
#                 logger.warning(f"Failed to retrieve models/baselines: {e}")
#                 models, scalers, baselines = {}, {}, {}


#             results_list = []
#             detection_methods_used = []

#             # 1. Statistical detection
#             try:
#                 if baselines:
#                     logger.debug("Running statistical anomaly detection")
#                     stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "process")
#                     if not stat_results.empty:
#                         results_list.append(stat_results)
#                         detection_methods_used.append("statistical")
#                         logger.debug(f"Statistical detection found {len(stat_results)} results")
#                     else:
#                         logger.debug("Statistical detection completed but found no anomalies")
#                 else:
#                     logger.debug("No baselines available for statistical detection")
#             except Exception as e:
#                 logger.warning(f"Statistical detection failed: {e}")

#             # 2. ML detection if models available
#             try:
#                 if models and scalers:
#                     logger.debug("Running ML anomaly detection")
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "process")
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                         detection_methods_used.append("ml")
#                         logger.debug(f"ML detection found {len(ml_results)} results")
#                     else:
#                         logger.debug("ML detection completed but found no anomalies")
#                 else:
#                     logger.debug("No models/scalers available for ML detection")
#             except Exception as e:
#                 logger.warning(f"ML detection failed: {e}")

#             # 3. Process-specific detection (rare processes)
#             try:
#                 logger.debug("Running rare process detection")
#                 process_results = detect_rare_processes_all_hosts(aggregated, self.config)
#                 if not process_results.empty:
#                     results_list.append(process_results)
#                     detection_methods_used.append("rare_process")
#                     logger.debug(f"Rare process detection found {len(process_results)} results")
#                 else:
#                     logger.debug("Rare process detection completed but found no anomalies")
#             except Exception as e:
#                 logger.warning(f"Rare process detection failed: {e}")

#             # Combine results safely
#             if results_list:
#                 logger.debug(f"Combining results from {len(results_list)} detection methods: {detection_methods_used}")

#                 final_results = results_list[0].copy()

#                 # Combine additional results
#                 for i, additional_result in enumerate(results_list[1:], 1):
#                     try:
#                         final_results = self._safe_combine_results(final_results, additional_result)
#                         logger.debug(f"Combined result set {i+1}")
#                     except Exception as e:
#                         logger.warning(f"Failed to combine result set {i+1}: {e}")

#                 # Ensure required columns exist in final results
#                 required_final_cols = ['anomaly_score', 'final_anomaly', 'detection_method']
#                 for col in required_final_cols:
#                     if col not in final_results.columns:
#                         if col == 'anomaly_score':
#                             final_results['anomaly_score'] = 0.5  # Default moderate score
#                         elif col == 'final_anomaly':
#                             final_results['final_anomaly'] = True  # Assume anomaly if in results
#                         elif col == 'detection_method':
#                             final_results['detection_method'] = ','.join(detection_methods_used)

#                 logger.info(f"Anomaly detection completed: {len(final_results)} anomalies found using {detection_methods_used}")
#                 return final_results

#             else:
#                 # No anomalies found - return aggregated data with baseline indicators
#                 logger.debug("No anomalies detected by any method, returning baseline aggregated data")

#                 # Add anomaly indicators to show detection ran successfully
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 aggregated['detection_methods_attempted'] = ','.join(['statistical', 'ml', 'rare_process'])

#                 logger.info(f"No anomalies detected in {len(aggregated)} aggregated process records")
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Critical error in _detect_anomalous_process_all_hosts: {e}")
#             import traceback
#             logger.error(f"Full traceback: {traceback.format_exc()}")

#             # Return minimal DataFrame with error indicators
#             error_df = pd.DataFrame({
#                 'error': ['detection_failed'],
#                 'error_message': [str(e)],
#                 'timestamp': [pd.Timestamp.now(tz='UTC')]
#             })
#             return error_df

#     def _detect_rare_process_by_host(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect processes unusual to particular Linux hosts."""
#         if data.empty:
#             return pd.DataFrame()

#         try:
#             bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))

#             if bucketed_data.empty:
#                 return pd.DataFrame()

#             # Ensure required columns
#             required_cols = ['process.name', 'host.hostname']
#             missing_cols = [col for col in required_cols if col not in bucketed_data.columns]
#             if missing_cols:
#                 logger.error(f"Missing required columns for host-based process detection: {missing_cols}")
#                 if 'host.hostname' not in bucketed_data.columns:
#                     bucketed_data['host.hostname'] = 'unknown_host'

#             # Aggregate by process, host, and time
#             agg_dict = {}
#             if 'process.pid' in bucketed_data.columns:
#                 agg_dict['process.pid'] = 'count'
#             else:
#                 bucketed_data['_event_marker'] = 1
#                 agg_dict['_event_marker'] = 'count'

#             aggregated = bucketed_data.groupby(['time_bucket', 'host.hostname', 'process.name']).agg(agg_dict).reset_index()

#             # Rename count column to event_count
#             count_col = 'process.pid' if 'process.pid' in agg_dict else '_event_marker'
#             aggregated = aggregated.rename(columns={count_col: 'event_count'})
#             aggregated['@timestamp'] = aggregated['time_bucket']

#             # Run detection
#             models, scalers, baselines = self.model_manager.get_models_for_group("process")
#             results_list = []

#             try:
#                 stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "process")
#                 if not stat_results.empty:
#                     results_list.append(stat_results)
#             except Exception as e:
#                 logger.warning(f"Statistical detection failed: {e}")

#             if models:
#                 try:
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "process")
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                 except Exception as e:
#                     logger.warning(f"ML detection failed: {e}")

#             try:
#                 host_results = detect_rare_processes_by_host(aggregated, self.config)
#                 if not host_results.empty:
#                     results_list.append(host_results)
#             except Exception as e:
#                 logger.warning(f"Host-specific detection failed: {e}")

#             # Combine results
#             if results_list:
#                 final_results = results_list[0]
#                 for additional_result in results_list[1:]:
#                     final_results = self._safe_combine_results(final_results, additional_result)

#                 if 'final_anomaly' not in final_results.columns:
#                     final_results['final_anomaly'] = False

#                 return final_results
#             else:
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Error in _detect_rare_process_by_host: {e}")
#             return pd.DataFrame()
#     def _generate_anomaly_index(self, results: Dict[str, Dict[str, pd.DataFrame]], anomalies_file: str):
#         """
#         Generate ML-only anomaly index with clean structure.

#         MODIFIED: Only indexes ML anomalies, ensures clean index
#         """
#         try:
#             if not os.path.exists(anomalies_file):
#                 logger.warning("Anomalies file not found for indexing")
#                 return

#             # Load the ML-only anomalies
#             with open(anomalies_file, 'r') as f:
#                 ml_data = json.load(f)

#             if ml_data.get('total_ml_anomalies', 0) == 0:
#                 logger.warning("No ML anomalies to index")
#                 return

#             # Create flat index of all ML anomalies
#             all_ml_anomalies = []

#             for job_name, job_data in ml_data.get('ml_jobs', {}).items():
#                 for anomaly in job_data.get('anomalies', []):
#                     # Create indexed entry
#                     index_entry = {
#                         "id": len(all_ml_anomalies) + 1,  # Clean sequential ID
#                         "job": job_name,
#                         "data_type": job_data["data_type"],
#                         "timestamp": anomaly["timestamp"],
#                         "score": anomaly["ml_score"],
#                         "confidence": anomaly.get("confidence", 0.0),
#                         "entity": anomaly.get("entity", "unknown"),
#                         "description": anomaly["description"]
#                     }

#                     # Add hostname if available
#                     if 'hostname' in anomaly:
#                         index_entry["hostname"] = anomaly['hostname']

#                     all_ml_anomalies.append(index_entry)

#             if not all_ml_anomalies:
#                 logger.warning("No ML anomalies to index")
#                 return

#             # Sort ML anomalies by score (highest first)
#             all_ml_anomalies.sort(key=lambda x: x['score'], reverse=True)

#             # Create ML index file
#             output_dir = os.path.dirname(anomalies_file)
#             index_file = os.path.join(output_dir, os.path.basename(anomalies_file).replace('anomalies_', 'ml_anomaly_index_'))

#             with open(index_file, 'w') as f:
#                 json.dump({
#                     "total_ml_anomalies": len(all_ml_anomalies),
#                     "detection_method": "machine_learning",
#                     "anomalies_file": os.path.basename(anomalies_file),
#                     "generated_at": datetime.utcnow().isoformat(),
#                     "clean_index": True,
#                     "ml_anomalies": all_ml_anomalies
#                 }, f, indent=2, default=str)

#             logger.info(f"Generated ML anomaly index with {len(all_ml_anomalies)} entries: {index_file}")

#         except Exception as e:
#             logger.error(f"Error generating ML anomaly index: {e}")
#     def _extract_ml_score_details(self, anomaly: pd.Series) -> Dict[str, Any]:
#         """Extract ML-specific scoring details from an anomaly."""
#         ml_details = {}

#         # ML anomaly score
#         if 'ml_anomaly_score' in anomaly:
#             ml_details['ml_anomaly_score'] = float(anomaly['ml_anomaly_score'])

#         # Confidence score
#         if 'confidence' in anomaly:
#             ml_details['confidence'] = float(anomaly['confidence'])

#         # Detection threshold used
#         if 'detection_threshold' in anomaly:
#             ml_details['threshold'] = float(anomaly['detection_threshold'])

#         # ML methods used
#         if 'methods_used' in anomaly:
#             ml_details['methods'] = str(anomaly['methods_used']).split(',')

#         # Combined score if available
#         if 'combined_score' in anomaly:
#             ml_details['combined_score'] = float(anomaly['combined_score'])

#         return ml_details


#     def _generate_ml_anomaly_description(self, anomaly: pd.Series, data_type: str) -> str:
#         """Generate a description specifically for ML-detected anomalies."""

#         # Get ML score and confidence
#         ml_score = anomaly.get('ml_anomaly_score', 0.0)
#         confidence = anomaly.get('confidence', 0.0)
#         threshold = anomaly.get('detection_threshold', 0.0)

#         # Base description
#         desc = f"ML-detected {data_type} anomaly"

#         # Add score information
#         if ml_score > 0:
#             desc += f" (score: {ml_score:.3f}"
#             if threshold > 0:
#                 desc += f", threshold: {threshold:.3f}"
#             desc += ")"

#         # Add confidence if available
#         if confidence > 0:
#             desc += f" with {confidence:.1%} confidence"

#         # Add entity-specific details
#         entity = self._extract_entity_from_row(anomaly, data_type)
#         if entity and entity != "unknown":
#             desc += f" for {entity}"

#         # Add event count if significant
#         event_count = anomaly.get('event_count', 0)
#         if event_count > 1:
#             desc += f" ({event_count} events)"

#         return desc

#     def extract_and_save_anomalies(self, results: Dict[str, Dict[str, pd.DataFrame]], output_dir: Optional[str] = None) -> str:
#         """
#         Extract ONLY ML anomalies from detection results and save to JSON file.

#         MODIFIED: Filters for machine_learning detection_method only, removes NaN index

#         Args:
#             results: Results from comprehensive detection
#             output_dir: Directory to save the anomaly JSON file (defaults to config output dir)

#         Returns:
#             str: Path to the saved JSON file
#         """
#         if not output_dir:
#             output_dir = self.config.get("output", {}).get("results_dir", "results")

#         os.makedirs(output_dir, exist_ok=True)

#         # Dictionary to hold ONLY ML anomalies organized by job
#         ml_only_anomalies = {}
#         ml_anomaly_count = 0

#         logger.info("Extracting ONLY ML anomalies from detection results")

#         for data_type, group_results in results.items():
#             for job_name, job_results in group_results.items():
#                 if job_results.empty:
#                     continue

#                 # CRITICAL FILTER: Only ML detection methods
#                 if 'detection_method' not in job_results.columns:
#                     logger.debug(f"Skipping {job_name} - no detection_method column")
#                     continue

#                 # Filter for ML anomalies ONLY
#                 ml_mask = (
#                     (job_results['detection_method'] == 'machine_learning') &
#                     (job_results.get('final_anomaly', False) == True)
#                 )

#                 ml_anomalies = job_results[ml_mask].copy()

#                 if ml_anomalies.empty:
#                     logger.debug(f"No ML anomalies found in {job_name}")
#                     continue

#                 # Clean index to remove any NaN values
#                 ml_anomalies = ml_anomalies.reset_index(drop=True)

#                 # Remove rows with NaN in critical columns
#                 critical_columns = ['final_anomaly', 'detection_method']
#                 for col in critical_columns:
#                     if col in ml_anomalies.columns:
#                         ml_anomalies = ml_anomalies.dropna(subset=[col])

#                 # Reset index again after cleaning
#                 ml_anomalies = ml_anomalies.reset_index(drop=True)

#                 if ml_anomalies.empty:
#                     logger.debug(f"No clean ML anomalies after NaN removal in {job_name}")
#                     continue

#                 # Create job entry
#                 if job_name not in ml_only_anomalies:
#                     ml_only_anomalies[job_name] = {
#                         "job_id": job_name,
#                         "data_type": data_type,
#                         "detection_method": "machine_learning",  # Explicitly ML only
#                         "anomaly_count": 0,
#                         "anomalies": []
#                     }

#                 # Process each ML anomaly
#                 for idx, anomaly in ml_anomalies.iterrows():
#                     # Verify this is actually an ML anomaly
#                     if anomaly.get('detection_method') != 'machine_learning':
#                         continue

#                     if not anomaly.get('final_anomaly', False):
#                         continue

#                     # Create structured ML anomaly record
#                     anomaly_record = {
#                         "timestamp": str(anomaly.get('@timestamp', '')),
#                         "ml_score": float(anomaly.get('ml_anomaly_score', 0.0)),  # ML specific score
#                         "confidence": float(anomaly.get('confidence', 0.0)),     # ML confidence
#                         "event_count": int(anomaly.get('event_count', 0)),
#                         "detection_method": "machine_learning",  # Explicitly set
#                         "clean_index": int(idx)  # Clean, NaN-free index
#                     }

#                     # Add ML-specific threshold info
#                     if 'detection_threshold' in anomaly:
#                         anomaly_record["threshold_used"] = float(anomaly['detection_threshold'])

#                     # Add methods used info
#                     if 'methods_used' in anomaly:
#                         anomaly_record["ml_methods"] = str(anomaly['methods_used'])

#                     # Add entity-specific fields based on data type
#                     entity_fields = self._extract_entity_fields(anomaly, data_type)
#                     if entity_fields:
#                         anomaly_record.update(entity_fields)

#                     # Add ML score details
#                     ml_score_details = self._extract_ml_score_details(anomaly)
#                     if ml_score_details:
#                         anomaly_record["ml_score_details"] = ml_score_details

#                     # Add feature details for ML
#                     feature_details = self._extract_feature_details(anomaly)
#                     if feature_details:
#                         anomaly_record["features"] = feature_details

#                     # Add context fields
#                     context = self._extract_context_fields(anomaly, data_type)
#                     if context:
#                         anomaly_record["context"] = context

#                     # Add ML-specific description
#                     anomaly_record["description"] = self._generate_ml_anomaly_description(anomaly, data_type)

#                     # Add the ML anomaly to the job's list
#                     ml_only_anomalies[job_name]["anomalies"].append(anomaly_record)
#                     ml_only_anomalies[job_name]["anomaly_count"] += 1
#                     ml_anomaly_count += 1

#         if ml_anomaly_count == 0:
#             logger.warning("No ML anomalies found in any data type - check ML detection thresholds")
#             # Create empty file for consistency
#             timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
#             anomalies_file = os.path.join(output_dir, f"ml_only_anomalies_{timestamp_str}.json")

#             with open(anomalies_file, 'w') as f:
#                 json.dump({
#                     "total_ml_anomalies": 0,
#                     "detection_summary": "No ML anomalies detected - check thresholds",
#                     "ml_jobs": {}
#                 }, f, indent=2)

#             return anomalies_file

#         # Save ML-only anomalies to JSON file
#         timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
#         anomalies_file = os.path.join(output_dir, f"ml_only_anomalies_{timestamp_str}.json")

#         # Create summary structure
#         ml_summary = {
#             "total_ml_anomalies": ml_anomaly_count,
#             "detection_method": "machine_learning_only",
#             "generated_at": datetime.utcnow().isoformat(),
#             "clean_index": True,  # Guaranteed no NaN
#             "ml_jobs": ml_only_anomalies
#         }

#         with open(anomalies_file, 'w') as f:
#             json.dump(ml_summary, f, indent=2, default=str)

#         logger.info(f"Saved {ml_anomaly_count} ML-only anomalies to {anomalies_file}")

#         # Also create a simple CSV for easy analysis
#         csv_file = anomalies_file.replace('.json', '.csv')
#         ml_records = []

#         for job_name, job_data in ml_only_anomalies.items():
#             for anomaly in job_data["anomalies"]:
#                 record = {
#                     "job_name": job_name,
#                     "data_type": job_data["data_type"],
#                     "timestamp": anomaly["timestamp"],
#                     "ml_score": anomaly["ml_score"],
#                     "confidence": anomaly["confidence"],
#                     "event_count": anomaly["event_count"],
#                     "clean_index": anomaly["clean_index"]
#                 }

#                 # Add entity info if available
#                 if "entity" in anomaly:
#                     record["entity"] = anomaly["entity"]

#                 ml_records.append(record)

#         if ml_records:
#             import pandas as pd
#             ml_df = pd.DataFrame(ml_records)
#             ml_df.to_csv(csv_file, index=False)
#             logger.info(f"Also saved ML anomalies to CSV: {csv_file}")

#         return anomalies_file


#     def _extract_entity_fields(self, anomaly: pd.Series, data_type: str) -> Dict[str, Any]:
#         """Extract entity-related fields from an anomaly."""
#         entity_fields = {}

#         # Host information
#         if 'host.hostname' in anomaly:
#             entity_fields["host"] = {
#                 "name": anomaly.get('host.hostname')
#             }
#         elif 'host.name' in anomaly:
#             entity_fields["host"] = {
#                 "name": anomaly.get('host.name')
#             }

#         # Process information
#         if 'process.name' in anomaly:
#             entity_fields["process"] = {
#                 "name": anomaly.get('process.name')
#             }
#             if 'process.args' in anomaly:
#                 entity_fields["process"]["args"] = anomaly.get('process.args')
#             if 'process.executable' in anomaly:
#                 entity_fields["process"]["executable"] = anomaly.get('process.executable')
#             if 'process.pid' in anomaly:
#                 entity_fields["process"]["pid"] = anomaly.get('process.pid')

#         # User information
#         if 'user.name' in anomaly:
#             entity_fields["user"] = {
#                 "name": anomaly.get('user.name')
#             }

#         # Network information
#         network_fields = {}
#         if 'destination.ip' in anomaly:
#             network_fields["destination"] = {
#                 "ip": anomaly.get('destination.ip')
#             }
#             if 'destination.port' in anomaly:
#                 network_fields["destination"]["port"] = anomaly.get('destination.port')
#             if 'destination.ip' in anomaly:
#                 network_fields["destination"]["country"] = anomaly.get('destination.ip')

#         if 'source.ip' in anomaly:
#             network_fields["source"] = {
#                 "ip": anomaly.get('source.ip')
#             }
#             if 'source.port' in anomaly:
#                 network_fields["source"]["port"] = anomaly.get('source.port')

#         if network_fields:
#             entity_fields.update(network_fields)

#         return entity_fields

#     def _extract_score_details(self, anomaly: pd.Series) -> Dict[str, float]:
#         """Extract score-related details from an anomaly."""
#         score_fields = {}

#         score_related_columns = [
#             'anomaly_score', 'initial_anomaly_score', 'record_score', 'initial_record_score',
#             'probability', 'combined_score', 'raw_anomaly_score'
#         ]

#         for col in score_related_columns:
#             if col in anomaly and not pd.isna(anomaly[col]):
#                 score_fields[col] = float(anomaly[col])

#         return score_fields

#     def _extract_feature_details(self, anomaly: pd.Series) -> Dict[str, Any]:
#         """Extract feature details (actual vs typical) from an anomaly."""
#         feature_details = {}

#         if 'actual' in anomaly and not pd.isna(anomaly['actual']):
#             feature_details["actual"] = float(anomaly['actual'])

#         if 'typical' in anomaly and not pd.isna(anomaly['typical']):
#             feature_details["typical"] = float(anomaly['typical'])

#         if 'field_name' in anomaly and not pd.isna(anomaly['field_name']):
#             feature_details["field_name"] = anomaly['field_name']

#         if 'function' in anomaly and not pd.isna(anomaly['function']):
#             feature_details["function"] = anomaly['function']

#         if 'function_description' in anomaly and not pd.isna(anomaly['function_description']):
#             feature_details["function_description"] = anomaly['function_description']

#         # Include any cause information (nested)
#         if 'causes' in anomaly and not pd.isna(anomaly['causes']):
#             # Handle causes which could be in string format or already parsed
#             try:
#                 if isinstance(anomaly['causes'], str):
#                     causes = json.loads(anomaly['causes'])
#                 else:
#                     causes = anomaly['causes']

#                 feature_details["causes"] = causes
#             except Exception as e:
#                 logger.debug(f"Failed to parse causes: {e}")

#         return feature_details

#     def _extract_context_fields(self, anomaly: pd.Series, data_type: str) -> Dict[str, Any]:
#         """Extract additional context fields from an anomaly."""
#         context = {
#             "data_type": data_type
#         }

#         # Check for boolean indicators
#         boolean_indicators = [
#             'is_root_user', 'is_system_path', 'is_tmp_execution', 'is_large_transfer',
#             'is_well_known_port', 'is_sudo_command', 'is_compiler_activity', 'is_service_user',
#             'is_business_hours', 'has_pipes', 'has_redirection', 'potential_cred_harvest'
#         ]

#         for indicator in boolean_indicators:
#             if indicator in anomaly and not pd.isna(anomaly[indicator]):
#                 context[indicator] = bool(anomaly[indicator])

#         # Add any categorical fields
#         categorical_fields = [
#             'discovery_category', 'metadata_service_type', 'result_type', 'by_field_name',
#             'by_field_value', 'over_field_name', 'over_field_value', 'partition_field_name',
#             'partition_field_value', 'detection_method'
#         ]

#         for field in categorical_fields:
#             if field in anomaly and not pd.isna(anomaly[field]):
#                 context[field] = anomaly[field]

#         # Include bucket information
#         if 'bucket_span' in anomaly and not pd.isna(anomaly['bucket_span']):
#             context["bucket_span"] = int(anomaly['bucket_span'])

#         if 'is_interim' in anomaly and not pd.isna(anomaly['is_interim']):
#             context["is_interim"] = bool(anomaly['is_interim'])

#         # Add host count if available
#         if 'host_count' in anomaly and not pd.isna(anomaly['host_count']):
#             context["host_count"] = int(anomaly['host_count'])

#         return context    # Discovery detection methods
#     def _detect_network_configuration_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect network configuration discovery commands."""
#         return self._detect_discovery_commands(data, "network")

#     def _detect_network_connection_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect network connection discovery commands."""
#         return self._detect_discovery_commands(data, "network")

#     def _detect_system_information_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect system information discovery commands."""
#         return self._detect_discovery_commands(data, "system")

#     def _detect_system_process_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect system process discovery commands."""
#         return self._detect_discovery_commands(data, "process")

#     def _detect_system_user_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
#         """Detect system user discovery commands."""
#         return self._detect_discovery_commands(data, "user")
#     def validate_anomaly_results(results, config):
#         """
#         Validate anomaly detection results and apply safety measures for extreme rates.

#         Args:
#             results (pd.DataFrame): Results from anomaly detection
#             config (dict): Configuration dictionary

#         Returns:
#             pd.DataFrame: Validated and possibly adjusted results
#         """
#         if results.empty or 'final_anomaly' not in results.columns:
#             return results

#         # Calculate anomaly percentage
#         anomaly_count = results['final_anomaly'].sum()
#         total_count = len(results)
#         anomaly_percent = (anomaly_count / total_count) * 100 if total_count > 0 else 0

#         logger.info(f"Anomaly validation: {anomaly_count}/{total_count} events ({anomaly_percent:.2f}%)")

#         # Get maximum acceptable anomaly rate from config or use default
#         max_anomaly_rate = config.get('detection', {}).get('max_anomaly_rate', 5.0)

#         # Check if the anomaly rate is excessive
#         if anomaly_percent > max_anomaly_rate:
#             logger.warning(f"EXCESSIVE ANOMALY RATE: {anomaly_percent:.2f}% exceeds threshold of {max_anomaly_rate:.2f}%")

#             # Apply safety measures depending on how extreme the rate is
#             if anomaly_percent > 90:
#                 logger.error("CRITICAL: Over 90% anomaly rate indicates serious misconfiguration")
#                 logger.error("Defaulting to treat all as normal until configuration is fixed")

#                 # In extreme cases (>90%), treat all as normal to prevent alert flooding
#                 results['final_anomaly'] = False
#                 results['combined_score'] = 0.0

#                 return results

#             # For high but not extreme rates, adjust threshold to limit anomalies
#             if 'combined_score' in results.columns:
#                 # Calculate new threshold that would give desired anomaly rate
#                 new_threshold = results['combined_score'].quantile(1 - (max_anomaly_rate / 100))

#                 # Apply new threshold
#                 results['final_anomaly'] = results['combined_score'] > new_threshold

#                 new_count = results['final_anomaly'].sum()
#                 new_percent = (new_count / total_count) * 100

#                 logger.warning(f"Adjusted threshold to {new_threshold:.4f}")
#                 logger.warning(f"New anomaly rate: {new_count}/{total_count} events ({new_percent:.2f}%)")

#         return results

#     def validate_entities(self, entities, available_models):
#         """Validate entities against available models."""

#         # REPLACE YOUR EXISTING VALIDATION WITH THIS:
#         validator = EntityValidator()
#         valid_entities, mapping = validator.validate_entities(entities, available_models)

#         if not valid_entities and available_models:
#             # Use fallback strategy
#             logger.warning("No entities passed validation - using fallback")
#             fallback_model = available_models[0]
#             return [entities[0]], {entities[0]: fallback_model}

#         return valid_entities, mapping
#     def whitelist_common_processes(results, config):
#         """
#         Apply whitelist to detected anomalies to reduce false positives.

#         Args:
#             results (pd.DataFrame): Results from anomaly detection
#             config (dict): Configuration with optional whitelists

#         Returns:
#             pd.DataFrame: Filtered results with whitelisted items removed from anomalies
#         """
#         if results.empty or 'final_anomaly' not in results.columns:
#             return results

#         logger.info(f"Running process whitelist filter on {results['final_anomaly'].sum()} anomalies")

#         # Default whitelist of common legitimate processes
#         default_whitelist = [
#             'falconctl', 'sh', 'sed', 'apt-config', 'dpkg', 'apt-get', 'systemd',
#             'systemctl', 'bash', 'cron', 'logrotate', 'rsyslogd', 'sshd', 'syslogd',
#             'dbus-daemon', 'snapd', 'networkd', 'resolved', 'timesyncd', 'python3',
#             'apt-update', 'apt', 'journalctl', 'dpkg-reconfigure'
#         ]

#         # Get custom whitelist from config if available
#         whitelist = config.get('detection', {}).get('process_whitelist', default_whitelist)

#         # Check if we have process names
#         if 'process.name' in results.columns:
#             # Create mask for whitelisted processes
#             whitelist_mask = results['process.name'].isin(whitelist)
#             whitelisted_count = whitelist_mask.sum()

#             if whitelisted_count > 0:
#                 # Remove these from anomalies
#                 anomaly_before = results['final_anomaly'].sum()
#                 results.loc[whitelist_mask, 'final_anomaly'] = False

#                 # Reduce scores for these processes
#                 if 'combined_score' in results.columns:
#                     results.loc[whitelist_mask, 'combined_score'] *= 0.1

#                 anomaly_after = results['final_anomaly'].sum()
#                 logger.info(f"Whitelisted {whitelisted_count} common processes")
#                 logger.info(f"Anomalies reduced from {anomaly_before} to {anomaly_after}")

#         return results
#     def _detect_discovery_commands(self, data: pd.DataFrame, category: str) -> pd.DataFrame:
#         """Common discovery command detection logic with enhanced filtering."""
#         data, self.config = apply_all_fixes(data, self.config, 'discovery')
#         if data.empty:
#             return pd.DataFrame()

#         try:
#             # Filter by discovery category if available
#             if 'discovery_category' in data.columns:
#                 category_data = data[data['discovery_category'] == category].copy()
#                 if category_data.empty:
#                     category_data = data.copy()  # Fallback to all data
#             else:
#                 category_data = data.copy()

#             bucketed_data = self._create_time_buckets_safe(category_data, self.config.get("detection", {}).get("bucket_span", "60m"))

#             if bucketed_data.empty:
#                 return pd.DataFrame()

#             # Ensure required columns
#             required_fields = {
#                 'command_length': 0,
#                 'has_pipes': 0,
#                 'has_redirection': 0,
#                 'user.name': 'unknown',
#                 'process.name': 'unknown',
#                 'event.category': 'unknown'
#             }

#             for field, default_value in required_fields.items():
#                 if field not in bucketed_data.columns:
#                     bucketed_data[field] = default_value

#             # Aggregate by user and command
#             agg_dict = {
#                 'event.category': 'count',
#                 'command_length': 'mean',
#                 'has_pipes': 'sum',
#                 'has_redirection': 'sum'
#             }

#             aggregated = bucketed_data.groupby(['time_bucket', 'user.name', 'process.name']).agg(agg_dict).reset_index()
#             aggregated = aggregated.rename(columns={'event.category': 'event_count'})
#             aggregated['@timestamp'] = aggregated['time_bucket']

#             # Run detection
#             models, scalers, baselines = self.model_manager.get_models_for_group("discovery")
#             results_list = []

#             try:
#                 stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "discovery")
#                 if not stat_results.empty:
#                     results_list.append(stat_results)
#             except Exception as e:
#                 logger.warning(f"Discovery statistical detection failed: {e}")

#             if models:
#                 try:
#                     ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "discovery")
#                     if not ml_results.empty:
#                         results_list.append(ml_results)
#                 except Exception as e:
#                     logger.warning(f"Discovery ML detection failed: {e}")

#             # Run discovery-specific detection
#             try:
#                 discovery_results = detect_discovery_command_anomalies(aggregated, self.config)
#                 if not discovery_results.empty:
#                     results_list.append(discovery_results)
#             except Exception as e:
#                 logger.warning(f"Discovery specific detection failed: {e}")

#             # Combine results
#             if results_list:
#                 combined = results_list[0]
#                 for additional_result in results_list[1:]:
#                     combined = self._safe_combine_results(combined, additional_result)

#                 if 'final_anomaly' not in combined.columns:
#                     combined['final_anomaly'] = False

#                 return combined
#             else:
#                 aggregated['anomaly_score'] = 0.0
#                 aggregated['final_anomaly'] = False
#                 aggregated['detection_method'] = 'baseline_aggregation'
#                 return aggregated

#         except Exception as e:
#             logger.error(f"Error in _detect_discovery_commands: {e}")
#             return pd.DataFrame()


"""
Complete Fixed Linux Anomaly Detector
=====================================
Comprehensive Linux anomaly detection system with job-specific handling for all 15 detection jobs.
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any

import pandas as pd

# Import all required modules
from config import load_config
from datamanager import (
    connect_to_elasticsearch,
    fetch_auth_data,
    fetch_baseline_data,
    fetch_discovery_commands_data,
    fetch_metadata_access_data,
    fetch_network_activity_data,
    fetch_process_data,
    fetch_user_activity_data,
    get_training_configuration,
    preprocess_auth_data,
    preprocess_discovery_data,
    preprocess_metadata_data,
    preprocess_network_data,
    preprocess_process_data,
    preprocess_user_data,
)

# Import FIXED detection methods
from detection_methods import (
    JOB_CONFIGURATIONS,
    # New job-specific functions
    detect_job_anomalies,
    validate_job_requirements,
)
from fixedLDS import ConfigManager, apply_all_fixes
from model_manager import (
    LinuxModelManager,
    train_auth_anomaly_models,
    train_discovery_command_models,
    train_host_anomaly_models,
    train_metadata_access_models,
    train_network_activity_models,
    train_process_anomaly_models,
    train_user_behavior_models,
)
from visualizer import LinuxAnomalyVisualizer

logger = logging.getLogger("linux_anomaly_detection")


def ensure_event_category(df):
    """Ensure the event.category column exists in the dataframe."""
    if 'event.category' not in df.columns:
        # Determine appropriate category based on data content
        if 'process.name' in df.columns:
            default_category = 'process'
        elif 'destination.ip' in df.columns or 'destination.port' in df.columns:
            default_category = 'network'
        elif 'user.name' in df.columns and 'is_sudo_command' in df.columns:
            default_category = 'user'
        else:
            default_category = 'unknown'

        df['event.category'] = default_category
        logger.debug(f"Added missing 'event.category' column with default value '{default_category}'")

    return df


def safe_string_join(items, separator=', '):
    """Safely join items into a string, handling mixed types."""
    try:
        str_items = []
        for item in items:
            if pd.isna(item) or item is None:
                str_items.append('Unknown')
            else:
                str_items.append(str(item))
        return separator.join(str_items)
    except Exception as e:
        logger.warning(f"Error in safe_string_join: {e}")
        return "Unknown"


def safe_column_check(df: pd.DataFrame, required_columns: list[str], operation_name: str) -> bool:
    """Check if required columns exist in DataFrame."""
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"Missing required columns for {operation_name}: {missing_columns}")
        logger.info(f"Available columns: {list(df.columns)}")
        return False
    return True


def add_default_columns(df: pd.DataFrame, default_columns: dict[str, Any]) -> pd.DataFrame:
    """Add default columns if they don't exist."""
    for col_name, default_value in default_columns.items():
        if col_name not in df.columns:
            df[col_name] = default_value
            logger.info(f"Added default column {col_name} with value {default_value}")
    return df


class LinuxAnomalyDetector:
    """
    COMPLETE FIXED: Linux anomaly detection system with job-specific handling.
    Supports all 15 detection jobs across 5 data groups with proper entity selection.
    """

    def __init__(self, config_path=None):
        """Initialize the Linux anomaly detector with configuration."""
        self.es = None
        self.model_manager = None
        self.visualizer = None
        self.config = load_config(config_path)
        self.connect_to_elasticsearch()

        # Initialize managers
        self.model_manager = LinuxModelManager(self.config)
        self.visualizer = LinuxAnomalyVisualizer(self.config)
        self.config = ConfigManager.fix_config(self.config)

        # FIXED: Detection jobs with proper job-specific routing
        self.detection_jobs = {
            "process": {
                "v3_linux_anomalous_process_all_hosts": {
                    "description": "Processes unusual to all Linux hosts",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_anomalous_process_all_hosts")
                },
                "v3_rare_process_by_host_linux": {
                    "description": "Processes unusual to particular Linux hosts",
                    "method": lambda data: self._run_job_detection(data, "v3_rare_process_by_host_linux")
                }
            },
            "network": {
                "v3_linux_anomalous_network_activity": {
                    "description": "Unusual network activity from processes",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_anomalous_network_activity")
                },
                "v3_linux_anomalous_network_port_activity": {
                    "description": "Unusual destination port activity",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_anomalous_network_port_activity")
                }
            },
            "user": {
                "v3_linux_anomalous_user_name": {
                    "description": "Rare and unusual user activity",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_anomalous_user_name")
                },
                "v3_linux_rare_sudo_user": {
                    "description": "Sudo activity from unusual users",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_rare_sudo_user")
                },
                "v3_linux_rare_user_compiler": {
                    "description": "Compiler activity from unusual users",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_rare_user_compiler")
                }
            },
            "discovery": {
                "v3_linux_network_configuration_discovery": {
                    "description": "Network configuration discovery commands",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_network_configuration_discovery")
                },
                "v3_linux_network_connection_discovery": {
                    "description": "Network connection discovery commands",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_network_connection_discovery")
                },
                "v3_linux_system_information_discovery": {
                    "description": "System information discovery commands",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_system_information_discovery")
                },
                "v3_linux_system_process_discovery": {
                    "description": "System process discovery commands",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_system_process_discovery")
                },
                "v3_linux_system_user_discovery": {
                    "description": "System user discovery commands",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_system_user_discovery")
                }
            },
            "metadata": {
                "v3_linux_rare_metadata_process": {
                    "description": "Unusual processes accessing metadata services",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_rare_metadata_process")
                },
                "v3_linux_rare_metadata_user": {
                    "description": "Unusual users accessing metadata services",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_rare_metadata_user")
                }
            },
            "auth": {
                "v3_linux_auth_rare_source_ip": {
                    "description": "Rare source IPs authenticating to hosts",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_auth_rare_source_ip")
                },
                "v3_linux_auth_high_count_logon_fails": {
                    "description": "Brute-force login attempts per user+host",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_auth_high_count_logon_fails")
                },
                "v3_linux_auth_rare_user": {
                    "description": "Rare user accounts authenticating",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_auth_rare_user")
                },
                "v3_linux_auth_rare_hour": {
                    "description": "Authentication at unusual hours",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_auth_rare_hour")
                }
            },
            "host": {
                "v3_linux_anomalous_host_activity": {
                    "description": "Anomalous host activity profiles (process diversity, user counts)",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_anomalous_host_activity")
                },
                "v3_linux_host_user_deviation": {
                    "description": "Unusual user activity patterns per host",
                    "method": lambda data: self._run_job_detection(data, "v3_linux_host_user_deviation")
                }
            }
        }

    def connect_to_elasticsearch(self):
        """Establish connection to Elasticsearch."""
        self.es = connect_to_elasticsearch(self.config)
    def _persist_and_verify_results(self, results: dict[str, 'pd.DataFrame'], out_dir: str = None, diagnostics: dict = None) -> dict[str, 'pd.DataFrame']:
        """
        Persist each job result to disk as Parquet (or CSV fallback) and reload it to verify type.
        Returns reloaded mapping job_name -> DataFrame. Logs any coercions or failures.
        """
        try:
            import pandas as pd
        except Exception:
            raise

        out_base = out_dir or os.path.join(self.config.get('output', {}).get('results_dir', 'results'), 'persisted_results')
        os.makedirs(out_base, exist_ok=True)

        reloaded = {}
        for job_name, df in (results or {}).items():
            try:
                if df is None:
                    df = pd.DataFrame()
                elif not isinstance(df, pd.DataFrame):
                    try:
                        df = pd.DataFrame(df)
                        logger.debug(f"Coerced job {job_name} output to DataFrame during persist step")
                    except Exception:
                        logger.warning(f"Could not coerce job {job_name} output to DataFrame; using empty DataFrame")
                        df = pd.DataFrame()

                parquet_path = os.path.join(out_base, f"{job_name}.parquet")
                try:
                    # Canonicalize anomaly flag before persisting so downstream consumers
                    # can rely on `final_anomaly` being present and boolean.
                    try:
                        if 'final_anomaly' not in df.columns:
                            if 'is_ml_anomaly' in df.columns:
                                df['final_anomaly'] = df['is_ml_anomaly'].fillna(False).astype(bool)
                            else:
                                df['final_anomaly'] = False
                        else:
                            df['final_anomaly'] = df['final_anomaly'].fillna(False).astype(bool)
                    except Exception:
                        # In case of unexpected types, ensure column exists
                        df['final_anomaly'] = df.get('final_anomaly', False)

                    try:
                        df.to_parquet(parquet_path, index=False)
                        logger.info(f"Successfully wrote Parquet for job {job_name}: {parquet_path}")
                        loaded = pd.read_parquet(parquet_path)
                        reloaded[job_name] = loaded
                        logger.info(f"Persisted and reloaded job {job_name}: {len(loaded)} rows")
                    except Exception as pe:
                        logger.warning(f"Parquet write/read failed for job {job_name}: {pe}")
                        raise
                except Exception:
                    # Fallback to CSV
                    csv_path = os.path.join(out_base, f"{job_name}.csv")
                    try:
                        df.to_csv(csv_path, index=False)
                        logger.info(f"Successfully wrote CSV fallback for job {job_name}: {csv_path}")
                        loaded = pd.read_csv(csv_path)
                        reloaded[job_name] = loaded
                        logger.info(f"Persisted job {job_name} to CSV and reloaded: {len(loaded)} rows")
                    except Exception as ce:
                        logger.error(f"CSV fallback write/read failed for job {job_name}: {ce}")
                        # rethrow so outer except can handle
                        raise

            except Exception as e:
                logger.warning(f"Error persisting/reloading job {job_name}: {e}")
                try:
                    reloaded[job_name] = pd.DataFrame(df) if not isinstance(df, pd.DataFrame) else df
                except Exception:
                    reloaded[job_name] = pd.DataFrame()

        # Save diagnostics JSON if provided
        try:
            if diagnostics:
                diag_path = os.path.join(out_base, "persisted_results_diagnostics.json")
                with open(diag_path, 'w') as f:
                    json.dump(diagnostics, f, default=str, indent=2)
                logger.info(f"Saved persistence diagnostics to {diag_path}")
        except Exception as e:
            logger.warning(f"Failed to write diagnostics JSON: {e}")

        return reloaded

    def _generate_comprehensive_outputs(self, results: dict[str, dict[str, pd.DataFrame]]) -> int:
        """Generate comprehensive reports, visualizations, and individual anomaly data."""
        try:
            logger.info("Generating comprehensive outputs")
            plotting_enabled = self.config.get("output", {}).get("visualization", False)

            # Generate reports and visualizations for each data group
            for data_type, group_results in results.items():
                if not group_results:
                    continue

                try:
                    # Generate group report
                    report_file, _ = self.visualizer.generate_comprehensive_report(
                        group_results, data_type
                    )

                    if report_file:
                        logger.info(f"Generated {data_type} report: {report_file}")

                    # Generate visualizations (disabled by default - see output.visualization
                    # config; PNG generation on every detection cycle with no retention was
                    # a major source of unbounded disk growth)
                    if plotting_enabled:
                        viz_paths = self.visualizer.create_data_type_visualizations(
                            group_results, data_type
                        )

                        if viz_paths:
                            logger.info(f"Generated {len(viz_paths)} visualizations for {data_type}")

                except Exception as e:
                    logger.error(f"Error generating outputs for {data_type}: {e}")

            # Generate overall summary report
            # _generate_summary_report may not have existed previously; ensure we call our safe implementation
            try:
                self._generate_summary_report(results)
            except AttributeError:
                # Fallback: create a minimal summary here
                logger.warning("_generate_summary_report missing; writing minimal summary instead")
                try:
                    self._generate_summary_report(results)
                except Exception as e:
                    logger.error(f"Failed to write summary report: {e}")

            return 1

        except Exception as e:
            logger.error(f"Error generating comprehensive outputs: {e}")
            return 0

    def _fetch_data_for_type(self, data_type: str, timeframe: dict[str, str] = None) -> pd.DataFrame:
        """Fetch data for a specific data type with improved error handling."""

        # CRITICAL FIX: Use same time range logic as training
        if timeframe is None:
            try:
                # Use training configuration for consistency
                training_config = get_training_configuration(data_type)
                detection_days = training_config.get("detection_period_days", 1)

                end_time = datetime.utcnow()
                start_time = end_time - timedelta(days=detection_days)
                timeframe = {
                    "gte": start_time.isoformat(),
                    "lte": end_time.isoformat()
                }
                logger.info(f"Using detection period: {detection_days} days for {data_type}")
            except Exception as e:
                logger.warning(f"Could not get detection time range, using defaults: {e}")
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=1)
                timeframe = {
                    "gte": start_time.isoformat(),
                    "lte": end_time.isoformat()
                }

        # Fetch data using same functions as training but with detection time range
        if data_type == "process":
            return fetch_process_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "network":
            return fetch_network_activity_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "user":
            return fetch_user_activity_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "discovery":
            return fetch_discovery_commands_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "metadata":
            return fetch_metadata_access_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "auth":
            return fetch_auth_data(self.es, self.config, timeframe, query_size=10000)
        elif data_type == "host":
            # Host group reuses process events; models partition by host.hostname
            return fetch_process_data(self.es, self.config, timeframe, query_size=10000)
        else:
            logger.error(f"Unknown data type: {data_type}")
            return pd.DataFrame()
    def _run_job_detection(self, data: pd.DataFrame, job_name: str) -> pd.DataFrame:
        """
        NEW: Central method to run job-specific detection using fixed detection methods.

        This method:
        1. Validates job requirements
        2. Applies data fixes
        3. Gets appropriate models (job-prefixed or fallback)
        4. Runs job-specific detection
        5. Adds metadata
        """
        try:
            # Validate job requirements
            validation = validate_job_requirements(data, job_name)
            if not validation['valid']:
                logger.error(f"Job validation failed for {job_name}: {validation['issues']}")
                return pd.DataFrame()

            if validation['warnings']:
                for warning in validation['warnings']:
                    logger.warning(f"Job {job_name} warning: {warning}")

            # Get data type for job
            data_type = self._get_data_type_for_job(job_name)

            # Apply fixes to data
            data, self.config = apply_all_fixes(data, self.config, data_type)

            if data.empty:
                logger.warning(f"No data after fixes for job {job_name}")
                return pd.DataFrame()

            # Get models for this data type
            models, scalers, baselines = self.model_manager.get_models_for_group(data_type)

            # Extract job-specific models if available
            job_models = {}
            job_scalers = {}

            for key, model in models.items():
                if key.startswith(f"{job_name}:"):
                    entity = key.replace(f"{job_name}:", "")
                    job_models[entity] = model

            for key, scaler in scalers.items():
                if key.startswith(f"{job_name}:"):
                    entity = key.replace(f"{job_name}:", "")
                    job_scalers[entity] = scaler

            # Use job-specific models if available, otherwise use general models
            if job_models:
                logger.info(f"Using {len(job_models)} job-specific models for {job_name}")
                models_to_use = job_models
                scalers_to_use = job_scalers
            else:
                logger.info(f"Using {len(models)} general models for {job_name}")
                models_to_use = models
                scalers_to_use = scalers

            # Set job name in config for detection
            self.config['current_job_name'] = job_name

            # Run job-specific detection
            results = detect_job_anomalies(
                data=data,
                models=models_to_use,
                scalers=scalers_to_use,
                config=self.config,
                job_name=job_name
            )

            # Add job metadata
            if not results.empty:
                results['detection_job'] = job_name
                results['data_type'] = data_type
                results['job_description'] = JOB_CONFIGURATIONS[job_name].get('description', '')

            return results

        except Exception as e:
            logger.error(f"Error in job detection {job_name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return pd.DataFrame()

    def _get_data_type_for_job(self, job_name: str) -> str:
        """Get data type for a specific job."""
        for data_type, jobs in self.detection_jobs.items():
            if job_name in jobs:
                return data_type

        # Check JOB_CONFIGURATIONS as fallback
        if job_name in JOB_CONFIGURATIONS:
            return JOB_CONFIGURATIONS[job_name].get('data_type', 'process')

        return "process"  # Default

    # Individual detection methods - all use the new job-specific approach
    def _detect_anomalous_process_all_hosts(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect processes unusual to all Linux hosts."""
        return self._run_job_detection(data, "v3_linux_anomalous_process_all_hosts")

    def _detect_rare_process_by_host(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect processes unusual to particular Linux hosts."""
        return self._run_job_detection(data, "v3_rare_process_by_host_linux")

    def _detect_anomalous_network_activity(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual network activity (IP-based)."""
        return self._run_job_detection(data, "v3_linux_anomalous_network_activity")

    def _detect_anomalous_network_port_activity(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual destination port activity."""
        return self._run_job_detection(data, "v3_linux_anomalous_network_port_activity")

    def _detect_anomalous_user_name(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect rare and unusual user activity."""
        return self._run_job_detection(data, "v3_linux_anomalous_user_name")

    def _detect_rare_sudo_user(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect sudo activity from unusual users."""
        return self._run_job_detection(data, "v3_linux_rare_sudo_user")

    def _detect_rare_user_compiler(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect compiler activity from unusual users."""
        return self._run_job_detection(data, "v3_linux_rare_user_compiler")

    def _detect_network_configuration_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect network configuration discovery commands."""
        return self._run_job_detection(data, "v3_linux_network_configuration_discovery")

    def _detect_network_connection_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect network connection discovery commands."""
        return self._run_job_detection(data, "v3_linux_network_connection_discovery")

    def _detect_system_information_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system information discovery commands."""
        return self._run_job_detection(data, "v3_linux_system_information_discovery")

    def _detect_system_process_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system process discovery commands."""
        return self._run_job_detection(data, "v3_linux_system_process_discovery")

    def _detect_system_user_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system user discovery commands."""
        return self._run_job_detection(data, "v3_linux_system_user_discovery")

    def _detect_rare_metadata_process(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual processes accessing metadata services."""
        return self._run_job_detection(data, "v3_linux_rare_metadata_process")

    def _detect_rare_metadata_user(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual users accessing metadata services."""
        return self._run_job_detection(data, "v3_linux_rare_metadata_user")

    def train_models_for_group(self, data_type: str, retrain: bool = False) -> bool:
        """
        Train machine learning models for a specific data group.

        Args:
            data_type: Data group to train models for
            retrain: Whether to retrain even if models exist

        Returns:
            bool: Success status
        """
        logger.info(f"Training models for {data_type} group")

        if data_type not in self.detection_jobs:
            raise ValueError(f"Unknown data type: {data_type}")

        try:
            # Check if models already exist
            if not retrain:
                success = self.model_manager.load_models(data_type)
                if success:
                    logger.info(f"Models already exist for {data_type}, skipping training")
                    return True

            # Fetch baseline data for training
            baseline_data = self._fetch_baseline_data_with_scroll(data_type)
            if baseline_data.empty:
                logger.error(f"No baseline data available for training {data_type} models")
                return False

            # Use specialized training functions from model_manager
            if data_type == "process":
                models, scalers, baselines = train_process_anomaly_models(baseline_data, self.config)
            elif data_type == "network":
                models, scalers, baselines = train_network_activity_models(baseline_data, self.config)
            elif data_type == "user":
                models, scalers, baselines = train_user_behavior_models(baseline_data, self.config)
            elif data_type == "discovery":
                models, scalers, baselines = train_discovery_command_models(baseline_data, self.config)
            elif data_type == "metadata":
                models, scalers, baselines = train_metadata_access_models(baseline_data, self.config)
            elif data_type == "auth":
                models, scalers, baselines = train_auth_anomaly_models(baseline_data, self.config)
            elif data_type == "host":
                models, scalers, baselines = train_host_anomaly_models(baseline_data, self.config)
            else:
                # Fallback to general training
                models, scalers = self.model_manager.train_models(baseline_data, data_type)
                baselines = self.model_manager.establish_baselines(baseline_data, data_type)

            if models or baselines:
                # Store in model manager
                if models:
                    self.model_manager.models[data_type] = models
                if scalers:
                    self.model_manager.scalers[data_type] = scalers
                if baselines:
                    self.model_manager.baselines[data_type] = baselines

                logger.info(f"Successfully trained and saved models for {data_type}")
                return True
            else:
                logger.error(f"Failed to train models for {data_type}")
                return False

        except Exception as e:
            logger.error(f"Error training models for {data_type}: {e}")
            return False

    def train_models_before_detection(self, data_groups: list[str] = None, force_retrain: bool = False) -> bool:
        """
        Train models before detection using the scroll API for 30+ day baselines.

        Args:
            data_groups: List of data groups to train models for
            force_retrain: Whether to retrain even if models exist

        Returns:
            bool: Success status
        """
        logger.info("Training models before detection")

        groups_to_train = data_groups if data_groups else list(self.detection_jobs.keys())
        overall_success = True

        for data_type in groups_to_train:
            try:
                # Check if models already exist
                models_exist = self.model_manager.load_models(data_type)

                if models_exist and not force_retrain:
                    logger.info(f"Models already exist for {data_type}, skipping training")
                    continue

                logger.info(f"Training models for {data_type} group")

                # Fetch comprehensive baseline data using scroll API
                baseline_data = self._fetch_baseline_data_with_scroll(data_type)

                if baseline_data.empty:
                    logger.error(f"No baseline data available for training {data_type} models")
                    overall_success = False
                    continue

                # Use specialized training functions from model_manager
                if data_type == "process":
                    models, scalers, baselines = train_process_anomaly_models(baseline_data, self.config)
                elif data_type == "network":
                    models, scalers, baselines = train_network_activity_models(baseline_data, self.config)
                elif data_type == "user":
                    models, scalers, baselines = train_user_behavior_models(baseline_data, self.config)
                elif data_type == "discovery":
                    models, scalers, baselines = train_discovery_command_models(baseline_data, self.config)
                elif data_type == "metadata":
                    models, scalers, baselines = train_metadata_access_models(baseline_data, self.config)
                else:
                    # Fallback to general training
                    models, scalers = self.model_manager.train_models(baseline_data, data_type)
                    baselines = self.model_manager.establish_baselines(baseline_data, data_type)

                if models or baselines:
                    # Store in model manager
                    if models:
                        self.model_manager.models[data_type] = models
                    if scalers:
                        self.model_manager.scalers[data_type] = scalers
                    if baselines:
                        self.model_manager.baselines[data_type] = baselines

                    logger.info(f"Successfully trained and saved models for {data_type}")
                else:
                    logger.error(f"Failed to train models for {data_type}")
                    overall_success = False

            except Exception as e:

                logger.error(f"Error training models for {data_type}: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                overall_success = False

        return overall_success

    def _fetch_baseline_data_with_scroll(self, data_type: str) -> pd.DataFrame:
        """
        Fetch comprehensive baseline data using scroll API for 30+ days.

        Args:
            data_type: Type of data to fetch

        Returns:
            pd.DataFrame: Baseline data
        """
        if not self.es:
            logger.error("No Elasticsearch connection available")
            return pd.DataFrame()

        try:
            # Use the fetch_baseline_data function from datamanager
            baseline_data = fetch_baseline_data(self.es, self.config, data_type)

            if not baseline_data.empty:
                logger.info(f"Retrieved {len(baseline_data)} baseline records for {data_type}")

                # Apply preprocessing specific to data type
                if data_type == "process":
                    baseline_data = preprocess_process_data(baseline_data)
                elif data_type == "network":
                    baseline_data = preprocess_network_data(baseline_data)
                elif data_type == "user":
                    baseline_data = preprocess_user_data(baseline_data)
                elif data_type == "discovery":
                    baseline_data = preprocess_discovery_data(baseline_data)
                elif data_type == "metadata":
                    baseline_data = preprocess_metadata_data(baseline_data)
                elif data_type == "auth":
                    baseline_data = preprocess_auth_data(baseline_data)
                elif data_type == "host":
                    # Host group reuses process-event preprocessing (same index)
                    baseline_data = preprocess_process_data(baseline_data)

                logger.info(f"Preprocessed baseline data shape: {baseline_data.shape}")
                return baseline_data
            else:
                logger.warning(f"No baseline data retrieved for {data_type}")
                return pd.DataFrame()

        except Exception as e:
            logger.error(f"Error fetching baseline data for {data_type}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return pd.DataFrame()

    def run_comprehensive_detection(self, data_groups: list[str] = None,
                                  use_baseline: bool = True,
                                  train_models: bool = True,
                                  force_retrain: bool = False) -> dict[str, dict[str, pd.DataFrame]]:
        """
        Run comprehensive Linux anomaly detection with improved model training.

        Args:
            data_groups: Data groups to process (default: all)
            use_baseline: Whether to use baseline data
            train_models: Whether to train models if needed
            force_retrain: Whether to force retrain existing models

        Returns:
            dict: Results organized by data group and job
        """
        logger.info("Running comprehensive Linux anomaly detection")

        # Determine which data groups to process
        available_groups = list(self.detection_jobs.keys())
        groups_to_process = data_groups if data_groups else available_groups

        # Validate groups
        invalid_groups = [group for group in groups_to_process if group not in available_groups]
        if invalid_groups:
            raise ValueError(f"Invalid data groups: {invalid_groups}")

        # Train models before detection if requested
        if train_models:
            logger.info("Training models before detection")
            training_success = self.train_models_before_detection(groups_to_process, force_retrain)
            if not training_success:
                logger.warning("Some models failed to train, continuing with available models")

        comprehensive_results = {}

        # Process each data group
        for data_type in groups_to_process:
            logger.info(f"Processing {data_type} data group")

            try:
                group_results = self.run_data_group_detection(
                    data_type=data_type,
                    use_baseline=use_baseline,
                    load_existing_models=True
                )

                comprehensive_results[data_type] = group_results

                # Log summary for this group
                total_anomalies = 0
                for _job_name, results in group_results.items():
                    if not results.empty and 'final_anomaly' in results.columns:
                        anomalies = results[results['final_anomaly']]
                        total_anomalies += len(anomalies)

                logger.info(f"Completed {data_type} group: {total_anomalies} total anomalies detected")

            except Exception as e:
                logger.error(f"Error processing {data_type} group: {e}")
                comprehensive_results[data_type] = {}

        # Generate comprehensive report and visualizations
        if self.config.get("output", {}).get("save_results", True):
            self._generate_comprehensive_outputs(comprehensive_results)

        logger.info("Comprehensive Linux anomaly detection completed")
        return comprehensive_results
    def extract_and_save_anomalies(self, results: dict[str, dict[str, pd.DataFrame]], output_dir: str | None = None) -> str:
        """
        Extract ONLY ML anomalies from detection results and save to JSON file.

        MODIFIED: Filters for machine_learning detection_method only, removes NaN index

        Args:
            results: Results from comprehensive detection
            output_dir: Directory to save the anomaly JSON file (defaults to config output dir)

        Returns:
            str: Path to the saved JSON file
        """
        if not output_dir:
            output_dir = self.config.get("output", {}).get("results_dir", "results")

        os.makedirs(output_dir, exist_ok=True)

        # Dictionary to hold ONLY ML anomalies organized by job
        ml_only_anomalies = {}
        ml_anomaly_count = 0

        logger.info("Extracting ONLY ML anomalies from detection results")

        for data_type, group_results in results.items():
            for job_name, job_results in group_results.items():
                if job_results.empty:
                    continue

                # CRITICAL FILTER: prefer detection_method + final_anomaly, but fall back to is_ml_anomaly
                if 'detection_method' not in job_results.columns and 'is_ml_anomaly' not in job_results.columns and 'final_anomaly' not in job_results.columns:
                    logger.debug(f"Skipping {job_name} - no anomaly indicator or detection_method column")
                    continue

                # Prefer 'final_anomaly' as the canonical flag; fallback to 'is_ml_anomaly'
                if 'final_anomaly' in job_results.columns:
                    anomaly_flag = 'final_anomaly'
                elif 'is_ml_anomaly' in job_results.columns:
                    anomaly_flag = 'is_ml_anomaly'
                else:
                    anomaly_flag = None

                # Log counts for debugging
                try:
                    flag_count = int(job_results[anomaly_flag].sum()) if anomaly_flag else 0
                except Exception:
                    flag_count = 0
                logger.debug(f"Job {job_name} has {flag_count} candidate anomalies by {anomaly_flag}")

                # Filter for ML anomalies ONLY. If detection_method missing, accept any with anomaly_flag True
                if 'detection_method' in job_results.columns and anomaly_flag:
                    ml_mask = (job_results['detection_method'] == 'machine_learning') & (job_results[anomaly_flag])
                elif anomaly_flag:
                    ml_mask = (job_results[anomaly_flag])
                else:
                    ml_mask = pd.Series([False] * len(job_results), index=job_results.index)

                ml_anomalies = job_results[ml_mask].copy()

                if ml_anomalies.empty:
                    logger.debug(f"No ML anomalies found in {job_name}")
                    continue

                # Clean index to remove any NaN values
                ml_anomalies = ml_anomalies.reset_index(drop=True)

                # Remove rows with NaN in critical columns
                critical_columns = ['final_anomaly', 'detection_method']
                for col in critical_columns:
                    if col in ml_anomalies.columns:
                        ml_anomalies = ml_anomalies.dropna(subset=[col])

                # Reset index again after cleaning
                ml_anomalies = ml_anomalies.reset_index(drop=True)

                if ml_anomalies.empty:
                    logger.debug(f"No clean ML anomalies after NaN removal in {job_name}")
                    continue

                # Create job entry
                if job_name not in ml_only_anomalies:
                    ml_only_anomalies[job_name] = {
                        "job_id": job_name,
                        "data_type": data_type,
                        "detection_method": "machine_learning",  # Explicitly ML only
                        "anomaly_count": 0,
                        "anomalies": []
                    }

                # Process each ML anomaly
                for idx, anomaly in ml_anomalies.iterrows():
                    # Verify this is actually an ML anomaly
                    if anomaly.get('detection_method') != 'machine_learning':
                        continue

                    if not anomaly.get('final_anomaly', False):
                        continue

                    # Canonical model output is always in [0, 1]. Keep
                    # both `ml_score` (back-compat) and `raw_ml_score`
                    # (new explicit contract) so downstream push/Kibana
                    # can threshold on the unambiguous field.
                    raw_ml = anomaly.get('raw_ml_score', anomaly.get('ml_anomaly_score', 0.0))
                    try:
                        raw_ml_f = float(raw_ml) if raw_ml is not None and not pd.isna(raw_ml) else 0.0
                    except Exception:
                        raw_ml_f = 0.0
                    raw_ml_f = max(0.0, min(1.0, raw_ml_f))

                    anomaly_record = {
                        "timestamp": str(anomaly.get('@timestamp', '')),
                        "ml_score": raw_ml_f,
                        "raw_ml_score": raw_ml_f,
                        "score_contract_version": 2,
                        "confidence": float(anomaly.get('confidence', 0.0)),
                        "event_count": int(anomaly.get('event_count', 0)),
                        "detection_method": "machine_learning",
                        "clean_index": int(idx),
                    }

                    # Add ML-specific threshold info
                    if 'detection_threshold' in anomaly:
                        anomaly_record["threshold_used"] = float(anomaly['detection_threshold'])

                    # Add methods used info
                    if 'methods_used' in anomaly:
                        anomaly_record["ml_methods"] = str(anomaly['methods_used'])

                    # Add entity-specific fields based on data type
                    entity_fields = self._extract_entity_fields(anomaly, data_type)
                    if entity_fields:
                        anomaly_record.update(entity_fields)

                    # Add ML score details
                    ml_score_details = self._extract_ml_score_details(anomaly)
                    if ml_score_details:
                        anomaly_record["ml_score_details"] = ml_score_details

                    # Add feature details for ML
                    feature_details = self._extract_feature_details(anomaly)
                    if feature_details:
                        anomaly_record["features"] = feature_details

                    # Add context fields
                    context = self._extract_context_fields(anomaly, data_type)
                    if context:
                        anomaly_record["context"] = context

                    # Add ML-specific description
                    anomaly_record["description"] = self._generate_ml_anomaly_description(anomaly, data_type)

                    # Add the ML anomaly to the job's list
                    ml_only_anomalies[job_name]["anomalies"].append(anomaly_record)
                    ml_only_anomalies[job_name]["anomaly_count"] += 1
                    ml_anomaly_count += 1

        if ml_anomaly_count == 0:
            logger.warning("No ML anomalies found in any data type - check ML detection thresholds")
            # Create empty file for consistency
            timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            anomalies_file = os.path.join(output_dir, f"ml_only_anomalies_{timestamp_str}.json")

            with open(anomalies_file, 'w') as f:
                json.dump({
                    "total_ml_anomalies": 0,
                    "detection_summary": "No ML anomalies detected - check thresholds",
                    "ml_jobs": {}
                }, f, indent=2)

            return anomalies_file

        # Save ML-only anomalies to JSON file
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        anomalies_file = os.path.join(output_dir, f"ml_only_anomalies_{timestamp_str}.json")

        # Create summary structure
        ml_summary = {
            "total_ml_anomalies": ml_anomaly_count,
            "detection_method": "machine_learning_only",
            "generated_at": datetime.utcnow().isoformat(),
            "clean_index": True,  # Guaranteed no NaN
            "ml_jobs": ml_only_anomalies
        }

        with open(anomalies_file, 'w') as f:
            json.dump(ml_summary, f, indent=2, default=str)

        logger.info(f"Saved {ml_anomaly_count} ML-only anomalies to {anomalies_file}")

        # Also create a simple CSV for easy analysis
        csv_file = anomalies_file.replace('.json', '.csv')
        ml_records = []

        for job_name, job_data in ml_only_anomalies.items():
            for anomaly in job_data["anomalies"]:
                record = {
                    "job_name": job_name,
                    "data_type": job_data["data_type"],
                    "timestamp": anomaly["timestamp"],
                    "ml_score": anomaly["ml_score"],
                    "confidence": anomaly["confidence"],
                    "event_count": anomaly["event_count"],
                    "clean_index": anomaly["clean_index"]
                }

                # Add entity info if available
                if "entity" in anomaly:
                    record["entity"] = anomaly["entity"]

                ml_records.append(record)

        if ml_records:
            # NOTE: pandas is already imported at module scope (line ~3090).
            # A local `import pandas as pd` here makes Python treat `pd` as a
            # local variable for the ENTIRE function, which raises
            # UnboundLocalError when `pd.isna(...)` runs earlier in the loop.
            # That silent exception was zeroing every anomaly's raw_ml_score,
            # blocking the push pipeline end-to-end. Keep this import removed.
            ml_df = pd.DataFrame(ml_records)
            ml_df.to_csv(csv_file, index=False)
            logger.info(f"Also saved ML anomalies to CSV: {csv_file}")

        return anomalies_file

    def _generate_summary_report(self, results: dict[str, dict[str, pd.DataFrame]]) -> str | None:
        """
        Create a minimal summary markdown report that lists anomaly counts per data_type and job.
        This ensures callers won't fail if the original detailed generator is missing.
        Returns path to the written report or None on failure.
        """
        try:
            out_dir = self.config.get('output', {}).get('results_dir', 'results')
            os.makedirs(out_dir, exist_ok=True)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            report_path = os.path.join(out_dir, f"anomaly_summary_{timestamp}.md")

            lines = [f"# Anomaly Summary - {datetime.utcnow().isoformat()}", ""]
            total = 0
            for data_type, group in (results or {}).items():
                lines.append(f"## {data_type}")
                if not group:
                    lines.append("- No jobs run or no results")
                    lines.append("")
                    continue
                for job_name, df in group.items():
                    try:
                        count = 0
                        if isinstance(df, dict):
                            count = df.get('anomaly_count', 0)
                        else:
                            if hasattr(df, 'empty') and not df.empty:
                                if 'final_anomaly' in df.columns:
                                    count = int(df['final_anomaly'].sum())
                                elif 'is_ml_anomaly' in df.columns:
                                    count = int(df['is_ml_anomaly'].sum())
                                else:
                                    count = 0
                        total += count
                        lines.append(f"- {job_name}: {count} anomalies")
                    except Exception:
                        lines.append(f"- {job_name}: error counting anomalies")
                lines.append("")

            lines.insert(1, f"Total anomalies detected across all jobs: {total}")

            with open(report_path, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join(lines))

            logger.info(f"Wrote minimal summary report: {report_path}")
            return report_path
        except Exception as e:
            logger.error(f"_generate_summary_report failed: {e}")
            return None

    @staticmethod
    def _is_valid_process_name(val: Any) -> bool:
        """Reject tokenisation artefacts like pure-numeric or 1-char tokens.

        Valid process names must be non-empty, not match only digits, and
        contain at least 2 characters after stripping whitespace. This
        guards against upstream tokenisation bugs that surface as
        `process.name == "6"` in Kibana alerts.
        """
        if val is None:
            return False
        try:
            if pd.isna(val):
                return False
        except Exception:
            pass
        s = str(val).strip()
        if not s:
            return False
        if len(s) < 2:
            return False
        if s.isdigit():
            return False
        return True

    @staticmethod
    def _derive_process_name_fallback(anomaly: Any) -> str:
        """Best-effort process name when the primary token is malformed.

        Prefers the basename of `process.executable`, then the first
        alphanumeric token of `process.command_line`, and finally a
        labelled placeholder so that downstream filtering can detect
        low-quality entities.
        """
        exe = anomaly.get('process.executable') if hasattr(anomaly, 'get') else None
        try:
            if exe is not None and not pd.isna(exe):
                exe_s = str(exe).strip()
                if exe_s:
                    base = os.path.basename(exe_s)
                    if LinuxAnomalyDetector._is_valid_process_name(base):
                        return base
        except Exception:
            pass

        cmd = anomaly.get('process.command_line') if hasattr(anomaly, 'get') else None
        try:
            if cmd is not None and not pd.isna(cmd):
                cmd_s = str(cmd).strip()
                if cmd_s:
                    first = cmd_s.split()[0] if cmd_s.split() else ''
                    base = os.path.basename(first) if first else ''
                    if LinuxAnomalyDetector._is_valid_process_name(base):
                        return base
        except Exception:
            pass

        return "invalid-process"

    # Helper extraction methods used by the ML-only exporter
    def _extract_entity_fields(self, anomaly: 'pd.Series', data_type: str) -> dict[str, Any]:
        """Extract canonical entity information from an anomaly row.

        Returns a mapping that can be merged into the anomaly record (e.g. {"entity": {...}}).
        This method is defensive: it accepts both flattened column names and nested dicts.
        """
        try:
            entity = {}

            # If the row contains an 'entity' column that's already a dict, merge it first
            entcol = anomaly.get('entity') if hasattr(anomaly, 'get') else None
            if isinstance(entcol, dict):
                entity.update(entcol)

            # Host
            host = (anomaly.get('host.hostname') if hasattr(anomaly, 'get') else None) or anomaly.get('host.name') or anomaly.get('host') or anomaly.get('hostname')
            if host and not pd.isna(host):
                entity.setdefault('host', host)

            # Process - with validation + fallback. Reject tokens like "6"
            # or 1-char artefacts, and fall back to executable basename.
            proc_raw = anomaly.get('process.name') or anomaly.get('process') or anomaly.get('process_name') or anomaly.get('proc')
            proc_valid = self._is_valid_process_name(proc_raw)
            if proc_valid:
                proc = proc_raw
            else:
                proc = self._derive_process_name_fallback(anomaly)
                entity.setdefault('process_extraction_fallback', True)
                entity.setdefault(
                    'process_original',
                    None if proc_raw is None else str(proc_raw),
                )
            if proc:
                entity.setdefault('process', proc)

            # User
            user = anomaly.get('user.name') or anomaly.get('user') or anomaly.get('username')
            if user and not pd.isna(user):
                entity.setdefault('user', user)

            # IPs & ports
            src_ip = anomaly.get('source.ip') or anomaly.get('src_ip') or anomaly.get('source_ip') or anomaly.get('ip_src') or anomaly.get('ip')
            if src_ip and not pd.isna(src_ip):
                entity.setdefault('ip_source', src_ip)

            dst_ip = anomaly.get('destination.ip') or anomaly.get('dest.ip') or anomaly.get('dst_ip') or anomaly.get('destination_ip') or anomaly.get('ip_dst')
            if dst_ip and not pd.isna(dst_ip):
                entity.setdefault('ip_destination', dst_ip)

            # Ports
            src_port = anomaly.get('source.port') or anomaly.get('src_port')
            if src_port and not pd.isna(src_port):
                entity.setdefault('port_source', int(src_port) if str(src_port).isdigit() else src_port)

            dst_port = anomaly.get('destination.port') or anomaly.get('dest.port') or anomaly.get('dst_port')
            if dst_port and not pd.isna(dst_port):
                entity.setdefault('port_destination', int(dst_port) if str(dst_port).isdigit() else dst_port)

            if not entity:
                return {}

            return {'entity': entity}
        except Exception as e:
            logger.debug(f"_extract_entity_fields failed: {e}")
            return {}

    def _extract_ml_score_details(self, anomaly: 'pd.Series') -> dict[str, Any]:
        """Extract ML scoring related fields into a small dict."""
        try:
            details: dict[str, Any] = {}
            if 'ml_anomaly_score' in anomaly and not pd.isna(anomaly['ml_anomaly_score']):
                details['ml_anomaly_score'] = float(anomaly['ml_anomaly_score'])
            if 'confidence' in anomaly and not pd.isna(anomaly['confidence']):
                try:
                    details['confidence'] = float(anomaly['confidence'])
                except Exception:
                    details['confidence'] = anomaly['confidence']
            if 'detection_threshold' in anomaly and not pd.isna(anomaly['detection_threshold']):
                details['threshold'] = float(anomaly['detection_threshold'])
            if 'methods_used' in anomaly and not pd.isna(anomaly['methods_used']):
                details['methods'] = [s.strip() for s in str(anomaly['methods_used']).split(',') if s.strip()]
            if 'combined_score' in anomaly and not pd.isna(anomaly['combined_score']):
                details['combined_score'] = float(anomaly['combined_score'])
            return details
        except Exception as e:
            logger.debug(f"_extract_ml_score_details failed: {e}")
            return {}

    def _extract_feature_details(self, anomaly: 'pd.Series') -> dict[str, Any]:
        """Extract feature-level details (actual vs typical, causes, etc.)."""
        try:
            feat = {}
            if 'actual' in anomaly and not pd.isna(anomaly['actual']):
                try:
                    feat['actual'] = float(anomaly['actual'])
                except Exception:
                    feat['actual'] = anomaly['actual']
            if 'typical' in anomaly and not pd.isna(anomaly['typical']):
                try:
                    feat['typical'] = float(anomaly['typical'])
                except Exception:
                    feat['typical'] = anomaly['typical']
            if 'field_name' in anomaly and not pd.isna(anomaly['field_name']):
                feat['field_name'] = anomaly['field_name']
            if 'function' in anomaly and not pd.isna(anomaly['function']):
                feat['function'] = anomaly['function']
            if 'function_description' in anomaly and not pd.isna(anomaly['function_description']):
                feat['function_description'] = anomaly['function_description']

            if 'causes' in anomaly and not pd.isna(anomaly['causes']):
                try:
                    if isinstance(anomaly['causes'], str):
                        causes = json.loads(anomaly['causes'])
                    else:
                        causes = anomaly['causes']
                    feat['causes'] = causes
                except Exception:
                    feat['causes'] = anomaly['causes']

            return feat
        except Exception as e:
            logger.debug(f"_extract_feature_details failed: {e}")
            return {}

    def _extract_context_fields(self, anomaly: 'pd.Series', data_type: str) -> dict[str, Any]:
        """Extract contextual metadata useful for triage."""
        try:
            context: dict[str, Any] = {'data_type': data_type}

            boolean_indicators = [
                'is_root_user', 'is_system_path', 'is_tmp_execution', 'is_large_transfer',
                'is_well_known_port', 'is_sudo_command', 'is_compiler_activity', 'is_service_user',
                'is_business_hours', 'has_pipes', 'has_redirection', 'potential_cred_harvest'
            ]
            for ind in boolean_indicators:
                if ind in anomaly and not pd.isna(anomaly[ind]):
                    context[ind] = bool(anomaly[ind])

            categorical_fields = [
                'discovery_category', 'metadata_service_type', 'result_type', 'by_field_name',
                'by_field_value', 'over_field_name', 'over_field_value', 'partition_field_name',
                'partition_field_value', 'detection_method'
            ]
            for field in categorical_fields:
                if field in anomaly and not pd.isna(anomaly[field]):
                    context[field] = anomaly[field]

            if 'bucket_span' in anomaly and not pd.isna(anomaly['bucket_span']):
                try:
                    context['bucket_span'] = int(anomaly['bucket_span'])
                except Exception:
                    context['bucket_span'] = anomaly['bucket_span']

            if 'is_interim' in anomaly and not pd.isna(anomaly['is_interim']):
                context['is_interim'] = bool(anomaly['is_interim'])

            if 'host_count' in anomaly and not pd.isna(anomaly['host_count']):
                try:
                    context['host_count'] = int(anomaly['host_count'])
                except Exception:
                    context['host_count'] = anomaly['host_count']

            return context
        except Exception as e:
            logger.debug(f"_extract_context_fields failed: {e}")
            return {'data_type': data_type}

    def _generate_ml_anomaly_description(self, anomaly: 'pd.Series', data_type: str) -> str:
        """Generate a short description string for an ML anomaly."""
        try:
            ml_score = anomaly.get('ml_anomaly_score', 0.0)
            try:
                ml_score_val = float(ml_score) if ml_score is not None and not pd.isna(ml_score) else 0.0
            except Exception:
                ml_score_val = 0.0
            confidence = anomaly.get('confidence', 0.0)
            try:
                confidence_val = float(confidence) if confidence is not None and not pd.isna(confidence) else 0.0
            except Exception:
                confidence_val = 0.0
            threshold = anomaly.get('detection_threshold', 0.0) or 0.0

            desc = f"ML-detected {data_type} anomaly"
            if ml_score_val > 0:
                desc += f" (score: {ml_score_val:.3f}"
                if threshold and not pd.isna(threshold):
                    try:
                        desc += f", threshold: {float(threshold):.3f}"
                    except Exception:
                        pass
                desc += ")"
            if confidence_val > 0:
                desc += f" with {confidence_val:.1%} confidence"

            # Append entity hint if possible
            ent = self._extract_entity_fields(anomaly, data_type)
            entmap = ent.get('entity') if isinstance(ent, dict) else None
            if entmap:
                hint = entmap.get('host') or entmap.get('process') or entmap.get('user')
                if hint:
                    desc += f" for {hint}"

            event_count = anomaly.get('event_count', 0) or 0
            try:
                if int(event_count) > 1:
                    desc += f" ({int(event_count)} events)"
            except Exception:
                pass

            return desc
        except Exception as e:
            logger.debug(f"_generate_ml_anomaly_description failed: {e}")
            return f"ML-detected {data_type} anomaly"


    def run_data_group_detection(self, data_type: str, jobs: list[str] = None,
                                use_baseline: bool = True, load_existing_models: bool = True) -> dict[str, pd.DataFrame]:
        """Enhanced detection with job-specific model loading."""
        logger.info(f"Running {data_type} group detection")

        if data_type not in self.detection_jobs:
            raise ValueError(f"Unknown data type: {data_type}")

        # Load models if requested
        if load_existing_models:
            try:
                models_loaded = self.model_manager.load_models(data_type)
                if models_loaded:
                    logger.info(f"Loaded existing models for {data_type}")

                    # Log which jobs have models
                    model_summary = self.model_manager.get_model_summary()
                    if data_type in model_summary.get('by_data_type', {}):
                        job_counts = model_summary['by_data_type'][data_type].get('jobs', {})
                        for job, count in job_counts.items():
                            logger.info(f"  Job {job}: {count} models")
                else:
                    logger.warning(f"No existing models found for {data_type}")
            except Exception as e:
                logger.error(f"Error loading models for {data_type}: {e}")

        # Fetch and preprocess data
        try:
            data = self._fetch_data_for_type(data_type)
            if data.empty:
                logger.warning(f"No data available for {data_type} group")
                return {}

            # Determine which jobs to run
            available_jobs = list(self.detection_jobs[data_type].keys())
            jobs_to_run = jobs if jobs else available_jobs

            # Validate jobs
            invalid_jobs = [job for job in jobs_to_run if job not in available_jobs]
            if invalid_jobs:
                raise ValueError(f"Invalid jobs for {data_type}: {invalid_jobs}")

            # Run each job
            results = {}
            # Diagnostics collected per job about coercions/fallbacks
            diagnostics = {"jobs": {}, "summary": {"total_jobs": 0, "coerced": 0, "fallbacks": 0}}

            for job_name in jobs_to_run:
                try:
                    logger.info(f"Running job: {job_name}")
                    job_method = self.detection_jobs[data_type][job_name]["method"]
                    job_results = job_method(data)

                    # Defensive normalization: coerce common non-DataFrame outputs into DataFrame
                    diagnostics['summary']['total_jobs'] += 1
                    original_type = type(job_results).__name__
                    normalized = None
                    diag_entry: dict[str, Any] = {"original_type": original_type, "coerced": False, "coercion_reason": None, "rows": 0}

                    # None -> empty DataFrame
                    if job_results is None:
                        normalized = pd.DataFrame()
                        diag_entry['coerced'] = True
                        diag_entry['coercion_reason'] = 'None->empty DataFrame'
                        diagnostics['summary']['coerced'] += 1

                    # If already a DataFrame, keep it
                    elif isinstance(job_results, pd.DataFrame):
                        normalized = job_results

                    # Tuple like (df, saveable)
                    elif isinstance(job_results, tuple) and len(job_results) > 0 and isinstance(job_results[0], pd.DataFrame):
                        normalized = job_results[0]
                        logger.debug(f"Normalized tuple result for job {job_name} to DataFrame")
                        diag_entry['coerced'] = True
                        diag_entry['coercion_reason'] = 'tuple->first-element DataFrame'
                        diagnostics['summary']['coerced'] += 1

                    # Dict -> try to convert to DataFrame
                    elif isinstance(job_results, dict):
                        try:
                            normalized = pd.DataFrame.from_dict(job_results)
                        except Exception:
                            normalized = pd.DataFrame([job_results])
                        logger.warning(f"Job {job_name} returned a dict; converted to DataFrame")
                        diag_entry['coerced'] = True
                        diag_entry['coercion_reason'] = 'dict->DataFrame'
                        diagnostics['summary']['coerced'] += 1

                    # List -> try to convert
                    elif isinstance(job_results, list):
                        try:
                            normalized = pd.DataFrame(job_results)
                        except Exception:
                            normalized = pd.DataFrame([{'value': job_results}])
                        logger.warning(f"Job {job_name} returned a list; converted to DataFrame")
                        diag_entry['coerced'] = True
                        diag_entry['coercion_reason'] = 'list->DataFrame'
                        diagnostics['summary']['coerced'] += 1

                    else:
                        # Unknown type: log and wrap into empty DataFrame
                        logger.warning(f"Job {job_name} returned unsupported type {original_type}; using empty DataFrame")
                        normalized = pd.DataFrame()
                        diag_entry['coerced'] = True
                        diag_entry['coercion_reason'] = f'unsupported_type->{original_type}->empty'
                        diagnostics['summary']['coerced'] += 1

                    # Ensure we have a DataFrame
                    if not isinstance(normalized, pd.DataFrame):
                        try:
                            normalized = pd.DataFrame(normalized)
                        except Exception:
                            normalized = pd.DataFrame()

                    # Add job metadata if results are non-empty
                    if not normalized.empty:
                        normalized['detection_job'] = job_name
                        normalized['data_type'] = data_type
                        if 'final_anomaly' in normalized.columns:
                            anomaly_count = normalized['final_anomaly'].sum()
                            logger.info(f"  {job_name}: {anomaly_count} anomalies detected")

                    diag_entry['rows'] = 0 if normalized is None else (len(normalized) if hasattr(normalized, '__len__') else 0)
                    # Attach any per-entity diagnostics collected by detection methods
                    try:
                        from detection_methods import pop_job_entity_diagnostics
                        entity_diags = pop_job_entity_diagnostics(job_name)
                        if entity_diags:
                            diag_entry['entity_diagnostics'] = entity_diags
                    except Exception:
                        # If import/pop fails, continue without entity diagnostics
                        pass

                    diagnostics['jobs'][job_name] = diag_entry
                    results[job_name] = normalized

                except Exception as e:
                    logger.error(f"Error in {job_name}: {e}")
                    results[job_name] = pd.DataFrame()
                    diagnostics['jobs'][job_name] = {"original_type": type(e).__name__, "coerced": True, "coercion_reason": f'exception->{e}', "rows": 0}

            # Persist and verify results before returning
            try:
                results = self._persist_and_verify_results(results, diagnostics=diagnostics)
            except Exception as e:
                logger.warning(f"Failed to persist/verify results: {e}")

            return results

        except Exception as e:
            logger.error(f"Error processing {data_type} group: {e}")
            return {}
