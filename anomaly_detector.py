import pandas as pd
import numpy as np
import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import logging

# Import project modules for Linux anomaly detection
from config import load_config
from datamanager import (
    connect_to_elasticsearch,
    fetch_process_data,
    fetch_network_activity_data, 
    fetch_user_activity_data,
    fetch_discovery_commands_data,
    fetch_metadata_access_data,
    fetch_baseline_data,
    preprocess_process_data,
    preprocess_network_data,
    preprocess_user_data,
    preprocess_discovery_data,
    preprocess_metadata_data,
    aggregate_data_by_group,
    create_time_buckets
)
from model_manager import (
    LinuxModelManager,
    establish_linux_baselines,
    train_linux_models,
    save_linux_models,
    load_linux_models,
    train_process_anomaly_models,
    train_network_activity_models,
    train_user_behavior_models,
    train_discovery_command_models,
    train_metadata_access_models
)
from detection_methods import (
    detect_statistical_anomalies,
    detect_ml_anomalies,
    combine_detection_results,
    detect_rare_processes_all_hosts,
    detect_rare_processes_by_host,
    detect_anomalous_user_activity,
    detect_sudo_anomalies,
    detect_compiler_anomalies,
    detect_discovery_command_anomalies,
    detect_metadata_access_anomalies,
    calculate_baselines
)
from visualizer import LinuxAnomalyVisualizer

logger = logging.getLogger("linux_anomaly_detection")


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


def safe_column_check(df: pd.DataFrame, required_columns: List[str], operation_name: str) -> bool:
    """Check if required columns exist in DataFrame."""
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"Missing required columns for {operation_name}: {missing_columns}")
        logger.info(f"Available columns: {list(df.columns)}")
        return False
    return True


def add_default_columns(df: pd.DataFrame, default_columns: Dict[str, Any]) -> pd.DataFrame:
    """Add default columns if they don't exist."""
    for col_name, default_value in default_columns.items():
        if col_name not in df.columns:
            df[col_name] = default_value
            logger.info(f"Added default column {col_name} with value {default_value}")
    return df


class LinuxAnomalyDetector:
    """
    Comprehensive Linux anomaly detection system supporting all 14 detection jobs
    across 5 data groups: process, network, user, discovery, and metadata.
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
        
        # Supported detection jobs organized by data group
        self.detection_jobs = {
            "process": {
                "v3_linux_anomalous_process_all_hosts": {
                    "description": "Processes unusual to all Linux hosts",
                    "method": self._detect_anomalous_process_all_hosts
                },
                "v3_rare_process_by_host_linux": {
                    "description": "Processes unusual to particular Linux hosts", 
                    "method": self._detect_rare_process_by_host
                }
            },
            "network": {
                "v3_linux_anomalous_network_activity": {
                    "description": "Unusual network activity from processes",
                    "method": self._detect_anomalous_network_activity
                },
                "v3_linux_anomalous_network_port_activity": {
                    "description": "Unusual destination port activity",
                    "method": self._detect_anomalous_network_port_activity
                }
            },
            "user": {
                "v3_linux_anomalous_user_name": {
                    "description": "Rare and unusual user activity",
                    "method": self._detect_anomalous_user_name
                },
                "v3_linux_rare_sudo_user": {
                    "description": "Sudo activity from unusual users",
                    "method": self._detect_rare_sudo_user
                },
                "v3_linux_rare_user_compiler": {
                    "description": "Compiler activity from unusual users",
                    "method": self._detect_rare_user_compiler
                }
            },
            "discovery": {
                "v3_linux_network_configuration_discovery": {
                    "description": "Network configuration discovery commands",
                    "method": self._detect_network_configuration_discovery
                },
                "v3_linux_network_connection_discovery": {
                    "description": "Network connection discovery commands",
                    "method": self._detect_network_connection_discovery
                },
                "v3_linux_system_information_discovery": {
                    "description": "System information discovery commands",
                    "method": self._detect_system_information_discovery
                },
                "v3_linux_system_process_discovery": {
                    "description": "System process discovery commands",
                    "method": self._detect_system_process_discovery
                },
                "v3_linux_system_user_discovery": {
                    "description": "System user discovery commands",
                    "method": self._detect_system_user_discovery
                }
            },
            "metadata": {
                "v3_linux_rare_metadata_process": {
                    "description": "Unusual processes accessing metadata services",
                    "method": self._detect_rare_metadata_process
                },
                "v3_linux_rare_metadata_user": {
                    "description": "Unusual users accessing metadata services",
                    "method": self._detect_rare_metadata_user
                }
            }
        }
        
    def _generate_summary_report(self, results: Dict[str, Dict[str, pd.DataFrame]]):
        """
        Generate a summary report across all data groups.
        
        Args:
            results: Results from comprehensive detection
        """
        try:
            # Count total anomalies across all data groups
            total_anomalies = 0
            anomalies_by_group = {}
            
            for data_type, group_results in results.items():
                group_anomalies = 0
                for job_name, job_results in group_results.items():
                    if not job_results.empty and 'final_anomaly' in job_results.columns:
                        job_anomalies = job_results['final_anomaly'].sum()
                        group_anomalies += job_anomalies
                
                anomalies_by_group[data_type] = group_anomalies
                total_anomalies += group_anomalies
            
            # Create a simple summary report
            timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            output_dir = self.config.get("output", {}).get("results_dir", "results")
            report_file = os.path.join(output_dir, f"summary_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
            
            with open(report_file, "w") as f:
                f.write(f"# Linux Anomaly Detection Summary Report\n\n")
                f.write(f"Generated: {timestamp_str}\n\n")
                
                f.write(f"## Overview\n\n")
                f.write(f"Total anomalies detected: **{total_anomalies}**\n\n")
                
                f.write("### Anomalies by Data Group\n\n")
                for group, count in anomalies_by_group.items():
                    f.write(f"- **{group.title()}**: {count} anomalies\n")
                
                f.write("\n## Group Summaries\n\n")
                for data_type, group_results in results.items():
                    f.write(f"### {data_type.title()} Group\n\n")
                    
                    if not group_results:
                        f.write("No data available for this group.\n\n")
                        continue
                    
                    for job_name, job_results in group_results.items():
                        if job_results.empty:
                            f.write(f"- {job_name}: No results\n")
                            continue
                        
                        job_anomalies = 0
                        if 'final_anomaly' in job_results.columns:
                            job_anomalies = job_results['final_anomaly'].sum()
                        
                        job_description = self.detection_jobs.get(data_type, {}).get(job_name, {}).get("description", "")
                        f.write(f"- **{job_name}**: {job_anomalies} anomalies")
                        
                        if job_description:
                            f.write(f" - {job_description}")
                        
                        f.write("\n")
                    
                    f.write("\n")
                
                f.write("\n## Next Steps\n\n")
                f.write("1. Review detailed reports for each data group\n")
                f.write("2. Investigate high-priority anomalies\n")
                f.write("3. Consider adjusting detection thresholds if needed\n")
                
                f.write("\n---\n\n")
                f.write("*Report generated by Linux Anomaly Detection System*\n")
            
            logger.info(f"Generated summary report: {report_file}")
            return report_file
            
        except Exception as e:
            logger.error(f"Error generating summary report: {e}")
            return None

    def _generate_comprehensive_outputs(self, results: Dict[str, Dict[str, pd.DataFrame]]):
        """Generate comprehensive reports, visualizations, and individual anomaly data."""
        try:
            logger.info("Generating comprehensive outputs")
            
            # Generate reports and visualizations for each data group
            for data_type, group_results in results.items():
                if not group_results:
                    continue
                
                try:
                    # Generate group report
                    report_file, csv_file = self.visualizer.generate_comprehensive_report(
                        group_results, data_type
                    )
                    
                    if report_file:
                        logger.info(f"Generated {data_type} report: {report_file}")
                    
                    # Generate visualizations
                    viz_paths = self.visualizer.create_data_type_visualizations(
                        group_results, data_type
                    )
                    
                    if viz_paths:
                        logger.info(f"Generated {len(viz_paths)} visualizations for {data_type}")
                        
                except Exception as e:
                    logger.error(f"Error generating outputs for {data_type}: {e}")
            
            # Generate overall summary report
            self._generate_summary_report(results)
            
            # NEW: Extract and save individual anomalies to JSON
            anomalies_file = self.extract_and_save_anomalies(results)
            
            # NEW: Generate a separate index of anomalies by severity
            self._generate_anomaly_index(results, anomalies_file)
            
        except Exception as e:
            logger.error(f"Error generating comprehensive outputs: {e}")

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
    
    def _detect_rare_metadata_user(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual users accessing metadata services."""
        return self._detect_metadata_anomalies(data, focus="user")
    def _detect_rare_sudo_user(self, data: pd.DataFrame) -> pd.DataFrame:
            """Detect sudo activity from unusual users."""
            return self._detect_user_anomalies(data, detect_sudo_anomalies)
    def _detect_anomalous_user_name(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect rare and unusual user activity."""
        return self._detect_user_anomalies(data, detect_anomalous_user_activity)
    def _detect_rare_user_compiler(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect compiler activity from unusual users."""
        return self._detect_user_anomalies(data, detect_compiler_anomalies)
    def _detect_anomalous_network_activity(self, data: pd.DataFrame) -> pd.DataFrame:
            if data.empty:
                return pd.DataFrame()
            
            try:
                # Add missing network fields with defaults
                required_fields = {
                    'destination.geo.country_name': 'Unknown',
                    'network.bytes': 0,
                    'network.packets': 0
                }
                
                for field, default_value in required_fields.items():
                    if field not in data.columns:
                        data[field] = default_value
                        logger.info(f"Added missing field '{field}' with default value")
                
                bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))
                
                if bucketed_data.empty:
                    return pd.DataFrame()
                
                # Safe aggregation for network data
                try:
                    agg_dict = {
                        'event.category': 'count',
                        'network.bytes': 'sum',
                        'network.packets': 'sum'
                    }
                    
                    group_cols = ['time_bucket', 'process.name', 'destination.geo.country_name']
                    aggregated = bucketed_data.groupby(group_cols).agg(agg_dict).reset_index()
                    aggregated = aggregated.rename(columns={'event.category': 'event_count'})
                    aggregated['@timestamp'] = aggregated['time_bucket']
                    
                    # Run detection
                    models, scalers, baselines = self.model_manager.get_models_for_group("network")
                    results_list = []
                    
                    try:
                        stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "network")
                        if not stat_results.empty:
                            results_list.append(stat_results)
                    except Exception as e:
                        logger.warning(f"Network statistical detection failed: {e}")
                    
                    if models:
                        try:
                            ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "network")
                            if not ml_results.empty:
                                results_list.append(ml_results)
                        except Exception as e:
                            logger.warning(f"Network ML detection failed: {e}")
                    
                    # Combine results
                    if results_list:
                        final_results = results_list[0]
                        for additional_result in results_list[1:]:
                            final_results = self._safe_combine_results(final_results, additional_result)
                        
                        if 'final_anomaly' not in final_results.columns:
                            final_results['final_anomaly'] = False
                        
                        return final_results
                    else:
                        aggregated['anomaly_score'] = 0.0
                        aggregated['final_anomaly'] = False
                        aggregated['detection_method'] = 'baseline_aggregation'
                        return aggregated
                        
                except Exception as agg_error:
                    logger.error(f"Error in network activity aggregation: {agg_error}")
                    return pd.DataFrame()
                    
            except Exception as e:
                logger.error(f"Error in _detect_anomalous_network_activity: {e}")
                return pd.DataFrame()
    def _detect_user_anomalies(self, data: pd.DataFrame, specific_detector) -> pd.DataFrame:
        """Common user anomaly detection logic with enhanced error handling."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "30m"))
            
            if bucketed_data.empty:
                return pd.DataFrame()
            
            # Ensure user column exists
            if 'user.name' not in bucketed_data.columns:
                logger.error("Missing user.name column for user detection")
                return pd.DataFrame()
            
            # Ensure required feature columns exist
            required_fields = {
                'is_sudo_command': 0,
                'is_compiler_activity': 0
            }
            
            for field, default_value in required_fields.items():
                if field not in bucketed_data.columns:
                    bucketed_data[field] = default_value
            
            # Aggregate by user
            agg_dict = {
                'event.category': 'count',
                'is_sudo_command': 'sum',
                'is_compiler_activity': 'sum'
            }
            
            aggregated = bucketed_data.groupby(['time_bucket', 'user.name']).agg(agg_dict).reset_index()
            aggregated = aggregated.rename(columns={'event.category': 'event_count'})
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Run detection
            models, scalers, baselines = self.model_manager.get_models_for_group("user")
            results_list = []
            
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "user")
                if not stat_results.empty:
                    results_list.append(stat_results)
            except Exception as e:
                logger.warning(f"User statistical detection failed: {e}")
            
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "user")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                except Exception as e:
                    logger.warning(f"User ML detection failed: {e}")
            
            # Run specific user detection
            try:
                specific_results = specific_detector(aggregated, self.config)
                if not specific_results.empty:
                    results_list.append(specific_results)
            except Exception as e:
                logger.warning(f"User specific detection failed: {e}")
            
            # Combine results
            if results_list:
                combined = results_list[0]
                for additional_result in results_list[1:]:
                    combined = self._safe_combine_results(combined, additional_result)
                
                if 'final_anomaly' not in combined.columns:
                    combined['final_anomaly'] = False
                
                return combined
            else:
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_user_anomalies: {e}")
            return pd.DataFrame()

    
    def _detect_metadata_anomalies(self, data: pd.DataFrame, focus: str) -> pd.DataFrame:
        """Common metadata access anomaly detection logic."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))
            
            if bucketed_data.empty:
                return pd.DataFrame()
            
            # Ensure required fields exist
            required_fields = {
                'metadata_service_type': 'unknown',
                'potential_cred_harvest': 0,
                'user_data_access': 0,
                'process.name': 'unknown',
                'user.name': 'unknown'
            }
            
            for field, default_value in required_fields.items():
                if field not in bucketed_data.columns:
                    bucketed_data[field] = default_value
            
            # Aggregate based on focus
            if focus == "process":
                group_cols = ['time_bucket', 'process.name', 'metadata_service_type']
            else:  # user
                group_cols = ['time_bucket', 'user.name', 'metadata_service_type']
            
            agg_dict = {
                'event.category': 'count',
                'potential_cred_harvest': 'sum',
                'user_data_access': 'sum'
            }
            
            aggregated = bucketed_data.groupby(group_cols).agg(agg_dict).reset_index()
            aggregated = aggregated.rename(columns={'event.category': 'event_count'})
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Run detection
            models, scalers, baselines = self.model_manager.get_models_for_group("metadata")
            results_list = []
            
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "metadata")
                if not stat_results.empty:
                    results_list.append(stat_results)
            except Exception as e:
                logger.warning(f"Metadata statistical detection failed: {e}")
            
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "metadata")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                except Exception as e:
                    logger.warning(f"Metadata ML detection failed: {e}")
            
            # Run metadata-specific detection
            try:
                metadata_results = detect_metadata_access_anomalies(aggregated, self.config)
                if not metadata_results.empty:
                    results_list.append(metadata_results)
            except Exception as e:
                logger.warning(f"Metadata specific detection failed: {e}")
            
            # Combine results
            if results_list:
                combined = results_list[0]
                for additional_result in results_list[1:]:
                    combined = self._safe_combine_results(combined, additional_result)
                
                if 'final_anomaly' not in combined.columns:
                    combined['final_anomaly'] = False
                
                return combined
            else:
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_metadata_anomalies: {e}")
            return pd.DataFrame()
        
    def _detect_rare_metadata_process(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual processes accessing metadata services."""
        return self._detect_metadata_anomalies(data, focus="process")
    def _detect_anomalous_network_port_activity(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect unusual destination port activity."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            # Ensure port column exists
            if 'destination.port' not in data.columns:
                data['destination.port'] = 0
                logger.info("Added default destination.port column")
            
            # Filter for data with meaningful port information
            port_data = data[data['destination.port'].notna() & (data['destination.port'] > 0)].copy()
            
            if port_data.empty:
                logger.warning("No meaningful port data available")
                # Create minimal result
                result = pd.DataFrame({
                    '@timestamp': [datetime.utcnow()],
                    'destination.port': [0],
                    # 'event_count': [0],
                    'anomaly_score': [0.0],
                    'final_anomaly': [False],
                    'detection_method': ['no_data']
                })
                return result
            
            bucketed_data = self._create_time_buckets_safe(port_data, self.config.get("detection", {}).get("bucket_span", "15m"))
            
            if bucketed_data.empty:
                return pd.DataFrame()
            
            # Aggregate by port
            agg_dict = {
                'event.category': 'count',
                'process.name': 'nunique'
            }
            
            aggregated = bucketed_data.groupby(['time_bucket', 'destination.port']).agg(agg_dict).reset_index()
            aggregated = aggregated.rename(columns={
                'event.category': 'event_count',
                'process.name': 'process_count'
            })
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Run detection
            models, scalers, baselines = self.model_manager.get_models_for_group("network")
            results_list = []
            
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "network")
                if not stat_results.empty:
                    results_list.append(stat_results)
            except Exception as e:
                logger.warning(f"Port statistical detection failed: {e}")
            
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "network")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                except Exception as e:
                    logger.warning(f"Port ML detection failed: {e}")
            
            # Combine results
            if results_list:
                final_results = results_list[0]
                for additional_result in results_list[1:]:
                    final_results = self._safe_combine_results(final_results, additional_result)
                
                if 'final_anomaly' not in final_results.columns:
                    final_results['final_anomaly'] = False
                
                return final_results
            else:
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_anomalous_network_port_activity: {e}")
            return pd.DataFrame()
        
    def connect_to_elasticsearch(self):
        """Establish connection to Elasticsearch."""
        self.es = connect_to_elasticsearch(self.config)
    
    def train_models_before_detection(self, data_groups: List[str] = None, force_retrain: bool = False) -> bool:
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
                    
                    # Save models to disk - they're already saved by specialized functions
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
    
    def run_comprehensive_detection(self, data_groups: List[str] = None, 
                                  use_baseline: bool = True, 
                                  train_models: bool = True,
                                  force_retrain: bool = False) -> Dict[str, Dict[str, pd.DataFrame]]:
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
                for job_name, results in group_results.items():
                    if not results.empty and 'final_anomaly' in results.columns:
                        anomalies = results[results['final_anomaly'] == True]
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
    
    def run_data_group_detection(self, data_type: str, jobs: List[str] = None,
                                use_baseline: bool = True, load_existing_models: bool = True) -> Dict[str, pd.DataFrame]:
        """
        Run all detection jobs for a specific data group with improved error handling.
        
        Args:
            data_type: Type of data group (process, network, user, discovery, metadata)
            jobs: Specific jobs to run (default: all for the group)
            use_baseline: Whether to use baseline data
            load_existing_models: Whether to load existing models
            
        Returns:
            dict: Results for each job in the group
        """
        logger.info(f"Running {data_type} group detection")
        
        if data_type not in self.detection_jobs:
            raise ValueError(f"Unknown data type: {data_type}")
        
        # Determine which jobs to run
        available_jobs = list(self.detection_jobs[data_type].keys())
        jobs_to_run = jobs if jobs else available_jobs
        
        # Validate jobs
        invalid_jobs = [job for job in jobs_to_run if job not in available_jobs]
        if invalid_jobs:
            raise ValueError(f"Invalid jobs for {data_type}: {invalid_jobs}")
        
        # Load models if requested
        if load_existing_models:
            try:
                models_loaded = self.model_manager.load_models(data_type)
                if models_loaded:
                    logger.info(f"Loaded existing models for {data_type}")
                else:
                    logger.warning(f"No existing models found for {data_type}")
            except Exception as e:
                logger.error(f"Error loading models for {data_type}: {e}")
        
        # Fetch and preprocess data once for the entire group
        data = self._fetch_data_for_type(data_type)
        if data.empty:
            logger.warning(f"No data available for {data_type} group")
            return {}
        
        # Run each job
        results = {}
        baselines_established = False
        
        for job_name in jobs_to_run:
            try:
                job_method = self.detection_jobs[data_type][job_name]["method"]
                job_results = job_method(data)
                
                # Establish baselines once on the first successful aggregated result
                if (use_baseline and not baselines_established and 
                    not job_results.empty and 'event_count' in job_results.columns):
                    try:
                        self._establish_baselines_for_aggregated_data(data_type, job_results)
                        baselines_established = True
                    except Exception as baseline_error:
                        logger.warning(f"Could not establish baselines for {data_type}: {baseline_error}")
                
                results[job_name] = job_results
                logger.info(f"Completed {job_name}: {len(job_results)} records processed")
                
            except Exception as e:
                logger.error(f"Error in {job_name}: {e}")
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                results[job_name] = pd.DataFrame()
        
        return results
    
    def _fetch_data_for_type(self, data_type: str, timeframe: Dict[str, str] = None) -> pd.DataFrame:
        """Fetch data for a specific data type with improved error handling."""
        if not self.es:
            logger.error("No Elasticsearch connection available")
            return pd.DataFrame()
        
        # Default timeframe (last 24 hours)
        if not timeframe:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=24)
            timeframe = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }
        
        try:
            # CORRECTED: Use proper function signatures from datamanager
            if data_type == "process":
                data = fetch_process_data(self.es, self.config, time_range=timeframe)
                return preprocess_process_data(data)
            elif data_type == "network":
                data = fetch_network_activity_data(self.es, self.config, time_range=timeframe)
                return preprocess_network_data(data)
            elif data_type == "user":
                data = fetch_user_activity_data(self.es, self.config, time_range=timeframe)
                return preprocess_user_data(data)
            elif data_type == "discovery":
                data = fetch_discovery_commands_data(self.es, self.config, time_range=timeframe)
                return preprocess_discovery_data(data)
            elif data_type == "metadata":
                data = fetch_metadata_access_data(self.es, self.config, time_range=timeframe)
                return preprocess_metadata_data(data)
            else:
                logger.error(f"Unknown data type: {data_type}")
                return pd.DataFrame()
                
        except Exception as e:
            logger.error(f"Error fetching {data_type} data: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return pd.DataFrame()
    
    def _establish_baselines_for_aggregated_data(self, data_type: str, aggregated_data: pd.DataFrame):
        """Establish baselines for aggregated data with event_count column."""
        try:
            if 'event_count' not in aggregated_data.columns:
                logger.warning(f"No event_count column in aggregated data for {data_type}")
                return
            
            if aggregated_data.empty:
                logger.warning(f"Empty aggregated data for {data_type} baseline establishment")
                return
            
            # Use the model manager's establish_baselines method
            baselines = self.model_manager.establish_baselines(aggregated_data, data_type)
            
            # Store baselines
            if data_type not in self.model_manager.baselines:
                self.model_manager.baselines[data_type] = {}
            
            self.model_manager.baselines[data_type].update(baselines)
            
            logger.info(f"Established baselines for {data_type} on aggregated data with {len(aggregated_data)} records")
            
        except Exception as e:
            logger.error(f"Error establishing baselines for {data_type}: {e}")
    
    def _create_time_buckets_safe(self, data: pd.DataFrame, bucket_span: str) -> pd.DataFrame:
        """Create time buckets with enhanced error handling."""
        try:
            if '@timestamp' not in data.columns:
                logger.error("No @timestamp column for time bucketing")
                return pd.DataFrame()
            
            # Use the create_time_buckets function from datamanager
            return create_time_buckets(data, bucket_span, "@timestamp")
            
        except Exception as e:
            logger.error(f"Error creating time buckets: {e}")
            return pd.DataFrame()
        
    def _safe_combine_results(self, result1: pd.DataFrame, result2: pd.DataFrame) -> pd.DataFrame:
        """Safely combine detection results with improved anomaly flag handling."""
        try:
            if result1.empty:
                return result2.copy()
            if result2.empty:
                return result1.copy()
            
            # Create a combined DataFrame
            common_columns = list(set(result1.columns) & set(result2.columns))
            if not common_columns:
                # If no common columns, concatenate with all columns
                combined = pd.concat([result1, result2], ignore_index=True, sort=False)
            else:
                # Align data types for common columns
                for col in common_columns:
                    if result1[col].dtype != result2[col].dtype:
                        # Convert both to string to avoid type conflicts
                        result1[col] = result1[col].astype(str)
                        result2[col] = result2[col].astype(str)
                
                # Concatenate the DataFrames
                combined = pd.concat([result1, result2], ignore_index=True, sort=False)
            
            # Handle anomaly flags - CRITICAL FIX
            anomaly_columns = [col for col in combined.columns if 'anomaly' in col.lower()]
            
            # Initialize final_anomaly column if it doesn't exist
            if 'final_anomaly' not in combined.columns:
                combined['final_anomaly'] = False
            
            # Set final_anomaly to True if any anomaly flag is True
            for col in anomaly_columns:
                if col != 'final_anomaly':  # Skip the final_anomaly column itself
                    # Convert column to boolean safely
                    if combined[col].dtype != bool:
                        try:
                            combined[col] = combined[col].astype(bool)
                        except:
                            combined[col] = combined[col].astype(str).str.lower() == 'true'
                    
                    # Update final_anomaly flag
                    combined['final_anomaly'] = combined['final_anomaly'] | combined[col]
            
            # Update anomaly score if needed
            if 'anomaly_score' not in combined.columns and any(col for col in combined.columns if 'score' in col.lower()):
                score_columns = [col for col in combined.columns if 'score' in col.lower() and col != 'anomaly_score']
                if score_columns:
                    # Use the first available score column
                    combined['anomaly_score'] = combined[score_columns[0]]
            
            # Remove duplicates if possible
            if '@timestamp' in combined.columns:
                duplicate_cols = ['@timestamp']
                if 'process.name' in combined.columns:
                    duplicate_cols.append('process.name')
                elif 'user.name' in combined.columns:
                    duplicate_cols.append('user.name')
                
                before_count = len(combined)
                combined = combined.drop_duplicates(subset=duplicate_cols, keep='first')
                after_count = len(combined)
                
                if before_count != after_count:
                    logger.info(f"Removed {before_count - after_count} duplicate records")
            
            return combined
                
        except Exception as e:
            logger.error(f"Error in safe combine results: {e}")
            return result1.copy() if not result1.empty else result2.copy()
    def _extract_entity_from_row(self, row, data_type):
        """
        Extract the primary entity identifier from an anomaly row based on data type.
        
        Args:
            row (pd.Series): A single anomaly record
            data_type (str): Type of data the anomaly belongs to
            
        Returns:
            str: Entity identifier (process name, user name, etc.)
        """
        try:
            if data_type == 'process':
                if 'process.name' in row:
                    return str(row['process.name'])
                elif 'process.executable' in row:
                    # Extract basename from executable path
                    executable = str(row['process.executable'])
                    return os.path.basename(executable) if executable else "unknown_process"
            
            elif data_type == 'network':
                if 'destination.ip' in row:
                    dest_ip = str(row['destination.ip'])
                    dest_port = str(row.get('destination.port', ''))
                    if dest_port:
                        return f"{dest_ip}:{dest_port}"
                    return dest_ip
                elif 'destination.geo.country_name' in row:
                    return str(row['destination.geo.country_name'])
            
            elif data_type == 'user':
                if 'user.name' in row:
                    return str(row['user.name'])
            
            elif data_type == 'discovery':
                if 'process.name' in row:
                    return str(row['process.name'])
                elif 'discovery_category' in row:
                    return f"{row['discovery_category']} discovery"
            
            elif data_type == 'metadata':
                if 'process.name' in row and 'metadata_service_type' in row:
                    return f"{row['process.name']} → {row['metadata_service_type']}"
                elif 'metadata_service_type' in row:
                    return str(row['metadata_service_type'])
                elif 'process.name' in row:
                    return str(row['process.name'])
            
            # Default fallbacks
            for key in ['process.name', 'user.name', 'destination.ip', 'host.hostname']:
                if key in row and not pd.isna(row[key]):
                    return str(row[key])
            
            return "unknown_entity"
        
        except Exception as e:
            self.logger.warning(f"Error extracting entity from row: {e}")
            return "unknown_entity"
    

    def _generate_anomaly_description(self, anomaly, data_type=None):
        """
        Generate a detailed description for a detected anomaly with improved handling
        of missing data, job-specific information, and optional LLM enhancement.
        
        Args:
            anomaly (pd.Series): A single anomaly record
            data_type (str, optional): Type of data the anomaly belongs to
            
        Returns:
            str: Human-readable description of the anomaly
        """
        description = []
        
        try:
            # Get basic anomaly information
            timestamp = anomaly.get('@timestamp', 'Unknown time')
            if isinstance(timestamp, pd.Timestamp):
                timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp_str = str(timestamp)
                
            # Better handling of detection job name
            job_name = anomaly.get('detection_job', '')
            if not job_name and 'job_id' in anomaly:
                job_name = anomaly['job_id']
                
            # Format the job name nicely
            if job_name:
                job_display = job_name.replace('v3_linux_', '').replace('_', ' ').title()
            else:
                job_display = "Unknown Detection"
                
            # Get score with better handling
            score = 0.0
            if 'combined_score' in anomaly and not pd.isna(anomaly['combined_score']):
                score = float(anomaly['combined_score'])
            elif 'anomaly_score' in anomaly and not pd.isna(anomaly['anomaly_score']):
                score = float(anomaly['anomaly_score'])
                
            description.append(f"[{timestamp_str}] {job_display} (Score: {score:.2f})")
            
            # Add entity information based on data type
            if data_type is None:
                if 'data_type' in anomaly:
                    data_type = anomaly['data_type']
                else:
                    # Try to infer data type from detection job
                    if 'process' in job_name:
                        data_type = 'process'
                    elif 'network' in job_name:
                        data_type = 'network'
                    elif 'user' in job_name:
                        data_type = 'user'
                    elif 'discovery' in job_name:
                        data_type = 'discovery'
                    elif 'metadata' in job_name:
                        data_type = 'metadata'
                    else:
                        data_type = 'unknown'
            
            # Add job-specific context
            if 'user' in job_name.lower():
                if job_name == 'v3_linux_anomalous_user_name':
                    description.append("Unusual user activity detected")
                elif job_name == 'v3_linux_rare_sudo_user':
                    description.append("Unusual sudo privileges detected")
                elif job_name == 'v3_linux_rare_user_compiler':
                    description.append("Unusual compiler activity detected")
            
            # Add entity-specific details with better NaN handling
            if data_type == 'process':
                process_name = None
                
                # Try different ways to extract process name
                if 'process.name' in anomaly and not pd.isna(anomaly['process.name']):
                    process_name = anomaly['process.name']
                elif isinstance(anomaly.get('process'), dict) and 'name' in anomaly['process']:
                    if not pd.isna(anomaly['process']['name']) and anomaly['process']['name'] != 0.0:
                        process_name = anomaly['process']['name']
                        
                if process_name:
                    description.append(f"Process: {process_name}")
                    
                if 'process.command_line' in anomaly and not pd.isna(anomaly['process.command_line']):
                    cmd = anomaly['process.command_line']
                    # Truncate long command lines
                    if len(cmd) > 100:
                        cmd = cmd[:97] + '...'
                    description.append(f"Command: {cmd}")
                    
            elif data_type == 'user':
                user_name = None
                
                # Try different ways to extract user name
                if 'user.name' in anomaly and not pd.isna(anomaly['user.name']):
                    user_name = anomaly['user.name']
                elif isinstance(anomaly.get('user'), dict) and 'name' in anomaly['user']:
                    if not pd.isna(anomaly['user']['name']):
                        user_name = anomaly['user']['name']
                        
                if user_name:
                    description.append(f"User: {user_name}")
                    
                # Add context about user activity
                is_root = False
                if 'is_root_user' in anomaly and anomaly['is_root_user']:
                    is_root = True
                elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_root_user'):
                    is_root = True
                elif user_name == 'root':
                    is_root = True
                    
                if is_root:
                    description.append("Root privileges used")
                    
                is_sudo = False
                if 'is_sudo_command' in anomaly and anomaly['is_sudo_command']:
                    is_sudo = True
                elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_sudo_command'):
                    is_sudo = True
                    
                if is_sudo:
                    description.append("Sudo command execution")
                    
                is_compiler = False
                if 'is_compiler_activity' in anomaly and anomaly['is_compiler_activity']:
                    is_compiler = True
                elif isinstance(anomaly.get('context'), dict) and anomaly['context'].get('is_compiler_activity'):
                    is_compiler = True
                    
                if is_compiler:
                    description.append("Compiler activity detected")
            
            # Add host information
            host_name = None
            if 'host.hostname' in anomaly and not pd.isna(anomaly['host.hostname']):
                host_name = anomaly['host.hostname']
            elif isinstance(anomaly.get('host'), dict) and 'name' in anomaly['host']:
                if not pd.isna(anomaly['host']['name']):
                    host_name = anomaly['host']['name']
                    
            if host_name:
                description.append(f"Host: {host_name}")
                
            # Add detection method info if available
            methods = []
            
            # Check direct attributes
            if 'ml_detection' in anomaly and anomaly['ml_detection']:
                methods.append("Machine Learning")
            if 'stat_detection' in anomaly and anomaly['stat_detection']:
                methods.append("Statistical")
            if 'ts_detection' in anomaly and anomaly['ts_detection']:
                methods.append("Time Series")
                
            # Check context dictionary
            if isinstance(anomaly.get('context'), dict):
                method = anomaly['context'].get('detection_method', '')
                if method and method not in methods:
                    if method == 'machine_learning':
                        methods.append("Machine Learning")
                    elif method == 'statistical':
                        methods.append("Statistical")
                    elif method == 'time_series':
                        methods.append("Time Series")
                    else:
                        methods.append(method.replace('_', ' ').title())
                
            if methods:
                description.append(f"Detection Methods: {', '.join(methods)}")
                
            # Add reason if available
            if 'anomaly_reason' in anomaly and anomaly['anomaly_reason']:
                description.append(f"Reason: {anomaly['anomaly_reason']}")
                
            # Add features with high contribution to anomaly
            high_deviation_features = []
            
            # Check for deviation in direct attributes
            for col in anomaly.index if hasattr(anomaly, 'index') else []:
                if col.endswith('_deviation') and not pd.isna(anomaly[col]) and float(anomaly[col]) > 2.0:
                    feature_name = col.replace('_deviation', '')
                    high_deviation_features.append(f"{feature_name} ({float(anomaly[col]):.2f}x)")
            
            # Check features that might be in context
            if isinstance(anomaly.get('features'), dict):
                for feature, value in anomaly['features'].items():
                    if feature.endswith('_deviation') and float(value) > 2.0:
                        feature_name = feature.replace('_deviation', '')
                        high_deviation_features.append(f"{feature_name} ({float(value):.2f}x)")
                    
            if high_deviation_features:
                description.append(f"Anomalous Features: {', '.join(high_deviation_features[:3])}")
            
            # Add event count information if available
            if 'event_count' in anomaly and not pd.isna(anomaly['event_count']):
                event_count = int(anomaly['event_count'])
                if event_count > 0:
                    description.append(f"Event Count: {event_count}")
                
            # Add temporal context if available
            is_business_hours = False
            if 'is_business_hours' in anomaly:
                is_business_hours = bool(anomaly['is_business_hours'])
            elif isinstance(anomaly.get('context'), dict) and 'is_business_hours' in anomaly['context']:
                is_business_hours = bool(anomaly['context']['is_business_hours'])
                
            if not is_business_hours:
                description.append("Activity occurred outside business hours")
                
            # Add job-specific summary based on data
            if data_type == 'user':
                event_count = int(anomaly.get('event_count', 0))
                if job_name == 'v3_linux_anomalous_user_name' and event_count > 200:
                    description.append(f"Unusually high volume of user activity ({event_count} events)")
                elif job_name == 'v3_linux_rare_sudo_user':
                    description.append("Potential privilege escalation attempt")
                elif job_name == 'v3_linux_rare_user_compiler':
                    description.append("Potential unauthorized code compilation")
            
            # Compile the basic description
            basic_description = "\n".join(description)
            
            # If Ollama is available, enhance the description with LLM
            global OLLAMA_AVAILABLE, ollama_client
            if 'OLLAMA_AVAILABLE' in globals() and OLLAMA_AVAILABLE and self.config.get("llm", {}).get("enhance_descriptions", False):
                try:
                    # Extract key information as context for the LLM
                    entity = "unknown"
                    if data_type == 'process' and process_name:
                        entity = process_name
                    elif data_type == 'user' and user_name:
                        entity = user_name
                    elif data_type == 'network' and 'destination.ip' in anomaly:
                        entity = anomaly['destination.ip']
                    
                    # Create a condensed description of the anomaly for the prompt
                    anomaly_summary = f"{job_display} - {entity} - Score: {score:.2f}"
                    if methods:
                        anomaly_summary += f" - Methods: {', '.join(methods)}"
                    
                    # Create prompt for the LLM
                    prompt = f"""
                    You are a cybersecurity analyst describing a detected Linux anomaly.
                    Here is the technical information about the anomaly:
                    
                    Timestamp: {timestamp_str}
                    Type: {data_type} anomaly ({job_display})
                    Entity: {entity}
                    Score: {score:.2f}
                    
                    Technical details:
                    {basic_description}
                    
                    Please provide a natural language description of this anomaly that:
                    1. Explains what was detected in simple terms
                    2. Indicates the potential security implications
                    3. Suggests possible next steps for investigation
                    4. Keeps the length under 200 words
                    5. Uses a professional but accessible tone
                    
                    Description:
                    """
                    
                    # Call Ollama
                    response = ollama_client.generate(
                        model=self.config.get("llm", {}).get("model", "llama3"), 
                        prompt=prompt,
                        max_tokens=300,
                        temperature=0.2
                    )
                    
                    # If we got a valid response, return the enhanced description
                    if response and hasattr(response, 'get') and response.get('response'):
                        # Combine the basic and enhanced descriptions
                        return basic_description + "\n\n### LLM Analysis ###\n" + response['response'].strip()
                
                except Exception as llm_error:
                    self.logger.warning(f"LLM enhancement failed: {llm_error}")
                    # Fall back to basic description if LLM fails
            
            # Return the basic description if LLM is not available or fails
            return basic_description
        
        except Exception as e:
            self.logger.warning(f"Error generating anomaly description: {e}")
            return f"Anomaly detected at {timestamp_str if 'timestamp_str' in locals() else 'unknown time'}"
        
    def _detect_anomalous_process_all_hosts(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect processes unusual to all Linux hosts with enhanced processing."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            # Create time buckets for analysis
            bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))
            
            if bucketed_data.empty:
                logger.warning("No data after time bucketing for anomalous_process_all_hosts")
                return pd.DataFrame()
            
            # Ensure required columns exist
            if 'process.name' not in bucketed_data.columns:
                logger.error("Missing process.name column for process detection")
                return pd.DataFrame()
            
            # Check if host.hostname exists, add if not
            if 'host.hostname' not in bucketed_data.columns:
                logger.warning("Missing host.hostname column, adding default")
                bucketed_data['host.hostname'] = 'unknown_host'
            
            # Safe aggregation with fallbacks
            # First ensure we have an event count column
            if 'event_count' not in bucketed_data.columns:
                bucketed_data['event_count'] = 1
            
            # Count unique hosts
            bucketed_data['host_count'] = 1  # Add a default host_count column
            
            # Group by time bucket and process name with proper aggregation
            agg_dict = {
                'event_count': 'sum',
                'host.hostname': 'nunique'  # Count unique hosts
            }
            
            # Perform aggregation
            aggregated = bucketed_data.groupby(['time_bucket', 'process.name']).agg(agg_dict).reset_index()
            
            # Rename host.hostname column to host_count
            aggregated = aggregated.rename(columns={'host.hostname': 'host_count'})
            
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Get models and baselines
            models, scalers, baselines = self.model_manager.get_models_for_group("process")
            
            # Run detection methods with safe error handling
            results_list = []
            
            # Statistical detection
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "process")
                if not stat_results.empty:
                    results_list.append(stat_results)
                    logger.debug("Statistical detection completed for processes")
            except Exception as e:
                logger.warning(f"Statistical detection failed for processes: {e}")
            
            # ML detection if models available
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "process")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                        logger.debug("ML detection completed for processes")
                except Exception as e:
                    logger.warning(f"ML detection failed for processes: {e}")
            
            # Process-specific detection
            try:
                process_results = detect_rare_processes_all_hosts(aggregated, self.config)
                if not process_results.empty:
                    results_list.append(process_results)
                    logger.debug("Rare process detection completed")
            except Exception as e:
                logger.warning(f"Process-specific detection failed: {e}")
            
            # Combine results safely
            if results_list:
                final_results = results_list[0]
                for additional_result in results_list[1:]:
                    final_results = self._safe_combine_results(final_results, additional_result)
                
                # Ensure final anomaly column exists
                if 'final_anomaly' not in final_results.columns:
                    final_results['final_anomaly'] = False
                
                return final_results
            else:
                # Return aggregated data with basic anomaly scoring
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_anomalous_process_all_hosts: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return pd.DataFrame()
    def _detect_rare_process_by_host(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect processes unusual to particular Linux hosts."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            bucketed_data = self._create_time_buckets_safe(data, self.config.get("detection", {}).get("bucket_span", "15m"))
            
            if bucketed_data.empty:
                return pd.DataFrame()
            
            # Ensure required columns
            required_cols = ['process.name', 'host.hostname']
            missing_cols = [col for col in required_cols if col not in bucketed_data.columns]
            if missing_cols:
                logger.error(f"Missing required columns for host-based process detection: {missing_cols}")
                if 'host.hostname' not in bucketed_data.columns:
                    bucketed_data['host.hostname'] = 'unknown_host'
            
            # Aggregate by process, host, and time
            agg_dict = {}
            if 'process.pid' in bucketed_data.columns:
                agg_dict['process.pid'] = 'count'
            else:
                bucketed_data['_event_marker'] = 1
                agg_dict['_event_marker'] = 'count'
            
            aggregated = bucketed_data.groupby(['time_bucket', 'host.hostname', 'process.name']).agg(agg_dict).reset_index()
            
            # Rename count column to event_count
            count_col = 'process.pid' if 'process.pid' in agg_dict else '_event_marker'
            aggregated = aggregated.rename(columns={count_col: 'event_count'})
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Run detection
            models, scalers, baselines = self.model_manager.get_models_for_group("process")
            results_list = []
            
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "process")
                if not stat_results.empty:
                    results_list.append(stat_results)
            except Exception as e:
                logger.warning(f"Statistical detection failed: {e}")
            
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "process")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                except Exception as e:
                    logger.warning(f"ML detection failed: {e}")
            
            try:
                host_results = detect_rare_processes_by_host(aggregated, self.config)
                if not host_results.empty:
                    results_list.append(host_results)
            except Exception as e:
                logger.warning(f"Host-specific detection failed: {e}")
            
            # Combine results
            if results_list:
                final_results = results_list[0]
                for additional_result in results_list[1:]:
                    final_results = self._safe_combine_results(final_results, additional_result)
                
                if 'final_anomaly' not in final_results.columns:
                    final_results['final_anomaly'] = False
                
                return final_results
            else:
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_rare_process_by_host: {e}")
            return pd.DataFrame()
    def _generate_anomaly_index(self, results: Dict[str, Dict[str, pd.DataFrame]], anomalies_file: str):
            """
            Generate an index of anomalies sorted by severity for quick reference.
            
            Args:
                results: Results from comprehensive detection
                anomalies_file: Path to the detailed anomalies JSON file
            """
            try:
                all_anomalies = []
                
                for data_type, group_results in results.items():
                    for job_name, job_results in group_results.items():
                        if job_results.empty or 'final_anomaly' not in job_results.columns:
                            continue
                        
                        anomalies = job_results[job_results['final_anomaly'] == True].copy()
                        if anomalies.empty:
                            continue
                        
                        for _, row in anomalies.iterrows():
                            anomaly_entry = {
                                "timestamp": str(row.get('@timestamp', '')),
                                "job_id": job_name,
                                "data_type": data_type,
                                "score": float(row.get('anomaly_score', row.get('combined_score', 0.0))),
                                "entity": self._extract_entity_from_row(row, data_type),
                                "description": self._generate_anomaly_description(row, data_type)
                            }
                            
                            # Add hostname if available
                            if 'host.hostname' in row:
                                anomaly_entry["hostname"] = row['host.hostname']
                            
                            all_anomalies.append(anomaly_entry)
                
                if not all_anomalies:
                    logger.warning("No anomalies to index")
                    return
                
                # Sort anomalies by score (highest first)
                all_anomalies.sort(key=lambda x: x['score'], reverse=True)
                
                # Create index file
                output_dir = os.path.dirname(anomalies_file)
                index_file = os.path.join(output_dir, os.path.basename(anomalies_file).replace('anomalies_', 'anomaly_index_'))
                
                with open(index_file, 'w') as f:
                    json.dump({
                        "total_anomalies": len(all_anomalies),
                        "anomalies_file": os.path.basename(anomalies_file),
                        "generated_at": datetime.utcnow().isoformat(),
                        "anomalies": all_anomalies
                    }, f, indent=2, default=str)
                
                logger.info(f"Generated anomaly index with {len(all_anomalies)} entries: {index_file}")
                
            except Exception as e:
                logger.error(f"Error generating anomaly index: {e}")
        
    def extract_and_save_anomalies(self, results: Dict[str, Dict[str, pd.DataFrame]], output_dir: Optional[str] = None) -> str:
        """
        Extract all individual anomalies from detection results and save to a structured JSON file.
        
        Args:
            results: Results from comprehensive detection
            output_dir: Directory to save the anomaly JSON file (defaults to config output dir)
            
        Returns:
            str: Path to the saved JSON file
        """
        if not output_dir:
            output_dir = self.config.get("output", {}).get("results_dir", "results")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Dictionary to hold all anomalies organized by job
        all_anomalies = {}
        anomaly_count = 0
        
        logger.info("Extracting individual anomalies from detection results")
        
        for data_type, group_results in results.items():
            for job_name, job_results in group_results.items():
                if job_results.empty:
                    continue
                    
                # Filter for actual anomalies
                if 'final_anomaly' in job_results.columns:
                    anomalies = job_results[job_results['final_anomaly'] == True].copy()
                    if anomalies.empty:
                        continue
                else:
                    # If no 'final_anomaly' column, use the entire dataset
                    # This might be the case if the data is pre-filtered
                    anomalies = job_results.copy()
                
                # Create job entry if it doesn't exist
                if job_name not in all_anomalies:
                    all_anomalies[job_name] = {
                        "job_id": job_name,
                        "data_type": data_type,
                        "anomaly_count": 0,
                        "anomalies": []
                    }
                
                # Process each anomaly
                for _, anomaly in anomalies.iterrows():
                    # Create structured anomaly record
                    anomaly_record = {
                        "timestamp": str(anomaly.get('@timestamp', '')),
                        "score": float(anomaly.get('anomaly_score', anomaly.get('combined_score', 0.0))),
                        "event_count": int(anomaly.get('event_count', 0)),
                    }
                    
                    # Add entity-specific fields based on data type
                    entity_fields = self._extract_entity_fields(anomaly, data_type)
                    if entity_fields:
                        anomaly_record.update(entity_fields)
                    
                    # Add score details
                    score_details = self._extract_score_details(anomaly)
                    if score_details:
                        anomaly_record["score_details"] = score_details
                    
                    # Add feature details (actual vs typical)
                    feature_details = self._extract_feature_details(anomaly)
                    if feature_details:
                        anomaly_record["features"] = feature_details
                    
                    # Add context fields
                    context = self._extract_context_fields(anomaly, data_type)
                    if context:
                        anomaly_record["context"] = context
                    
                    # Add description
                    anomaly_record["description"] = self._generate_anomaly_description(anomaly, data_type)
                    
                    # Add the anomaly to the job's list
                    all_anomalies[job_name]["anomalies"].append(anomaly_record)
                    all_anomalies[job_name]["anomaly_count"] += 1
                    anomaly_count += 1
        
        # Save to JSON file
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        anomalies_file = os.path.join(output_dir, f"linux_anomalies_{timestamp_str}.json")
        
        with open(anomalies_file, 'w') as f:
            json.dump(all_anomalies, f, indent=2, default=str)
        
        logger.info(f"Saved {anomaly_count} individual anomalies to {anomalies_file}")
        return anomalies_file
    
    def _extract_entity_fields(self, anomaly: pd.Series, data_type: str) -> Dict[str, Any]:
        """Extract entity-related fields from an anomaly."""
        entity_fields = {}
        
        # Host information
        if 'host.hostname' in anomaly:
            entity_fields["host"] = {
                "name": anomaly.get('host.hostname')
            }
        elif 'host.name' in anomaly:
            entity_fields["host"] = {
                "name": anomaly.get('host.name')
            }
        
        # Process information
        if 'process.name' in anomaly:
            entity_fields["process"] = {
                "name": anomaly.get('process.name')
            }
            if 'process.args' in anomaly:
                entity_fields["process"]["args"] = anomaly.get('process.args')
            if 'process.executable' in anomaly:
                entity_fields["process"]["executable"] = anomaly.get('process.executable')
            if 'process.pid' in anomaly:
                entity_fields["process"]["pid"] = anomaly.get('process.pid')
        
        # User information
        if 'user.name' in anomaly:
            entity_fields["user"] = {
                "name": anomaly.get('user.name')
            }
        
        # Network information
        network_fields = {}
        if 'destination.ip' in anomaly:
            network_fields["destination"] = {
                "ip": anomaly.get('destination.ip')
            }
            if 'destination.port' in anomaly:
                network_fields["destination"]["port"] = anomaly.get('destination.port')
            if 'destination.geo.country_name' in anomaly:
                network_fields["destination"]["country"] = anomaly.get('destination.geo.country_name')
        
        if 'source.ip' in anomaly:
            network_fields["source"] = {
                "ip": anomaly.get('source.ip')
            }
            if 'source.port' in anomaly:
                network_fields["source"]["port"] = anomaly.get('source.port')
        
        if network_fields:
            entity_fields.update(network_fields)
        
        return entity_fields
    
    def _extract_score_details(self, anomaly: pd.Series) -> Dict[str, float]:
        """Extract score-related details from an anomaly."""
        score_fields = {}
        
        score_related_columns = [
            'anomaly_score', 'initial_anomaly_score', 'record_score', 'initial_record_score',
            'probability', 'combined_score', 'raw_anomaly_score'
        ]
        
        for col in score_related_columns:
            if col in anomaly and not pd.isna(anomaly[col]):
                score_fields[col] = float(anomaly[col])
        
        return score_fields
    
    def _extract_feature_details(self, anomaly: pd.Series) -> Dict[str, Any]:
        """Extract feature details (actual vs typical) from an anomaly."""
        feature_details = {}
        
        if 'actual' in anomaly and not pd.isna(anomaly['actual']):
            feature_details["actual"] = float(anomaly['actual'])
        
        if 'typical' in anomaly and not pd.isna(anomaly['typical']):
            feature_details["typical"] = float(anomaly['typical'])
        
        if 'field_name' in anomaly and not pd.isna(anomaly['field_name']):
            feature_details["field_name"] = anomaly['field_name']
        
        if 'function' in anomaly and not pd.isna(anomaly['function']):
            feature_details["function"] = anomaly['function']
        
        if 'function_description' in anomaly and not pd.isna(anomaly['function_description']):
            feature_details["function_description"] = anomaly['function_description']
        
        # Include any cause information (nested)
        if 'causes' in anomaly and not pd.isna(anomaly['causes']):
            # Handle causes which could be in string format or already parsed
            try:
                if isinstance(anomaly['causes'], str):
                    causes = json.loads(anomaly['causes'])
                else:
                    causes = anomaly['causes']
                
                feature_details["causes"] = causes
            except Exception as e:
                logger.debug(f"Failed to parse causes: {e}")
        
        return feature_details
    
    def _extract_context_fields(self, anomaly: pd.Series, data_type: str) -> Dict[str, Any]:
        """Extract additional context fields from an anomaly."""
        context = {
            "data_type": data_type
        }
        
        # Check for boolean indicators
        boolean_indicators = [
            'is_root_user', 'is_system_path', 'is_tmp_execution', 'is_large_transfer',
            'is_well_known_port', 'is_sudo_command', 'is_compiler_activity', 'is_service_user',
            'is_business_hours', 'has_pipes', 'has_redirection', 'potential_cred_harvest'
        ]
        
        for indicator in boolean_indicators:
            if indicator in anomaly and not pd.isna(anomaly[indicator]):
                context[indicator] = bool(anomaly[indicator])
        
        # Add any categorical fields
        categorical_fields = [
            'discovery_category', 'metadata_service_type', 'result_type', 'by_field_name',
            'by_field_value', 'over_field_name', 'over_field_value', 'partition_field_name',
            'partition_field_value', 'detection_method'
        ]
        
        for field in categorical_fields:
            if field in anomaly and not pd.isna(anomaly[field]):
                context[field] = anomaly[field]
        
        # Include bucket information
        if 'bucket_span' in anomaly and not pd.isna(anomaly['bucket_span']):
            context["bucket_span"] = int(anomaly['bucket_span'])
        
        if 'is_interim' in anomaly and not pd.isna(anomaly['is_interim']):
            context["is_interim"] = bool(anomaly['is_interim'])
        
        # Add host count if available
        if 'host_count' in anomaly and not pd.isna(anomaly['host_count']):
            context["host_count"] = int(anomaly['host_count'])
        
        return context    # Discovery detection methods
    def _detect_network_configuration_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect network configuration discovery commands."""
        return self._detect_discovery_commands(data, "network")
    
    def _detect_network_connection_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect network connection discovery commands."""
        return self._detect_discovery_commands(data, "network")
    
    def _detect_system_information_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system information discovery commands."""
        return self._detect_discovery_commands(data, "system")
    
    def _detect_system_process_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system process discovery commands."""
        return self._detect_discovery_commands(data, "process")
    
    def _detect_system_user_discovery(self, data: pd.DataFrame) -> pd.DataFrame:
        """Detect system user discovery commands."""
        return self._detect_discovery_commands(data, "user")
    
    def _detect_discovery_commands(self, data: pd.DataFrame, category: str) -> pd.DataFrame:
        """Common discovery command detection logic with enhanced filtering."""
        if data.empty:
            return pd.DataFrame()
        
        try:
            # Filter by discovery category if available
            if 'discovery_category' in data.columns:
                category_data = data[data['discovery_category'] == category].copy()
                if category_data.empty:
                    category_data = data.copy()  # Fallback to all data
            else:
                category_data = data.copy()
            
            bucketed_data = self._create_time_buckets_safe(category_data, self.config.get("detection", {}).get("bucket_span", "60m"))
            
            if bucketed_data.empty:
                return pd.DataFrame()
            
            # Ensure required columns
            required_fields = {
                'command_length': 0,
                'has_pipes': 0,
                'has_redirection': 0,
                'user.name': 'unknown',
                'process.name': 'unknown'
            }
            
            for field, default_value in required_fields.items():
                if field not in bucketed_data.columns:
                    bucketed_data[field] = default_value
            
            # Aggregate by user and command
            agg_dict = {
                'event.category': 'count',
                'command_length': 'mean',
                'has_pipes': 'sum',
                'has_redirection': 'sum'
            }
            
            aggregated = bucketed_data.groupby(['time_bucket', 'user.name', 'process.name']).agg(agg_dict).reset_index()
            aggregated = aggregated.rename(columns={'event.category': 'event_count'})
            aggregated['@timestamp'] = aggregated['time_bucket']
            
            # Run detection
            models, scalers, baselines = self.model_manager.get_models_for_group("discovery")
            results_list = []
            
            try:
                stat_results = detect_statistical_anomalies(aggregated, baselines, self.config, "discovery")
                if not stat_results.empty:
                    results_list.append(stat_results)
            except Exception as e:
                logger.warning(f"Discovery statistical detection failed: {e}")
            
            if models:
                try:
                    ml_results = detect_ml_anomalies(aggregated, models, scalers, self.config, "discovery")
                    if not ml_results.empty:
                        results_list.append(ml_results)
                except Exception as e:
                    logger.warning(f"Discovery ML detection failed: {e}")
            
            # Run discovery-specific detection
            try:
                discovery_results = detect_discovery_command_anomalies(aggregated, self.config)
                if not discovery_results.empty:
                    results_list.append(discovery_results)
            except Exception as e:
                logger.warning(f"Discovery specific detection failed: {e}")
            
            # Combine results
            if results_list:
                combined = results_list[0]
                for additional_result in results_list[1:]:
                    combined = self._safe_combine_results(combined, additional_result)
                
                if 'final_anomaly' not in combined.columns:
                    combined['final_anomaly'] = False
                
                return combined
            else:
                aggregated['anomaly_score'] = 0.0
                aggregated['final_anomaly'] = False
                aggregated['detection_method'] = 'baseline_aggregation'
                return aggregated
                
        except Exception as e:
            logger.error(f"Error in _detect_discovery_commands: {e}")
            return pd.DataFrame()