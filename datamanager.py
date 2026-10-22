"""
Updated Linux Anomaly Detection Data Manager
Integrated with enhanced training period configuration

Date: 2025-08-13
Changes: Added training period configuration integration to existing functions
Reason: Enable configurable training periods while maintaining existing function signatures
"""

import hashlib
import logging
import re
import time
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch

from es_tls import diagnose_connection_failure, es_tls_kwargs


def validate_and_add_missing_fields(df: "pd.DataFrame", data_type: str = "process") -> "pd.DataFrame":
    """Add missing fields with default values instead of just warning."""

    required_field_defaults = {
        # Process fields
        'is_sudo_command': 0,
        'is_su_command': 0,
        'is_compiler_activity': 0,
        'is_dev_tool': 0,
        'hour_of_day': 12,
        'is_business_hours': 1,
        'command_length': 0,
        'args_count': 0,
        'has_suspicious_chars': 0,

        # Discovery fields
        'discovery_category': 'unknown',
        'has_pipes': 0,
        'has_redirection': 0,
        'is_root_discovery': 0,
        'is_regular_user_discovery': 1
    }

    missing_fields = []
    for field, default_value in required_field_defaults.items():
        if field not in df.columns:
            df[field] = default_value
            missing_fields.append(field)

    if missing_fields:
        logger.debug(f"Added {len(missing_fields)} missing fields with defaults for {data_type}")

    return df

# Then call this function after creating the DataFrame:

def _calculate_hourly_distribution(total_records: int, time_range: dict,
                                 strategy: str = "balanced") -> dict:
    """
    Calculate how many records to fetch from each hour for balanced temporal distribution.

    Args:
        total_records: Total number of records to fetch
        time_range: Dictionary with 'gte' and 'lte' timestamps
        strategy: Distribution strategy ('balanced', 'recent_weighted', 'old_weighted')

    Returns:
        Dictionary mapping hour windows to target record counts
    """
    start_time = pd.to_datetime(time_range['gte'])
    end_time = pd.to_datetime(time_range['lte'])

    # Calculate total hours in the time range
    total_hours = int((end_time - start_time).total_seconds() / 3600)

    if total_hours <= 0:
        return {}

    # Create hourly time windows
    hour_windows = []
    current_time = start_time

    while current_time < end_time:
        next_hour = current_time + timedelta(hours=1)
        if next_hour > end_time:
            next_hour = end_time

        hour_windows.append({
            'start': current_time,
            'end': next_hour,
            'hour_key': current_time.strftime('%Y-%m-%d_%H')
        })
        current_time = next_hour

    # Calculate records per hour based on strategy
    if strategy == "balanced":
        # Equal distribution across all hours
        records_per_hour = total_records // len(hour_windows)
        remainder = total_records % len(hour_windows)

        distribution = {}
        for i, window in enumerate(hour_windows):
            # Distribute remainder across first few hours
            extra = 1 if i < remainder else 0
            distribution[window['hour_key']] = {
                'records': records_per_hour + extra,
                'time_range': {
                    'gte': window['start'].isoformat(),
                    'lte': window['end'].isoformat()
                }
            }

    elif strategy == "recent_weighted":
        # More records from recent hours, less from older hours
        weights = []
        for i, window in enumerate(hour_windows):
            # Higher weight for more recent hours (reverse chronological)
            weight = (len(hour_windows) - i) / len(hour_windows)
            weights.append(weight)

        total_weight = sum(weights)
        distribution = {}

        for i, window in enumerate(hour_windows):
            records = int((weights[i] / total_weight) * total_records)
            distribution[window['hour_key']] = {
                'records': records,
                'time_range': {
                    'gte': window['start'].isoformat(),
                    'lte': window['end'].isoformat()
                }
            }

    elif strategy == "old_weighted":
        # More records from older hours for better historical coverage
        weights = []
        for i, window in enumerate(hour_windows):
            # Higher weight for older hours
            weight = (i + 1) / len(hour_windows)
            weights.append(weight)

        total_weight = sum(weights)
        distribution = {}

        for i, window in enumerate(hour_windows):
            records = int((weights[i] / total_weight) * total_records)
            distribution[window['hour_key']] = {
                'records': records,
                'time_range': {
                    'gte': window['start'].isoformat(),
                    'lte': window['end'].isoformat()
                }
            }

    logger.info(f"Calculated hourly distribution: {len(distribution)} hours, "
                f"strategy={strategy}, avg_per_hour={total_records//len(distribution)}")

    return distribution
def _fetch_data_for_hour_window(es: "Elasticsearch", index_pattern: str, base_query, time_window, target_records):
    """
    Fetch data for a specific hour window with fallback strategies.

    Args:
        es: Elasticsearch client
        index_pattern: Index pattern to search
        base_query: Base query structure
        time_window: Time range for this hour
        target_records: Target number of records to fetch

    Returns:
        List of hits from Elasticsearch
    """
    if target_records <= 0:
        return []

    # Create hour-specific query
    hour_query = base_query.copy()
    hour_query["query"]["bool"]["must"][0]["range"]["@timestamp"] = time_window
    hour_query["size"] = min(10000, target_records)

    # Strategy 1: Try to get exact target from this hour
    try:
        all_hits = []
        search_after_val = None

        while len(all_hits) < target_records:
            if search_after_val:
                hour_query["search_after"] = search_after_val

            remaining = target_records - len(all_hits)
            hour_query["size"] = min(10000, remaining)

            response = es.search(index=index_pattern, body=hour_query)
            hits = response["hits"]["hits"]

            if not hits:
                break

            all_hits.extend(hits)
            search_after_val = hits[-1]["sort"]

            if len(hits) < hour_query["size"]:
                break  # No more data in this hour

        if len(all_hits) > 0:
            logger.debug(f"Hour window {time_window}: fetched {len(all_hits)}/{target_records} records")

        return all_hits[:target_records]  # Ensure we don't exceed target

    except Exception as e:
        logger.warning(f"Error fetching data for hour window {time_window}: {e}")
        return []
def _apply_intelligent_backfill(es: "Elasticsearch", index_pattern: str, base_query, time_range: dict | None,
                              existing_hits, target_size):
    """
    Apply intelligent backfill to reach target size while maintaining temporal balance.
    """
    shortfall = target_size - len(existing_hits)
    if shortfall <= 0:
        return existing_hits

    logger.info(f"Applying intelligent backfill for {shortfall} records")

    # Strategy: Fill gaps by fetching from time periods with lowest representation
    existing_timestamps = [hit['_source']['@timestamp'] for hit in existing_hits if '@timestamp' in hit['_source']]
    existing_df = pd.DataFrame({'@timestamp': pd.to_datetime(existing_timestamps)})

    if not existing_df.empty:
        # Find hours with low representation
        existing_df['hour'] = existing_df['@timestamp'].dt.floor('H')
        existing_df['hour'].value_counts()

        # Focus backfill on under-represented hours
        pd.to_datetime(time_range['gte'])
        pd.to_datetime(time_range['lte'])

        backfill_query = base_query.copy()
        backfill_query["size"] = min(10000, shortfall)

        # Use a broader time range but with different sorting for diversity
        backfill_query["sort"] = [{"@timestamp": {"order": "asc"}}]  # Different order for variety

        try:
            response = es.search(index=index_pattern, body=backfill_query)
            backfill_hits = response["hits"]["hits"][:shortfall]

            logger.info(f"Backfill complete: added {len(backfill_hits)} records")
            return existing_hits + backfill_hits

        except Exception as e:
            logger.warning(f"Backfill failed: {e}")
            return existing_hits

    return existing_hits
def _log_temporal_distribution_analysis(df: pd.DataFrame, data_type: str):
    """Log analysis of temporal distribution in fetched data."""
    if df.empty or '@timestamp' not in df.columns:
        return

    try:
        df_analysis = df.copy()
        df_analysis['@timestamp'] = pd.to_datetime(df_analysis['@timestamp'])
        df_analysis['hour'] = df_analysis['@timestamp'].dt.floor('H')

        hourly_counts = df_analysis['hour'].value_counts().sort_index()

        analysis = {
            'total_records': len(df_analysis),
            'unique_hours': len(hourly_counts),
            'time_span_hours': (df_analysis['@timestamp'].max() - df_analysis['@timestamp'].min()).total_seconds() / 3600,
            'avg_per_hour': hourly_counts.mean(),
            'std_per_hour': hourly_counts.std(),
            'min_per_hour': hourly_counts.min(),
            'max_per_hour': hourly_counts.max(),
            'distribution_balance': hourly_counts.std() / hourly_counts.mean() if hourly_counts.mean() > 0 else 0
        }

        logger.info(f"Temporal distribution analysis for {data_type}: "
                   f"{analysis['unique_hours']} hours covered, "
                   f"avg={analysis['avg_per_hour']:.0f} records/hour, "
                   f"balance_score={analysis['distribution_balance']:.2f}")

    except Exception as e:
        logger.debug(f"Could not analyze temporal distribution: {e}")

def _fallback_to_standard_fetch(es: "Elasticsearch", index_pattern: str, base_query, time_range: dict | None, query_size: int):
    """Fallback to standard fetch method if hourly stratification fails."""
    logger.info("Using standard fetch as fallback")

    query = base_query.copy()
    query["query"]["bool"]["must"][0]["range"]["@timestamp"] = time_range
    query["size"] = min(10000, query_size)

    all_hits = []
    search_after_val = None

    while len(all_hits) < query_size:
        if search_after_val:
            query["search_after"] = search_after_val

        try:
            response = es.search(index=index_pattern, body=query)
            hits = response["hits"]["hits"]

            if not hits:
                break

            all_hits.extend(hits)
            search_after_val = hits[-1]["sort"]

            if len(hits) < query["size"]:
                break

        except Exception as e:
            logger.error(f"Error in fallback fetch: {e}")
            break

    return all_hits

def _fetch_with_hourly_stratification(es: "Elasticsearch", config: dict, index_pattern: str, base_query,
                                    time_range, query_size, strategy="balanced"):
    """
    Enhanced fetch function with hourly stratified sampling.

    Args:
        es: Elasticsearch client
        config: Configuration dictionary
        index_pattern: Index pattern to search
        base_query: Base query structure (without time range)
        time_range: Overall time range
        query_size: Total number of records to fetch
        strategy: Distribution strategy

    Returns:
        List of all hits with temporal distribution
    """
    logger.info(f"Starting hourly stratified fetch: {query_size} records across time range")

    # Calculate hourly distribution
    hourly_distribution = _calculate_hourly_distribution(query_size, time_range, strategy)

    if not hourly_distribution:
        logger.warning("No hourly distribution calculated, falling back to standard fetch")
        return _fallback_to_standard_fetch(es, index_pattern, base_query, time_range, query_size)

    all_hits = []
    successful_hours = 0
    total_hours = len(hourly_distribution)

    # Fetch data for each hour window
    for _hour_key, hour_config in hourly_distribution.items():
        target_records = hour_config['records']
        hour_time_range = hour_config['time_range']

        if target_records > 0:
            hour_hits = _fetch_data_for_hour_window(
                es, index_pattern, base_query, hour_time_range, target_records
            )

            if hour_hits:
                all_hits.extend(hour_hits)
                successful_hours += 1

                # Progress logging
                if successful_hours % 12 == 0:  # Every 12 hours
                    logger.info(f"Hourly stratified progress: {successful_hours}/{total_hours} hours, "
                              f"{len(all_hits)} total records")

    # Handle shortfall with intelligent backfill
    if len(all_hits) < query_size * 0.8:  # If we got less than 80% of target
        logger.info(f"Hourly stratification yielded {len(all_hits)}/{query_size} records, applying backfill")
        all_hits = _apply_intelligent_backfill(es, index_pattern, base_query, time_range,
                                             all_hits, query_size)

    logger.info(f"Hourly stratified fetch complete: {len(all_hits)} records from {successful_hours}/{total_hours} hours")
    return all_hits
class OptimizedRetriever:
    """Optimized data retrieval with search_after for large datasets."""

    def __init__(self, es: "Elasticsearch", config: dict):
        self.es = es
        self.batch_size = config.get("batch_size", 10000)
        self.debug_mode = config.get("debug_mode", True)

    def retrieve_with_search_after(self, index_pattern: str, query_body: dict, source_fields: list | None, max_records: int):
        """Retrieve data using search_after for efficient pagination - FIXED for Elasticsearch compatibility."""
        all_records = []
        search_after = None

        # Use a more compatible sort configuration
        query_body["sort"] = [{"@timestamp": {"order": "desc"}}]

        while len(all_records) < max_records:
            current_batch_size = min(self.batch_size, max_records - len(all_records))
            query_body["size"] = current_batch_size
            query_body["_source"] = source_fields

            if search_after:
                query_body["search_after"] = search_after

            try:
                response = self.es.search(index=index_pattern, body=query_body)
                hits = response.get('hits', {}).get('hits', [])

                if not hits:
                    break

                # Extract records and flatten
                batch_records = []
                for hit in hits:
                    record = self._flatten_elasticsearch_document(hit['_source'])
                    batch_records.append(record)

                all_records.extend(batch_records)

                # Update search_after for next iteration
                last_hit = hits[-1]
                search_after = last_hit.get('sort')

                # Progress logging
                progress_pct = (len(all_records) / max_records) * 100
                if self.debug_mode and len(all_records) % 5000 == 0:
                    logger.info(f"Progress: {len(all_records):,}/{max_records:,} records ({progress_pct:.1f}%)")
                elif len(all_records) % 25000 == 0:
                    logger.info(f"Retrieved {len(all_records):,} records so far ({progress_pct:.1f}%)")

            except Exception as e:
                logger.error(f"Error in batch retrieval: {e}")
                break

        return all_records

    def _flatten_elasticsearch_document(self, doc: dict, parent_key: str='', sep: str='.'):
        """Flatten nested Elasticsearch document."""
        items = []
        for k, v in doc.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_elasticsearch_document(v, new_key, sep=sep).items())
            elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
                items.extend(self._flatten_elasticsearch_document(v[0], new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, ','.join(map(str, v)) if v else ''))
            else:
                items.append((new_key, v))
        return dict(items)
# Import configuration if available
try:
    from config import get_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    get_config = None

logger = logging.getLogger("linux_anomaly_detection")


DATA_GROUP_CONFIG = {
    "process": {
        "endpoint": ".ds-logs-endpoint.events.process-default-*",
        "jobs": ["v3_linux_anomalous_process_all_hosts", "v3_rare_process_by_host_linux"],
        "required_fields": [
            "process.name", "process.executable", "process.command_line", "process.args",
            "process.parent.name", "process.parent.executable", "user.name", "user.id",
            "host.hostname", "@timestamp", "process.hash.sha256", "process.working_directory"
        ]
    },
    "network": {
        "endpoint": ".ds-logs-endpoint.events.network-default-*",
        "jobs": ["v3_linux_anomalous_network_activity", "v3_linux_anomalous_network_port_activity"],
        "required_fields": [
            "destination.ip", "destination.port", "source.ip", "source.port",
            "network.transport", "network.direction", "destination.bytes", "source.bytes",
            "process.name", "process.executable", "event.action", "process.thread.capabilities.effective",
            "network.type"
        ]
    },
    "user": {
        "endpoint": ".ds-logs-endpoint.events.process-default-*",
        "jobs": ["v3_linux_anomalous_user_name", "v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"],
        "required_fields": [
            "user.name", "user.id", "process.name", "process.command_line",
            "is_sudo_command", "is_su_command", "is_compiler_activity", "is_dev_tool",
            "host.hostname", "hour_of_day", "is_business_hours", "command_length",
            "args_count", "has_suspicious_chars"
        ]
    },
    "discovery": {
        "endpoint": ".ds-logs-endpoint.events.process-default-*",
        "jobs": [
            "v3_linux_network_configuration_discovery", "v3_linux_network_connection_discovery",
            "v3_linux_system_information_discovery", "v3_linux_system_process_discovery",
            "v3_linux_system_user_discovery"
        ],
        "required_fields": [
            "process.name", "process.command_line", "discovery_category", "user.name",
            "host.hostname", "@timestamp", "has_pipes", "has_redirection", "command_length",
            "args_count", "is_root_discovery", "is_regular_user_discovery"
        ]
    },
    "metadata": {
        "endpoint": ".ds-logs-endpoint.events.network-default-*",  # Fixed: was process-default
        "jobs": ["v3_linux_rare_metadata_process", "v3_linux_rare_metadata_user"],
        "required_fields": [
            "destination.ip", "destination.port", "process.name", "process.executable",
            "user.name", "is_service_account", "access_method", "potential_cred_harvest",
            "user_data_access", "@timestamp", "network.transport", "is_root_access",
            "process.command_line"
        ]
    },
    "auth": {
        "endpoint": ".ds-logs-system.auth-default-*",
        "jobs": [
            "v3_linux_auth_rare_source_ip", "v3_linux_auth_high_count_logon_fails",
            "v3_linux_auth_rare_user", "v3_linux_auth_rare_hour"
        ],
        "required_fields": [
            "@timestamp", "host.name", "user.name", "source.ip", "source.port",
            "event.action", "event.outcome", "process.name",
            "hour_of_day", "is_business_hours", "is_failed_login", "is_ssh", "is_sudo"
        ]
    },
    "host": {
        "endpoint": ".ds-logs-endpoint.events.process-default-*",
        "jobs": ["v3_linux_anomalous_host_activity", "v3_linux_host_user_deviation"],
        "required_fields": [
            "process.name", "process.executable", "process.command_line", "process.args",
            "process.parent.name", "process.parent.executable", "user.name", "user.id",
            "host.hostname", "@timestamp", "process.hash.sha256", "process.working_directory"
        ]
    }
}

def get_training_configuration(data_type: str) -> dict:
    """Get training configuration for data type."""
    training_configs = {
        "process": {
            "training_period_days": 5,
            "detection_period_days": 0.042,
            "baseline_query_size": 500000,
            "min_records_for_detection": 5
        },
        "network": {
            "training_period_days": 5,
            "detection_period_days": 0.083,
            "baseline_query_size": 2000000,
            "min_records_for_detection": 10
        },
        "user": {
            "training_period_days": 5,
            "detection_period_days": 0.167,
            "baseline_query_size": 2000000,
            "min_records_for_detection": 3
        },
        "discovery": {
            "training_period_days": 5,
            "detection_period_days": 0.167,
            "baseline_query_size": 2000000,
            "min_records_for_detection": 2
        },
        "metadata": {
            "training_period_days": 5,
            "detection_period_days": 1,
            "baseline_query_size": 2000000,
            "min_records_for_detection": 5
        },
        "auth": {
            "training_period_days": 14,
            "detection_period_days": 0.042,
            "baseline_query_size": 500000,
            "min_records_for_detection": 10
        },
        "host": {
            "training_period_days": 5,
            "detection_period_days": 0.083,
            "baseline_query_size": 500000,
            "min_records_for_detection": 10
        }
    }

    return training_configs.get(data_type, {
        "training_period_days": 5,
        "detection_period_days": 0.042,
        "baseline_query_size": 1000000,
        "min_records_for_detection": 5
    })


def get_configured_time_range(data_type: str = "process") -> dict[str, str]:
    """
    Get configured time range for training data based on data type.

    Args:
        data_type (str): The data type (process, network, user, discovery, metadata)

    Returns:
        Dict[str, str]: Time range with 'gte' and 'lte' keys
    """
    config = get_training_configuration(data_type)

    if config.get("use_custom_period", False):
        start_time = config.get("custom_training_start")
        end_time = config.get("custom_training_end")

        if start_time and end_time:
            return {
                "gte": start_time,
                "lte": end_time
            }

    # Calculate time range based on configured period
    end_time = datetime.utcnow() - timedelta(days=config.get("training_start_offset_days", 1))
    start_time = end_time - timedelta(days=config.get("training_period_days", 30))

    return {
        "gte": start_time.isoformat(),
        "lte": end_time.isoformat()
    }

def apply_training_time_filters(df: pd.DataFrame, data_type: str = "process") -> pd.DataFrame:
    """
    Apply time-based training filters to DataFrame.

    Args:
        df (pd.DataFrame): Input DataFrame
        data_type (str): Data type for configuration

    Returns:
        pd.DataFrame: Filtered DataFrame
    """
    if df.empty or "@timestamp" not in df.columns:
        return df

    config = get_training_configuration(data_type)


    if not pd.api.types.is_datetime64_any_dtype(df["@timestamp"]):
        df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

    # Extract time components
    df_time = df["@timestamp"].dt

    # Apply business hours filter if configured
    if config.get("include_business_hours_only", False):
        start_hour = config.get("business_hours_start", 8)
        end_hour = config.get("business_hours_end", 18)

        business_hours_mask = (df_time.hour >= start_hour) & (df_time.hour < end_hour)
        df = df[business_hours_mask]
        logger.info(f"Applied business hours filter: {start_hour}:00-{end_hour}:00")

    # Apply weekend filter if configured
    if not config.get("include_weekends", True):
        weekday_mask = df_time.dayofweek < 5  # Monday=0, Sunday=6
        df = df[weekday_mask]
        logger.info("Applied weekday-only filter")

    return df

def connect_to_elasticsearch(config: dict) -> "Elasticsearch | None":
    """
    Connect to Elasticsearch with enhanced error handling and configuration support.

    Args:
        config (dict): Configuration dictionary containing Elasticsearch settings

    Returns:
        Elasticsearch: Connected Elasticsearch client or None if failed
    """
    try:
        es_config = config.get("elasticsearch", {})

        # Extract connection parameters
        host = es_config.get("host", "localhost:9200")
        username = es_config.get("username")
        password = es_config.get("password")
        timeout = es_config.get("timeout", 60)

        # Build Elasticsearch client configuration
        es_client_config = {
            "hosts": [host],
            "timeout": timeout,
            "max_retries": 3,
            "retry_on_timeout": True
        }

        if username and password:
            es_client_config["http_auth"] = (username, password)

        # Verification is on unless ES_VERIFY_CERTS=false; ES_CA_CERT supplies a private CA.
        es_client_config.update(
            es_tls_kwargs(es_config.get("verify_certs"), es_config.get("ca_certs") or None)
        )

        # Create Elasticsearch client
        es = Elasticsearch(**es_client_config)

        # Test connection
        if es.ping():
            logger.info(f"Successfully connected to Elasticsearch at {host}")
            return es
        else:
            hint = diagnose_connection_failure(es)
            logger.error(f"Failed to connect to Elasticsearch. {hint or ''}".strip())
            return None

    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {e}")
        return None
def _flatten_elasticsearch_document(doc: dict, parent_key: str='', sep: str='.'):
    """Flatten nested Elasticsearch document safely without dropping data."""
    items = []
    for k, v in doc.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k

        if isinstance(v, dict):
            items.extend(_flatten_elasticsearch_document(v, new_key, sep=sep).items())

        elif isinstance(v, list) and len(v) > 0 and isinstance(v[0], dict):
            for i, elem in enumerate(v):
                items.extend(_flatten_elasticsearch_document(elem, f"{new_key}[{i}]", sep=sep).items())

        elif isinstance(v, list):
            items.append((new_key, ','.join(map(str, v)) if v else ''))

        else:
            items.append((new_key, v))

    return dict(items)

def fetch_process_data(es: "Elasticsearch", config: dict, time_range: dict | None = None, query_size: int = 10000) -> "pd.DataFrame":
    """
    Fetch process data with search_after pagination to bypass 10k limit.
    Maintains original function signature & arguments.
    Includes Linux filtering and required fields as in the original query.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["process"]
    index_pattern = group_config["endpoint"]

    # Configure time range
    if time_range is None:
        try:
            time_range = get_configured_time_range("process")
            logger.info("Using configured training period for process data")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }


    try:
        query_size = int(query_size)
        if query_size == 10000:
            training_config = get_training_configuration("process")
            training_days = training_config.get("training_period_days", 30)
            if training_days >= 30:
                query_size = min(50000, max(200000, query_size * 20))
                logger.info(f"Applied process training constraint: increased query_size to {query_size}")
    except (TypeError, ValueError):
        query_size = 10000
        logger.warning("Invalid query_size, using default of 10000")

    # Required fields
    source_fields = [
    "@timestamp", "host.hostname", "host.ip", "host.id", "host.name", "host.os.name", "host.os.type", "host.os.platform",
        "process.name", "process.executable", "process.command_line", "process.args",
        "process.pid", "process.entity_id", "process.working_directory",
        "process.parent.name", "process.parent.executable", "process.parent.command_line",
        "process.parent.pid", "process.parent.entity_id",
        "process.hash.sha256", "process.hash.sha1", "process.hash.md5",
        "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
        "group.name", "group.id", "group.Ext.real.name", "group.Ext.real.id",
    "event.action", "event.type", "event.id", "event.category", "event.outcome",
        "agent.id", "agent.type", "agent.version"
    ]

    # Hard-coded filtered query (matches your original query exactly)
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    },
                    {
                        "term": {
                            "host.os.type": "linux"
                        }
                    }
                ],
                "filter": [
                    {
                        "exists": {
                            "field": "process.name"
                        }
                    }
                ]
            }
        },
        "_source": source_fields,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    }

    try:
        # ENHANCED: Use hourly stratified fetching
        logger.info(f"Fetching process data from {index_pattern} using hourly stratified sampling")

        # Determine distribution strategy based on query size
        if query_size >= 100000:  # Large datasets: balanced distribution
            strategy = "balanced"
        elif query_size >= 50000:   # Medium datasets: slight recent bias
            strategy = "recent_weighted"
        else:                       # Small datasets: standard approach
            strategy = "recent_weighted"

        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, strategy
        )

        logger.info(f"Retrieved {len(all_hits)} process records from Elasticsearch")

        if not all_hits:
            logger.warning("No process data found matching the criteria")
            return pd.DataFrame()

        # Process records (existing logic preserved)
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)
        df = validate_and_add_missing_fields(df, "process")

        # Timestamp processing (existing logic preserved)
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training time filters (existing logic preserved)
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Field validation (existing logic preserved)
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for process group: {missing_fields}")
            for field in missing_fields:
                if field in ["process.name", "process.executable", "user.name"]:
                    df[field] = "unknown"
                elif field in ["user.id", "process.args"]:
                    df[field] = 0
                else:
                    df[field] = ""

        # ENHANCED: Log temporal distribution analysis
        _log_temporal_distribution_analysis(df, "process")

        logger.info(f"Successfully processed {len(df)} Linux process records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching process data: {e}")
        return pd.DataFrame()


def fetch_network_activity_data(es: "Elasticsearch", config: dict, time_range: dict | None = None, query_size: int = 10000) -> "pd.DataFrame":
    """
    Fetch network activity data with search_after pagination to bypass 10k limit.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["network"]
    index_pattern = group_config["endpoint"]

    # Use training configuration if no time_range provided
    if time_range is None:
        try:
            time_range = get_configured_time_range("network")
            logger.info("Using configured training period for network data")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    # Required fields for network data
    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
    "destination.ip", "destination.port", "destination.domain",
    "host.ip",
        "source.ip", "source.port", "network.transport", "network.direction", "network.type",
        "destination.bytes", "source.bytes", "process.name", "process.executable",
        "process.pid", "process.command_line", "event.action", "event.type",
    "event.id",
        "process.thread.capabilities.effective", "process.thread.capabilities.permitted",
        "user.name", "user.id", "agent.id", "agent.type"
    ]

    # Build query with Linux filtering
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    },
                    {
                        "term": {
                            "host.os.type": "linux"
                        }
                    }
                ],
                "filter": [
                    {
                        "exists": {
                            "field": "destination.ip"
                        }
                    }
                ]
            }
        },
        "_source": source_fields,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    }

    try:
        # ENHANCED: Use hourly stratified fetching
        logger.info(f"Fetching process data from {index_pattern} using hourly stratified sampling")

        # Determine distribution strategy based on query size
        if query_size >= 100000:  # Large datasets: balanced distribution
            strategy = "balanced"
        elif query_size >= 50000:   # Medium datasets: slight recent bias
            strategy = "recent_weighted"
        else:                       # Small datasets: standard approach
            strategy = "recent_weighted"

        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, strategy
        )

        logger.info(f"Retrieved {len(all_hits)} process records from Elasticsearch")

        if not all_hits:
            logger.warning("No process data found matching the criteria")
            return pd.DataFrame()

        # Process records (existing logic preserved)
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)

        # Timestamp processing (existing logic preserved)
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training time filters (existing logic preserved)
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Field validation (existing logic preserved)
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for process group: {missing_fields}")
            for field in missing_fields:
                if field in ["process.name", "process.executable", "user.name"]:
                    df[field] = "unknown"
                elif field in ["user.id", "process.args"]:
                    df[field] = 0
                else:
                    df[field] = ""

        # ENHANCED: Log temporal distribution analysis
        _log_temporal_distribution_analysis(df, "process")

        logger.info(f"Successfully processed {len(df)} Linux process records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching process data: {e}")
        return pd.DataFrame()
##############################################################################################################################
##############################################################################################################################
def _flatten_elasticsearch_document(source: dict):
    """
    CORRECTED: Flatten Elasticsearch document preserving nested IP addresses.
    """
    flattened = {}

    def _flatten_dict(obj: dict, parent_key: str=''):
        if not isinstance(obj, dict):
            return

        for key, value in obj.items():
            new_key = f"{parent_key}.{key}" if parent_key else key

            if isinstance(value, dict):
                # Recursively flatten nested objects
                _flatten_dict(value, new_key)
            elif isinstance(value, list):
                if len(value) == 0:
                    flattened[new_key] = None
                elif len(value) == 1:
                    # Single item - use the value
                    if isinstance(value[0], dict):
                        _flatten_dict(value[0], new_key)
                    else:
                        flattened[new_key] = value[0]
                else:
                    # Multiple items - prefer joining strings, else take first item
                    if all(isinstance(item, str) for item in value):
                        flattened[new_key] = ', '.join(value)
                    else:
                        flattened[new_key] = value[0]
            else:
                # Simple value - store directly
                flattened[new_key] = value

    _flatten_dict(source)

    # CRITICAL: Ensure IP fields are strings and preserved
    ip_fields = [
        'destination.ip', 'source.ip', 'destination.address', 'source.address',
        'host.ip', 'client.ip', 'server.ip'
    ]

    for ip_field in ip_fields:
        if ip_field in flattened and flattened[ip_field] is not None:
            try:
                flattened[ip_field] = str(flattened[ip_field]).strip()
            except Exception:
                flattened[ip_field] = None

            # Additional validation - ensure it's not empty after conversion
            if flattened[ip_field] in ['', 'None', 'null']:
                flattened[ip_field] = None

    # Add convenient flat alias columns to reduce brittle dotted lookups
    host_hostname = flattened.get('host.hostname') or flattened.get('host.name') or flattened.get('host') or None
    if host_hostname is not None:
        flattened['host'] = host_hostname
        flattened['hostname'] = host_hostname
    else:
        # ensure keys exist to avoid KeyErrors downstream
        flattened.setdefault('host', None)
        flattened.setdefault('hostname', None)

    process_name = flattened.get('process.name') or flattened.get('process') or None
    if process_name is not None:
        flattened['process'] = process_name
        flattened['process_name'] = process_name
    else:
        flattened.setdefault('process', None)
        flattened.setdefault('process_name', None)

    username = flattened.get('user.name') or flattened.get('user.Ext.real.name') or flattened.get('user') or None
    if username is not None:
        flattened['username'] = username
    else:
        flattened.setdefault('username', None)

    # Synthesize a deterministic event.id when missing so downstream code can reliably join/identify events
    if not flattened.get('event.id'):
        key_parts = []
        for k in ['@timestamp', 'host.hostname', 'host.ip', 'process.pid', 'process.entity_id', 'process.command_line',
                  'destination.ip', 'source.ip', 'destination.port', 'source.port']:
            v = flattened.get(k)
            if v is None:
                key_parts.append('')
            else:
                key_parts.append(str(v))

        raw = '|'.join(key_parts)
        try:
            h = hashlib.sha256(raw.encode('utf-8')).hexdigest()
            flattened['event.id'] = f"synth-{h[:12]}"
        except Exception:
            # Last resort stable fallback
            flattened['event.id'] = f"synth-{int(time.time())}"

    return flattened



def debug_document_flattening(source: dict) -> None:
    """Debug function to trace document flattening issues."""
    print("=== DOCUMENT FLATTENING DEBUG ===")
    print(f"Raw source keys: {list(source.keys())}")

    # Check nested destination
    if 'destination' in source:
        dest = source['destination']
        print(f"Destination object: {dest}")
        if isinstance(dest, dict):
            print(f"  destination.ip: {dest.get('ip', 'MISSING')}")
            print(f"  destination.address: {dest.get('address', 'MISSING')}")

    # Check nested source
    if 'source' in source:
        src = source['source']
        print(f"Source object: {src}")
        if isinstance(src, dict):
            print(f"  source.ip: {src.get('ip', 'MISSING')}")
            print(f"  source.address: {src.get('address', 'MISSING')}")

    # Test flattening
    flattened = _flatten_elasticsearch_document(source)
    print("After flattening:")
    print(f"  destination.ip: {flattened.get('destination.ip', 'MISSING')}")
    print(f"  source.ip: {flattened.get('source.ip', 'MISSING')}")
    print(f"  destination.address: {flattened.get('destination.address', 'MISSING')}")
    print("==============================")

    return flattened


def fetch_network_activity_data_corrected(es: "Elasticsearch", config: dict, time_range: dict | None = None, query_size: int = 10000) -> "pd.DataFrame":
    """
    CORRECTED: Network data fetching with proper document flattening.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["network"]
    index_pattern = group_config["endpoint"]

    # Time range setup (unchanged)
    if time_range is None:
        try:
            time_range = get_configured_time_range("network")
            logger.info("Using configured training period for network data")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    # Source fields (unchanged)
    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
        "destination.ip", "destination.port", "destination.domain", "destination.address",
        "source.ip", "source.port", "source.address",
    "host.ip",
        "network.transport", "network.direction", "network.type",
        "destination.bytes", "source.bytes", "network.bytes", "network.packets",
        "process.name", "process.executable", "process.pid", "process.command_line",
    "event.action", "event.type", "event.id", "user.name", "user.id", "agent.id", "agent.type"
    ]

    # Query (unchanged from your version)
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": time_range}},
                    {"term": {"host.os.type": "linux"}}
                ],
                "filter": [
                    {"exists": {"field": "destination.ip"}}
                ]
            }
        },
        "_source": source_fields,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}]
    }

    try:
        logger.info(f"Fetching network data from {index_pattern}")

        # Fetch data (using your existing strategy)
        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, "recent_weighted"
        )

        logger.info(f"Retrieved {len(all_hits)} network records from Elasticsearch")

        if not all_hits:
            logger.warning("No network data found")
            return pd.DataFrame()

        # DEBUG: Test first document
        if all_hits:
            logger.info("DEBUGGING FIRST DOCUMENT:")
            debug_document_flattening(all_hits[0]["_source"])

        # CORRECTED: Process records with proper flattening
        records = []
        processing_errors = 0

        for i, hit in enumerate(all_hits):
            try:
                source = hit["_source"]

                # Use corrected flattening
                flattened = _flatten_elasticsearch_document(source)

                # Validate critical fields exist
                if not flattened.get("destination.ip"):
                    # Try alternative field
                    if flattened.get("destination.address"):
                        flattened["destination.ip"] = flattened["destination.address"]
                        logger.debug(f"Record {i}: Used destination.address as destination.ip")
                    else:
                        logger.warning(f"Record {i}: No destination IP found, skipping")
                        processing_errors += 1
                        continue

                records.append(flattened)

            except Exception as e:
                logger.error(f"Error processing record {i}: {e}")
                processing_errors += 1
                continue

        if processing_errors > 0:
            logger.warning(f"Processing errors: {processing_errors}/{len(all_hits)} records")

        if not records:
            logger.error("No valid records after processing")
            return pd.DataFrame()

        # Create DataFrame
        df = pd.DataFrame(records)

        # Validate IPs in DataFrame
        logger.info("POST-PROCESSING VALIDATION:")
        if 'destination.ip' in df.columns:
            unique_ips = df['destination.ip'].unique()
            logger.info(f"  destination.ip: {len(unique_ips)} unique values")
            logger.info(f"  Sample IPs: {list(unique_ips)[:5]}")

            # Check for problematic values
            bad_ips = [ip for ip in unique_ips if str(ip) in ['0.0.0.0', '', 'None', 'nan']]
            if bad_ips:
                logger.error(f"  PROBLEM: Found bad IPs: {bad_ips}")
            else:
                logger.info("  SUCCESS: All destination IPs are valid")
        else:
            logger.error("  CRITICAL: destination.ip column missing from DataFrame")

        # Continue with rest of processing (timestamp, filters, etc.)
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

        # Apply your existing filters and processing...
        df = apply_training_time_filters(df, "network")

        # SAFE preprocessing - no IP defaults
        df = preprocess_network_data_safe(df)
        if 'destination.ip' in df.columns:
            invalid_mask = (df['destination.ip'] == '0.0.0.0') | df['destination.ip'].isna() | (df['destination.ip'] == '')
        df = df[~invalid_mask]
        logger.info(f"Filtered out {invalid_mask.sum()} invalid network records")

        logger.info(f"Final result: {len(df)} records with {len(df.columns)} fields")
        df.to_csv("network_data_final.csv", index=False)
        return df


    except Exception as e:
        logger.error(f"Error fetching network data: {e}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return pd.DataFrame()


def preprocess_network_data_safe(df: "pd.DataFrame"):
    """Safe network preprocessing that never touches IP fields."""
    if df.empty:
        return df

    logger.info(f"Safe network preprocessing: {len(df)} records")

    # ONLY add non-IP defaults
    safe_fields = {
        'destination.port': 0,
        'source.port': 0,
        'network.transport': 'tcp',
        'network.direction': 'unknown',
        'network.bytes': 0,
        'process.name': 'unknown',
        'user.name': 'unknown',
        'host.hostname': 'unknown',
        'event.action': 'network_flow',
        'event.category': 'network'
    }

    for field, default in safe_fields.items():
        if field not in df.columns:
            df[field] = default

    # Add features without touching IPs
    if "destination.port" in df.columns:
        df["is_common_port"] = df["destination.port"].isin([80, 443, 22, 21, 25, 53]).astype(int)
        df["is_high_port"] = (df["destination.port"] > 1024).astype(int)

    if "network.bytes" in df.columns:
        df["large_transfer"] = (df["network.bytes"] > 1000000).astype(int)
        df["bytes_log"] = np.log1p(df["network.bytes"])

    df["event_count"] = 1
    df.to_csv("network_data_debug.csv", index=False)
    return df
############################################################################################
############################################################################################
def fetch_user_activity_data(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000):
    """
    Fetch user activity data with search_after pagination to bypass 10k limit.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["user"]
    index_pattern = group_config["endpoint"]

    # Use training configuration
    if time_range is None:
        try:
            time_range = get_configured_time_range("user")
            logger.info("Using configured training period for user data")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    # Required fields for user data
    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
    "user.name", "user.id", "process.name", "process.command_line",
        "process.executable", "process.args", "process.pid",
    "event.action", "event.type", "event.id", "agent.id", "host.ip"
    ]

    # Build query with Linux filtering
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    },
                    {
                        "term": {
                            "host.os.type": "linux"
                        }
                    }
                ],
                "filter": [
                    {
                        "exists": {
                            "field": "user.name"
                        }
                    }
                ]
            }
        },
        "_source": source_fields,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    }

    try:
        # ENHANCED: Use hourly stratified fetching
        logger.info(f"Fetching process data from {index_pattern} using hourly stratified sampling")

        # Determine distribution strategy based on query size
        if query_size >= 100000:  # Large datasets: balanced distribution
            strategy = "balanced"
        elif query_size >= 50000:   # Medium datasets: slight recent bias
            strategy = "recent_weighted"
        else:                       # Small datasets: standard approach
            strategy = "recent_weighted"

        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, strategy
        )

        logger.info(f"Retrieved {len(all_hits)} process records from Elasticsearch")

        if not all_hits:
            logger.warning("No process data found matching the criteria")
            return pd.DataFrame()

        # Process records (existing logic preserved)
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)

        # Timestamp processing (existing logic preserved)
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training time filters (existing logic preserved)
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Field validation (existing logic preserved)
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for process group: {missing_fields}")
            for field in missing_fields:
                if field in ["process.name", "process.executable", "user.name"]:
                    df[field] = "unknown"
                elif field in ["user.id", "process.args"]:
                    df[field] = 0
                else:
                    df[field] = ""

        # ENHANCED: Log temporal distribution analysis
        _log_temporal_distribution_analysis(df, "process")

        logger.info(f"Successfully processed {len(df)} Linux process records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching process data: {e}")
        return pd.DataFrame()
def fetch_discovery_commands_data(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000):
    """
    Fetch discovery commands data with search_after pagination to bypass 10k limit.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["discovery"]
    index_pattern = group_config["endpoint"]

    if time_range is None:
        try:
            time_range = get_configured_time_range("discovery")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    # Discovery command patterns
    discovery_commands = [
        "whoami", "id", "groups", "ps", "netstat", "ss", "lsof", "ifconfig", "ip",
        "route", "arp", "ping", "nslookup", "dig", "cat", "ls", "find", "locate",
        "which", "whereis", "uname", "uptime", "w", "who", "last", "history"
    ]

    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
    "process.name", "process.command_line", "process.args",
        "user.name", "user.id", "event.action", "event.type"
    ]

    # Build query with Linux filtering and discovery command filtering
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    },
                    {
                        "term": {
                            "host.os.type": "linux"
                        }
                    }
                ],
                "should": [
                    {
                        "terms": {
                            "process.name": discovery_commands
                        }
                    }
                ],
                "minimum_should_match": 1,
                "filter": [
                    {
                        "exists": {
                            "field": "process.command_line"
                        }
                    }
                ]
            }
        },
        "_source": source_fields,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    }

    try:
        # ENHANCED: Use hourly stratified fetching
        logger.info(f"Fetching process data from {index_pattern} using hourly stratified sampling")

        # Determine distribution strategy based on query size
        if query_size >= 100000:  # Large datasets: balanced distribution
            strategy = "balanced"
        elif query_size >= 50000:   # Medium datasets: slight recent bias
            strategy = "recent_weighted"
        else:
            strategy = "recent_weighted"

        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, strategy
        )

        logger.info(f"Retrieved {len(all_hits)} process records from Elasticsearch")

        if not all_hits:
            logger.warning("No process data found matching the criteria")
            return pd.DataFrame()

        # Process records (existing logic preserved)
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)
        df = validate_and_add_missing_fields(df, "process")

        # Timestamp processing (existing logic preserved)
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training time filters (existing logic preserved)
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Field validation (existing logic preserved)
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for process group: {missing_fields}")
            for field in missing_fields:
                if field in ["process.name", "process.executable", "user.name"]:
                    df[field] = "unknown"
                elif field in ["user.id", "process.args"]:
                    df[field] = 0
                else:
                    df[field] = ""

        # ENHANCED: Log temporal distribution analysis
        _log_temporal_distribution_analysis(df, "process")

        logger.info(f"Successfully processed {len(df)} Linux process records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching process data: {e}")
        return pd.DataFrame()
def fetch_metadata_access_data(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000):
    """
    Fetch metadata access data with search_after pagination to bypass 10k limit.
    Includes correct handling of IP (terms) and domain (wildcard) fields.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["metadata"]
    index_pattern = group_config["endpoint"]  # Uses network index

    # Time range fallback
    if time_range is None:
        try:
            time_range = get_configured_time_range("metadata")
        except Exception as e:
            logger.warning(f"Could not get configured time range: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {
                "gte": start_time.isoformat(),
                "lte": end_time.isoformat()
            }

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    # Metadata service IPs/domains
    metadata_ips = [
        "169.254.169.254",  # AWS/Azure/GCP
        "169.254.169.253"   # Azure alternate
    ]
    metadata_domains = [
        "metadata.google.internal",
        "metadata.azure.internal",
        "metadata.aws"
    ]

    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
    "destination.ip", "destination.port", "destination.domain",
    "host.ip",
        "process.name", "process.executable", "process.command_line",
        "user.name", "user.id", "network.transport",
    "event.action", "event.type", "event.id"
    ]

    # Build query with correct field types
    base_query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": time_range
                        }
                    },
                    {
                        "term": {
                            "host.os.type": "linux"
                        }
                    }
                ],
                "should": [
                    {   # IP filter (ip type → use terms)
                        "terms": {
                            "destination.ip": metadata_ips
                        }
                    },
                    {   # Domain filter (string type → use wildcard)
                        "wildcard": {
                            "destination.domain": "*metadata*"
                        }
                    },
                    {   # Optional explicit metadata domains
                        "terms": {
                            "destination.domain": metadata_domains
                        }
                    }
                ],
                "minimum_should_match": 1
            }
        },
        "_source": source_fields,
        "sort": [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]
    }

    try:
        logger.info(f"Fetching metadata access data from {index_pattern} with stratified sampling")

        # Strategy selection
        if query_size >= 100000:
            strategy = "balanced"
        elif query_size >= 50000:
            strategy = "recent_weighted"
        else:
            strategy = "recent_weighted"

        all_hits = _fetch_with_hourly_stratification(
            es, config, index_pattern, base_query, time_range, query_size, strategy
        )

        logger.info(f"Retrieved {len(all_hits)} metadata access records from Elasticsearch")

        if not all_hits:
            logger.warning("No metadata access events found")
            return pd.DataFrame()

        # Flatten results
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)
        df = validate_and_add_missing_fields(df, "process")

        # Timestamp processing
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training filters
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Fill missing required fields
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for process group: {missing_fields}")
            for field in missing_fields:
                if field in ["process.name", "process.executable", "user.name"]:
                    df[field] = "unknown"
                elif field in ["user.id", "process.args"]:
                    df[field] = 0
                else:
                    df[field] = ""

        # Log temporal distribution
        _log_temporal_distribution_analysis(df, "process")

        logger.info(f"Successfully processed {len(df)} metadata access records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching metadata access data: {e}")
        return pd.DataFrame()


def fetch_baseline_data(es: "Elasticsearch", config: dict, data_type: str="process", days_back: int=None):
    """
    Fetch baseline data for model training with enhanced configuration support.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    # Use training configuration if days_back not specified
    if days_back is None:
        training_config = get_training_configuration(data_type)
        days_back = training_config.get("training_period_days", 30)
        logger.info(f"Using configured training period: {days_back} days for {data_type}")

    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=days_back)
    time_range = {
        "gte": start_time.isoformat(),
        "lte": end_time.isoformat()
    }

    # Determine query size based on data type and training config
    training_config = get_training_configuration(data_type)
    base_size = 500000
    base_size = training_config.get("baseline_query_size", base_size)
    # print(f"This is the query size: {base_size}")

    # Adjust query size based on training period length
    period_days = training_config.get("training_period_days", 30)
    if period_days > 60:
        query_size = base_size * 2
    elif period_days < 7:
        query_size = base_size // 2
    else:
        query_size = base_size

    logger.info(f"Fetching baseline data for {data_type} with {period_days} day period, query_size={query_size}")

    if data_type == "process":
        return fetch_process_data(es, config, time_range, query_size)
    elif data_type == "network":
        return fetch_network_activity_data(es, config, time_range, query_size)
    elif data_type == "user":
        return fetch_user_activity_data(es, config, time_range, query_size)
    elif data_type == "discovery":
        return fetch_discovery_commands_data(es, config, time_range, query_size)
    elif data_type == "metadata":
        return fetch_metadata_access_data(es, config, time_range, query_size)
    elif data_type == "auth":
        return fetch_auth_data(es, config, time_range, query_size)
    elif data_type == "host":
        # Host group reuses process events; models partition by host.hostname
        return fetch_process_data(es, config, time_range, query_size)
    else:
        logger.error(f"Unknown data type for baseline: {data_type}")
        return pd.DataFrame()

SYSTEM_PATHS = {
    "system_binaries": [
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/usr/local/bin/", "/usr/local/sbin/"
    ],
    "user_paths": ["/home/", "~/", "/Users/"],
    "temp_paths": ["/tmp/", "/var/tmp/", "/dev/shm/"],
    "script_paths": ["/opt/", "/usr/share/", "/etc/init.d/", "/etc/systemd/"],
    "suspicious_paths": ["/var/www/", "/srv/", "/mnt/", "/media/", "/proc/self/", "/.hidden/"]
}

def ensure_process_fields(df: "pd.DataFrame"):
    """
    Ensure all critical fields exist in process data.
    """
    # Define all fields that models might expect
    required_fields = {
        # Process fields
        'process.pid': -1,
        'process.parent.pid': -1,
        'process.name': 'unknown',
        'process.executable': '',
        'process.command_line': '',
        'process.args': [],
        'process.working_directory': '',
        'process.hash.sha256': '',

        # User fields
        'user.name': 'unknown',
        # 'user.id': -1,
        'user.Ext.real.id': -1,

        # Group fields
        # 'group.id': -1,
        'group.name': 'unknown',
        'group.Ext.real.id': -1,

        # Host fields
        'host.hostname': 'unknown',
        'host.id': 'unknown',

        # Event fields
        'event.category': 'process',
        'event.type': 'start',
        'event.action': 'process_started',

        # Timestamp
        '@timestamp': pd.Timestamp.now(tz='UTC')
    }

    for field, default_value in required_fields.items():
        if field not in df.columns:
            df[field] = default_value
            logger.debug(f"Added missing field '{field}' with default value")

    return df

def preprocess_process_data(df: "pd.DataFrame"):
    """
    Enhanced preprocessing that ensures ALL features are calculated correctly.
    """
    if df.empty:
        return df

    logger.info(f"Preprocessing process data: {len(df)} records with {len(df.columns)} fields")

    # Ensure all required fields exist first
    df = ensure_process_fields(df)

    # Validate and fix field mappings
    df = validate_and_fix_field_mappings(df)

    # === COMMAND LINE ANALYSIS ===
    if "process.command_line" in df.columns:
        cmd_line = df["process.command_line"].fillna("")

        # Command length and word count
        df["command_length"] = cmd_line.str.len()
        df["command_word_count"] = cmd_line.str.split().apply(len)  # Fixed: use apply(len) instead of str.len()

        # Security indicators
        df["has_pipe"] = cmd_line.str.contains('|', regex=False, na=False).astype(int)
        df["has_redirection"] = cmd_line.str.contains('[<>]', regex=True, na=False).astype(int)
        df["has_backtick"] = cmd_line.str.contains('`', regex=False, na=False).astype(int)
        df["has_dollar_paren"] = cmd_line.str.contains(r'\$\(', regex=True, na=False).astype(int)
        df["has_semicolon"] = cmd_line.str.contains(';', regex=False, na=False).astype(int)
        df["has_ampersand"] = cmd_line.str.contains('&', regex=False, na=False).astype(int)
        df["has_suspicious_chars"] = (
            df["has_pipe"] | df["has_redirection"] | df["has_backtick"] |
            df["has_dollar_paren"] | df["has_semicolon"] | df["has_ampersand"]
        ).astype(int)

        # Command risk score
        df["command_risk_score"] = (
            df["has_pipe"] * 2 +
            df["has_redirection"] * 3 +
            df["has_backtick"] * 4 +
            df["has_dollar_paren"] * 4 +
            df["has_semicolon"] * 2 +
            df["has_ampersand"] * 2
        )
    else:
        # Ensure ALL command features exist with defaults
        df["command_length"] = 0
        df["command_word_count"] = 0
        df["has_pipe"] = 0
        df["has_redirection"] = 0
        df["has_backtick"] = 0
        df["has_dollar_paren"] = 0
        df["has_semicolon"] = 0
        df["has_ampersand"] = 0
        df["has_suspicious_chars"] = 0
        df["command_risk_score"] = 0

    # === PID RELATIONSHIP FEATURES ===
    # Ensure PID fields are numeric
    if "process.pid" in df.columns:
        df["process.pid"] = pd.to_numeric(df["process.pid"], errors='coerce').fillna(-1)
    else:
        df["process.pid"] = -1

    if "process.parent.pid" in df.columns:
        df["process.parent.pid"] = pd.to_numeric(df["process.parent.pid"], errors='coerce').fillna(-1)
    else:
        df["process.parent.pid"] = -1

    # Calculate PID difference
    df["pid_difference"] = df["process.pid"] - df["process.parent.pid"]
    df["unusual_pid_relationship"] = (df["pid_difference"] < 0).astype(int)

    # === PROCESS RELATIONSHIPS ===
    if "process.parent.name" in df.columns and "process.name" in df.columns:
        parent = df["process.parent.name"].fillna("")
        child = df["process.name"].fillna("")

        # Define suspicious parent-child relationships
        df["suspicious_parent"] = (
            # Web servers spawning shells
            ((parent.str.contains("apache|nginx|httpd", case=False, na=False)) &
             (child.str.contains("sh$|bash|cmd|nc|netcat", case=False, na=False))) |
            # Databases spawning shells
            ((parent.str.contains("mysql|postgres|mongo|oracle", case=False, na=False)) &
             (child.str.contains("sh$|bash|cmd", case=False, na=False))) |
            # System processes spawning network tools
            ((parent.isin(["systemd", "init"])) &
             (child.isin(["nc", "netcat", "nmap", "tcpdump", "wget", "curl"]))) |
            # Office applications spawning shells
            ((parent.str.contains("word|excel|powerpoint|acrobat", case=False, na=False)) &
             (child.str.contains("sh$|bash|cmd", case=False, na=False)))
        ).astype(int)
    else:
        df["suspicious_parent"] = 0

    # === PROCESS CATEGORIZATION ===
    if "process.name" in df.columns:
        proc_name = df["process.name"].fillna("")

        # All process categories needed by models
        df["is_sudo_command"] = (proc_name == "sudo").astype(int)
        df["is_su_command"] = (proc_name == "su").astype(int)
        df["is_compiler_activity"] = proc_name.isin([
            'gcc', 'g++', 'cc', 'make', 'cmake', 'clang', 'javac'
        ]).astype(int)
        df["is_dev_tool"] = proc_name.isin([
            'gdb', 'strace', 'ltrace', 'objdump', 'readelf', 'strings'
        ]).astype(int)
        df["is_network_tool"] = proc_name.isin([
            'nc', 'netcat', 'nmap', 'tcpdump', 'wireshark', 'curl', 'wget'
        ]).astype(int)

    # === PATH ANALYSIS ===
    if "process.executable" in df.columns:
        exe_path = df["process.executable"].fillna("")
        df["is_system_path"] = exe_path.str.contains(
            "/bin/|/sbin/|/usr/bin/|/usr/sbin/", na=False
        ).astype(int)
        df["is_temp_path"] = exe_path.str.contains(
            "/tmp/|/var/tmp/|/dev/shm/", na=False
        ).astype(int)
        df["is_home_path"] = exe_path.str.contains("/home/", na=False).astype(int)
    else:
        df["is_system_path"] = 0
        df["is_temp_path"] = 0
        df["is_home_path"] = 0

    # === USER CONTEXT ===
    if "user.name" in df.columns:
        df["is_root_user"] = (df["user.name"] == "root").astype(int)
        df["is_service_account"] = df["user.name"].str.match(
            r'^(www-data|nginx|apache|mysql|postgres|mongodb|redis|elasticsearch|nobody|daemon)$',
            na=False
        ).astype(int)
    else:
        df["is_root_user"] = 0
        df["is_service_account"] = 0

    # Hash verification
    df["has_hash"] = df["process.hash.sha256"].notna().astype(int)

    # Event count
    df["event_count"] = 1

    # Log feature creation
    feature_list = [
        "command_word_count", "pid_difference", "unusual_pid_relationship",
        "suspicious_parent", "has_dollar_paren", "has_semicolon", "has_ampersand"
    ]
    logger.info(f"Created critical features: {feature_list}")
    required_fields = {
        'is_sudo_command': 0,
        'is_su_command': 0,
        'is_compiler_activity': 0,
        'is_dev_tool': 0,
        'hour_of_day': 12,
        'is_business_hours': 1,
        'command_length': 0,
        'args_count': 0,
        'has_suspicious_chars': 0
    }

    for field, default_value in required_fields.items():
        if field not in df.columns:
            df[field] = default_value

    # GENERATE COMPUTED FIELDS if base data exists:
    if 'process.command_line' in df.columns:
        cmd_line = df['process.command_line'].fillna('').astype(str)

        # Update fields that were set to defaults
        if 'command_length' not in df.columns or df['command_length'].iloc[0] == 0:
            df['command_length'] = cmd_line.str.len()

        if 'args_count' not in df.columns or df['args_count'].iloc[0] == 0:
            df['args_count'] = cmd_line.str.split().str.len() - 1
            df['args_count'] = df['args_count'].clip(lower=0)

        if 'has_suspicious_chars' not in df.columns or df['has_suspicious_chars'].iloc[0] == 0:
            df['has_suspicious_chars'] = cmd_line.str.contains(r'[;&|`$<>()]', regex=True, na=False).astype(int)

        if 'is_sudo_command' not in df.columns or df['is_sudo_command'].iloc[0] == 0:
            df['is_sudo_command'] = cmd_line.str.startswith('sudo', na=False).astype(int)

        if 'is_su_command' not in df.columns or df['is_su_command'].iloc[0] == 0:
            df['is_su_command'] = cmd_line.str.startswith('su ', na=False).astype(int)

    # Generate temporal fields
    if 'hour_of_day' not in df.columns and '@timestamp' in df.columns:
        try:
            timestamps = pd.to_datetime(df['@timestamp'], errors='coerce')
            df['hour_of_day'] = timestamps.dt.hour.fillna(12)
        except:
            df['hour_of_day'] = 12

    if 'is_business_hours' not in df.columns and 'hour_of_day' in df.columns:
        hour = pd.to_numeric(df['hour_of_day'], errors='coerce').fillna(12)
        df['is_business_hours'] = ((hour >= 9) & (hour <= 17)).astype(int)
    return df



# def preprocess_network_data(df):
#     """
#     Enhanced network data preprocessing that preserves all fields.
#     """
#     if df.empty:
#         return df

#     logger.info(f"Preprocessing network data: {len(df)} records")

#     # Ensure network-specific fields exist
#     network_fields = {
#         'destination.ip': '0.0.0.0',
#         'destination.port': 0,
#         'source.ip': '0.0.0.0',
#         'source.port': 0,
#         'network.transport': 'unknown',
#         'network.direction': 'unknown',
#         'network.bytes': 0,
#         'network.packets': 0,
#         'destination.geo.country_name': 'unknown',
#         'event.action': 'network_flow',
#         'event.category': 'network',
#         'process.name': 'unknown',
#         'user.name': 'unknown',
#         'host.hostname': 'unknown'
#     }

#     for field, default in network_fields.items():
#         if field not in df.columns:
#             df[field] = default
#             logger.debug(f"Added missing network field '{field}'")

#     # Network-specific features
#     if "destination.port" in df.columns:
#         df["is_common_port"] = df["destination.port"].isin([80, 443, 22, 21, 25, 53, 110, 143]).astype(int)
#         df["is_high_port"] = (df["destination.port"] > 1024).astype(int)
#         df["is_privileged_port"] = (df["destination.port"] < 1024).astype(int)
#         df["is_ephemeral_port"] = ((df["destination.port"] >= 49152) & (df["destination.port"] <= 65535)).astype(int)

#     if "network.transport" in df.columns:
#         df["is_tcp"] = (df["network.transport"].str.lower() == "tcp").astype(int)
#         df["is_udp"] = (df["network.transport"].str.lower() == "udp").astype(int)
#         df["is_icmp"] = (df["network.transport"].str.lower() == "icmp").astype(int)

#     if "network.bytes" in df.columns:
#         df["large_transfer"] = (df["network.bytes"] > 1000000).astype(int)  # > 1MB
#         df["bytes_log"] = np.log1p(df["network.bytes"])

#     df["event_count"] = 1

#     return df

def preprocess_network_data(df: "pd.DataFrame"):
    """
    FIXED: Enhanced network data preprocessing that preserves real IP addresses.
    """
    if df.empty:
        return df

    logger.info(f"Preprocessing network data: {len(df)} records")

    # CRITICAL FIX: Only add defaults for truly missing fields, preserve existing IPs
    network_fields_safe = {
        'destination.port': 0,
        'source.port': 0,
        'network.transport': 'unknown',
        'network.direction': 'unknown',
        'network.bytes': 0,
        'network.packets': 0,
        'destination.geo.country_name': 'unknown',
        'event.action': 'network_flow',
        'event.category': 'network',
        'process.name': 'unknown',
        'user.name': 'unknown',
        'host.hostname': 'unknown'
    }

    # CRITICAL: Handle IP fields separately - only add if completely missing
    ip_fields_conditional = {
        'destination.ip': '0.0.0.0',
        'source.ip': '0.0.0.0'
    }

    # Add safe defaults (non-IP fields)
    for field, default in network_fields_safe.items():
        if field not in df.columns:
            df[field] = default
            logger.debug(f"Added missing network field '{field}'")

    # FIXED: Handle IP fields with validation
    for ip_field, default_ip in ip_fields_conditional.items():
        if ip_field not in df.columns:
            # Only add default if column is completely missing
            logger.warning(f"IP field '{ip_field}' completely missing - adding default")
            df[ip_field] = default_ip
        else:
            # Field exists - check for invalid values and warn
            invalid_ips = df[ip_field].isin(['0.0.0.0', '', 'unknown', None]) | df[ip_field].isna()
            invalid_count = invalid_ips.sum()

            if invalid_count > 0:
                logger.warning("NETWORK DATA QUALITY ISSUE:")
                logger.warning(f"  Field '{ip_field}' has {invalid_count} invalid/missing values")
                logger.warning(f"  Total records: {len(df)}")
                logger.warning(f"  Invalid percentage: {invalid_count/len(df)*100:.1f}%")

                # Show sample of what we're getting
                sample_invalid = df[invalid_ips][ip_field].value_counts()
                logger.warning(f"  Invalid values found: {dict(sample_invalid)}")

                # Option 1: Remove records with invalid IPs (RECOMMENDED)
                if invalid_count / len(df) < 0.5:  # Less than 50% invalid
                    logger.warning(f"  REMOVING {invalid_count} records with invalid {ip_field}")
                    df = df[~invalid_ips]
                else:
                    # Option 2: If too many invalid, investigate further
                    logger.error(f"  TOO MANY INVALID IPs ({invalid_count}/{len(df)}) - DATA PIPELINE ISSUE!")

                    # Try to salvage data by using alternative fields
                    if ip_field == 'destination.ip' and 'source.ip' in df.columns:
                        # Use source.ip as fallback for destination.ip
                        source_valid = ~df['source.ip'].isin(['0.0.0.0', '', 'unknown', None])
                        salvageable = invalid_ips & source_valid

                        if salvageable.any():
                            logger.warning(f"  SALVAGING: Using source.ip for {salvageable.sum()} records")
                            df.loc[salvageable, 'destination.ip'] = df.loc[salvageable, 'source.ip']

                            # Recalculate invalid after salvage
                            still_invalid = df[ip_field].isin(['0.0.0.0', '', 'unknown', None])
                            df = df[~still_invalid]
                            logger.warning(f"  After salvage: removed {still_invalid.sum()} still-invalid records")

    # Continue with feature engineering only if we have valid data
    if df.empty:
        logger.error("All records removed due to invalid IP addresses!")
        return df

    # Log final IP distribution
    for ip_field in ['destination.ip', 'source.ip']:
        if ip_field in df.columns:
            unique_ips = df[ip_field].unique()
            logger.info(f"Final {ip_field} distribution: {len(unique_ips)} unique IPs")
            if '0.0.0.0' in unique_ips:
                zero_count = (df[ip_field] == '0.0.0.0').sum()
                logger.warning(f"  WARNING: Still have {zero_count} records with '0.0.0.0'")

    # Network-specific features (existing code)
    if "destination.port" in df.columns:
        df["is_common_port"] = df["destination.port"].isin([80, 443, 22, 21, 25, 53, 110, 143]).astype(int)
        df["is_high_port"] = (df["destination.port"] > 1024).astype(int)
        df["is_privileged_port"] = (df["destination.port"] < 1024).astype(int)
        df["is_ephemeral_port"] = ((df["destination.port"] >= 49152) & (df["destination.port"] <= 65535)).astype(int)

    if "network.transport" in df.columns:
        df["is_tcp"] = (df["network.transport"].str.lower() == "tcp").astype(int)
        df["is_udp"] = (df["network.transport"].str.lower() == "udp").astype(int)
        df["is_icmp"] = (df["network.transport"].str.lower() == "icmp").astype(int)

    if "network.bytes" in df.columns:
        df["large_transfer"] = (df["network.bytes"] > 1000000).astype(int)
        df["bytes_log"] = np.log1p(df["network.bytes"])

    df["event_count"] = 1

    logger.info(f"Network preprocessing complete: {len(df)} records with valid IP addresses")
    return df
def preprocess_user_data(df: "pd.DataFrame"):
    """Enhanced user data preprocessing."""
    if df.empty:
        return df

    df = validate_and_fix_field_mappings(df)

    # Calculate user-specific features before aggregation
    if "process.command_line" in df.columns:
        df["command_length"] = df["process.command_line"].fillna("").str.len()
        df["has_suspicious_chars"] = df["process.command_line"].str.contains(
            r'[;&|`$<>]', regex=True, na=False
        ).astype(int)

    # Ensure required fields exist
    required_fields = [
        "is_sudo_command", "is_su_command", "is_compiler_activity",
        "is_dev_tool", "hour_of_day", "is_business_hours"
    ]

    for field in required_fields:
        if field not in df.columns:
            if field.startswith("is_"):
                df[field] = 0
            elif field == "hour_of_day":
                df[field] = 12  # Default noon

    df["event_count"] = 1
    return df

def preprocess_discovery_data(df: "pd.DataFrame"):
    """
    Enhanced discovery data preprocessing with complete feature extraction.
    FIXES: All missing discovery fields identified in logs.
    """
    if df.empty:
        return df

    logger.info(f"Enhanced preprocessing discovery data: {len(df)} records")

    # === BASIC FIELD VALIDATION ===
    base_fields = {
        "process.name": "unknown",
        "process.command_line": "",
        "user.name": "unknown",
        "host.hostname": "unknown",
        "@timestamp": pd.Timestamp.now(tz='UTC'),
        "event.category": "process"
    }

    for field, default_value in base_fields.items():
        if field not in df.columns:
            df[field] = default_value

    # === COMMAND ANALYSIS ===
    if "process.command_line" in df.columns:
        cmd_line = df["process.command_line"].fillna("").astype(str)

        # Command complexity analysis
        df["has_pipes"] = cmd_line.str.contains(r'\|', na=False).astype(int)
        df["has_redirection"] = cmd_line.str.contains(r'[<>]', na=False).astype(int)
        df["command_length"] = cmd_line.str.len()

        # Arguments count
        df["args_count"] = cmd_line.str.split().str.len() - 1
        df["args_count"] = df["args_count"].clip(lower=0)

    else:
        df["has_pipes"] = 0
        df["has_redirection"] = 0
        df["command_length"] = 0
        df["args_count"] = 0

    # === DISCOVERY CATEGORIZATION ===
    discovery_categories = {
        "network": ["netstat", "ss", "ifconfig", "ip", "route", "arp", "ping", "nslookup", "dig"],
        "process": ["ps", "pstree", "top", "htop"],
        "user": ["whoami", "id", "groups", "w", "who", "last"],
        "system": ["uname", "uptime", "df", "mount", "lsblk"],
        "other": []
    }

    def categorize_discovery(process_name: str):
        """Categorize a process name into discovery type."""
        for category, commands in discovery_categories.items():
            if process_name in commands:
                return category
        return "other"

    if "process.name" in df.columns:
        process_name = df["process.name"].fillna("").astype(str)
        df["discovery_category"] = process_name.apply(categorize_discovery)

        # Granular discovery categorization for ML
        network_recon = ['netstat', 'ss', 'lsof', 'nmap', 'masscan']
        df["is_network_recon"] = process_name.str.lower().isin(network_recon).astype(int)

        system_recon = ['ps', 'top', 'htop', 'pstree', 'systemctl', 'service']
        df["is_system_recon"] = process_name.str.lower().isin(system_recon).astype(int)

        user_recon = ['whoami', 'id', 'groups', 'w', 'who', 'last', 'lastlog']
        df["is_user_recon"] = process_name.str.lower().isin(user_recon).astype(int)

        file_recon = ['find', 'locate', 'ls', 'cat', 'head', 'tail', 'grep']
        df["is_file_recon"] = process_name.str.lower().isin(file_recon).astype(int)
    else:
        df["discovery_category"] = "other"
        df["is_network_recon"] = 0
        df["is_system_recon"] = 0
        df["is_user_recon"] = 0
        df["is_file_recon"] = 0

    # === USER CONTEXT ANALYSIS ===
    if "user.name" in df.columns:
        user_name = df["user.name"].fillna("").astype(str)

        # Discovery by user type
        df["is_root_discovery"] = (user_name == "root").astype(int)
        df["is_regular_user_discovery"] = ((user_name != "root") & (user_name != "")).astype(int)
    else:
        df["is_root_discovery"] = 0
        df["is_regular_user_discovery"] = 1

    # === ENSURE ALL REQUIRED FIELDS ===
    required_fields = [
        "discovery_category", "has_pipes", "has_redirection", "command_length",
        "args_count", "is_root_discovery", "is_regular_user_discovery"
    ]

    for field in required_fields:
        if field not in df.columns:
            if "is_" in field:
                df[field] = 0
            else:
                df[field] = ""

    df["event_count"] = 1

    # Ensure proper data types
    numeric_fields = ["command_length", "args_count", "event_count"]
    for field in numeric_fields:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors='coerce').fillna(0)

    binary_fields = [
        "has_pipes", "has_redirection", "is_root_discovery", "is_regular_user_discovery",
        "is_network_recon", "is_system_recon", "is_user_recon", "is_file_recon"
    ]
    for field in binary_fields:
        if field in df.columns:
            df[field] = df[field].astype(int)

    logger.info(f"Enhanced discovery preprocessing completed: {len(df)} records with {len(df.columns)} fields")
    logger.info(f"Generated all required fields: {required_fields}")

    return df

def preprocess_metadata_data(df: "pd.DataFrame"):
    """
    Preprocess metadata data with enhanced training configuration support.
    """
    if df.empty:
        return df

    group_config = DATA_GROUP_CONFIG["metadata"]

    # Validate required fields exist
    missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
    if missing_fields:
        logger.warning(f"Missing metadata fields: {missing_fields}")
        for field in missing_fields:
            if "port" in field:
                df[field] = 0
            elif "is_" in field:
                df[field] = 0
            else:
                df[field] = ""

    # Ensure proper data types
    if "destination.port" in df.columns:
        df["destination.port"] = pd.to_numeric(df["destination.port"], errors='coerce').fillna(0)

    df["event_count"] = 1

    logger.info(f"Preprocessed metadata data: {len(df)} records with {len(df.columns)} fields")
    return df


def validate_and_fix_field_mappings(df: "pd.DataFrame"):
    """
    Validate and fix field mappings from flattened Elasticsearch documents.
    """
    if df.empty:
        return df

    # Common field mappings from flattened names to expected names
    field_mappings = {
        'process.name': ['process.name', 'process_name'],
        'process.executable': ['process.executable', 'process_executable'],
        'process.command_line': ['process.command_line', 'process_command_line'],
        'process.args': ['process.args', 'process_args'],
        'process.pid': ['process.pid', 'process_pid'],
        'process.working_directory': ['process.working_directory', 'process_working_directory'],
        'process.parent.name': ['process.parent.name', 'process_parent_name'],
        'process.parent.executable': ['process.parent.executable', 'process_parent_executable'],
        'user.name': ['user.name', 'user_name'],
        # 'user.id': ['user.id', 'user_id'],
        'host.hostname': ['host.hostname', 'host_hostname'],
        'host.id': ['host.id', 'host_id'],
        'network.transport': ['network.transport', 'network_transport'],
        'network.direction': ['network.direction', 'network_direction'],
        'network.type': ['network.type', 'network_type'],
        'source.ip': ['source.ip', 'source_ip'],
        'source.port': ['source.port', 'source_port'],
        'destination.ip': ['destination.ip', 'destination_ip'],
        'destination.port': ['destination.port', 'destination_port'],
        'source.bytes': ['source.bytes', 'source_bytes'],
        'destination.bytes': ['destination.bytes', 'destination_bytes'],
        'event.action': ['event.action', 'event_action'],
        'event.type': ['event.type', 'event_type'],
        'process.hash.sha256': ['process.hash.sha256', 'process_hash_sha256']
    }

    # Apply field mappings
    for expected_field, possible_fields in field_mappings.items():
        if expected_field not in df.columns:
            for alt_field in possible_fields:
                if alt_field in df.columns:
                    df[expected_field] = df[alt_field]
                    logger.debug(f"Mapped {alt_field} -> {expected_field}")
                    break

    return df

def aggregate_data_by_group(df: "pd.DataFrame", group_columns: list, agg_columns: list | None):
    """
    Enhanced aggregation that preserves ALL features needed by ML models.
    """
    if df.empty:
        return df

    # Ensure group columns exist
    group_columns = [col for col in group_columns if col in df.columns]
    if not group_columns:
        logger.error("No valid grouping columns")
        return df

    logger.info(f"Aggregating {len(df)} records by {group_columns}")

    # === COMPREHENSIVE AGGREGATION DICTIONARY ===
    agg_dict = {}

    # Command features - ALL must be preserved
    command_features = {
        'command_length': ['mean', 'max', 'std'],
        'command_word_count': ['mean', 'max', 'std'],  # This was missing!
        'has_pipe': 'max',
        'has_redirection': 'max',
        'has_backtick': 'max',
        'has_dollar_paren': 'max',
        'has_semicolon': 'max',
        'has_ampersand': 'max',
        'has_suspicious_chars': 'max',
        'command_risk_score': ['max', 'mean', 'std']
    }

    # PID features - Critical for relationships
    pid_features = {
        'process.pid': lambda x: list(x.unique())[:10],
        'process.parent.pid': lambda x: list(x.unique())[:10],
        'pid_difference': ['mean', 'min', 'max', 'std'],  # This was missing!
        'unusual_pid_relationship': ['sum', 'max']         # This was missing!
    }

    # Process relationship features
    relationship_features = {
        'suspicious_parent': ['max', 'sum']  # This was missing in some cases!
    }

    # Process categorization
    process_features = {
        'args_count': ['mean', 'max'],
        'is_sudo_command': 'sum',
        'is_su_command': 'sum',
        'is_compiler_activity': 'sum',
        'is_dev_tool': 'sum',
        'is_network_tool': 'sum',
        'has_hash': ['mean', 'min'],
        'is_system_path': 'mean',
        'is_temp_path': 'max',
        'is_home_path': 'mean'
    }

    # User features
    user_features = {
        'is_root_user': 'max',
        'is_service_account': 'max',
        # 'user.id': lambda x: list(x.unique()),
        # 'group.id': lambda x: list(x.unique())
    }

    # Temporal features
    temporal_features = {
        'hour_sin': 'mean',
        'hour_cos': 'mean',
        'day_sin': 'mean',
        'day_cos': 'mean',
        'is_weekend': 'max',
        'is_business_hours': 'mean',
        'is_night_time': 'max'
    }

    # Event metadata
    event_features = {
        'event_count': 'sum',
        'event.category': lambda x: x.mode()[0] if len(x) > 0 else 'process'
    }

    # Data preservation
    preservation_features = {
        'process.command_line': lambda x: list(x.unique())[:20],
        'process.executable': lambda x: list(x.unique()),
        'process.parent.name': lambda x: list(x.unique()),
        'process.hash.sha256': lambda x: list(x.unique())[:10]
    }

    # Combine all features
    all_feature_dicts = [
        command_features, pid_features, relationship_features,
        process_features, user_features, temporal_features,
        event_features, preservation_features
    ]

    for feature_dict in all_feature_dicts:
        for col, agg_func in feature_dict.items():
            if col in df.columns:
                agg_dict[col] = agg_func

    # Add remaining numeric columns
    for col in agg_columns:
        if col in df.columns and col not in agg_dict:
            if pd.api.types.is_numeric_dtype(df[col]):
                agg_dict[col] = ['mean', 'sum', 'count']

    try:
        # Perform aggregation
        logger.info(f"Aggregating {len(agg_dict)} features")
        aggregated = df.groupby(group_columns).agg(agg_dict).reset_index()

        # Flatten column names
        new_columns = []
        for col in aggregated.columns:
            if isinstance(col, tuple):
                if col[1] == '<lambda>':
                    new_columns.append(f"{col[0]}_list")
                elif col[1]:
                    new_columns.append(f"{col[0]}_{col[1]}")
                else:
                    new_columns.append(col[0])
            else:
                new_columns.append(col)

        aggregated.columns = new_columns

        # === POST-AGGREGATION FEATURE RECOVERY ===

        # Ensure single-value versions exist for ML models
        feature_recovery_mappings = {
            # Command features
            'command_length': 'command_length_mean',
            'command_word_count': 'command_word_count_mean',

            # PID features
            'pid_difference': 'pid_difference_mean',
            'unusual_pid_relationship': 'unusual_pid_relationship_max',

            # Relationship features
            'suspicious_parent': 'suspicious_parent_max',

            # Temporal features
            'hour_sin': 'hour_sin_mean',
            'hour_cos': 'hour_cos_mean',
            'day_sin': 'day_sin_mean',
            'day_cos': 'day_cos_mean'
        }

        for target, source in feature_recovery_mappings.items():
            if target not in aggregated.columns and source in aggregated.columns:
                aggregated[target] = aggregated[source]
                logger.debug(f"Recovered feature {target} from {source}")

        # Ensure binary features exist
        binary_features = [
            'has_pipe', 'has_redirection', 'has_backtick',
            'has_dollar_paren', 'has_semicolon', 'has_ampersand',
            'has_suspicious_chars', 'is_root_user', 'is_service_account'
        ]

        for feat in binary_features:
            if feat not in aggregated.columns and f"{feat}_max" in aggregated.columns:
                aggregated[feat] = aggregated[f"{feat}_max"]

        # Extract PIDs from lists
        if 'process.pid_list' in aggregated.columns:
            aggregated['process.pid'] = aggregated['process.pid_list'].apply(
                lambda x: x[0] if isinstance(x, list) and len(x) > 0 else -1
            )

        if 'process.parent.pid_list' in aggregated.columns:
            aggregated['process.parent.pid'] = aggregated['process.parent.pid_list'].apply(
                lambda x: x[0] if isinstance(x, list) and len(x) > 0 else -1
            )

        logger.info(f"Aggregated into {len(aggregated)} groups with {len(aggregated.columns)} features")

        return aggregated

    except Exception as e:
        logger.error(f"Error in data aggregation: {e}")
        return df


# def create_time_buckets(df, time_column="@timestamp", bucket_size="15min"):
#     """
#     Enhanced time bucketing that creates all temporal features needed by models.
#     """
#     if df.empty or time_column not in df.columns:
#         logger.warning(f"Cannot create time buckets: empty data or missing {time_column}")
#         return df

#     try:
#         # Ensure timestamp is datetime
#         df[time_column] = pd.to_datetime(df[time_column], errors='coerce', utc=True)

#         # Convert bucket size
#         if bucket_size.endswith('m'):
#             pandas_freq = f"{bucket_size[:-1]}min"
#         elif bucket_size.endswith('h'):
#             pandas_freq = f"{bucket_size[:-1]}H"
#         else:
#             pandas_freq = "15min"

#         # Create time bucket
#         df["time_bucket"] = df[time_column].dt.floor(pandas_freq)

#         # === CREATE ALL TEMPORAL FEATURES ===

#         # Basic temporal features
#         df["hour_of_day"] = df[time_column].dt.hour
#         df["minute_of_hour"] = df[time_column].dt.minute
#         df["day_of_week"] = df[time_column].dt.dayofweek
#         df["day_of_month"] = df[time_column].dt.day
#         df["month"] = df[time_column].dt.month

#         # Circular encoding - THESE ARE EXPECTED BY MODELS
#         df["hour_sin"] = np.sin(2 * np.pi * df["hour_of_day"] / 24)
#         df["hour_cos"] = np.cos(2 * np.pi * df["hour_of_day"] / 24)
#         df["day_sin"] = np.sin(2 * np.pi * df["day_of_week"] / 7)
#         df["day_cos"] = np.cos(2 * np.pi * df["day_of_week"] / 7)
#         df["month_sin"] = np.sin(2 * np.pi * df["month"] / 12)
#         df["month_cos"] = np.cos(2 * np.pi * df["month"] / 12)

#         # Business context
#         df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
#         df["is_business_hours"] = (
#             (df["hour_of_day"] >= 8) &
#             (df["hour_of_day"] < 18) &
#             (df["day_of_week"] < 5)
#         ).astype(int)
#         df["is_night_time"] = (
#             (df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)
#         ).astype(int)

#         # Sequence detection
#         df = df.sort_values([time_column])

#         # Group by entity for sequence detection
#         entity_cols = ["process.name", "user.name", "host.hostname"]
#         existing_entity_cols = [col for col in entity_cols if col in df.columns]

#         if existing_entity_cols:
#             # Time since previous event for same entity
#             df["prev_timestamp"] = df.groupby(existing_entity_cols)[time_column].shift(1)
#             df["seconds_since_prev"] = (
#                 df[time_column] - df["prev_timestamp"]
#             ).dt.total_seconds().fillna(999999)
#             df["is_rapid_sequence"] = (df["seconds_since_prev"] < 5).astype(int)
#             df["is_burst_activity"] = (df["seconds_since_prev"] < 1).astype(int)

#         # Events per bucket (for anomaly detection)
#         df["events_in_bucket"] = df.groupby("time_bucket")[time_column].transform('count')
#         df["events_in_bucket_by_entity"] = df.groupby(
#             ["time_bucket"] + existing_entity_cols
#         )[time_column].transform('count') if existing_entity_cols else 1

#         # Log temporal feature creation
#         temporal_features = [
#             'hour_sin', 'hour_cos', 'day_sin', 'day_cos', 'month_sin', 'month_cos',
#             'is_weekend', 'is_business_hours', 'is_night_time', 'is_rapid_sequence'
#         ]
#         logger.info(f"Created {len(temporal_features)} temporal features")

#         unique_buckets = df["time_bucket"].nunique()
#         logger.info(f"Created time buckets with {bucket_size} intervals: {len(df)} records, {unique_buckets} unique buckets")

#         return df

#     except Exception as e:
#         logger.error(f"Error creating time buckets: {e}")
#         return df
def create_time_buckets(df: "pd.DataFrame", time_column: str="@timestamp", bucket_size: str="15min", min_buckets: int=10):
    """
    Enhanced time bucketing that dynamically adjusts bucket size based on data characteristics.
    Ensures sufficient temporal granularity for anomaly detection.

    Args:
        df: DataFrame with timestamp data
        time_column: Name of timestamp column
        bucket_size: Initial bucket size (can be adjusted)
        min_buckets: Minimum number of buckets to create (default 10)
    """
    if df.empty or time_column not in df.columns:
        logger.warning(f"Cannot create time buckets: empty data or missing {time_column}")
        return df

    try:
        # Ensure timestamp is datetime
        df[time_column] = pd.to_datetime(df[time_column], errors='coerce', utc=True)
        df = df.dropna(subset=[time_column])

        if df.empty:
            logger.warning("No valid timestamps found after parsing")
            return df

        # Calculate time span
        time_min = df[time_column].min()
        time_max = df[time_column].max()
        time_span = time_max - time_min
        time_span_seconds = time_span.total_seconds()
        time_span_hours = time_span_seconds / 3600
        record_count = len(df)

        logger.info(f"Data time span: {time_span_hours:.2f} hours ({record_count} records)")
        # logger.info("coluumns in data frame", df.columns)

        # Convert bucket_size to pandas frequency if needed
        if bucket_size.endswith('m') and not bucket_size.endswith('min'):
            bucket_size = f"{bucket_size[:-1]}min"
        elif bucket_size.endswith('s') and len(bucket_size) > 1:
            bucket_size = bucket_size.upper()  # Convert 's' to 'S'
        elif bucket_size.endswith('h'):
            bucket_size = bucket_size.upper()  # Convert 'h' to 'H'

        # Use the provided bucket size directly
        selected_bucket = bucket_size
        logger.info(f"Using bucket size: {selected_bucket}")

        # Create time buckets
        df["time_bucket"] = df[time_column].dt.floor(selected_bucket)
        unique_buckets = df["time_bucket"].nunique()
        logger.info(f"Created {unique_buckets} time buckets")
        # logger.info(f"columns after time bucketing: {df.columns}")

        # === CREATE COMPREHENSIVE TEMPORAL FEATURES ===

        # Basic temporal features
        df["hour_of_day"] = df[time_column].dt.hour
        df["minute_of_hour"] = df[time_column].dt.minute
        df["second_of_minute"] = df[time_column].dt.second
        df["day_of_week"] = df[time_column].dt.dayofweek
        df["day_of_month"] = df[time_column].dt.day
        df["month"] = df[time_column].dt.month

        # Circular encoding for cyclical features
        df["hour_sin"] = np.sin(2 * np.pi * df["hour_of_day"] / 24)
        df["hour_cos"] = np.cos(2 * np.pi * df["hour_of_day"] / 24)
        df["minute_sin"] = np.sin(2 * np.pi * df["minute_of_hour"] / 60)
        df["minute_cos"] = np.cos(2 * np.pi * df["minute_of_hour"] / 60)
        df["day_sin"] = np.sin(2 * np.pi * df["day_of_week"] / 7)
        df["day_cos"] = np.cos(2 * np.pi * df["day_of_week"] / 7)
        df["month_sin"] = np.sin(2 * np.pi * df["month"] / 12)
        df["month_cos"] = np.cos(2 * np.pi * df["month"] / 12)

        # Business context features
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        df["is_business_hours"] = (
            (df["hour_of_day"] >= 8) &
            (df["hour_of_day"] < 18) &
            (df["day_of_week"] < 5)
        ).astype(int)
        df["is_night_time"] = (
            (df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)
        ).astype(int)

        # Time-based sequence features
        df = df.sort_values([time_column])

        # Calculate time deltas
        if time_span_seconds > 0:
            df["time_since_start"] = (df[time_column] - time_min).dt.total_seconds()
            df["time_until_end"] = (time_max - df[time_column]).dt.total_seconds()
            df["relative_time_position"] = df["time_since_start"] / time_span_seconds
        else:
            df["time_since_start"] = 0
            df["time_until_end"] = 0
            df["relative_time_position"] = 0

        # Group by entity for sequence detection
        entity_cols = ["process.name", "user.name", "host.hostname", "destination.ip", "source.ip"]
        existing_entity_cols = [col for col in entity_cols if col in df.columns and df[col].notna().any()]

        if existing_entity_cols:
            # For efficiency, only use the first available entity column
            main_entity_col = existing_entity_cols[0]
            df["prev_timestamp"] = df.groupby(main_entity_col)[time_column].shift(1)
            df["seconds_since_prev"] = (
                df[time_column] - df["prev_timestamp"]
            ).dt.total_seconds().fillna(999999)
            df["is_rapid_sequence"] = (df["seconds_since_prev"] < 5).astype(int)
            df["is_burst_activity"] = (df["seconds_since_prev"] < 1).astype(int)

        # Aggregate features per bucket
        df["events_in_bucket"] = df.groupby("time_bucket")[time_column].transform('count')
        df["bucket_event_density"] = df["events_in_bucket"] / max(record_count, 1)

        # Add percentile-based features
        df['time_percentile'] = df[time_column].rank(pct=True)

        # Log results
        temporal_features = [
            'hour_sin', 'hour_cos', 'minute_sin', 'minute_cos', 'day_sin', 'day_cos',
            'month_sin', 'month_cos', 'is_weekend', 'is_business_hours', 'is_night_time',
            'relative_time_position', 'time_percentile'
        ]

        logger.info(f"Created {len(temporal_features)} temporal features")

        return df

    except Exception as e:
        logger.error(f"Error creating time buckets: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return df


def validate_temporal_coverage(df: "pd.DataFrame", entity_col: str, min_buckets: int=3):
    """
    Validate if an entity has sufficient temporal coverage for anomaly detection.
    """
    if 'time_bucket' not in df.columns:
        return False

    entity_buckets = df[df[entity_col].notna()].groupby(entity_col)['time_bucket'].nunique()
    entities_with_coverage = entity_buckets[entity_buckets >= min_buckets]

    if len(entities_with_coverage) == 0:
        logger.warning(f"No entities have minimum temporal coverage ({min_buckets} buckets)")
        return False

    logger.info(f"{len(entities_with_coverage)} entities have sufficient temporal coverage")
    return True
import os


def save_dataframe_to_files(df: "pd.DataFrame", base_filename: str, save_json: bool=True, save_excel: bool=True):
    """
    Save a DataFrame to JSON and/or Excel files in the current directory.

    Args:
        df (pd.DataFrame): DataFrame to save
        base_filename (str): Base filename to use
        save_json (bool): Whether to save to JSON
        save_excel (bool): Whether to save to Excel

    Returns:
        dict: Paths to the saved files
    """
    if df.empty:
        logger.warning(f"No data to save for {base_filename}")
        return {}

    # Create filenames
    current_dir = os.getcwd()
    json_path = os.path.join(current_dir, f"{base_filename}.json")
    excel_path = os.path.join(current_dir, f"{base_filename}.xlsx")
    saved_files = {}

    try:
        # Save to JSON
        if save_json:
            # Convert DataFrame to JSON, handling complex objects
            df_json = df.copy()

            # Convert lists and other complex objects to strings
            for col in df_json.columns:
                if df_json[col].apply(lambda x: isinstance(x, (list, dict))).any():
                    df_json[col] = df_json[col].apply(lambda x: str(x) if isinstance(x, (list, dict)) else x)

            # Convert timestamp columns to strings for better JSON serialization
            for col in df_json.columns:
                if pd.api.types.is_datetime64_any_dtype(df_json[col]):
                    df_json[col] = df_json[col].astype(str)

            # Save to JSON
            df_json.to_json(json_path, orient="records", date_format="iso")
            logger.info(f"Saved JSON data to {json_path}")
            saved_files["json"] = json_path

        # Save to Excel
        if save_excel:
            try:
                with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
                    # For Excel, limit columns if there are too many (Excel has a limit)
                    if len(df.columns) > 16000:
                        logger.warning(f"Too many columns ({len(df.columns)}) for Excel, truncating to 16000")
                        df_excel = df.iloc[:, :16000]
                    else:
                        df_excel = df

                    # Convert timestamp columns to string to avoid Excel date issues
                    for col in df_excel.columns:
                        if pd.api.types.is_datetime64_any_dtype(df_excel[col]):
                            df_excel[col] = df_excel[col].astype(str)

                    # Convert complex objects to strings
                    for col in df_excel.columns:
                        if df_excel[col].apply(lambda x: isinstance(x, (list, dict))).any():
                            df_excel[col] = df_excel[col].apply(lambda x: str(x) if isinstance(x, (list, dict)) else x)

                    df_excel.to_excel(writer, sheet_name="Data", index=False)

                logger.info(f"Saved Excel data to {excel_path}")
                saved_files["excel"] = excel_path
            except Exception as excel_err:
                logger.error(f"Error saving Excel file: {excel_err}")
                # Try CSV as a fallback
                csv_path = os.path.join(current_dir, f"{base_filename}.csv")
                df.to_csv(csv_path, index=False)
                logger.info(f"Saved CSV data to {csv_path} (Excel failed)")
                saved_files["csv"] = csv_path

        return saved_files

    except Exception as e:
        logger.error(f"Error saving data to files: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {}


def fetch_process_data_with_save(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000,
                                save: bool=False, base_filename: str="process_data"):
    """
    Fetch process data and optionally save it to files.

    Args:
        es: Elasticsearch client
        config: Configuration dictionary
        time_range: Time range for query
        query_size: Number of records to fetch
        save (bool): Whether to save the data to files
        base_filename (str): Base filename for saved files

    Returns:
        pd.DataFrame: Process data DataFrame
    """
    # Use the original fetch function
    # from linux_data_manager import fetch_process_data
    df = fetch_process_data(es, config, time_range, query_size)

    # Save if requested
    if save and not df.empty:
        save_dataframe_to_files(df, base_filename)

    return df


# ---------------------------------------------------------------------------
# Auth data group — fetch and preprocess
# ---------------------------------------------------------------------------

_AUTH_PATTERNS = {
    'failed_password': re.compile(
        r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)',
        re.IGNORECASE,
    ),
    'accepted_password': re.compile(
        r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)',
        re.IGNORECASE,
    ),
    'session_opened': re.compile(
        r'session opened for user (\S+?)[\s(]',
        re.IGNORECASE,
    ),
    'session_closed': re.compile(
        r'session closed for user (\S+)',
        re.IGNORECASE,
    ),
    'sudo': re.compile(
        r'(\S+)\s*:\s*.*COMMAND=(.*)',
        re.IGNORECASE,
    ),
    'invalid_user': re.compile(
        r'Invalid user (\S+) from (\S+)',
        re.IGNORECASE,
    ),
}


def _parse_auth_message(message: str) -> dict:
    """Parse a syslog auth message into structured ECS-like fields."""
    result: dict[str, Any] = {
        'user.name': '',
        'source.ip': '',
        'source.port': 0,
        'event.action': 'unknown',
        'event.outcome': 'unknown',
        'process.name': '',
    }
    if not message:
        return result

    msg = str(message)

    proc_match = re.search(
        r'\b(sshd|sudo|su|login|CRON|systemd-logind|gdm|lightdm)\b',
        msg, re.IGNORECASE,
    )
    if proc_match:
        result['process.name'] = proc_match.group(1).lower()

    m = _AUTH_PATTERNS['failed_password'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['source.ip'] = m.group(2)
        result['source.port'] = int(m.group(3))
        result['event.action'] = 'failed_login'
        result['event.outcome'] = 'failure'
        return result

    m = _AUTH_PATTERNS['accepted_password'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['source.ip'] = m.group(2)
        result['source.port'] = int(m.group(3))
        result['event.action'] = 'accepted_login'
        result['event.outcome'] = 'success'
        return result

    m = _AUTH_PATTERNS['invalid_user'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['source.ip'] = m.group(2)
        result['event.action'] = 'invalid_user'
        result['event.outcome'] = 'failure'
        return result

    m = _AUTH_PATTERNS['session_opened'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['event.action'] = 'session_opened'
        result['event.outcome'] = 'success'
        return result

    m = _AUTH_PATTERNS['session_closed'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['event.action'] = 'session_closed'
        result['event.outcome'] = 'success'
        return result

    m = _AUTH_PATTERNS['sudo'].search(msg)
    if m:
        result['user.name'] = m.group(1)
        result['event.action'] = 'sudo_command'
        result['event.outcome'] = 'success'
        result['process.name'] = 'sudo'
        return result

    return result


def fetch_auth_data(es: "Elasticsearch", config: dict, time_range: dict | None = None, query_size: int = 10000) -> "pd.DataFrame":
    """Fetch authentication data from .ds-logs-system.auth-default-*.

    Parses raw syslog messages into structured ECS-like fields
    (user.name, source.ip, event.action, event.outcome).
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["auth"]
    index_pattern = group_config["endpoint"]

    if time_range is None:
        try:
            time_range = get_configured_time_range("auth")
            logger.info("Using configured training period for auth data")
        except Exception as e:
            logger.warning(f"Could not get configured time range for auth: {e}")
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=1)
            time_range = {"gte": start_time.isoformat(), "lte": end_time.isoformat()}

    try:
        query_size = int(query_size)
    except (TypeError, ValueError):
        query_size = 10000

    source_fields = [
        "@timestamp", "host.hostname", "host.name", "host.id",
        "host.os.type", "host.os.name", "host.os.platform",
        "message", "event.original",
        "log.syslog.appname", "log.syslog.hostname", "log.syslog.procid",
        "user.name", "source.ip", "source.port",
        "event.action", "event.outcome", "event.dataset",
        "agent.id", "agent.type", "agent.name",
    ]

    query = {
        "size": min(10000, query_size),
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": time_range}},
                ],
                "should": [
                    {"match_phrase": {"message": "Failed password"}},
                    {"match_phrase": {"message": "Accepted"}},
                    {"match_phrase": {"message": "Invalid user"}},
                    {"match_phrase": {"message": "sudo"}},
                    {"match_phrase": {"message": "session opened"}},
                    {"match_phrase": {"message": "session closed"}},
                    {"match_phrase": {"message": "sshd"}},
                ],
                "minimum_should_match": 1,
                "must_not": [
                    {"match_phrase": {"message": "CRON"}},
                ],
            }
        },
        "_source": source_fields,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }

    try:
        logger.info(f"Fetching auth data from {index_pattern} using search_after")
        all_hits: list[dict] = []
        search_after_val = None

        while len(all_hits) < query_size:
            if search_after_val:
                query["search_after"] = search_after_val
            response = es.search(index=index_pattern, body=query)
            hits = response["hits"]["hits"]
            if not hits:
                break
            all_hits.extend(hits)
            search_after_val = hits[-1]["sort"]
            if len(hits) < query["size"]:
                break

        logger.info(f"Retrieved {len(all_hits)} auth records from Elasticsearch")
        if not all_hits:
            logger.warning("No auth data found matching the criteria")
            return pd.DataFrame()

        records = []
        for hit in all_hits:
            source = hit["_source"]
            flat = _flatten_elasticsearch_document(source)
            parsed = _parse_auth_message(flat.get("message", ""))
            for key, val in parsed.items():
                if key not in flat or not flat[key]:
                    flat[key] = val
            if not flat.get("host.name"):
                flat["host.name"] = flat.get("host.hostname", flat.get("agent.name", ""))
            records.append(flat)

        df = pd.DataFrame(records)

        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors="coerce", utc=True)

        if "@timestamp" in df.columns and df["@timestamp"].notna().any():
            df["hour_of_day"] = df["@timestamp"].dt.hour
            df["day_of_week"] = df["@timestamp"].dt.dayofweek
        else:
            df["hour_of_day"] = 0
            df["day_of_week"] = 0
        df["is_business_hours"] = df["hour_of_day"].apply(lambda h: 1 if 8 <= h <= 17 else 0)
        df["is_failed_login"] = (df.get("event.outcome", pd.Series(dtype=str)) == "failure").astype(int)
        df["is_ssh"] = (df.get("process.name", pd.Series(dtype=str)).str.lower() == "sshd").astype(int)
        df["is_sudo"] = (df.get("process.name", pd.Series(dtype=str)).str.lower() == "sudo").astype(int)

        for col in group_config["required_fields"]:
            if col not in df.columns:
                df[col] = "" if col not in ("hour_of_day", "is_business_hours", "source.port") else 0

        df = apply_training_time_filters(df, "auth")

        logger.info(f"Successfully fetched {len(df)} Linux auth records")
        return df

    except Exception as e:
        logger.error(f"Error fetching auth data: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return pd.DataFrame()


def preprocess_auth_data(df: "pd.DataFrame"):
    """Preprocess authentication data with enhanced training configuration support."""
    if df.empty:
        return df

    group_config = DATA_GROUP_CONFIG["auth"]
    missing_fields = [f for f in group_config["required_fields"] if f not in df.columns]
    if missing_fields:
        logger.warning(f"Missing auth fields: {missing_fields}")
        for field in missing_fields:
            if field in ("hour_of_day", "is_business_hours", "source.port", "is_failed_login", "is_ssh", "is_sudo"):
                df[field] = 0
            else:
                df[field] = ""

    for col in ("hour_of_day", "day_of_week", "source.port", "is_business_hours",
                "is_failed_login", "is_ssh", "is_sudo"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)

    # Composite entity for brute-force detection
    df["user_host"] = (
        df.get("user.name", pd.Series("", index=df.index)).astype(str) + "@" +
        df.get("host.name", pd.Series("", index=df.index)).astype(str)
    )
    df["event_count"] = 1
    logger.info(f"Preprocessed auth data: {len(df)} records with {len(df.columns)} fields")
    return df
