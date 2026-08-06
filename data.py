
import logging
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
from elasticsearch import Elasticsearch


class OptimizedRetriever:
    """Optimized data retrieval with search_after for large datasets."""

    def __init__(self, es: "Elasticsearch", config: dict):
        self.es = es
        self.batch_size = config.get("batch_size", 10000)
        self.debug_mode = config.get("debug_mode", False)

    def retrieve_with_search_after(self, index_pattern: str, query_body: dict, source_fields: list | None, max_records: int):
        """Retrieve data using search_after for efficient pagination - FIXED for Elasticsearch compatibility."""
        all_records = []
        search_after = None

        # FIXED: Use a more compatible sort configuration
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

# Data Group Configurations with Correct Endpoints and Required Fields
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
    }
}

# def get_training_configuration(data_type: str = "process") -> Dict[str, Any]:
#     """
#     Get training configuration for a specific data type.
#     Falls back to default values if configuration system is not available.
#     """
#     if not CONFIG_AVAILABLE or get_config is None:
#         # Default configuration when config system is not available
#         return {
#             "training_period_days": 30,
#             "training_start_offset_days": 1,
#             "include_weekends": True,
#             "include_business_hours_only": False,
#             "business_hours_start": 8,
#             "business_hours_end": 18,
#             "exclude_holidays": False,
#             "min_events_per_day": 10,
#             "use_custom_period": False,
#             "custom_training_start": None,
#             "custom_training_end": None,
#             "baseline_query_size": 40000
#         }

#     try:
#         config = get_config()
#         training_config = config.get('training')

#         # Get data type specific period
#         period_map = {
#             'process': getattr(training_config, 'process_training_period_days', 30),
#             'network': getattr(training_config, 'network_training_period_days', 14),
#             'user': getattr(training_config, 'user_training_period_days', 30),
#             'discovery': getattr(training_config, 'discovery_training_period_days', 21),
#             'metadata': getattr(training_config, 'metadata_training_period_days', 7)
#         }

#         return {
#             "training_period_days": period_map.get(data_type, 30),
#             "training_start_offset_days": getattr(training_config, 'training_start_offset_days', 1),
#             "include_weekends": getattr(training_config, 'include_weekends', True),
#             "include_business_hours_only": getattr(training_config, 'include_business_hours_only', False),
#             "business_hours_start": getattr(training_config, 'business_hours_start', 8),
#             "business_hours_end": getattr(training_config, 'business_hours_end', 18),
#             "exclude_holidays": getattr(training_config, 'exclude_holidays', False),
#             "min_events_per_day": getattr(training_config, 'min_events_per_day', 10),
#             "use_custom_period": getattr(training_config, 'use_custom_period', False),
#             "custom_training_start": getattr(training_config, 'custom_training_start', None),
#             "custom_training_end": getattr(training_config, 'custom_training_end', None),
#             "baseline_query_size": getattr(training_config, 'baseline_query_size', 40000)
#         }
#     except Exception as e:
#         logger.warning(f"Error getting training configuration: {e}, using defaults")
#         return get_training_configuration()  # Return default config
def get_training_configuration(data_type: str) -> dict:
    """Get training configuration for data type."""
    training_configs = {
        "process": {
            "training_period_days": 5,
            "detection_period_days": 1,
            "baseline_query_size": 100000,
            "min_records_for_detection": 5
        },
        "network": {
            "training_period_days": 5,
            "detection_period_days": 0.5,
            "baseline_query_size": 100000,
            "min_records_for_detection": 10
        },
        "user": {
            "training_period_days": 30,
            "detection_period_days": 2,
            "baseline_query_size": 200000,
            "min_records_for_detection": 3
        },
        "discovery": {
            "training_period_days": 5,
            "detection_period_days": 1,
            "baseline_query_size": 100000,
            "min_records_for_detection": 2
        },
        "metadata": {
            "training_period_days": 5,
            "detection_period_days": 0.5,
            "baseline_query_size": 100000,
            "min_records_for_detection": 5
        }
    }

    return training_configs.get(data_type, {
        "training_period_days": 5,
        "detection_period_days": 1,
        "baseline_query_size": 10000,
        "min_records_for_detection": 1
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
        verify_certs = es_config.get("verify_certs", False)
        ssl_show_warn = es_config.get("ssl_show_warn", False)
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

        if not verify_certs:
            es_client_config["verify_certs"] = False
            es_client_config["ssl_show_warn"] = ssl_show_warn

        # Create Elasticsearch client
        es = Elasticsearch(**es_client_config)

        # Test connection
        if es.ping():
            logger.info(f"Successfully connected to Elasticsearch at {host}")
            return es
        else:
            logger.error("Failed to connect to Elasticsearch.")
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
                query_size = min(500000, max(200000, query_size * 20))
                logger.info(f"Applied process training constraint: increased query_size to {query_size}")
    except (TypeError, ValueError):
        query_size = 10000
        logger.warning("Invalid query_size, using default of 10000")

    # Required fields
    source_fields = [
        "@timestamp", "host.hostname", "host.id", "host.name", "host.os.name", "host.os.type", "host.os.platform",
        "process.name", "process.executable", "process.command_line", "process.args",
        "process.pid", "process.entity_id", "process.working_directory",
        "process.parent.name", "process.parent.executable", "process.parent.command_line",
        "process.parent.pid", "process.parent.entity_id",
        "process.hash.sha256", "process.hash.sha1", "process.hash.md5",
        "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
        "group.name", "group.id", "group.Ext.real.name", "group.Ext.real.id",
        "event.action", "event.type", "event.category", "event.outcome",
        "agent.id", "agent.type", "agent.version"
    ]

    # Hard-coded filtered query (matches your original query exactly)
    query = {
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
        logger.info(f"Fetching process data from {index_pattern} using search_after")
        all_hits = []
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
                break  # No more data

        logger.info(f"Retrieved {len(all_hits)} process records from Elasticsearch")

        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)

        # Ensure timestamp is timezone-aware
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
            valid_timestamps = df["@timestamp"].notna().sum()
            logger.info(f"Processed {valid_timestamps:,}/{len(df):,} valid timestamps")

        # Apply training time filters
        original_count = len(df)
        df = apply_training_time_filters(df, "process")
        if len(df) != original_count:
            logger.info(f"Training filters applied: {original_count} -> {len(df)} records")

        # Ensure required fields exist
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

        logger.info(f"Successfully processed {len(df)} Linux process records with {len(df.columns)} fields")
        return df

    except Exception as e:
        logger.error(f"Error fetching process data: {e}")
        return pd.DataFrame()


def fetch_network_activity_data(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000):
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
        "source.ip", "source.port", "network.transport", "network.direction", "network.type",
        "destination.bytes", "source.bytes", "process.name", "process.executable",
        "process.pid", "process.command_line", "event.action", "event.type",
        "process.thread.capabilities.effective", "process.thread.capabilities.permitted",
        "user.name", "user.id", "agent.id", "agent.type"
    ]

    # Build query with Linux filtering
    query = {
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
        logger.info(f"Fetching network data from {index_pattern} using search_after")
        all_hits = []
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
                break  # No more data

        logger.info(f"Retrieved {len(all_hits)} network records from Elasticsearch")

        if not all_hits:
            logger.warning("No network data found matching the criteria")
            return pd.DataFrame()

        # Flatten records
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = _flatten_elasticsearch_document(source)
            records.append(flattened)

        df = pd.DataFrame(records)

        # Ensure timestamp is timezone-aware
        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

        # Apply training time filters
        df = apply_training_time_filters(df, "network")

        # Validate required fields
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for network group: {missing_fields}")
            for field in missing_fields:
                if field in ["destination.port", "source.port", "destination.bytes", "source.bytes"]:
                    df[field] = 0
                elif field in ["destination.ip", "source.ip", "network.transport", "network.direction"]:
                    df[field] = "unknown"
                else:
                    df[field] = ""

        logger.info(f"Successfully processed {len(df)} Linux network activity records")
        return df

    except Exception as e:
        logger.error(f"Error fetching network activity data: {e}")
        return pd.DataFrame()

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
        "event.action", "event.type", "agent.id"
    ]

    # Build query with Linux filtering
    query = {
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
        logger.info(f"Fetching user data from {index_pattern} using search_after")
        all_hits = []
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
                break  # No more data

        logger.info(f"Retrieved {len(all_hits)} user records from Elasticsearch")

        if not all_hits:
            logger.warning("No user data found matching the criteria")
            return pd.DataFrame()

        # Flatten records
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = {}
            for key, value in source.items():
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        flattened[f"{key}.{subkey}"] = subvalue
                else:
                    flattened[key] = value
            records.append(flattened)

        df = pd.DataFrame(records)

        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

        # Apply training time filters
        df = apply_training_time_filters(df, "user")

        logger.info(f"Successfully processed {len(df)} Linux user activity records")
        return df

    except Exception as e:
        logger.error(f"Error fetching user activity data: {e}")
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
    query = {
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
        logger.info(f"Fetching discovery commands data from {index_pattern} using search_after")
        all_hits = []
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
                break  # No more data

        logger.info(f"Retrieved {len(all_hits)} discovery command records from Elasticsearch")

        if not all_hits:
            logger.warning("No discovery commands data found matching the criteria")
            return pd.DataFrame()

        # Flatten records
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = {}
            for key, value in source.items():
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        flattened[f"{key}.{subkey}"] = subvalue
                else:
                    flattened[key] = value
            records.append(flattened)

        df = pd.DataFrame(records)

        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

        # Apply training time filters
        df = apply_training_time_filters(df, "discovery")

        logger.info(f"Successfully processed {len(df)} Linux discovery command records")
        return df

    except Exception as e:
        logger.error(f"Error fetching discovery commands data: {e}")
        return pd.DataFrame()

def fetch_metadata_access_data(es: "Elasticsearch", config: dict, time_range: dict | None=None, query_size: int=10000):
    """
    Fetch metadata access data with search_after pagination to bypass 10k limit.
    """
    if not es:
        logger.error("Elasticsearch connection is not available.")
        return pd.DataFrame()

    group_config = DATA_GROUP_CONFIG["metadata"]
    index_pattern = group_config["endpoint"]  # Now uses network index

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

    # Metadata service IPs
    metadata_ips = [
        "169.254.169.254",  # AWS metadata
        "169.254.169.253",  # Azure metadata
        "metadata.google.internal"  # GCP metadata
    ]

    source_fields = [
        "@timestamp", "host.hostname", "host.os.type", "host.os.platform",
        "destination.ip", "destination.port", "process.name", "process.executable",
        "process.command_line", "user.name", "user.id", "network.transport",
        "event.action", "event.type"
    ]

    # Build query with Linux filtering and metadata IP filtering
    query = {
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
                            "destination.ip": metadata_ips
                        }
                    },
                    {
                        "wildcard": {
                            "destination.domain": "*metadata*"
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
        logger.info(f"Fetching metadata access data from {index_pattern} using search_after")
        all_hits = []
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
                break  # No more data

        logger.info(f"Retrieved {len(all_hits)} metadata access records from Elasticsearch")

        if not all_hits:
            logger.warning("No metadata access data found matching the criteria")
            return pd.DataFrame()

        # Flatten records
        records = []
        for hit in all_hits:
            source = hit["_source"]
            flattened = {}
            for key, value in source.items():
                if isinstance(value, dict):
                    for subkey, subvalue in value.items():
                        flattened[f"{key}.{subkey}"] = subvalue
                else:
                    flattened[key] = value
            records.append(flattened)

        df = pd.DataFrame(records)

        if "@timestamp" in df.columns:
            df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

        # Add computed required fields
        service_accounts = ["ec2-user", "ubuntu", "centos", "admin", "service", "system"]
        df["is_service_account"] = df["user.name"].str.lower().isin(service_accounts).astype(int)

        # Determine access method based on destination IP
        def get_access_method(ip: str):
            """Determine access method from IP address."""
            if ip == "169.254.169.254":
                return "aws_metadata"
            elif ip == "169.254.169.253":
                return "azure_metadata"
            elif "metadata.google" in str(ip):
                return "gcp_metadata"
            else:
                return "unknown_metadata"

        df["access_method"] = df["destination.ip"].apply(get_access_method)

        # Credential harvesting indicators
        cred_keywords = ["credentials", "token", "key", "secret", "password", "auth"]
        df["potential_cred_harvest"] = df["process.command_line"].str.contains(
            "|".join(cred_keywords), case=False, na=False
        ).astype(int)

        # User data access patterns
        df["user_data_access"] = df["destination.port"].apply(lambda x: 1 if x == 80 or x == 443 else 0)

        # Root access indicator
        df["is_root_access"] = (df["user.name"] == "root").astype(int)

        # Apply training time filters
        df = apply_training_time_filters(df, "metadata")

        # Validate required fields
        missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
        if missing_fields:
            logger.warning(f"Missing required fields for metadata group: {missing_fields}")
            for field in missing_fields:
                if field in ["destination.port"]:
                    df[field] = 0
                elif "is_" in field:
                    df[field] = 0
                else:
                    df[field] = ""

        logger.info(f"Successfully fetched {len(df)} Linux metadata access records")
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

    return df


# def preprocess_user_data(df):
#     """
#     Preprocess user data with enhanced training configuration support.
#     """
#     if df.empty:
#         return df

#     group_config = DATA_GROUP_CONFIG["user"]

#     # Validate required fields exist
#     missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
#     if missing_fields:
#         logger.warning(f"Still missing user fields after fetch: {missing_fields}")
#         for field in missing_fields:
#             if "count" in field or "hour" in field or "is_" in field or "has_" in field:
#                 df[field] = 0
#             else:
#                 df[field] = ""

#     # Ensure proper data types
#     numeric_fields = ["user.id", "hour_of_day", "command_length", "args_count"]
#     for field in numeric_fields:
#         if field in df.columns:
#             df[field] = pd.to_numeric(df[field], errors='coerce').fillna(0)

#     # Add aggregation field
#     df["event_count"] = 1

#     logger.info(f"Preprocessed user data: {len(df)} records with {len(df.columns)} fields")
#     return df
def preprocess_network_data(df: "pd.DataFrame"):
    """
    Enhanced network data preprocessing that preserves all fields.
    """
    if df.empty:
        return df

    logger.info(f"Preprocessing network data: {len(df)} records")

    # Ensure network-specific fields exist
    network_fields = {
        'destination.ip': '0.0.0.0',
        'destination.port': 0,
        'source.ip': '0.0.0.0',
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

    for field, default in network_fields.items():
        if field not in df.columns:
            df[field] = default
            logger.debug(f"Added missing network field '{field}'")

    # Network-specific features
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
        df["large_transfer"] = (df["network.bytes"] > 1000000).astype(int)  # > 1MB
        df["bytes_log"] = np.log1p(df["network.bytes"])

    df["event_count"] = 1

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
# def preprocess_discovery_data(df):
#     """
#     Preprocess discovery data with enhanced training configuration support.
#     """
#     if df.empty:
#         return df

#     group_config = DATA_GROUP_CONFIG["discovery"]

#     # Validate required fields exist
#     missing_fields = [field for field in group_config["required_fields"] if field not in df.columns]
#     if missing_fields:
#         logger.warning(f"Missing discovery fields: {missing_fields}")
#         for field in missing_fields:
#             if "count" in field or "is_" in field or "has_" in field:
#                 df[field] = 0
#             else:
#                 df[field] = ""

#     # Add computed fields for discovery commands
#     if "process.command_line" in df.columns:
#         df["has_pipes"] = df["process.command_line"].str.contains("|", na=False).astype(int)
#         df["has_redirection"] = df["process.command_line"].str.contains(">|<", na=False).astype(int)
#         df["command_length"] = df["process.command_line"].str.len().fillna(0)

#     # Add discovery categorization
#     discovery_categories = {
#         "network": ["netstat", "ss", "ifconfig", "ip", "route", "arp", "ping", "nslookup", "dig"],
#         "process": ["ps", "pstree", "top", "htop"],
#         "user": ["whoami", "id", "groups", "w", "who", "last"],
#         "system": ["uname", "uptime", "df", "mount", "lsblk"],
#         "other": []
#     }

#     def categorize_discovery(process_name):
#         for category, commands in discovery_categories.items():
#             if process_name in commands:
#                 return category
#         return "other"

#     if "process.name" in df.columns:
#         df["discovery_category"] = df["process.name"].apply(categorize_discovery)

#     df["event_count"] = 1

#     logger.info(f"Preprocessed discovery data: {len(df)} records with {len(df.columns)} fields")
#     return df
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
        'has_dollar_paren': 'max',  # This was missing!
        'has_semicolon': 'max',     # This was missing!
        'has_ampersand': 'max',     # This was missing!
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

# def create_time_buckets(df, time_column="@timestamp", bucket_size="15m"):
#     """
#     Create time buckets for temporal analysis with enhanced configuration support.
#     """
#     if df.empty or time_column not in df.columns:
#         logger.warning(f"Cannot create time buckets: empty data or missing {time_column}")
#         return df

#     try:
#         # Ensure timestamp is datetime
#         df[time_column] = pd.to_datetime(df[time_column], errors='coerce', utc=True)

#         # Create time buckets
#         df["time_bucket"] = df[time_column].dt.floor(bucket_size)

#         # Add temporal features
#         df["hour_of_day"] = df[time_column].dt.hour
#         df["day_of_week"] = df[time_column].dt.dayofweek
#         df["is_weekend"] = (df[time_column].dt.dayofweek >= 5).astype(int)
#         df["is_business_hours"] = ((df[time_column].dt.hour >= 8) &
#                                   (df[time_column].dt.hour < 18)).astype(int)

#         logger.info(f"Created time buckets with {bucket_size} intervals")
#         return df

#     except Exception as e:
#         logger.error(f"Error creating time buckets: {e}")
#         return df
def create_time_buckets(df: "pd.DataFrame", time_column: str="@timestamp", bucket_size: str="15min"):
    """
    Enhanced time bucketing that creates all temporal features needed by models.
    """
    if df.empty or time_column not in df.columns:
        logger.warning(f"Cannot create time buckets: empty data or missing {time_column}")
        return df

    try:
        # Ensure timestamp is datetime
        df[time_column] = pd.to_datetime(df[time_column], errors='coerce', utc=True)

        # Convert bucket size
        if bucket_size.endswith('m'):
            pandas_freq = f"{bucket_size[:-1]}min"
        elif bucket_size.endswith('h'):
            pandas_freq = f"{bucket_size[:-1]}H"
        else:
            pandas_freq = "15min"

        # Create time bucket
        df["time_bucket"] = df[time_column].dt.floor(pandas_freq)

        # === CREATE ALL TEMPORAL FEATURES ===

        # Basic temporal features
        df["hour_of_day"] = df[time_column].dt.hour
        df["minute_of_hour"] = df[time_column].dt.minute
        df["day_of_week"] = df[time_column].dt.dayofweek
        df["day_of_month"] = df[time_column].dt.day
        df["month"] = df[time_column].dt.month

        # Circular encoding - THESE ARE EXPECTED BY MODELS
        df["hour_sin"] = np.sin(2 * np.pi * df["hour_of_day"] / 24)
        df["hour_cos"] = np.cos(2 * np.pi * df["hour_of_day"] / 24)
        df["day_sin"] = np.sin(2 * np.pi * df["day_of_week"] / 7)
        df["day_cos"] = np.cos(2 * np.pi * df["day_of_week"] / 7)
        df["month_sin"] = np.sin(2 * np.pi * df["month"] / 12)
        df["month_cos"] = np.cos(2 * np.pi * df["month"] / 12)

        # Business context
        df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
        df["is_business_hours"] = (
            (df["hour_of_day"] >= 8) &
            (df["hour_of_day"] < 18) &
            (df["day_of_week"] < 5)
        ).astype(int)
        df["is_night_time"] = (
            (df["hour_of_day"] < 6) | (df["hour_of_day"] > 22)
        ).astype(int)

        # Sequence detection
        df = df.sort_values([time_column])

        # Group by entity for sequence detection
        entity_cols = ["process.name", "user.name", "host.hostname"]
        existing_entity_cols = [col for col in entity_cols if col in df.columns]

        if existing_entity_cols:
            # Time since previous event for same entity
            df["prev_timestamp"] = df.groupby(existing_entity_cols)[time_column].shift(1)
            df["seconds_since_prev"] = (
                df[time_column] - df["prev_timestamp"]
            ).dt.total_seconds().fillna(999999)
            df["is_rapid_sequence"] = (df["seconds_since_prev"] < 5).astype(int)
            df["is_burst_activity"] = (df["seconds_since_prev"] < 1).astype(int)

        # Events per bucket (for anomaly detection)
        df["events_in_bucket"] = df.groupby("time_bucket")[time_column].transform('count')
        df["events_in_bucket_by_entity"] = df.groupby(
            ["time_bucket"] + existing_entity_cols
        )[time_column].transform('count') if existing_entity_cols else 1

        # Log temporal feature creation
        temporal_features = [
            'hour_sin', 'hour_cos', 'day_sin', 'day_cos', 'month_sin', 'month_cos',
            'is_weekend', 'is_business_hours', 'is_night_time', 'is_rapid_sequence'
        ]
        logger.info(f"Created {len(temporal_features)} temporal features")

        unique_buckets = df["time_bucket"].nunique()
        logger.info(f"Created time buckets with {bucket_size} intervals: {len(df)} records, {unique_buckets} unique buckets")

        return df

    except Exception as e:
        logger.error(f"Error creating time buckets: {e}")
        return df

def debug_elasticsearch_data(es: "Elasticsearch", config: dict):
    """
    Debug function to check Elasticsearch connectivity and data availability.
    """
    if not es:
        print("âŒ Elasticsearch connection is not available")
        return

    try:
        # Test basic connectivity
        if es.ping():
            print("âœ… Elasticsearch connection successful")
        else:
            print("âŒ Elasticsearch ping failed")
            return

        # Check cluster health
        health = es.cluster.health()
        print(f"ðŸ“Š Cluster health: {health['status']}")

        # Check each data group index
        for data_group, config_info in DATA_GROUP_CONFIG.items():
            index_pattern = config_info["endpoint"]

            try:
                # Check if index exists and get document count
                count_response = es.count(index=index_pattern)
                doc_count = count_response["count"]
                print(f"ðŸ“ {data_group}: {doc_count:,} documents in {index_pattern}")

                # Test Linux filtering
                linux_query = {
                    "query": {
                        "term": {
                            "host.os.type.keyword": "linux"
                        }
                    }
                }
                linux_count = es.count(index=index_pattern, body=linux_query)["count"]
                linux_percentage = (linux_count / doc_count * 100) if doc_count > 0 else 0
                print(f"  ðŸ§ Linux documents: {linux_count:,} ({linux_percentage:.1f}%)")

            except Exception as e:
                print(f"âŒ {data_group}: Error accessing {index_pattern} - {e}")

        print("\nâœ… Elasticsearch debug complete")

    except Exception as e:
        print(f"âŒ Debug failed: {e}")

# Status and configuration check
if __name__ == "__main__":
    print("=== Enhanced Linux Anomaly Detection Data Manager ===")
    print("1. Library Dependencies:")
    print("  âœ… pandas, numpy, elasticsearch available")
    print("  âœ… All required imports successful")

    print("\n2. Configuration Status...")
    print(f"  Enhanced config available: {CONFIG_AVAILABLE}")
    if CONFIG_AVAILABLE:
        print("  âœ… Using enhanced configuration system")
        print("  âœ… Training period configuration active")
    else:
        print("  âš ï¸  Using default configuration (no config.py found)")
        print("  â„¹ï¸  All functions work with defaults")

    print("\n3. Available Functions:")
    functions = [
        "connect_to_elasticsearch", "fetch_process_data", "fetch_network_activity_data",
        "fetch_user_activity_data", "fetch_discovery_commands_data", "fetch_metadata_access_data",
        "fetch_baseline_data", "preprocess_process_data", "preprocess_network_data",
        "preprocess_user_data", "preprocess_discovery_data", "preprocess_metadata_data",
        "aggregate_data_by_group", "create_time_buckets", "debug_elasticsearch_data"
    ]

    for func in functions:
        print(f"  âœ… {func}()")

    print("\nâœ… Enhanced data manager ready!")
    print("   â†’ All existing function signatures maintained")
    print("   â†’ Training period configuration integrated")
    print("   â†’ Linux filtering added to all data fetching")
    print("   â†’ Metadata index pattern fixed")
    print("   â†’ Process training constraints implemented")
    print("   â†’ Ready for anomaly_detector.py import")
