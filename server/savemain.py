import pandas as pd
import numpy as np
import logging
import sys
import os
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
load_dotenv() 
import config
# Import the data manager module (assuming it's saved as linux_data_manager.py)
# If your module has a different name, adjust the import accordingly
import datamanager as ldm
from Savedata import *
# Import our new save functions
from Savedata import (
    save_process_data_to_files,
    save_network_data_to_files,
    save_user_data_to_files,
    save_discovery_data_to_files,
    save_metadata_data_to_files
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('data_fetching.log')
    ]
)

logger = logging.getLogger("data_fetcher")

def connect_to_elasticsearch(config):
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
def main():
    # Create a basic configuration
    config = {
        "elasticsearch": {
            "host": "https://***REMOVED_INTERNAL_IP***:9200",  # Change this to your Elasticsearch host
            "verify_certs": False,
            "ssl_show_warn": False,
            "timeout": 120,
            'username': os.getenv("ES_USERNAME"),
            'password': os.getenv("ES_PASSWORD")
        },
        "batch_size": 10000,
        "debug_mode": True
    }

    # Configure Elasticsearch connection
    es_host = config["elasticsearch"]["host"]
    
    # Ensure proper URL format with scheme
    if not es_host.startswith(('http://', 'https://')):
        es_host = f"http://{es_host}"
        config["elasticsearch"]["host"] = es_host
        logger.info(f"Updated Elasticsearch host to include scheme: {es_host}")
    
    # Connect to Elasticsearch
    logger.info(f"Connecting to Elasticsearch at {es_host}...")
    es = ldm.connect_to_elasticsearch(config)
    
    if not es:
        logger.error(f"Failed to connect to Elasticsearch at {es_host}. Please check your configuration.")
        logger.error("Common issues: Elasticsearch not running, incorrect host/port, or network connectivity problems.")
        return
    
    logger.info("Successfully connected to Elasticsearch.")
    
    # Define time range (last 7 days)
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    time_range = {
        "gte": start_time.isoformat(),
        "lte": end_time.isoformat()
    }
    
    # Fetch and save process data
    logger.info("Fetching process data...")
    process_df = ldm.fetch_process_data(es, config, time_range, query_size=10000)
    
    if not process_df.empty:
        logger.info(f"Retrieved {len(process_df)} process records. Saving to files...")
        json_path, excel_path = save_process_data_to_files(process_df, config, "process_data")
        logger.info(f"Process data saved to {json_path} and {excel_path}")
    else:
        logger.warning("No process data retrieved.")
    
    # Fetch and save network data
    logger.info("Fetching network data...")
    network_df = ldm.fetch_network_activity_data(es, config, time_range, query_size=10000)
    
    if not network_df.empty:
        logger.info(f"Retrieved {len(network_df)} network records. Saving to files...")
        json_path, excel_path = save_network_data_to_files(network_df, config, "network_data")
        logger.info(f"Network data saved to {json_path} and {excel_path}")
    else:
        logger.warning("No network data retrieved.")
    
    # Fetch and save user activity data
    logger.info("Fetching user activity data...")
    user_df = ldm.fetch_user_activity_data(es, config, time_range, query_size=10000)
    
    if not user_df.empty:
        logger.info(f"Retrieved {len(user_df)} user activity records. Saving to files...")
        json_path, excel_path = save_user_data_to_files(user_df, config, "user_data")
        logger.info(f"User data saved to {json_path} and {excel_path}")
    else:
        logger.warning("No user data retrieved.")
    
    # Fetch and save discovery commands data
    logger.info("Fetching discovery commands data...")
    discovery_df = ldm.fetch_discovery_commands_data(es, config, time_range, query_size=10000)
    
    if not discovery_df.empty:
        logger.info(f"Retrieved {len(discovery_df)} discovery command records. Saving to files...")
        json_path, excel_path = save_discovery_data_to_files(discovery_df, config, "discovery_data")
        logger.info(f"Discovery data saved to {json_path} and {excel_path}")
    else:
        logger.warning("No discovery data retrieved.")
    
    # Fetch and save metadata access data
    logger.info("Fetching metadata access data...")
    metadata_df = ldm.fetch_metadata_access_data(es, config, time_range, query_size=10000)
    
    if not metadata_df.empty:
        logger.info(f"Retrieved {len(metadata_df)} metadata access records. Saving to files...")
        json_path, excel_path = save_metadata_data_to_files(metadata_df, config, "metadata_data")
        logger.info(f"Metadata data saved to {json_path} and {excel_path}")
    else:
        logger.warning("No metadata data retrieved.")
    
    logger.info("Data fetching and saving complete!")

if __name__ == "__main__":
    main()