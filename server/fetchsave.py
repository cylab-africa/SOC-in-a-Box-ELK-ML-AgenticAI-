import pandas as pd
import numpy as np
import logging
import sys
import os
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch

# Import the data manager module (assuming it's saved as linux_data_manager.py)
# If your module has a different name, adjust the import accordingly
import datamanager as ldm

# Import our new save functions
from fetchsave import (
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

def main():
    # Create a basic configuration
    config = {
        "elasticsearch": {
            "host": "localhost:9200",  # Change this to your Elasticsearch host
            "verify_certs": False,
            "ssl_show_warn": False,
            "timeout": 120
        },
        "batch_size": 10000,
        "debug_mode": True
    }

    # Connect to Elasticsearch
    logger.info("Connecting to Elasticsearch...")
    es = ldm.connect_to_elasticsearch(config)
    
    if not es:
        logger.error("Failed to connect to Elasticsearch. Please check your configuration.")
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