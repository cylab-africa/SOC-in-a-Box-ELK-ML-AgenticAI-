import pandas as pd
from typing import List, Dict, Any
import logging
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
def safe_column_check(df: pd.DataFrame, required_columns: List[str], operation_name: str) -> bool:
    """
    Check if required columns exist in DataFrame.
    
    Args:
        df: DataFrame to check
        required_columns: List of required column names
        operation_name: Name of operation for logging
        
    Returns:
        bool: True if all required columns exist
    """
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        logger.error(f"Missing required columns for {operation_name}: {missing_columns}")
        logger.info(f"Available columns: {list(df.columns)}")
        return False
    return True


def add_default_columns(df: pd.DataFrame, default_columns: Dict[str, Any]) -> pd.DataFrame:
    """
    Add default columns if they don't exist.
    
    Args:
        df: DataFrame to modify
        default_columns: Dict of column_name -> default_value
        
    Returns:
        pd.DataFrame: DataFrame with default columns added
    """
    for col_name, default_value in default_columns.items():
        if col_name not in df.columns:
            df[col_name] = default_value
            logger.info(f"Added default column {col_name} with value {default_value}")
    
    return df