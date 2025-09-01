import pandas as pd
import json
import os
import logging

logger = logging.getLogger("linux_anomaly_detection")

def save_process_data_to_files(df, config=None, base_filename="process_data"):
    """
    Save process data to both JSON and Excel files in the current directory.
    
    Args:
        df (pd.DataFrame): Process data DataFrame
        config (dict, optional): Configuration dictionary
        base_filename (str, optional): Base filename to use
    
    Returns:
        tuple: Paths to the saved files (json_path, excel_path)
    """
    if df.empty:
        logger.warning("No data to save")
        return None, None
    
    # Create filenames
    current_dir = os.getcwd()
    json_path = os.path.join(current_dir, f"{base_filename}.json")
    excel_path = os.path.join(current_dir, f"{base_filename}.xlsx")
    
    try:
        # Convert DataFrame to JSON
        # Handle complex objects that aren't JSON serializable
        df_json = df.copy()
        
        # Convert lists and other complex objects to strings
        for col in df_json.columns:
            if df_json[col].apply(lambda x: isinstance(x, (list, dict))).any():
                df_json[col] = df_json[col].apply(lambda x: str(x) if isinstance(x, (list, dict)) else x)
        
        # Save to JSON
        df_json.to_json(json_path, orient="records", date_format="iso")
        logger.info(f"Saved JSON data to {json_path}")
        
        # Save to Excel
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
            
            df_excel.to_excel(writer, sheet_name="Process_Data", index=False)
            
        logger.info(f"Saved Excel data to {excel_path}")
        return json_path, excel_path
        
    except Exception as e:
        logger.error(f"Error saving data to files: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return None, None

def save_network_data_to_files(df, config=None, base_filename="network_data"):
    """
    Save network data to both JSON and Excel files in the current directory.
    
    Args:
        df (pd.DataFrame): Network data DataFrame
        config (dict, optional): Configuration dictionary
        base_filename (str, optional): Base filename to use
    
    Returns:
        tuple: Paths to the saved files (json_path, excel_path)
    """
    return save_process_data_to_files(df, config, base_filename)

def save_user_data_to_files(df, config=None, base_filename="user_data"):
    """
    Save user activity data to both JSON and Excel files in the current directory.
    
    Args:
        df (pd.DataFrame): User data DataFrame
        config (dict, optional): Configuration dictionary
        base_filename (str, optional): Base filename to use
    
    Returns:
        tuple: Paths to the saved files (json_path, excel_path)
    """
    return save_process_data_to_files(df, config, base_filename)

def save_discovery_data_to_files(df, config=None, base_filename="discovery_data"):
    """
    Save discovery commands data to both JSON and Excel files in the current directory.
    
    Args:
        df (pd.DataFrame): Discovery data DataFrame
        config (dict, optional): Configuration dictionary
        base_filename (str, optional): Base filename to use
    
    Returns:
        tuple: Paths to the saved files (json_path, excel_path)
    """
    return save_process_data_to_files(df, config, base_filename)

def save_metadata_data_to_files(df, config=None, base_filename="metadata_data"):
    """
    Save metadata access data to both JSON and Excel files in the current directory.
    
    Args:
        df (pd.DataFrame): Metadata data DataFrame
        config (dict, optional): Configuration dictionary
        base_filename (str, optional): Base filename to use
    
    Returns:
        tuple: Paths to the saved files (json_path, excel_path)
    """
    return save_process_data_to_files(df, config, base_filename)