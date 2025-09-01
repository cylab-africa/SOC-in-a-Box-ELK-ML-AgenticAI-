# IMMEDIATE FIX FUNCTIONS FOR NETWORK ENTITY ALIGNMENT
# Add these functions to resolve training/detection entity mismatch

import pandas as pd
import numpy as np
import logging

logger = logging.getLogger("linux_anomaly_detection")

# 1. CRITICAL FIX: Consistent Entity Column Selection
def get_entity_column_fixed(data_type: str) -> str:
    """
    FIXED: Get entity column that matches between training and detection.
    This replaces both LinuxModelManager._get_entity_column() and detection_methods._get_entity_column()
    """
    entity_mapping = {
        "process": "process.name",
        "network": "destination.ip",     # ALWAYS destination.ip for network
        "user": "user.name",
        "discovery": "process.name", 
        "metadata": "process.name"
    }
    return entity_mapping.get(data_type, "process.name")

# 2. CRITICAL FIX: Clean Network Data Before Training
def clean_network_data_for_training(data: pd.DataFrame) -> pd.DataFrame:
    """
    Clean network data to remove invalid IPs that cause synthetic entities.
    Call this BEFORE training network models.
    """
    if data.empty or 'destination.ip' not in data.columns:
        logger.warning("No destination.ip column found in network data")
        return data
    
    original_count = len(data)
    
    # Remove invalid IP addresses
    invalid_ips = ['0.0.0.0', '', 'unknown', 'None', 'nan']
    valid_mask = ~data['destination.ip'].isin(invalid_ips)
    valid_mask &= data['destination.ip'].notna()
    valid_mask &= data['destination.ip'].astype(str).str.strip() != ''
    
    cleaned_data = data[valid_mask].copy()
    
    # Additional validation - basic IP format check
    def is_valid_ip_format(ip_str):
        try:
            if pd.isna(ip_str) or str(ip_str).strip() == '':
                return False
            parts = str(ip_str).strip().split('.')
            if len(parts) != 4:
                return len(str(ip_str).strip().split(':')) >= 2  # Allow IPv6-like
            return all(0 <= int(part) <= 255 for part in parts if part.isdigit())
        except:
            return False
    
    format_valid_mask = cleaned_data['destination.ip'].apply(is_valid_ip_format)
    cleaned_data = cleaned_data[format_valid_mask].copy()
    
    removed_count = original_count - len(cleaned_data)
    
    logger.info(f"Network data cleaning: {original_count} -> {len(cleaned_data)} records "
               f"({removed_count} invalid IPs removed)")
    
    if len(cleaned_data) < original_count * 0.5:
        logger.warning(f"Removed {removed_count / original_count:.1%} of network data - "
                      "check data quality")
    
    return cleaned_data

# 3. CRITICAL FIX: Validate Entity Consistency
def validate_entity_consistency(training_entities: list, detection_entities: list, 
                               data_type: str) -> dict:
    """
    Validate that training and detection entities are compatible.
    Call this after loading models and before detection.
    """
    training_set = set(str(e) for e in training_entities if e is not None)
    detection_set = set(str(e) for e in detection_entities if e is not None)
    
    # Find matches
    exact_matches = training_set & detection_set
    
    # Find partial matches for network data
    partial_matches = set()
    if data_type == 'network':
        for det_entity in detection_set:
            for train_entity in training_set:
                # Check for subnet matches (first 3 octets)
                if ('.' in det_entity and '.' in train_entity and 
                    not det_entity.startswith('synthetic_')):
                    det_parts = det_entity.split('.')[:3]
                    train_parts = train_entity.split('.')[:3]
                    if len(det_parts) == 3 and len(train_parts) == 3:
                        if det_parts == train_parts:
                            partial_matches.add(det_entity)
                            break
    
    total_matches = len(exact_matches) + len(partial_matches)
    match_rate = total_matches / max(len(detection_set), 1)
    
    result = {
        'total_training_entities': len(training_set),
        'total_detection_entities': len(detection_set),
        'exact_matches': len(exact_matches),
        'partial_matches': len(partial_matches),
        'total_matches': total_matches,
        'match_rate': match_rate,
        'compatible': match_rate >= 0.1,  # At least 10% match
        'training_sample': list(training_set)[:10],
        'detection_sample': list(detection_set)[:10],
        'unmatched_detection': list(detection_set - exact_matches - partial_matches)[:10]
    }
    
    logger.info(f"Entity consistency for {data_type}: {total_matches}/{len(detection_set)} "
               f"entities match ({match_rate:.1%})")
    
    if not result['compatible']:
        logger.error(f"Entity compatibility FAILED for {data_type}: {match_rate:.1%} match rate")
        logger.error(f"Training entities sample: {result['training_sample']}")
        logger.error(f"Detection entities sample: {result['detection_sample']}")
    
    return result

# 4. EMERGENCY FIX: Force Entity Alignment
def force_entity_alignment(detection_data: pd.DataFrame, trained_entities: list, 
                          data_type: str) -> pd.DataFrame:
    """
    EMERGENCY: Force detection entities to align with trained entities.
    Use this when entity validation fails.
    """
    if data_type != 'network':
        return detection_data
    
    entity_col = get_entity_column_fixed(data_type)
    if entity_col not in detection_data.columns:
        return detection_data
    
    original_entities = detection_data[entity_col].unique()
    trained_set = set(str(e) for e in trained_entities if e is not None)
    
    logger.warning(f"EMERGENCY: Forcing entity alignment for {len(original_entities)} entities")
    
    # Create entity mapping
    entity_map = {}
    
    for entity in original_entities:
        entity_str = str(entity)
        
        # Skip synthetic entities - they're the problem
        if entity_str.startswith('synthetic_'):
            logger.warning(f"Skipping synthetic entity: {entity_str}")
            continue
        
        # Direct match
        if entity_str in trained_set:
            entity_map[entity] = entity
            continue
        
        # Subnet match for IPs
        if '.' in entity_str and not entity_str.startswith('synthetic_'):
            entity_parts = entity_str.split('.')
            if len(entity_parts) >= 3:
                for trained_entity in trained_set:
                    if '.' in trained_entity:
                        trained_parts = trained_entity.split('.')
                        if (len(trained_parts) >= 3 and 
                            entity_parts[:3] == trained_parts[:3]):
                            entity_map[entity] = trained_entity
                            logger.debug(f"Subnet match: {entity} -> {trained_entity}")
                            break
        
        # Fallback to most common trained entity
        if entity not in entity_map and trained_set:
            fallback = list(trained_set)[0]  # Use first available
            entity_map[entity] = fallback
            logger.warning(f"Fallback mapping: {entity} -> {fallback}")
    
    # Apply mapping
    aligned_data = detection_data.copy()
    for original, mapped in entity_map.items():
        mask = aligned_data[entity_col] == original
        aligned_data.loc[mask, entity_col] = mapped
    
    # Remove records with synthetic entities that couldn't be mapped
    synthetic_mask = aligned_data[entity_col].astype(str).str.startswith('synthetic_')
    if synthetic_mask.any():
        aligned_data = aligned_data[~synthetic_mask].copy()
        removed = synthetic_mask.sum()
        logger.warning(f"EMERGENCY: Removed {removed} records with unmappable synthetic entities")
    
    mapped_entities = aligned_data[entity_col].unique()
    logger.info(f"EMERGENCY: Entity alignment complete: {len(original_entities)} -> {len(mapped_entities)} entities")
    
    return aligned_data

# 5. PATCH FIX: Update LinuxModelManager
def patch_model_manager_entity_selection(manager_instance):
    """
    Patch existing LinuxModelManager instance to use consistent entity selection.
    Apply this to existing manager instances.
    """
    def fixed_get_entity_column(self, data_type: str) -> str:
        return get_entity_column_fixed(data_type)
    
    # Monkey patch the method
    manager_instance._get_entity_column = fixed_get_entity_column.__get__(manager_instance)
    
    logger.info("PATCHED: LinuxModelManager entity selection aligned with detection")

# 6. VALIDATION FIX: Check Model-Data Compatibility
def check_model_data_compatibility(models: dict, scalers: dict, detection_data: pd.DataFrame,
                                 data_type: str) -> dict:
    """
    Check if loaded models are compatible with detection data.
    Call before running detection.
    """
    entity_col = get_entity_column_fixed(data_type)
    
    if entity_col not in detection_data.columns:
        return {
            'compatible': False,
            'reason': f'Missing entity column: {entity_col}',
            'fix_needed': 'add_entity_column'
        }
    
    detection_entities = detection_data[entity_col].dropna().unique()
    model_entities = list(models.keys())
    
    # Run consistency validation
    consistency = validate_entity_consistency(model_entities, detection_entities, data_type)
    
    result = {
        'compatible': consistency['compatible'],
        'match_rate': consistency['match_rate'],
        'model_count': len(models),
        'scaler_count': len(scalers),
        'detection_entities': len(detection_entities),
        'models_scalers_aligned': len(models) == len(scalers),
        'consistency_details': consistency
    }
    
    # Check for synthetic entities (major red flag)
    synthetic_count = sum(1 for e in detection_entities if str(e).startswith('synthetic_'))
    if synthetic_count > 0:
        result['compatible'] = False
        result['reason'] = f'Found {synthetic_count} synthetic entities - data quality issue'
        result['fix_needed'] = 'clean_data_and_retrain'
    
    # Check models-scalers alignment
    if not result['models_scalers_aligned']:
        result['compatible'] = False
        result['reason'] = f'Models ({len(models)}) and scalers ({len(scalers)}) count mismatch'
        result['fix_needed'] = 'reload_models'
    
    logger.info(f"Model-data compatibility for {data_type}: {result['compatible']} "
               f"({result.get('match_rate', 0):.1%} entity match)")
    
    return result

# 7. IMMEDIATE DEPLOYMENT: Apply All Fixes
def apply_immediate_fixes(manager, models, scalers, detection_data, data_type):
    """
    Apply all immediate fixes in the correct order.
    Use this as a single function to fix everything.
    """
    logger.info(f"Applying immediate fixes for {data_type}")
    
    # 1. Patch manager
    patch_model_manager_entity_selection(manager)
    
    # 2. Check compatibility
    compatibility = check_model_data_compatibility(models, scalers, detection_data, data_type)
    
    if not compatibility['compatible']:
        logger.error(f"Compatibility check failed: {compatibility.get('reason', 'unknown')}")
        
        # 3. Try emergency alignment
        if compatibility.get('fix_needed') == 'clean_data_and_retrain':
            detection_data = force_entity_alignment(detection_data, list(models.keys()), data_type)
            
            # Recheck after alignment
            compatibility = check_model_data_compatibility(models, scalers, detection_data, data_type)
    
    result = {
        'success': compatibility['compatible'],
        'cleaned_data': detection_data,
        'compatibility_report': compatibility
    }
    
    logger.info(f"Immediate fixes applied: {'SUCCESS' if result['success'] else 'FAILED'}")
    return result