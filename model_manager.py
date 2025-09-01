

def train_process_anomaly_models(historical_data, config):
    """
    Train specialized models for process anomaly detection.
    Supports: v3_linux_anomalous_process_all_hosts, v3_rare_process_by_host_linux
    
    Args:
        historical_data (pd.DataFrame): Historical process data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized process anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Establish baselines for both global and per-host process patterns
    baselines = {}
    
    # Global process baselines (for v3_linux_anomalous_process_all_hosts)
    global_baselines = manager.establish_baselines(historical_data, "process")
    baselines["global"] = global_baselines
    
    # Per-host process baselines (for v3_rare_process_by_host_linux)
    if "host.hostname" in historical_data.columns:
        host_baselines = {}
        for hostname in historical_data["host.hostname"].unique():
            if pd.isna(hostname) or hostname == "":
                continue
            
            host_data = historical_data[historical_data["host.hostname"] == hostname]
            if len(host_data) >= 10:
                host_process_baselines = manager.establish_baselines(host_data, "process")
                host_baselines[hostname] = host_process_baselines
        
        baselines["per_host"] = host_baselines
        logger.info(f"Established per-host baselines for {len(host_baselines)} hosts")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "process")
    
    # Save everything
    manager.baselines["process"] = baselines
    manager.models["process"] = models
    manager.scalers["process"] = scalers
    manager.save_models("process")
    
    return models, scalers, baselines

def train_network_activity_models(historical_data, config):
    """
    Train specialized models for network activity anomaly detection.
    Supports: v3_linux_anomalous_network_activity, v3_linux_anomalous_network_port_activity
    
    Args:
        historical_data (pd.DataFrame): Historical network data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized network activity anomaly detection models")
    logger.info(f"Network data shape: {historical_data.shape}")
    logger.info(f"Network data columns: {historical_data.columns.tolist()}")
    logger.info(f"Sample of network data:\n{historical_data.head()}")
    manager = LinuxModelManager(config)
    
    # Establish baselines for network patterns
    baselines = {}
    
    # IP-based baselines (Fixed: was country-based)
    ip_baselines = manager.establish_baselines(historical_data, "network")
    baselines["destinations"] = ip_baselines
    logger.info(f"Established baselines for {len(ip_baselines)} destination IPs")
    logger.info("0")
    logger.info("0")
    logger.info("0")
    # Port-based baselines
    if "destination.port" in historical_data.columns:
        port_baselines = {}
        logger.info("1")
        logger.info("2")
        # Group by port for common ports
        port_groups = historical_data.groupby("destination.port")
        logger.info("3")
        logger.info(f"Found {len(port_groups)} unique destination ports")
        for port, port_data in port_groups:
            if len(port_data) >= 20:  # Only for ports with significant traffic
                port_stats = {
                    "mean": float(port_data["event_count"].mean()),
                    "std": float(port_data["event_count"].std()),
                    "percentiles": {
                        "p95": float(port_data["event_count"].quantile(0.95)),
                        "p99": float(port_data["event_count"].quantile(0.99))
                    }
                }
                
                # Add process associations for this port
                if "process.name" in port_data.columns:
                    process_dist = port_data["process.name"].value_counts().head(10).to_dict()
                    port_stats["common_processes"] = {str(k): int(v) for k, v in process_dist.items()}
                
                port_baselines[int(port)] = port_stats
        
        baselines["ports"] = port_baselines
        logger.info(f"Established baselines for {len(port_baselines)} network ports")
    
    # Train models
    models, scalers = manager.train_models(historical_data, "network")
    
    # Save everything
    manager.baselines["network"] = baselines
    manager.models["network"] = models
    manager.scalers["network"] = scalers
    manager.save_models("network")
    
    return models, scalers, baselines

def train_user_behavior_models(historical_data, config):
    """
    Train specialized models for user behavior anomaly detection.
    Supports: v3_linux_anomalous_user_name, v3_linux_rare_sudo_user, v3_linux_rare_user_compiler
    
    Args:
        historical_data (pd.DataFrame): Historical user data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized user behavior anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Train models
    models, scalers = manager.train_models(historical_data, "user")
    baselines = manager.establish_baselines(historical_data, "user")
    
    # Save everything
    manager.baselines["user"] = baselines
    manager.models["user"] = models
    manager.scalers["user"] = scalers
    manager.save_models("user")
    
    return models, scalers, baselines

def train_discovery_command_models(historical_data, config):
    """
    Train specialized models for discovery command anomaly detection.
    Supports: v3_linux_network_configuration_discovery, v3_linux_network_connection_discovery,
             v3_linux_system_information_discovery, v3_linux_system_process_discovery,
             v3_linux_system_user_discovery
    
    Args:
        historical_data (pd.DataFrame): Historical discovery data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized discovery command anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Train models
    models, scalers = manager.train_models(historical_data, "discovery")
    baselines = manager.establish_baselines(historical_data, "discovery")
    
    # Save everything
    manager.baselines["discovery"] = baselines
    manager.models["discovery"] = models
    manager.scalers["discovery"] = scalers
    manager.save_models("discovery")
    
    return models, scalers, baselines  # Make sure to return the tuple
    
#     # Save everything
#     manager.baselines["discovery"] = baselines
#     manager.models["discovery"] = models
#     manager.scalers["discovery"] = scalers
#     manager.save_models("discovery")
    
#     return models, scalers, baselines

def train_metadata_access_models(historical_data, config):
    """
    Train specialized models for metadata access anomaly detection.
    Supports: v3_linux_rare_metadata_process, v3_linux_rare_metadata_user
    
    Args:
        historical_data (pd.DataFrame): Historical metadata data
        config (dict): Configuration dictionary
        
    Returns:
        tuple: (models, scalers, baselines)
    """
    logger.info("Training specialized metadata access anomaly detection models")
    
    manager = LinuxModelManager(config)
    
    # Train models
    models, scalers = manager.train_models(historical_data, "metadata")
    baselines = manager.establish_baselines(historical_data, "metadata")
    
    # Save everything
    manager.baselines["metadata"] = baselines
    manager.models["metadata"] = models
    manager.scalers["metadata"] = scalers
    manager.save_models("metadata")
    
    return models, scalers, baselines

import numpy as np
import pandas as pd
import re
import os
import logging
import joblib
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import DBSCAN, KMeans
from sklearn.svm import OneClassSVM
from sklearn.neighbors import NearestNeighbors
import warnings
from typing import Dict, Tuple, List, Optional, Callable
from detection_methods import extract_ml_features
from entity_alignment import clean_network_data_for_training

logger = logging.getLogger("linux_anomaly_detection")
def filter_process_data(df):
    """Filter process data for anomaly detection."""
    if 'process.name' not in df.columns:
        return df
    return df[df['process.name'].notna()]

def filter_host_process(df):
    """Filter process data by host."""
    if 'host.hostname' not in df.columns or 'process.name' not in df.columns:
        return df
    return df[df['host.hostname'].notna() & df['process.name'].notna()]

def filter_network_ip(df):
    """Filter network data by IP."""
    if 'destination.ip' not in df.columns:
        return df
    return df[df['destination.ip'].notna()]

def filter_network_port(df):
    """Filter network data by port."""
    if 'destination.port' not in df.columns:
        return df
    return df[df['destination.port'].notna()]
def filter_sudo_users(df):
    return df[df['process.name'] == 'sudo'] if 'process.name' in df.columns else df

def filter_compiler_users(df):
    compiler_list = ['gcc', 'g++', 'clang', 'make', 'cmake', 'javac', 'rustc', 'go', 'python', 'perl']
    return df[df['process.name'].isin(compiler_list)] if 'process.name' in df.columns else df

def filter_network_config(df):
    commands = ['ifconfig', 'ip', 'route', 'iptables', 'netstat', 'ss']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

def filter_network_connection(df):
    commands = ['netstat', 'ss', 'lsof', 'nmap', 'nc', 'telnet']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

def filter_system_info(df):
    commands = ['uname', 'hostname', 'hostnamectl', 'systeminfo', 'lscpu', 'lshw', 'dmidecode', 'cat', 'more', 'less']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

def filter_process_discovery(df):
    commands = ['ps', 'top', 'htop', 'pgrep', 'pidof', 'pstree', 'lsof']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

def filter_user_discovery(df):
    commands = ['who', 'w', 'last', 'lastlog', 'id', 'users', 'finger', 'getent']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

def filter_linux_process(df):
    commands = ['bash', 'sh', 'zsh', 'ksh', 'csh']
    return df[df['process.name'].isin(commands)] if 'process.name' in df.columns else df

class LinuxModelManager:
    """
    FIXED: Complete model manager with correct job-specific implementations.
    Each job gets appropriate entity selection, filtering, and features.
    """
    
    def __init__(self, config):
        self.config = config
        self.models = {}
        self.scalers = {}
        self.baselines = {}
        self.feature_definitions = {}
        self.model_metadata = {}
        self.common_ports = []
        # Replace lambda functions with named functions
        self.job_definitions = {
            "process": {
            "v3_linux_anomalous_process_all_hosts": {
                "entity_column": "process.name",
                "secondary_entity": None,
                "filter_func": filter_process_data,
                "description": "Global process anomaly detection"
            },
            "v3_rare_process_by_host_linux": {
                "entity_column": "composite:host_process",
                "secondary_entity": "process.name",
                "filter_func": filter_host_process,
                "description": "Host-specific rare process detection"
            }
            },
            "network": {
            "v3_linux_anomalous_network_activity": {
                "entity_column": "destination.ip",
                "secondary_entity": "composite:ip_port",
                "filter_func": filter_network_ip,
                "description": "IP-based network anomaly detection"
            },
            "v3_linux_anomalous_network_port_activity": {
                "entity_column": "destination.port",
                "secondary_entity": "composite:ip_port",
                "filter_func": filter_network_port,
                "description": "Port-based anomaly detection"
            }
            },
            "user": {
            "v3_linux_anomalous_user_name": {
                "entity_column": "user.name",
                "secondary_entity": "composite:user_host",
                "filter_func": None,
                "description": "General user behavior anomaly detection"
            },
            "v3_linux_rare_sudo_user": {
                "entity_column": "user.name",
                "secondary_entity": None,
                "filter_func": filter_sudo_users,  # Use named function
                "description": "Rare sudo usage detection"
            },
            "v3_linux_rare_user_compiler": {
                "entity_column": "user.name",
                "secondary_entity": None,
                "filter_func": filter_compiler_users,  # Use named function
                "description": "Rare compiler usage detection"
            }
            },
            "discovery": {
            "v3_linux_network_configuration_discovery": {
                "entity_column": "process.name",
                "secondary_entity": "user.name",
                "filter_func": filter_network_config,  # Use named function
                "description": "Network configuration discovery detection"
            },
            "v3_linux_network_connection_discovery": {
                "entity_column": "process.name",
                "secondary_entity": "user.name",
                "filter_func": filter_network_connection,  # Use named function
                "description": "Network connection discovery detection"
            },
            "v3_linux_system_information_discovery": {
                "entity_column": "process.name",
                "secondary_entity": "user.name",
                "filter_func": filter_system_info,  # Use named function
                "description": "System information discovery detection"
            },
            "v3_linux_system_process_discovery": {
                "entity_column": "process.name",
                "secondary_entity": "user.name",
                "filter_func": filter_process_discovery,  # Use named function
                "description": "Process discovery detection"
            },
            "v3_linux_system_user_discovery": {
                "entity_column": "process.name",
                "secondary_entity": "user.name",
                "filter_func": filter_user_discovery,  # Use named function
                "description": "User discovery detection"
            }
            },
            "metadata": {
            "v3_linux_rare_metadata_process": {
                "entity_column": "composite:process_args",
                "secondary_entity": "process.name",
                "filter_func": None,
                "description": "Rare process arguments detection"
            },
            "v3_linux_rare_metadata_user": {
                "entity_column": "composite:user_group",
                "secondary_entity": "user.name",
                "filter_func": None,
                "description": "Rare user/group combination detection"
            }
            }
        }
        
        # # Define discovery command groups for better organization
        # self.discovery_commands = {
        #     'network_config': ['ifconfig', 'ip', 'route', 'iptables', 'tc', 'ethtool'],
        #     'network_connection': ['netstat', 'ss', 'lsof', 'nmap', 'nc', 'telnet'],
        #     'system_info': ['uname', 'hostname', 'hostnamectl', 'systeminfo', 'lscpu', 'lshw', 'dmidecode'],
        #     'process_discovery': ['ps', 'top', 'htop', 'pgrep', 'pidof', 'pstree'],
        #     'user_discovery': ['who', 'w', 'last', 'lastlog', 'id', 'users', 'finger', 'getent']
        # }
        
        # # Common service ports for focused training
        # self.common_ports = [
        #     21, 22, 23, 25, 53, 80, 110, 143, 443, 445,  # Standard services
        #     1433, 3306, 3389, 5432, 5900, 6379,  # Databases and remote access
        #     8080, 8443, 9200, 27017,  # Web and NoSQL
        #     4444, 4445, 31337, 1337  # Common backdoor ports
            
        # ]
        self.discovery_commands = {
        'network_config': [
            'ifconfig', 'ip', 'route', 'iptables', 'tc', 'ethtool',
            'iwconfig', 'nmcli', 'brctl', 'bridge', 'networkctl',
            'firewall-cmd', 'ufw', 'nft', 'ipset', 'arptables',
            'dig', 'nslookup', 'host', 'resolvectl', 'traceroute'
        ],
        'network_connection': [
            'netstat', 'ss', 'lsof', 'nmap', 'nc', 'telnet',
            'socat', 'tcpdump', 'tshark', 'wireshark-cli',
            'arp', 'ping', 'mtr', 'curl', 'wget',
            'sockstat', 'netcat', 'iftop', 'nethogs'
        ],
        'system_info': [
            'uname', 'hostname', 'hostnamectl', 'systeminfo', 'lscpu', 'lshw', 'dmidecode',
            'cat /proc/cpuinfo', 'cat /proc/meminfo', 'free', 'df', 'du',
            'lsblk', 'blkid', 'fdisk', 'parted', 'mount',
            'systemctl', 'service', 'journalctl', 'dmesg',
            'uptime', 'vmstat', 'iostat', 'mpstat'
        ],
        'process_discovery': [
            'ps', 'top', 'htop', 'pgrep', 'pidof', 'pstree',
            'atop', 'lsof', 'fuser', 'strace', 'ltrace',
            '/proc', 'sysctl', 'systemctl status',
            'jobs', 'bg', 'fg', 'nice', 'renice',
            'kill', 'pkill', 'killall', 'xkill'
        ],
        'user_discovery': [
            'who', 'w', 'last', 'lastlog', 'id', 'users', 'finger', 'getent',
            'cat /etc/passwd', 'cat /etc/group', 'cat /etc/shadow',
            'groups', 'whoami', 'sudo -l', 'su', 'useradd',
            'usermod', 'userdel', 'passwd', 'chage',
            'ac', 'lastcomm', 'aureport', 'ausearch'
        ]
    }

        self.common_ports = [
            # Standard services
            20, 21,       # FTP
            22,           # SSH
            23,           # Telnet
            25, 587, 465, # SMTP, SUBMISSION, SMTPS
            53,           # DNS
            67, 68,       # DHCP
            80, 443,      # HTTP, HTTPS
            110, 995,     # POP3, POP3S
            143, 993,     # IMAP, IMAPS
            389, 636,     # LDAP, LDAPS
            445,          # SMB
            514,          # Syslog
            
            # Databases
            1433, 1434,   # MSSQL
            3306,         # MySQL/MariaDB
            5432,         # PostgreSQL
            6379,         # Redis
            27017, 27018, # MongoDB
            9200, 9300,   # Elasticsearch
            
            # Remote Access & Management
            3389,         # RDP
            5900, 5901,   # VNC
            5985, 5986,   # WinRM
            22222,        # Alternative SSH
            
            # Web Services
            8080, 8443,   # Alternative HTTP/HTTPS
            8008, 8888,   # Alternative HTTP
            4443,         # Alternative HTTPS
            9000,         # Common dev port
            
            # Common Backdoor Ports
            4444, 4445,   # Metasploit
            31337, 1337,  # Historical backdoors
            6666, 6667,   # IRC/Backdoors
            
            # Application Specific
            2375, 2376,   # Docker
            6443,         # Kubernetes
            8472,         # Kubernetes overlay network
            10250,        # Kubernetes kubelet
            
            # Monitoring & Logging
            8125,         # StatsD
            9090, 9091,   # Prometheus
            9100,         # Node Exporter
            5601          # Kibana
        ]
    
    # def train_models(self, historical_data: pd.DataFrame, data_type: str = "process") -> Tuple[Dict, Dict]:
    #     """
    #     FIXED: Train models with job-specific entity selection and filtering.
    #     """
    #     logger.info(f"Training {data_type} anomaly detection models with {len(historical_data):,} records")
        
    #     if historical_data.empty:
    #         logger.warning(f"No historical data for training {data_type} models")
    #         return {}, {}
        
    #     # Extract features first
    #     try:
    #         # feature_data = extract_ml_features(historical_data, self.config)
    #         filtered_data = historical_data.copy()
    #         job_name = list(self.job_definitions.get(data_type, {}).keys())[0] if self.job_definitions.get(data_type) else "default_job"
    #         config = self.config.get("features", {}).get(data_type, {})
    #         feature_data = extract_ml_features(filtered_data, config, job_name)
    #         logger.info(f"Extracted features, resulting in {len(feature_data.columns)} features")
    #     except Exception as e:
    #         logger.error(f"Feature extraction failed: {e}, using basic features")
    #         feature_data = self._add_basic_features(historical_data)
        
    #     if feature_data.empty:
    #         logger.error("Feature extraction resulted in empty dataframe")
    #         return {}, {}
        
    #     all_models = {}
    #     all_scalers = {}
        
    #     # Get job definitions for this data type
    #     jobs = self.job_definitions.get(data_type, {})
        
    #     if not jobs:
    #         logger.warning(f"No job definitions found for data type: {data_type}")
    #         return {}, {}
        
    #     # Process each job separately
    #     for job_name, job_config in jobs.items():
    #         logger.info(f"\n{'='*60}")
    #         logger.info(f"Training models for job: {job_name}")
    #         logger.info(f"Description: {job_config.get('description', 'N/A')}")
    #         logger.info(f"{'='*60}")
            
    #         # Apply job-specific filtering
    #         if job_config.get('filter_func'):
    #             try:
    #                 working_data = job_config['filter_func'](feature_data)
    #                 logger.info(f"Applied filter: {len(feature_data)} -> {len(working_data)} records")
    #             except Exception as e:
    #                 logger.error(f"Filter function failed: {e}")
    #                 working_data = feature_data.copy()
    #         else:
    #             working_data = feature_data.copy()
            
    #         if working_data.empty:
    #             logger.warning(f"No data after filtering for {job_name}")
    #             continue
            
    #         # Create composite entity columns if needed
    #         entity_column = job_config['entity_column']
            
    #         if entity_column.startswith('composite:'):
    #             composite_type = entity_column.replace('composite:', '')
    #             entity_column = self._create_composite_entity(working_data, composite_type)
                
    #             if not entity_column:
    #                 logger.error(f"Failed to create composite entity for {job_name}")
    #                 continue
            
    #         # Verify entity column exists
    #         if entity_column not in working_data.columns:
    #             logger.error(f"Entity column '{entity_column}' not found for {job_name}")
    #             logger.info(f"Available columns: {list(working_data.columns)[:10]}")
    #             continue
            
    #         # Train primary entity models
    #         primary_models, primary_scalers = self._train_entity_models(
    #             working_data,
    #             entity_column,
    #             job_name,
    #             data_type
    #         )
            
    #         # Add models with job prefix
    #         for entity, model in primary_models.items():
    #             model_key = f"{job_name}:{entity}"
    #             all_models[model_key] = model
    #             logger.debug(f"Added model: {model_key}")
            
    #         for entity, scaler in primary_scalers.items():
    #             scaler_key = f"{job_name}:{entity}"
    #             all_scalers[scaler_key] = scaler
            
    #         # Train secondary entity models if specified
    #         if job_config.get('secondary_entity'):
    #             secondary_entity = job_config['secondary_entity']
                
    #             if secondary_entity.startswith('composite:'):
    #                 composite_type = secondary_entity.replace('composite:', '')
    #                 secondary_entity = self._create_composite_entity(working_data, composite_type)
                
    #             if secondary_entity and secondary_entity in working_data.columns:
    #                 logger.info(f"Training secondary models on: {secondary_entity}")
    #                 secondary_models, secondary_scalers = self._train_entity_models(
    #                     working_data,
    #                     secondary_entity,
    #                     f"{job_name}_secondary",
    #                     data_type
    #                 )
                    
    #                 for entity, model in secondary_models.items():
    #                     model_key = f"{job_name}_ctx:{entity}"
    #                     all_models[model_key] = model
    #                     logger.debug(f"Added secondary model: {model_key}")
                    
    #                 for entity, scaler in secondary_scalers.items():
    #                     scaler_key = f"{job_name}_ctx:{entity}"
    #                     all_scalers[scaler_key] = scaler
        
    #     # Store metadata
    #     self.model_metadata[data_type] = {
    #         "total_models": len(all_models),
    #         "total_scalers": len(all_scalers),
    #         "jobs_trained": list(jobs.keys()),
    #         "training_timestamp": datetime.now().isoformat(),
    #         "training_samples": len(historical_data)
    #     }
        
    #     logger.info(f"\n{'='*60}")
    #     logger.info(f"Training complete for {data_type}")
    #     logger.info(f"Total models trained: {len(all_models)}")
    #     logger.info(f"Total scalers created: {len(all_scalers)}")
    #     logger.info(f"{'='*60}")
        
    #     return all_models, all_scalers
    def train_models(self, historical_data: pd.DataFrame, data_type: str = "process") -> Tuple[Dict, Dict]:
        """Train models with proper entity handling and improved error handling."""
        logger.info(f"Training {data_type} anomaly detection models with {len(historical_data):,} records")
        
        if historical_data.empty:
            logger.warning(f"No historical data for training {data_type} models")
            return {}, {}
        
        # Extract features first
        try:
            filtered_data = historical_data.copy()
            job_name = list(self.job_definitions.get(data_type, {}).keys())[0] if self.job_definitions.get(data_type) else "default_job"
            config = self.config.get("features", {}).get(data_type, {})
            
            # Add basic features before extraction
            filtered_data = self._add_basic_features(filtered_data)
            
            # Extract ML features
            feature_data = extract_ml_features(filtered_data, config, job_name)
            logger.info(f"Extracted features, resulting in {len(feature_data.columns)} features")
            
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}, using basic features only")
            feature_data = filtered_data
        
        if feature_data.empty:
            logger.error("Feature extraction resulted in empty dataframe")
            return {}, {}
        
        all_models = {}
        all_scalers = {}
        
        # Get job definitions for this data type
        jobs = self.job_definitions.get(data_type, {})
        
        if not jobs:
            logger.warning(f"No job definitions found for data type: {data_type}")
            return {}, {}
        
        # Process each job separately
        for job_name, job_config in jobs.items():
            logger.info(f"\n{'='*60}")
            logger.info(f"Training models for job: {job_name}")
            logger.info(f"Description: {job_config.get('description', 'N/A')}")
            logger.info(f"{'='*60}")
            
            # Apply job-specific filtering
            try:
                working_data = feature_data.copy()
                if job_config.get('filter_func'):
                    working_data = job_config['filter_func'](working_data)
                    logger.info(f"Applied filter: {len(feature_data)} -> {len(working_data)} records")
            except Exception as e:
                logger.error(f"Filter function failed for {job_name}: {e}")
                continue
            
            if working_data.empty:
                logger.warning(f"No data after filtering for {job_name}")
                continue
            
            # Create composite entity columns if needed
            try:
                entity_column = job_config['entity_column']
                
                if entity_column.startswith('composite:'):
                    composite_type = entity_column.replace('composite:', '')
                    entity_column = self._create_composite_entity(working_data, composite_type)
                    
                    if not entity_column:
                        logger.error(f"Failed to create composite entity for {job_name}")
                        continue
                
                # Verify entity column exists
                if entity_column not in working_data.columns:
                    logger.error(f"Entity column '{entity_column}' not found for {job_name}")
                    logger.info(f"Available columns: {list(working_data.columns)}")
                    continue
                
                # Train primary entity models
                primary_models, primary_scalers = self._train_entity_models(
                    working_data,
                    entity_column,
                    job_name,
                    data_type
                )
                
                if not primary_models or not primary_scalers:
                    logger.error(f"No models trained for {job_name}")
                    continue
                
                # Add models with job prefix
                for entity, model in primary_models.items():
                    model_key = f"{job_name}:{entity}"
                    all_models[model_key] = model
                
                for entity, scaler in primary_scalers.items():
                    scaler_key = f"{job_name}:{entity}"
                    all_scalers[scaler_key] = scaler
                
                # Train secondary entity models if specified
                if job_config.get('secondary_entity'):
                    try:
                        secondary_entity = job_config['secondary_entity']
                        
                        if secondary_entity.startswith('composite:'):
                            composite_type = secondary_entity.replace('composite:', '')
                            secondary_entity = self._create_composite_entity(working_data, composite_type)
                        
                        if secondary_entity and secondary_entity in working_data.columns:
                            logger.info(f"Training secondary models on: {secondary_entity}")
                            secondary_models, secondary_scalers = self._train_entity_models(
                                working_data,
                                secondary_entity,
                                f"{job_name}_secondary",
                                data_type
                            )
                            
                            if secondary_models and secondary_scalers:
                                for entity, model in secondary_models.items():
                                    model_key = f"{job_name}_ctx:{entity}"
                                    all_models[model_key] = model
                                
                                for entity, scaler in secondary_scalers.items():
                                    scaler_key = f"{job_name}_ctx:{entity}"
                                    all_scalers[scaler_key] = scaler
                    except Exception as e:
                        logger.error(f"Error training secondary models for {job_name}: {e}")
                        
            except Exception as e:
                logger.error(f"Error processing job {job_name}: {e}")
                continue
        
        # Store metadata
        self.model_metadata[data_type] = {
            "total_models": len(all_models),
            "total_scalers": len(all_scalers),
            "jobs_trained": list(jobs.keys()),
            "training_timestamp": datetime.now().isoformat(),
            "training_samples": len(historical_data)
        }
        
        logger.info(f"\n{'='*60}")
        logger.info(f"Training complete for {data_type}")
        logger.info(f"Total models trained: {len(all_models)}")
        logger.info(f"Total scalers created: {len(all_scalers)}")
        logger.info(f"{'='*60}")
        
        return all_models, all_scalers
    def _create_composite_entity(self, data: pd.DataFrame, composite_type: str) -> Optional[str]:
        """Create composite entity columns with proper validation."""
        column_name = f"entity_{composite_type}"
        
        try:
            if composite_type == "host_process":
                if 'host.hostname' in data.columns and 'process.name' in data.columns:
                    # Clean hostname and process name
                    hostname = data['host.hostname'].fillna('unknown_host')
                    process = data['process.name'].fillna('unknown_process')
                    
                    # Create composite key
                    data[column_name] = hostname + ':' + process
                    
                    # Count unique combinations
                    unique_combinations = data[column_name].nunique()
                    logger.info(f"Created {unique_combinations} host:process combinations")
                    
                    if unique_combinations == 0:
                        logger.error("No valid host:process combinations found")
                        return None
                        
                    return column_name
                else:
                    logger.error("Missing required columns: host.hostname and/or process.name")
                    return None
                    
            elif composite_type == "ip_port":
                if 'destination.ip' in data.columns and 'destination.port' in data.columns:
                    # Validate IP addresses
                    def validate_ip(ip):
                        try:
                            import ipaddress
                            ipaddress.ip_address(str(ip))
                            return ip
                        except:
                            return '0.0.0.0'
                    
                    # Clean and validate IPs
                    ip_str = data['destination.ip'].apply(validate_ip).fillna('0.0.0.0').astype(str)
                    
                    # Validate ports (ensure numeric and in valid range)
                    def validate_port(port):
                        try:
                            p = int(float(port))
                            return str(p) if 0 <= p <= 65535 else '0'
                        except:
                            return '0'
                            
                    port_str = data['destination.port'].apply(validate_port)
                    
                    # Create composite key
                    data[column_name] = ip_str + ':' + port_str
                    
                    # Filter out invalid combinations
                    invalid_mask = data[column_name].isin(['0.0.0.0:0', ':0', '0.0.0.0:'])
                    data.loc[invalid_mask, column_name] = None
                    
                    unique_combinations = data[column_name].nunique()
                    logger.info(f"Created {unique_combinations} valid IP:Port combinations")
                    
                    if unique_combinations == 0:
                        logger.error("No valid IP:Port combinations found!")
                        return None
                        
                    return column_name
                    
                else:
                    logger.error("Missing required columns: destination.ip and/or destination.port")
                    return None
                    
        except Exception as e:
            logger.error(f"Error creating composite entity {composite_type}: {e}")
            return None

    # def _create_composite_entity(self, data: pd.DataFrame, composite_type: str) -> Optional[str]:
    #     """
    #     Create composite entity columns for specific job requirements.
    #     """
    #     column_name = f"entity_{composite_type}"
        
    #     try:
    #         if composite_type == "host_process":
    #             if 'host.hostname' in data.columns and 'process.name' in data.columns:
    #                 data[column_name] = (
    #                     data['host.hostname'].fillna('unknown').astype(str) + ':' +
    #                     data['process.name'].fillna('unknown').astype(str)
    #                 )
    #                 logger.info(f"Created composite entity: {column_name}")
    #                 return column_name
            
    #         elif composite_type == "ip_port":
    #             if 'destination.ip' in data.columns and 'destination.port' in data.columns:
    #                 data[column_name] = (
    #                     data['destination.ip'].fillna('0.0.0.0').astype(str) + ':' +
    #                     data['destination.port'].fillna('0').astype(str)
    #                 )
    #                 logger.info(f"Created composite entity: {column_name}")
    #                 return column_name
            
    #         elif composite_type == "process_args":
    #             if 'process.name' in data.columns:
    #                 if 'process.args' in data.columns:
    #                     # Include arguments if available
    #                     data[column_name] = (
    #                         data['process.name'].fillna('unknown').astype(str) + '::' +
    #                         data['process.args'].fillna('').astype(str).str[:100]  # Limit args length
    #                     )
    #                 else:
    #                     # Fall back to just process name
    #                     data[column_name] = data['process.name'].fillna('unknown').astype(str)
    #                 logger.info(f"Created composite entity: {column_name}")
    #                 return column_name
            
    #         elif composite_type == "user_group":
    #             if 'user.name' in data.columns:
    #                 if 'user.group' in data.columns:
    #                     data[column_name] = (
    #                         data['user.name'].fillna('unknown').astype(str) + '::' +
    #                         data['user.group'].fillna('unknown').astype(str)
    #                     )
    #                 else:
    #                     # Fall back to just user name
    #                     data[column_name] = data['user.name'].fillna('unknown').astype(str)
    #                 logger.info(f"Created composite entity: {column_name}")
    #                 return column_name
            
    #     except Exception as e:
    #         logger.error(f"Failed to create composite entity {composite_type}: {e}")
        
    #     return None
    def get_models_for_group(self, data_type: str) -> Tuple[Dict, Dict, Dict]:
        """
        FIXED: Get models, scalers, and baselines for a data group.
        """
        models = self.models.get(data_type, {})
        scalers = self.scalers.get(data_type, {})
        baselines = self.baselines.get(data_type, {})
        
        logger.debug(f"Retrieved {len(models)} models, {len(scalers)} scalers, {len(baselines)} baselines for {data_type}")
        
        return models, scalers, baselines
    def _prepare_features_for_entity(self, data: pd.DataFrame, entity_column: str) -> pd.DataFrame:
        """
        Ensure all numeric features required for modeling are present.
        Specifically adds port-related features if entity is a port.
        """
        feature_data = data.copy()
        
        # Add basic features if not already present
        feature_data = self._add_basic_features(feature_data)
        
        # If this is a port entity, make sure port_number exists
        if 'port' in entity_column.lower() or entity_column == 'destination.port':
            if 'port_number' not in feature_data.columns:
                feature_data['port_number'] = pd.to_numeric(feature_data[entity_column], errors='coerce').fillna(0)
            if 'is_common_port' not in feature_data.columns:
                feature_data['is_common_port'] = feature_data['port_number'].apply(lambda x: 1 if x in self.common_ports else 0)
            if 'is_high_port' not in feature_data.columns:
                feature_data['is_high_port'] = (feature_data['port_number'] > 1024).astype(int)

        return feature_data
    def _train_entity_models(self, data: pd.DataFrame, entity_column: str, 
                            job_name: str, data_type: str) -> Tuple[Dict, Dict]:
        """Train models for specific entities within a job."""
        models = {}
        scalers = {}
        
        # Configure model parameters
        ml_config = self.config.get("ml", {})
        contamination = ml_config.get("contamination", 0.1)  
        min_samples = ml_config.get("min_samples", 50)  
        
        # Get unique entities
        entities = data[entity_column].unique()
        print(f"DEBUG: Initial entities count: {len(entities)}")
        
        # Special handling for port entities
        if 'port' in entity_column.lower() or entity_column == 'destination.port':
            # Convert ports to numeric if they aren't already
            data[entity_column] = pd.to_numeric(data[entity_column], errors='coerce')
            entities = self._filter_port_entities(data, entity_column, min_samples=20)
            logger.info(f"Filtered to {len(entities)} port entities")
            print(f"DEBUG: Port entities after filtering: {entities[:5]}")
        
        logger.info(f"Training models for {len(entities)} entities in {job_name}")
        
        successful_models = 0
        for entity in entities:
            print(f"\nDEBUG: Processing entity: {entity}")
            # FIXED: Convert entity to numeric for comparison when dealing with ports
            if 'port' in entity_column.lower():
                numeric_entity = float(entity)
                entity_data = data[data[entity_column] == numeric_entity].copy()
            else:
                entity_data = data[data[entity_column] == entity].copy()
                
            print(f"DEBUG: Entity data shape: {entity_data.shape}")
            
            if len(entity_data) < min_samples:
                print(f"DEBUG: Insufficient samples for {entity}: {len(entity_data)} < {min_samples}")
                continue
            
            try:
                # Select features
                features = self._select_features_for_job(entity_data, job_name, data_type)
                print(f"DEBUG: Selected features count: {len(features)}")
                print(f"DEBUG: Features: {features[:5]}")
                
                if not features:
                    print(f"DEBUG: No valid features for entity: {entity}")
                    continue
                
                # Prepare feature matrix
                X = entity_data[features].values
                print(f"DEBUG: Feature matrix shape: {X.shape}")
                
                # Handle NaN and infinite values
                X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
                
                # Check for valid data
                print(f"DEBUG: Any NaN in X: {np.isnan(X).any()}")
                print(f"DEBUG: Any Inf in X: {np.isinf(X).any()}")
                
                # Scale features
                scaler = RobustScaler()
                X_scaled = scaler.fit_transform(X)
                print(f"DEBUG: Scaled matrix shape: {X_scaled.shape}")
                
                # Store scaler with feature names
                scaler.feature_names_in_ = features
                scalers[entity] = scaler
                
                # Initialize model dict
                entity_models = {}
                
                # Train Isolation Forest
                print(f"DEBUG: Training Isolation Forest for {entity}")
                iso_forest = IsolationForest(
                    contamination=contamination,
                    n_estimators=100,
                    max_samples='auto',
                    random_state=42,
                    n_jobs=1
                )
                iso_forest.fit(X_scaled)
                entity_models["isolation_forest"] = iso_forest
                
                # Train LOF if enough samples
                if len(X_scaled) >= 20:
                    print(f"DEBUG: Training LOF for {entity}")
                    try:
                        lof = LocalOutlierFactor(
                            n_neighbors=min(20, len(X_scaled) // 4),
                            contamination=contamination,
                            novelty=True
                        )
                        lof.fit(X_scaled)
                        entity_models["lof"] = lof
                    except Exception as e:
                        print(f"DEBUG: LOF training failed for {entity}: {e}")
                
                # Store metadata
                entity_models["features_used"] = features
                entity_models["training_samples"] = len(X_scaled)
                entity_models["job_name"] = job_name
                entity_models["entity_type"] = entity_column
                entity_models["data_type"] = data_type
                
                models[entity] = entity_models
                successful_models += 1
                print(f"DEBUG: Successfully trained models for {entity}")
                
            except Exception as e:
                print(f"DEBUG: Failed to train model for {entity}: {e}")
                logger.error(f"Failed to train model for {entity}: {e}")
                continue
        
        logger.info(f"Successfully trained {successful_models} models for {job_name}")
        return models, scalers

    

    # def _filter_port_entities(self, data: pd.DataFrame, entity_column: str, 
    #                         min_samples: int = 20) -> List:  # Lowered threshold
    #     """
    #     Special filtering for port entities to focus on important ports.
    #     """
    #     try:
    #         # Convert ports to numeric, handling common formats
    #         data['port_numeric'] = pd.to_numeric(data[entity_column].astype(str).str.extract('(\d+)', expand=False), 
    #                                         errors='coerce')
            
    #         # Get port frequency
    #         port_counts = data['port_numeric'].value_counts()
            
    #         # Lower threshold for common ports
    #         common_port_threshold = min(10, min_samples // 2)
            
    #         # Get ports with samples
    #         frequent_ports = port_counts[port_counts >= min_samples].index.tolist()
            
    #         # Always include common service ports if they have any data
    #         important_ports = []
    #         for port in self.common_ports:
    #             if port in port_counts.index and port_counts[port] >= common_port_threshold:
    #                 important_ports.append(port)
            
    #         # Combine and deduplicate
    #         all_ports = list(set(frequent_ports + important_ports))
            
    #         # Convert back to original format
    #         port_entities = [str(int(p)) for p in all_ports if pd.notna(p)]
            
    #         logger.info(f"Selected {len(port_entities)} ports for modeling from {len(port_counts)} unique ports")
    #         logger.debug(f"Port selection: {port_entities[:20]}")
            
    #         return port_entities
            
    #     except Exception as e:
    #         logger.error(f"Error in port filtering: {e}")
    #         return list(data[entity_column].unique())[:100]  # Fallback
    def _filter_port_entities(self, data: pd.DataFrame, entity_column: str, 
                         min_samples: int = 20) -> List[str]:
        """Special filtering for port entities to focus on important ports."""
        try:
            # Handle composite entities
            if 'composite:' in entity_column:
                # Extract port from composite key
                data['port_numeric'] = data['destination.port'].astype(str).str.extract('(\d+)').astype(float)
            else:
                # Convert ports to numeric
                data['port_numeric'] = pd.to_numeric(data[entity_column], errors='coerce')
            
            # Get port frequency
            port_counts = data['port_numeric'].value_counts()
            
            # Get ports with enough samples
            frequent_ports = port_counts[port_counts >= min_samples].index.tolist()
            
            # Add common service ports if they have any data
            important_ports = []
            for port in self.common_ports:
                if port in port_counts.index and port_counts[port] >= min_samples // 2:
                    important_ports.append(port)
            
            # Combine and deduplicate
            all_ports = list(set(frequent_ports + important_ports))
            
            # Convert to strings
            port_entities = [str(int(p)) for p in all_ports if pd.notna(p)]
            
            logger.info(f"Selected {len(port_entities)} ports for modeling from {len(port_counts)} unique ports")
            
            return port_entities
            
        except Exception as e:
            logger.error(f"Error in port filtering: {e}")
            return []


    
    def _select_features_for_job(self, data: pd.DataFrame, job_name: str, data_type: str) -> List[str]:
        """Select appropriate features based on job type."""
        
        # Add derived network features
        if data_type == "network":
            try:
                # Convert existing columns to numeric
                data['bytes_total'] = pd.to_numeric(data['destination.bytes'], errors='coerce') + \
                                    pd.to_numeric(data['source.bytes'], errors='coerce')
                data['port_number'] = pd.to_numeric(data['destination.port'], errors='coerce')
                
                # Add network-specific features
                data['is_internal_ip'] = data['destination.ip'].str.startswith(('10.', '172.', '192.168.', '127.')).astype(int)
                data['is_common_port'] = data['port_number'].isin(self.common_ports).astype(int)
                data['connection_count'] = 1  # Will be aggregated later
                data['data_volume'] = np.log1p(data['bytes_total'])
                
                # Add temporal features if not present
                if '@timestamp' in data.columns:
                    data['hour'] = pd.to_datetime(data['@timestamp']).dt.hour
                    data['minute'] = pd.to_datetime(data['@timestamp']).dt.minute
                    data['connection_duration'] = 0  # Placeholder for future enhancement
            except Exception as e:
                logger.warning(f"Error adding network features: {e}")
        
        # Get numeric columns including derived features
        numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
        
        # Remove entity columns and identifiers
        exclude_patterns = [
            'process.name', 'user.name', 'host.hostname',
            'agent.id', '.id$', '_id$', 'timestamp'
        ]
        
        valid_features = []
        for col in numeric_cols:
            if not any(re.search(pattern, col) for pattern in exclude_patterns):
                if col in data.columns:
                    col_values = data[col].dropna()
                    if len(col_values) > 0 and col_values.std() > 1e-8:
                        valid_features.append(col)
        
        logger.debug(f"Valid features after filtering: {valid_features[:5]}")
        
        # Ensure minimum feature set
        if len(valid_features) < 3:
            logger.warning("Too few valid features, adding basic metrics")
            basic_features = ['bytes_total', 'data_volume', 'is_common_port']
            valid_features.extend([f for f in basic_features if f in data.columns])
        
        return list(set(valid_features))  # Deduplicate
    
    def _get_priority_features(self, job_name: str, data_type: str) -> List[str]:
        """
        Get priority features for specific job types.
        """
        priority_map = {
            "process": [
                "hour_sin", "hour_cos", "day_sin", "day_cos",
                "is_business_hours", "is_weekend", "event_count",
                "process_name_length", "execution_frequency"
            ],
            "network": [
                "port_number", "is_internal_ip", "connection_count",
                "data_volume", "connection_duration", "hour_sin", "hour_cos"
            ],
            "user": [
                "login_frequency", "command_diversity", "sudo_count",
                "session_duration", "hour_sin", "hour_cos", "is_business_hours"
            ],
            "discovery": [
                "discovery_breadth", "command_sequence", "output_size",
                "execution_speed", "hour_sin", "hour_cos"
            ],
            "metadata": [
                "argument_length", "argument_entropy", "special_char_count",
                "path_depth", "command_complexity"
            ]
        }
        
        return priority_map.get(data_type, [])
    
    
        
    #     return baselines
    def _get_entity_column(self, data_type: str) -> str:
        """
        Get appropriate entity column for data type.
        
        Args:
            data_type (str): Type of data (process, network, user, discovery, metadata)
            
        Returns:
            str: Name of the entity column to use
        """
        entity_map = {
            "process": "process.name",
            "network": "destination.ip", 
            "user": "user.name",
            "discovery": "process.name",
            "metadata": "process.name"
        }
        
        # Get the default entity column for this data type
        entity_column = entity_map.get(data_type)
        
        if not entity_column:
            logger.warning(f"Unknown data type: {data_type}, defaulting to process.name")
            entity_column = "process.name"
        
        logger.debug(f"Selected entity column '{entity_column}' for {data_type}")
        return entity_column
    
    def establish_baselines(self, historical_data: pd.DataFrame, data_type: str = "process") -> Dict:
        """
        Establish baseline patterns for Linux entities based on data type.
        """
        logger.info(f"Establishing baselines for {data_type} with {len(historical_data):,} records")
        
        if historical_data.empty:
            logger.warning(f"No historical data for establishing {data_type} baselines")
            return {}
        
        baselines = {}
        entity_col = self._get_entity_column(data_type)
        
        # Ensure entity column exists
        if entity_col not in historical_data.columns:
            logger.warning(f"Entity column '{entity_col}' not found, using global baseline")
            historical_data[entity_col] = 'global'
        
        # Add event count if not present
        if "event_count" not in historical_data.columns:
            historical_data["event_count"] = 1
        
        # Group by entity and calculate baselines
        try:
            grouped = historical_data.groupby(entity_col)

            for entity, group in grouped:
                if len(group) < 5:  # Skip entities with too few samples
                    continue
                
                # Calculate statistical baselines
                stats = {
                    "count": len(group),
                    "mean": float(group["event_count"].mean()),
                    "std": float(group["event_count"].std()),
                    "min": float(group["event_count"].min()),
                    "max": float(group["event_count"].max()),
                    "median": float(group["event_count"].median())
                }
                
                # Handle zero standard deviation
                if stats["std"] == 0:
                    stats["std"] = max(0.1, stats["mean"] * 0.1)
                
                # Calculate percentiles
                stats["percentiles"] = {
                    "p25": float(group["event_count"].quantile(0.25)),
                    "p75": float(group["event_count"].quantile(0.75)),
                    "p95": float(group["event_count"].quantile(0.95)),
                    "p99": float(group["event_count"].quantile(0.99))
                }
                
                # Add temporal patterns if timestamp available
                if "@timestamp" in group.columns:
                    try:
                        group_with_time = group.copy()
                        group_with_time["hour"] = pd.to_datetime(group_with_time["@timestamp"]).dt.hour
                        hourly_patterns = group_with_time.groupby("hour")["event_count"].mean().to_dict()
                        stats["hourly_patterns"] = {str(k): float(v) for k, v in hourly_patterns.items()}
                    except Exception as e:
                        logger.warning(f"Could not calculate temporal patterns for {entity}: {e}")
                
                baselines[str(entity)] = stats
            
            # Add global baseline
            global_stats = {
                "count": len(historical_data),
                "mean": float(historical_data["event_count"].mean()),
                "std": float(historical_data["event_count"].std()),
                "median": float(historical_data["event_count"].median()),
                "total_entities": len(grouped)
            }
            baselines["global"] = global_stats
            
            logger.info(f"Established baselines for {len(baselines)} entities in {data_type}")
            return baselines
            
        except Exception as e:
            logger.error(f"Error establishing baselines: {e}")
            return {"global": {"count": len(historical_data), "error": str(e)}}
    
    def _add_basic_features(self, data: pd.DataFrame) -> pd.DataFrame:
        """
        Add basic features when enhanced feature extraction is not available.
        """
        feature_data = data.copy()
        
        # Add temporal features
        if "@timestamp" in feature_data.columns:
            try:
                ts = pd.to_datetime(feature_data["@timestamp"])
                
                # Cyclical encoding
                feature_data["hour_sin"] = np.sin(2 * np.pi * ts.dt.hour / 24)
                feature_data["hour_cos"] = np.cos(2 * np.pi * ts.dt.hour / 24)
                feature_data["day_sin"] = np.sin(2 * np.pi * ts.dt.dayofweek / 7)
                feature_data["day_cos"] = np.cos(2 * np.pi * ts.dt.dayofweek / 7)
                
                # Binary features
                feature_data["is_business_hours"] = ((ts.dt.hour >= 9) & (ts.dt.hour <= 17)).astype(int)
                feature_data["is_weekend"] = (ts.dt.dayofweek >= 5).astype(int)
            except Exception as e:
                logger.debug(f"Could not add temporal features: {e}")
        
        # Add event count
        if "event_count" not in feature_data.columns:
            feature_data["event_count"] = 1
        
        # Add process features
        if "process.name" in feature_data.columns:
            feature_data["process_name_length"] = feature_data["process.name"].str.len().fillna(0)
            feature_data["process_name_entropy"] = feature_data["process.name"].apply(
                lambda x: self._calculate_entropy(x) if pd.notna(x) else 0
            )
        
        # Add network features
        if "destination.ip" in feature_data.columns:
            feature_data["is_internal_ip"] = feature_data["destination.ip"].apply(
                lambda x: self._is_internal_ip(x) if pd.notna(x) else 0
            )
        
        if "destination.port" in feature_data.columns:
            feature_data["port_number"] = pd.to_numeric(feature_data["destination.port"], errors='coerce').fillna(0)
            feature_data["is_common_port"] = feature_data["port_number"].apply(
                lambda x: 1 if x in self.common_ports else 0
            )
            feature_data["is_high_port"] = (feature_data["port_number"] > 1024).astype(int)
        
        # Add user features
        if "user.name" in feature_data.columns:
            feature_data["user_name_length"] = feature_data["user.name"].str.len().fillna(0)
            feature_data["is_system_user"] = feature_data["user.name"].apply(
                lambda x: 1 if pd.notna(x) and (x.startswith('_') or x in ['root', 'daemon', 'bin', 'sys']) else 0
            )
        
        # Add argument features for metadata jobs
        if "process.args" in feature_data.columns:
            feature_data["args_length"] = feature_data["process.args"].str.len().fillna(0)
            feature_data["args_entropy"] = feature_data["process.args"].apply(
                lambda x: self._calculate_entropy(x) if pd.notna(x) else 0
            )
            feature_data["has_base64"] = feature_data["process.args"].str.contains(
                r'[A-Za-z0-9+/]{20,}={0,2}', regex=True, na=False
            ).astype(int)
            feature_data["has_url"] = feature_data["process.args"].str.contains(
                r'https?://', regex=True, na=False
            ).astype(int)
        
        return feature_data
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        
        import math
        from collections import Counter
        
        # Calculate frequency of each character
        freq = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _is_internal_ip(self, ip_str: str) -> int:
        """Check if IP is internal/private."""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_str)
            return int(ip.is_private)
        except:
            return 0
    
    def load_models(self, data_type: str, models_dir: str = None) -> bool:
        """
        FIXED: Load models with job-aware structure.
        """
        if models_dir is None:
            models_dir = self.config.get("models", {}).get("storage", {}).get("base_path", "/tmp/linux_anomaly_models")
        
        try:
            model_file = os.path.join(models_dir, f"{data_type}_models.joblib")
            scaler_file = os.path.join(models_dir, f"{data_type}_scalers.joblib")
            baseline_file = os.path.join(models_dir, f"{data_type}_baselines.joblib")
            metadata_file = os.path.join(models_dir, f"{data_type}_metadata.joblib")
            
            if not os.path.exists(model_file) or not os.path.exists(scaler_file):
                logger.warning(f"Model files not found for {data_type} in {models_dir}")
                return False
            
            # Load models and scalers
            models = joblib.load(model_file)
            scalers = joblib.load(scaler_file)
            
            # Load baselines if available
            baselines = {}
            if os.path.exists(baseline_file):
                baselines = joblib.load(baseline_file)
            
            # Load metadata
            if os.path.exists(metadata_file):
                metadata = joblib.load(metadata_file)
                self.feature_definitions[data_type] = metadata.get("feature_definitions", {})
                self.model_metadata[data_type] = metadata.get("model_metadata", {})
            
            # Validate loaded models
            valid_models = {}
            valid_scalers = {}
            
            for entity_key, model in models.items():
                # Check if we have corresponding scaler
                if entity_key in scalers:
                    if self._validate_model(model, scalers[entity_key]):
                        valid_models[entity_key] = model
                        valid_scalers[entity_key] = scalers[entity_key]
                    else:
                        logger.warning(f"Model validation failed for: {entity_key}")
                else:
                    logger.warning(f"Scaler missing for: {entity_key}")
            
            # Store in class attributes
            self.models[data_type] = valid_models
            self.scalers[data_type] = valid_scalers
            self.baselines[data_type] = baselines
            
            # Log summary
            jobs_found = set()
            for key in valid_models.keys():
                if ':' in key:
                    job_name = key.split(':')[0]
                    jobs_found.add(job_name)
            
            logger.info(f" Loaded {len(valid_models)} models for {data_type}")
            logger.info(f"  Jobs covered: {', '.join(jobs_found)}")
            
            return len(valid_models) > 0
            
        except Exception as e:
            logger.error(f"Error loading models for {data_type}: {e}")
            return False
    
    def save_models(self, data_type: str, models_dir: str = None) -> bool:
        """
        FIXED: Save models with job-aware structure and metadata.
        """
        if models_dir is None:
            models_dir = self.config.get("models", {}).get("storage", {}).get("base_path", "/tmp/linux_anomaly_models")
        
        try:
            os.makedirs(models_dir, exist_ok=True)
            
            # Save models
            if data_type in self.models and self.models[data_type]:
                model_file = os.path.join(models_dir, f"{data_type}_models.joblib")
                joblib.dump(self.models[data_type], model_file)
                
                # Count models per job
                job_counts = {}
                for key in self.models[data_type].keys():
                    if ':' in key:
                        job_name = key.split(':')[0]
                        job_counts[job_name] = job_counts.get(job_name, 0) + 1
                
                logger.info(f" Saved {len(self.models[data_type])} models to {model_file}")
                for job, count in job_counts.items():
                    logger.info(f"  - {job}: {count} models")
            
            # Save scalers
            if data_type in self.scalers and self.scalers[data_type]:
                scaler_file = os.path.join(models_dir, f"{data_type}_scalers.joblib")
                joblib.dump(self.scalers[data_type], scaler_file)
                logger.info(f" Saved {len(self.scalers[data_type])} scalers")

                # Persist a per-entity feature manifest (human-readable JSON) next to the scalers
                try:
                    manifests = {}
                    for entity, scaler in self.scalers[data_type].items():
                        entry = {}
                        if hasattr(scaler, 'feature_names_in_'):
                            entry['feature_names_in_'] = list(scaler.feature_names_in_)
                        for attr in ('center_', 'mean_', 'median_', 'scale_'):
                            if hasattr(scaler, attr):
                                val = getattr(scaler, attr)
                                try:
                                    import numpy as _np
                                    if isinstance(val, _np.ndarray):
                                        entry[attr] = val.tolist()
                                    else:
                                        entry[attr] = val
                                except Exception:
                                    entry[attr] = str(val)
                        manifests[str(entity)] = entry

                    manifest_file = os.path.join(models_dir, f"{data_type}_feature_manifests.json")
                    with open(manifest_file, 'w', encoding='utf-8') as fh:
                        import json
                        json.dump(manifests, fh, indent=2)
                    logger.info(f" Wrote feature manifest JSON: {manifest_file}")
                except Exception as e:
                    logger.warning(f"Failed to write feature manifests: {e}")
            
            # Save baselines
            if data_type in self.baselines and self.baselines[data_type]:
                baseline_file = os.path.join(models_dir, f"{data_type}_baselines.joblib")
                joblib.dump(self.baselines[data_type], baseline_file)
                logger.info(f" Saved {len(self.baselines[data_type])} baselines")
            
            # Save metadata with job information
            metadata = {
                "feature_definitions": self.feature_definitions.get(data_type, {}),
                "model_metadata": self.model_metadata.get(data_type, {}),
                "job_definitions": self.job_definitions.get(data_type, {}),
                "save_timestamp": datetime.now().isoformat(),
                "config_hash": str(hash(str(self.config)))
            }
            metadata_file = os.path.join(models_dir, f"{data_type}_metadata.joblib")
            joblib.dump(metadata, metadata_file)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving models for {data_type}: {e}")
            return False
    
    def get_models_for_job(self, job_name: str) -> Tuple[Dict, Dict, Dict]:
        """
        NEW: Get models for a specific job.
        """
        # Determine data type from job name
        data_type = None
        for dt, jobs in self.job_definitions.items():
            if job_name in jobs:
                data_type = dt
                break
        
        if not data_type:
            logger.warning(f"Job {job_name} not found in definitions")
            return {}, {}, {}
        
        # Get all models for this data type
        all_models = self.models.get(data_type, {})
        all_scalers = self.scalers.get(data_type, {})
        all_baselines = self.baselines.get(data_type, {})
        
        # Filter for this specific job
        job_models = {}
        job_scalers = {}
        job_baselines = {}
        
        for key, model in all_models.items():
            if key.startswith(f"{job_name}:"):
                # Extract entity from key
                entity = key.replace(f"{job_name}:", "")
                job_models[entity] = model
        
        for key, scaler in all_scalers.items():
            if key.startswith(f"{job_name}:"):
                entity = key.replace(f"{job_name}:", "")
                job_scalers[entity] = scaler
        
        for key, baseline in all_baselines.items():
            if key.startswith(f"{job_name}:"):
                entity = key.replace(f"{job_name}:", "")
                job_baselines[entity] = baseline
        
        logger.debug(f"Retrieved {len(job_models)} models for job {job_name}")
        return job_models, job_scalers, job_baselines
    
    def _validate_model(self, model: Dict, scaler) -> bool:
        """
        Validate model structure and compatibility.
        """
        try:
            if not isinstance(model, dict):
                return False
            
            # Check for at least one ML model
            ml_methods = ['isolation_forest', 'lof', 'one_class_svm']
            has_ml_model = any(method in model for method in ml_methods)
            
            # Check for required metadata
            required_fields = ['features_used', 'training_samples', 'job_name']
            has_metadata = all(field in model for field in required_fields)
            
            return has_ml_model and has_metadata
            
        except Exception:
            return False
    
    def get_model_summary(self) -> Dict:
        """
        Get comprehensive summary of all loaded models.
        """
        summary = {
            "total_models": 0,
            "total_scalers": 0,
            "total_baselines": 0,
            "by_data_type": {},
            "by_job": {}
        }
        
        for data_type in self.models:
            models = self.models.get(data_type, {})
            scalers = self.scalers.get(data_type, {})
            baselines = self.baselines.get(data_type, {})
            
            summary["total_models"] += len(models)
            summary["total_scalers"] += len(scalers)
            summary["total_baselines"] += len(baselines)
            
            # Count by job
            job_counts = {}
            for key in models.keys():
                if ':' in key:
                    job_name = key.split(':')[0]
                    job_counts[job_name] = job_counts.get(job_name, 0) + 1
            
            summary["by_data_type"][data_type] = {
                "models": len(models),
                "scalers": len(scalers),
                "baselines": len(baselines),
                "jobs": job_counts,
                "metadata": self.model_metadata.get(data_type, {})
            }
            
            # Aggregate by job
            for job, count in job_counts.items():
                if job not in summary["by_job"]:
                    summary["by_job"][job] = {
                        "data_type": data_type,
                        "model_count": 0
                    }
                summary["by_job"][job]["model_count"] += count
        
        return summary
    
    def validate_job_coverage(self) -> Dict:
        """
        NEW: Validate which jobs have proper model coverage.
        """
        coverage = {
            "fully_covered": [],
            "partially_covered": [],
            "not_covered": [],
            "details": {}
        }
        
        for data_type, jobs in self.job_definitions.items():
            models = self.models.get(data_type, {})
            
            for job_name in jobs:
                # Count models for this job
                job_models = [k for k in models.keys() if k.startswith(f"{job_name}:")]
                
                coverage["details"][job_name] = {
                    "data_type": data_type,
                    "model_count": len(job_models),
                    "description": jobs[job_name].get("description", ""),
                    "status": "not_covered"
                }
                
                if len(job_models) >= 10:  # Arbitrary threshold for "good coverage"
                    coverage["fully_covered"].append(job_name)
                    coverage["details"][job_name]["status"] = "fully_covered"
                elif len(job_models) > 0:
                    coverage["partially_covered"].append(job_name)
                    coverage["details"][job_name]["status"] = "partially_covered"
                else:
                    coverage["not_covered"].append(job_name)
        
        # Add summary
        coverage["summary"] = {
            "total_jobs": len(coverage["details"]),
            "fully_covered_count": len(coverage["fully_covered"]),
            "partially_covered_count": len(coverage["partially_covered"]),
            "not_covered_count": len(coverage["not_covered"]),
            "coverage_percentage": round(
                (len(coverage["fully_covered"]) + len(coverage["partially_covered"])) / 
                len(coverage["details"]) * 100, 2
            )
        }
        
        return coverage


# Convenience functions for backward compatibility
def establish_linux_baselines(historical_data, config, data_type="process"):
    """
    Establish baselines for Linux data with job-specific logic.
    """
    manager = LinuxModelManager(config)
    return manager.establish_baselines(historical_data, data_type)

def train_linux_models(historical_data, config, data_type="process"):
    """
    Train Linux anomaly detection models with job-specific logic.
    """
    manager = LinuxModelManager(config)
    models, scalers = manager.train_models(historical_data, data_type)
    
    # Store in manager for saving
    manager.models[data_type] = models
    manager.scalers[data_type] = scalers
    
    return models, scalers

def save_linux_models(models, scalers, baselines, config, data_type="process"):
    """
    Save Linux models with job-aware structure.
    """
    manager = LinuxModelManager(config)
    manager.models[data_type] = models
    manager.scalers[data_type] = scalers
    manager.baselines[data_type] = baselines
    return manager.save_models(data_type)

def load_linux_models(config, data_type="process"):
    """
    Load Linux models with job-aware structure.
    """
    manager = LinuxModelManager(config)
    success = manager.load_models(data_type)
    
    if success:
        models = manager.models.get(data_type, {})
        scalers = manager.scalers.get(data_type, {})
        baselines = manager.baselines.get(data_type, {})
        return models, scalers, baselines, True
    else:
        return {}, {}, {}, False

def validate_model_coverage(config):
    """
    NEW: Validate which jobs have proper model coverage.
    """
    manager = LinuxModelManager(config)
    
    # Load all data types
    for data_type in ["process", "network", "user", "discovery", "metadata"]:
        manager.load_models(data_type)
    
    coverage = manager.validate_job_coverage()
    
    # Print summary
    print("\n" + "="*80)
    print("MODEL COVERAGE VALIDATION REPORT")
    print("="*80)
    
    print(f"\nSUMMARY:")
    print(f"  Total Jobs: {coverage['summary']['total_jobs']}")
    print(f"  Fully Covered: {coverage['summary']['fully_covered_count']}")
    print(f"  Partially Covered: {coverage['summary']['partially_covered_count']}")
    print(f"  Not Covered: {coverage['summary']['not_covered_count']}")
    print(f"  Overall Coverage: {coverage['summary']['coverage_percentage']}%")
    
    if coverage["not_covered"]:
        print(f"\n❌ JOBS WITHOUT MODELS:")
        for job in coverage["not_covered"]:
            details = coverage["details"][job]
            print(f"  - {job}: {details['description']}")
    
    if coverage["partially_covered"]:
        print(f"\n  JOBS WITH PARTIAL COVERAGE:")
        for job in coverage["partially_covered"]:
            details = coverage["details"][job]
            print(f"  - {job}: {details['model_count']} models - {details['description']}")
    
    if coverage["fully_covered"]:
        print(f"\n JOBS WITH FULL COVERAGE:")
        for job in coverage["fully_covered"]:
            details = coverage["details"][job]
            print(f"  - {job}: {details['model_count']} models - {details['description']}")
    
    return coverage


def load_all_models(config=None, candidates=None):
    """
    Utility: attempt to load any model/scaler joblib files from candidate locations.
    Returns (models, scalers) dicts. This helper is conservative and only used by
    diagnostic scripts when the full manager APIs are not wired up.
    """
    import joblib
    from pathlib import Path

    if config is None:
        config = {}

    models = {}
    scalers = {}

    # Candidate paths: explicit config -> results directory -> /tmp
    candidates = candidates or []
    models_base = config.get('models', {}).get('storage', {}).get('base_path', '/tmp/linux_anomaly_models')
    candidates = list(dict.fromkeys(candidates + [str(models_base), 'results', '/tmp', '.']))

    for base in candidates:
        try:
            p = Path(base)
            if not p.exists():
                continue

            # Look for *_models.joblib and *_scalers.joblib
            for f in p.glob('*_models.joblib'):
                try:
                    loaded = joblib.load(str(f))
                    if isinstance(loaded, dict):
                        # Merge into models with keys preserved
                        models.update(loaded)
                except Exception as e:
                    logger.debug(f"Failed to load models from {f}: {e}")

            for f in p.glob('*_scalers.joblib'):
                try:
                    loaded = joblib.load(str(f))
                    if isinstance(loaded, dict):
                        scalers.update(loaded)
                except Exception as e:
                    logger.debug(f"Failed to load scalers from {f}: {e}")

        except Exception:
            continue

    logger.info(f"load_all_models: found {len(models)} models and {len(scalers)} scalers from candidates: {candidates}")
    return models, scalers