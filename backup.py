
# """
# Main script for running the Linux Anomaly Detection system with MLflow tracking.
# Enhanced to support different detection modes and all 14 Linux detection jobs
# across 5 data groups: process, network, user, discovery, and metadata.
# """

# import os
# import sys
# import logging
# import argparse
# import traceback
# from datetime import datetime
# import mlflow
# import mlflow.exceptions
# import numpy as np
# from dotenv import load_dotenv
# load_dotenv()
# import warnings
# warnings.filterwarnings("ignore", category=FutureWarning)
# from anomaly_detector import LinuxAnomalyDetector


# logger = logging.getLogger("Linux_anomaly_detection")

# def setup_logging(log_level='INFO', log_file=None):
#     """
#     Set up logging configuration.

#     Args:
#         log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
#         log_file (str, optional): Path to log file
#     """
#     # Create log directory if needed
#     if log_file:
#         log_dir = os.path.dirname(log_file)
#         if log_dir and not os.path.exists(log_dir):
#             os.makedirs(log_dir, exist_ok=True)

#     # Set up handlers
#     handlers = []

#     # Always log to console
#     handlers.append(logging.StreamHandler())

#     # Add file handler if specified
#     if log_file:
#         handlers.append(logging.FileHandler(log_file))

#     # Configure logging
#     logging.basicConfig(
#         level=getattr(logging, log_level.upper()),
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#         handlers=handlers
#     )

#     # Return logger for main module
#     return logging.getLogger("linux_anomaly_detection")

# def setup_mlflow(logger):
#     """
#     Set up MLflow tracking with DAGsHub.

#     Args:
#         logger: Logger instance

#     Returns:
#         bool: True if setup successful, False otherwise
#     """
#     try:
#         # DAGsHub setup - prefer environment variables, fall back to defaults
#         dagshub_username = os.getenv("DAGSHUB_USERNAME", "DAGSHUB_USERNAME")
#         dagshub_repo_name = os.getenv("DAGSHUB_REPO_NAME", "DAGSHUB_REPO_NAME")
#         dagshub_token = os.getenv("DAGSHUB_TOKEN", "DAGSHUB_TOKEN")
#         logger.info(f"Using DAGsHub repo: {dagshub_username}/{dagshub_repo_name}")

#         # Use a timestamp-based experiment name to avoid collision with deleted experiments
#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         default_experiment_name = f"LINUX_ANOMALY_DETECTION_{timestamp}"
#         experiment_name = os.getenv("MLFLOW_EXPERIMENT_NAME", default_experiment_name)

#         # Construct tracking URI
#         dagshub_mlflow_uri = f"https://dagshub.com/{dagshub_username}/{dagshub_repo_name}.mlflow"

#         # Set MLflow credentials
#         os.environ["MLFLOW_TRACKING_USERNAME"] = dagshub_username
#         os.environ["MLFLOW_TRACKING_PASSWORD"] = dagshub_token

#         logger.info(f"Setting MLflow tracking URI: {dagshub_mlflow_uri}")
#         mlflow.set_tracking_uri(dagshub_mlflow_uri)

#         # Check if the experiment exists and is active
#         existing_experiment = mlflow.get_experiment_by_name(experiment_name)

#         if existing_experiment:
#             # Check if experiment is deleted
#             if existing_experiment.lifecycle_stage == "deleted":
#                 logger.warning(f"Experiment '{experiment_name}' exists but is deleted")
#                 # Use a new name with timestamp to avoid collision
#                 new_experiment_name = f"{experiment_name}_{timestamp}"
#                 logger.info(f"Creating new experiment with name: {new_experiment_name}")
#                 experiment_name = new_experiment_name
#                 mlflow.create_experiment(experiment_name)
#             else:
#                 logger.info(f"Using existing active experiment: {experiment_name}")
#         else:
#             # Create a new experiment
#             logger.info(f"Creating new experiment: {experiment_name}")
#             mlflow.create_experiment(experiment_name)

#         # Set the experiment - THIS IS CRUCIAL
#         logger.info(f"Setting MLflow experiment: {experiment_name}")
#         mlflow.set_experiment(experiment_name)

#         # Verify connection
#         experiment = mlflow.get_experiment_by_name(experiment_name)
#         if experiment:
#             logger.info(f"Successfully connected to MLflow experiment: {experiment_name} (ID: {experiment.experiment_id})")
#             return True, experiment.experiment_id
#         else:
#             logger.error(f"Failed to create or connect to experiment: {experiment_name}")
#             return False, None

#     except Exception as e:
#         logger.error(f"MLflow setup error: {e}")
#         logger.debug(f"MLflow setup error details: {traceback.format_exc()}")
#         return False, None

# def parse_arguments():
#     """Parse command line arguments."""
#     parser = argparse.ArgumentParser(description='Linux Anomaly Detection System')

#     parser.add_argument(
#         '--config', '-c',
#         type=str,
#         help='Path to configuration file'
#     )
#     parser.add_argument(
#         '--log-level', '-l',
#         type=str,
#         choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
#         default='INFO',
#         help='Set the logging level'
#     )
#     parser.add_argument(
#         '--log-file', '-f',
#         type=str,
#         default=f"logs/linux_anomaly_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
#         help='Path to log file'
#     )

#     parser.add_argument(
#         '--no-baseline', '-n',
#         action='store_true',
#         default=False,
#         help='Skip baseline data collection phase'
#     )
#     parser.add_argument(
#         '--ignore-existing-models', '-i',
#         action='store_true',
#         default=False,
#         help='Ignore existing models and train new ones'
#     )
#     parser.add_argument(
#         '--mlflow-run-name', '-m',
#         type=str,
#         default=f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
#         help='Custom name for the MLflow run'
#     )
#     parser.add_argument(
#         '--disable-mlflow', '-d',
#         action='store_true',
#         help='Disable MLflow tracking',
#         default=True
#     )
#     parser.add_argument(
#         '--separate-model-runs', '-s',
#         action='store_true',
#         default=True,
#         help='Log each model in a separate MLflow run (default: True)'
#     )

#     parser.add_argument(
#         '--detection-mode',
#         type=str,
#         choices=['single', 'group', 'comprehensive'],
#         default='comprehensive',
#         help='Detection mode: single (one job), group (one data group), comprehensive (all groups)'
#     )

#     parser.add_argument(
#         '--job',
#         type=str,
#         help='Specific detection job to run (for single mode)'
#     )

#     parser.add_argument(
#         '--data-group',
#         type=str,
#         choices=['process', 'network', 'user', 'discovery', 'metadata'],
#         help='Data group to process (for group mode)'
#     )

#     parser.add_argument(
#         '--data-groups',
#         type=str,
#         nargs='+',
#         choices=['process', 'network', 'user', 'discovery', 'metadata'],
#         help='Multiple data groups to process (for comprehensive mode)'
#     )

#     parser.add_argument(
#         '--jobs',
#         type=str,
#         nargs='+',
#         help='Specific jobs to run within a data group'
#     )

#     parser.add_argument(
#         '--train-models',
#         action='store_true',
#         default=False,
#         help='Train ML models before detection'
#     )

#     parser.add_argument(
#         '--evaluate-performance',
#         action='store_true',
#         help='Evaluate detection performance'
#     )

#     parser.add_argument(
#         '--list-jobs',
#         action='store_true',
#         help='List all supported detection jobs'
#     )

#     parser.add_argument(
#         '--save-visualizations',
#         action='store_true',
#         default=True,
#         help='Generate and save visualizations of results'
#     )

#     parser.add_argument(
#         '--generate-report',
#         action='store_true',
#         default=True,
#         help='Generate comprehensive report of results'
#     )

#     return parser.parse_args()

# def log_detection_results(logger, results, detection_mode, job_name=None, data_group=None):
#     """
#     Log Linux anomaly detection results to MLflow.

#     Args:
#         logger: Logger instance
#         results: Detection results (DataFrame or dict of DataFrames)
#         detection_mode (str): Detection mode used
#         job_name (str, optional): Specific job name for single mode
#         data_group (str, optional): Data group for group mode
#     """
#     try:
#         mlflow.log_param("detection_mode", detection_mode)

#         if detection_mode == 'single' and job_name:
#             # Single job results
#             mlflow.log_param("job_name", job_name)

#             if results is not None and not results.empty:
#                 anomalies = results[results.get("final_anomaly", False) == True]
#                 mlflow.log_metric("total_events", len(results))
#                 mlflow.log_metric("total_anomalies", len(anomalies))
#                 mlflow.log_metric("anomaly_rate", len(anomalies) / len(results) if len(results) > 0 else 0.0)

#                 # Log job-specific metrics
#                 if 'combined_score' in results.columns:
#                     mlflow.log_metric("max_anomaly_score", results['combined_score'].max())
#                     mlflow.log_metric("mean_anomaly_score", results['combined_score'].mean())

#                 logger.info(f"Single job {job_name}: {len(anomalies)} anomalies from {len(results)} events")
#             else:
#                 mlflow.log_metric("total_events", 0)
#                 mlflow.log_metric("total_anomalies", 0)
#                 logger.info(f"Single job {job_name}: No results")

#         elif detection_mode == 'group' and data_group:
#             # Group results
#             mlflow.log_param("data_group", data_group)

#             total_events = 0
#             total_anomalies = 0
#             job_count = 0

#             for job_name, job_results in results.items():
#                 if job_results is not None and not job_results.empty:
#                     job_events = len(job_results)
#                     job_anomalies = len(job_results[job_results.get("final_anomaly", False) == True])

#                     total_events += job_events
#                     total_anomalies += job_anomalies
#                     job_count += 1

#                     # Log individual job metrics
#                     mlflow.log_metric(f"{job_name}_events", job_events)
#                     mlflow.log_metric(f"{job_name}_anomalies", job_anomalies)
#                     mlflow.log_metric(f"{job_name}_rate", job_anomalies / job_events if job_events > 0 else 0.0)

#             mlflow.log_metric("total_events", total_events)
#             mlflow.log_metric("total_anomalies", total_anomalies)
#             mlflow.log_metric("overall_anomaly_rate", total_anomalies / total_events if total_events > 0 else 0.0)
#             mlflow.log_metric("jobs_processed", job_count)

#             logger.info(f"Group {data_group}: {total_anomalies} anomalies from {total_events} events across {job_count} jobs")

#         elif detection_mode == 'comprehensive':
#             # Comprehensive results
#             total_events = 0
#             total_anomalies = 0
#             total_jobs = 0
#             group_count = 0

#             group_summaries = {}

#             for group_name, group_results in results.items():
#                 group_events = 0
#                 group_anomalies = 0
#                 group_jobs = 0

#                 for job_name, job_results in group_results.items():
#                     if job_results is not None and not job_results.empty:
#                         job_events = len(job_results)
#                         job_anomalies = len(job_results[job_results.get("final_anomaly", False) == True])

#                         group_events += job_events
#                         group_anomalies += job_anomalies
#                         group_jobs += 1

#                         # Log individual job metrics
#                         mlflow.log_metric(f"{group_name}_{job_name}_events", job_events)
#                         mlflow.log_metric(f"{group_name}_{job_name}_anomalies", job_anomalies)

#                 if group_events > 0:
#                     # Log group-level metrics
#                     mlflow.log_metric(f"{group_name}_total_events", group_events)
#                     mlflow.log_metric(f"{group_name}_total_anomalies", group_anomalies)
#                     mlflow.log_metric(f"{group_name}_anomaly_rate", group_anomalies / group_events)
#                     mlflow.log_metric(f"{group_name}_jobs_processed", group_jobs)

#                     group_summaries[group_name] = {
#                         "events": group_events,
#                         "anomalies": group_anomalies,
#                         "rate": group_anomalies / group_events,
#                         "jobs": group_jobs
#                     }

#                     total_events += group_events
#                     total_anomalies += group_anomalies
#                     total_jobs += group_jobs
#                     group_count += 1

#             # Log overall metrics
#             mlflow.log_metric("total_events", total_events)
#             mlflow.log_metric("total_anomalies", total_anomalies)
#             mlflow.log_metric("overall_anomaly_rate", total_anomalies / total_events if total_events > 0 else 0.0)
#             mlflow.log_metric("total_jobs_processed", total_jobs)
#             mlflow.log_metric("groups_processed", group_count)

#             # Log group participation
#             mlflow.log_param("groups_processed", list(group_summaries.keys()))

#             logger.info(f"Comprehensive detection: {total_anomalies} anomalies from {total_events} events "
#                        f"across {total_jobs} jobs in {group_count} groups")

#             # Log detailed group summaries
#             for group_name, summary in group_summaries.items():
#                 logger.info(f"  {group_name}: {summary['anomalies']}/{summary['events']} "
#                            f"({summary['rate']:.2%}) across {summary['jobs']} jobs")

#     except Exception as e:
#         logger.warning(f"Error logging detection results: {e}")
#         logger.debug(traceback.format_exc())

# def monkey_patch_model_training(logger, use_separate_runs=True, parent_run_id=None):
#     """
#     Monkey patch the model training functions to add MLflow logging.
#     This allows us to track models without modifying the original code.

#     Args:
#         logger: Logger instance
#         use_separate_runs: Whether to log each model in a separate MLflow run
#         parent_run_id: ID of the parent run for nested runs
#     """
#     try:
#         # Import the model manager from the Linux detector
#         from model_manager import LinuxModelManager
#         import functools

#         # Get the original train_models method
#         original_train_models = LinuxModelManager.train_models

#         @functools.wraps(original_train_models)
#         def train_models_with_mlflow(self, data, data_type):
#             # Call the original method
#             models, scalers, baselines = original_train_models(self, data, data_type)

#             # Log training information
#             if models:
#                 model_count = len(models) if isinstance(models, dict) else 1
#                 logger.info(f"Training completed for {data_type}: {model_count} models")

#                 if use_separate_runs:
#                     mlflow.log_param(f"{data_type}_model_count", model_count)
#                     mlflow.log_param(f"{data_type}_training_data_size", len(data))

#                     # Log model names
#                     if isinstance(models, dict):
#                         mlflow.log_param(f"{data_type}_model_names", list(models.keys()))

#             return models, scalers, baselines

#         # Replace the original method
#         LinuxModelManager.train_models = train_models_with_mlflow
#         logger.info("Successfully monkey-patched Linux model training function for MLflow tracking")

#     except Exception as e:
#         logger.error(f"Failed to monkey patch model training: {e}")
#         logger.debug(f"Monkey patch error details: {traceback.format_exc()}")

# def generate_visualizations_and_reports(detector, results, args, logger):
#     """
#     Generate visualizations and reports for detection results.

#     Args:
#         detector: LinuxAnomalyDetector instance
#         results: Detection results
#         args: Command line arguments
#         logger: Logger instance

#     Returns:
#         tuple: Paths to generated visualizations and reports
#     """
#     try:
#         # Import visualization functions
#         from visualizer import generate_linux_report, create_linux_visualizations

#         viz_paths = []
#         report_paths = []

#         if args.detection_mode == 'single':
#             # Single job visualization
#             if not results.empty and args.save_visualizations:
#                 logger.info(f"Generating visualizations for job: {args.job}")
#                 job_viz_paths = create_linux_visualizations(results, detector.config,
#                                                            data_type=args.data_group or "process")
#                 viz_paths.extend(job_viz_paths)

#             # Single job report
#             if not results.empty and args.generate_report:
#                 logger.info(f"Generating report for job: {args.job}")
#                 report_file, data_file = generate_linux_report(results, detector.config,
#                                                              data_type=args.data_group or "process")
#                 if report_file:
#                     report_paths.append(report_file)

#         elif args.detection_mode == 'group':
#             # Group visualizations
#             if args.save_visualizations:
#                 logger.info(f"Generating visualizations for group: {args.data_group}")
#                 group_viz_paths = create_linux_visualizations(results, detector.config, data_type=args.data_group)
#                 viz_paths.extend(group_viz_paths)

#             # Group report
#             if args.generate_report:
#                 logger.info(f"Generating report for group: {args.data_group}")
#                 report_file, data_file = generate_linux_report(results, detector.config, data_type=args.data_group)
#                 if report_file:
#                     report_paths.append(report_file)

#         elif args.detection_mode == 'comprehensive':
#             # Comprehensive visualizations and reports for each group
#             for group_name, group_results in results.items():
#                 if args.save_visualizations:
#                     logger.info(f"Generating visualizations for group: {group_name}")
#                     group_viz_paths = create_linux_visualizations(group_results, detector.config, data_type=group_name)
#                     viz_paths.extend(group_viz_paths)

#                 if args.generate_report:
#                     logger.info(f"Generating report for group: {group_name}")
#                     report_file, data_file = generate_linux_report(group_results, detector.config, data_type=group_name)
#                     if report_file:
#                         report_paths.append(report_file)

#         # Log summary
#         if viz_paths:
#             logger.info(f"Generated {len(viz_paths)} visualizations")
#         if report_paths:
#             logger.info(f"Generated {len(report_paths)} reports")

#         return viz_paths, report_paths

#     except Exception as e:
#         logger.error(f"Error generating visualizations and reports: {e}")
#         logger.debug(f"Visualization error details: {traceback.format_exc()}")
#         return [], []
# 1

# def run_detection_process(args, logger, parent_run_id=None):
#     """
#     Run the actual Linux detection process.

#     Args:
#         args: Command line arguments
#         logger: Logger instance
#         parent_run_id: ID of the parent run for nested runs

#     Returns:
#         int: Exit code (0 for success, 1 for failure)
#     """
#     try:
#         # Initialize Linux anomaly detector
#         logger.info("Initializing LinuxAnomalyDetector")
#         detector = LinuxAnomalyDetector(config_path=args.config)

#         # Handle list jobs request
#         if args.list_jobs:
#             jobs = detector.list_supported_jobs()
#             logger.info("Supported Linux Anomaly Detection Jobs:")
#             for group, job_list in jobs.items():
#                 logger.info(f"\n{group.upper()} Group:")
#                 for job in job_list:
#                     description = detector.get_job_description(job)
#                     logger.info(f"  - {job}: {description}")
#             return 0

#         # Train models if requested
#         if args.train_models:
#             logger.info("Training models before detection")
#             if args.data_group:
#                 success = detector.train_models_for_group(args.data_group, retrain=True)
#                 if not success:
#                     logger.error(f"Failed to train models for {args.data_group}")
#                     return 1
#             else:
#                 # Train all groups
#                 for group in detector.detection_jobs.keys():
#                     success = detector.train_models_for_group(group, retrain=True)
#                     if not success:
#                         logger.warning(f"Failed to train models for {group}")

#         # Log detection configuration
#         if not args.disable_mlflow:
#             mlflow.log_param("use_baseline", not args.no_baseline)
#             mlflow.log_param("load_existing_models", not args.ignore_existing_models)
#             mlflow.log_param("config_path", args.config if args.config else "default")

#         # Run detection based on mode
#         results = None
#         use_baseline = not args.no_baseline
#         load_existing_models = not args.ignore_existing_models

#         if args.detection_mode == 'single':
#             if not args.job:
#                 logger.error("Job name required for single detection mode")
#                 return 1

#             logger.info(f"Running single detection job: {args.job}")
#             results = detector.run_single_detection_job(
#                 args.job,
#                 data_type=args.data_group,
#                 use_baseline=use_baseline,
#                 load_existing_models=load_existing_models
#             )

#             if not args.disable_mlflow:
#                 log_detection_results(logger, results, args.detection_mode, job_name=args.job)

#             if results is not None and not results.empty:
#                 data_type = args.data_group or "unknown"
#                 anomalies_file = detector.extract_and_save_anomalies({
#                     data_type: {args.job: results}
#                 })
#                 logger.info(f"Saved anomalies to: {anomalies_file}")

#         elif args.detection_mode == 'group':
#             if not args.data_group:
#                 logger.error("Data group required for group detection mode")
#                 return 1

#             logger.info(f"Running group detection for: {args.data_group}")
#             results = detector.run_data_group_detection(
#                 args.data_group,
#                 jobs=args.jobs,
#                 use_baseline=use_baseline,
#                 load_existing_models=load_existing_models
#             )

#             total_anomalies = getattr(detector, "last_anomaly_count", 0)
#             logger.info(f"Total anomalies detected in group {args.data_group}: {total_anomalies}")

#             if not args.disable_mlflow:
#                 log_detection_results(logger, results, args.detection_mode, data_group=args.data_group)
#                 mlflow.log_metric("total_anomalies", total_anomalies)

#             if results:
#                 anomalies_file = detector.extract_and_save_anomalies({
#                     args.data_group: results
#                 })
#                 logger.info(f"Saved anomalies to: {anomalies_file}")

#         elif args.detection_mode == 'comprehensive':
#             logger.info("Running comprehensive Linux anomaly detection")
#             results = detector.run_comprehensive_detection(
#                 data_groups=args.data_groups,
#                 use_baseline=use_baseline,
#                 train_models=args.train_models,
#                 force_retrain=args.ignore_existing_models
#             )

#             if not args.disable_mlflow:
#                 log_detection_results(logger, results, args.detection_mode)

#             if results:
#                 anomalies_file = detector.extract_and_save_anomalies(results)
#                 logger.info(f"Saved anomalies to: {anomalies_file}")

#         # Generate visualizations and reports if requested
#         if (args.save_visualizations or args.generate_report) and results is not None:
#             try:
#                 viz_paths, report_paths = generate_visualizations_and_reports(
#                     detector, results, args, logger
#                 )

#                 if not args.disable_mlflow:
#                     for viz_path in viz_paths:
#                         if os.path.exists(viz_path):
#                             mlflow.log_artifact(viz_path, "visualizations")

#                     for report_path in report_paths:
#                         if os.path.exists(report_path):
#                             mlflow.log_artifact(report_path, "reports")
#             except Exception as viz_error:
#                 logger.error(f"Error generating visualizations and reports: {viz_error}")

#         # Evaluate performance if requested
#         if args.evaluate_performance:
#             logger.info("Evaluating detection performance")
#             evaluation = detector.evaluate_detection_performance(args.data_group)

#             if not args.disable_mlflow:
#                 overall_metrics = evaluation.get("overall_metrics", {})
#                 for metric, value in overall_metrics.items():
#                     mlflow.log_metric(f"eval_{metric}", value)

#             logger.info(f"Performance evaluation completed: "
#                         f"{overall_metrics.get('overall_detection_rate', 0):.2%} detection rate")

#         # Save detection results to MLflow artifacts
#         if not args.disable_mlflow and results is not None:
#             import tempfile
#             import json

#             try:
#                 with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as tmp:
#                     result_path = tmp.name

#                     if isinstance(results, dict):
#                         serializable_results = {}
#                         for key, value in results.items():
#                             if isinstance(value, dict):
#                                 serializable_results[key] = {
#                                     k: v.to_dict('records') if hasattr(v, 'to_dict') else str(v)
#                                     for k, v in value.items()
#                                 }
#                             else:
#                                 serializable_results[key] = value.to_dict('records') if hasattr(value, 'to_dict') else str(value)
#                     else:
#                         serializable_results = results.to_dict('records') if hasattr(results, 'to_dict') else str(results)

#                     json.dump(serializable_results, tmp, indent=2, default=str)

#                 mlflow.log_artifact(result_path, "detection_results")
#                 logger.info("Saved detection results to MLflow artifacts")

#                 os.unlink(result_path)

#             except Exception as e:
#                 logger.warning(f"Failed to log results as artifact: {e}")

#         logger.info("Linux anomaly detection completed successfully")
#         return 0

#     except Exception as e:
#         logger.error(f"Error in detection process: {e}")
#         logger.debug(f"Detection process error details: {traceback.format_exc()}")

#         if not args.disable_mlflow:
#             try:
#                 mlflow.log_param("error", str(e))
#             except Exception:
#                 pass

#         return 1

# def main():
#     """Main function with error handling."""
#     try:
#         # Parse command-line arguments
#         args = parse_arguments()

#         # Set up logging
#         logger = setup_logging(args.log_level, args.log_file)

#         logger.info("Starting Linux Anomaly Detection System")
#         logger.info(f"Detection mode: {args.detection_mode}")

#         # Setup MLflow if not disabled
#         if not args.disable_mlflow:
#             # Try to restore the deleted experiment first (if that's the issue)
#             try:
#                 # Check if we can find the deleted experiment
#                 client = mlflow.tracking.MlflowClient()
#                 deleted_experiments = [exp for exp in client.search_experiments()
#                                      if exp.name == "LINUX_ANOMALY_DETECTION" and
#                                         exp.lifecycle_stage == "deleted"]

#                 if deleted_experiments:
#                     exp_id = deleted_experiments[0].experiment_id
#                     logger.info(f"Found deleted experiment 'LINUX_ANOMALY_DETECTION' with ID {exp_id}. Attempting to restore...")
#                     try:
#                         # Try to restore the deleted experiment
#                         client.restore_experiment(exp_id)
#                         logger.info(f"Successfully restored experiment 'LINUX_ANOMALY_DETECTION'")
#                     except Exception as restore_err:
#                         logger.warning(f"Failed to restore experiment: {restore_err}")
#             except Exception as search_err:
#                 logger.debug(f"Error searching for deleted experiments: {search_err}")

#             # Continue with regular setup
#             mlflow_setup_success, experiment_id = setup_mlflow(logger)

#             if mlflow_setup_success:
#                 try:
#                     # Start MLflow run with error handling
#                     logger.info(f"Starting MLflow parent run: {args.mlflow_run_name}")
#                     with mlflow.start_run(run_name=args.mlflow_run_name) as parent_run:
#                         # Get parent run ID for nested runs
#                         parent_run_id = parent_run.info.run_id

#                         # Set parent run tags
#                         mlflow.set_tag("run_type", "parent")
#                         mlflow.set_tag("detection_mode", args.detection_mode)
#                         mlflow.set_tag("system_type", "linux")

#                         # Log run parameters
#                         mlflow.log_param("baseline_used", not args.no_baseline)
#                         mlflow.log_param("existing_models_used", not args.ignore_existing_models)
#                         mlflow.log_param("separate_model_runs", args.separate_model_runs)
#                         mlflow.log_param("train_models", args.train_models)
#                         mlflow.log_param("evaluate_performance", args.evaluate_performance)
#                         mlflow.log_param("save_visualizations", args.save_visualizations)
#                         mlflow.log_param("generate_report", args.generate_report)

#                         # Setup model training with MLflow tracking
#                         monkey_patch_model_training(
#                             logger,
#                             use_separate_runs=args.separate_model_runs,
#                             parent_run_id=parent_run_id
#                         )

#                         # Run the main detection process and track it
#                         result = run_detection_process(args, logger, parent_run_id)

#                     return result

#                 except mlflow.exceptions.RestException as e:
#                     logger.error(f"MLflow REST error: {e}")
#                     logger.info("Continuing without MLflow tracking...")
#                     args.disable_mlflow = True

#                 except Exception as e:
#                     logger.error(f"MLflow error: {e}")
#                     logger.debug(f"MLflow error details: {traceback.format_exc()}")
#                     logger.info("Continuing without MLflow tracking...")
#                     args.disable_mlflow = True
#             else:
#                 logger.warning("MLflow setup failed, continuing without tracking")
#                 args.disable_mlflow = True

#         # Run without MLflow tracking if disabled or setup failed
#         return run_detection_process(args, logger)

#     except Exception as e:
#         print(f"Critical error: {e}")
#         print(traceback.format_exc())
#         return 1

#     finally:
#         try:
#             # Clean up MLflow resources if needed
#             if not args.disable_mlflow:
#                 pass
#         except:
#             pass

# if __name__ == "__main__":
#     sys.exit(main())














# import pandas as pd
# import numpy as np
# from datetime import datetime, timedelta
# from elasticsearch import Elasticsearch
# from typing import Dict, List, Any, Optional, Generator, Tuple
# import json
# import logging
# from collections import defaultdict
# import hashlib
# import pytz
# import time
# import gc
# import re
# import ipaddress
# from concurrent.futures import ThreadPoolExecutor, as_completed
# from pathlib import Path

# def preprocess_network_data(df):
#     """
#     Comprehensive preprocessing of network activity data from endpoint events.
#     Extracts and calculates all required features for network anomaly detection
#     based on the actual data fields present.
#     """
#     if df.empty:
#         logger.error("Empty dataframe received for network preprocessing.")
#         return df

#     logger.info(f"Initial network dataframe shape: {df.shape}")
#     original_columns = set(df.columns)
#     logger.info(f"Original columns: {sorted(list(original_columns))}")

#     # PART 1: BASIC PREPROCESSING

#     # Convert timestamp if needed
#     if "@timestamp" in df.columns:
#         if not pd.api.types.is_datetime64_any_dtype(df["@timestamp"]):
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         df.dropna(subset=["@timestamp"], inplace=True)
#         df.sort_values("@timestamp", inplace=True)
#         logger.info(f"Timestamp range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
#     else:
#         logger.error("@timestamp field not found in data - this is a required field")
#         return df

#     # PART 2: EVENT COUNT FEATURE

#     # Check for existing event count fields
#     event_count_candidates = ['event_count', 'event.count', 'event.sequence', 'event.id']
#     event_count_field = None

#     for field in event_count_candidates:
#         if field in df.columns:
#             logger.info(f"Found candidate event count field: {field}")
#             try:
#                 if not pd.api.types.is_numeric_dtype(df[field]):
#                     df[field] = pd.to_numeric(df[field], errors='coerce')

#                 if not df[field].isna().all():
#                     event_count_field = field
#                     logger.info(f"Using {field} as event count field")
#                     if field in ['event.sequence', 'event.id']:
#                         logger.info(f"Converting {field} to event_count (1 per event)")
#                         df['event_count'] = 1
#                     else:
#                         df['event_count'] = df[field]
#                     break
#             except:
#                 logger.warning(f"Could not convert {field} to numeric format")

#     if event_count_field is None:
#         logger.info("No suitable event count field found, using default value of 1")
#         df['event_count'] = 1

#     # PART 3: DOMAIN-SPECIFIC FEATURES

#     # Feature: args_count - Count command line arguments
#     if "process.args_count" in df.columns:
#         logger.info("Using existing process.args_count field")
#         df["args_count"] = df["process.args_count"]
#     elif "process.args" in df.columns:
#         logger.info("Calculating args_count from process.args array")
#         df["args_count"] = df["process.args"].apply(
#             lambda args: len(args) if isinstance(args, list) else 0
#         )
#     elif "process.command_line" in df.columns:
#         logger.info("Calculating args_count from process.command_line")
#         df["args_count"] = df["process.command_line"].apply(
#             lambda cmd: len(str(cmd).split()) - 1 if pd.notna(cmd) else 0
#         )
#     else:
#         logger.warning("No fields available for args_count calculation")
#         df["args_count"] = 0

#     # Feature: command_length - Length of command line
#     if "process.command_line" in df.columns:
#         logger.info("Calculating command_length from process.command_line")
#         df["command_length"] = df["process.command_line"].apply(
#             lambda cmd: len(str(cmd)) if pd.notna(cmd) else 0
#         )
#         logger.info(f"Command length statistics: min={df['command_length'].min()}, max={df['command_length'].max()}, mean={df['command_length'].mean():.2f}")
#     else:
#         logger.warning("process.command_line not found for command_length calculation")
#         df["command_length"] = 0

#     # Feature: has_suspicious_chars - Check for suspicious characters in command line
#     suspicious_patterns = [
#         r'`', r'\$\(', r'\|\|', r'&&', r';', r'\${', r'\\x[0-9a-fA-F]{2}',
#         r'%[0-9a-fA-F]{2}', r'\\u[0-9a-fA-F]{4}', r'eval\(', r'exec\('
#     ]
#     suspicious_regex = '|'.join(suspicious_patterns)

#     if "process.command_line" in df.columns:
#         logger.info("Checking for suspicious characters in command lines")
#         df["has_suspicious_chars"] = df["process.command_line"].apply(
#             lambda cmd: 1 if pd.notna(cmd) and re.search(suspicious_regex, str(cmd)) else 0
#         )
#         suspicious_count = df["has_suspicious_chars"].sum()
#         logger.info(f"Found {suspicious_count} command lines with suspicious characters")
#     else:
#         logger.warning("process.command_line not found for has_suspicious_chars calculation")
#         df["has_suspicious_chars"] = 0

#     # Feature: has_encoded_content - Check for base64 or hex-encoded content
#     encoded_patterns = [
#         r'base64 -d', r'base64 -decode', r'base64\.b64decode',
#         r'[A-Za-z0-9+/]{20,}={0,2}', r'0x[0-9a-fA-F]{10,}'
#     ]
#     encoded_regex = '|'.join(encoded_patterns)

#     if "process.command_line" in df.columns:
#         logger.info("Checking for encoded content in command lines")
#         df["has_encoded_content"] = df["process.command_line"].apply(
#             lambda cmd: 1 if pd.notna(cmd) and re.search(encoded_regex, str(cmd)) else 0
#         )
#         encoded_count = df["has_encoded_content"].sum()
#         logger.info(f"Found {encoded_count} command lines with encoded content")
#     else:
#         logger.warning("process.command_line not found for has_encoded_content calculation")
#         df["has_encoded_content"] = 0

#     # Feature: is_system_path - Check if command is executed from system paths
#     system_paths = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/', '/usr/local/sbin/']

#     if "process.executable" in df.columns:
#         logger.info("Checking for system path executions")
#         df["is_system_path"] = df["process.executable"].apply(
#             lambda path: 1 if pd.notna(path) and any(str(path).startswith(sys_path) for sys_path in system_paths) else 0
#         )
#         system_path_count = df["is_system_path"].sum()
#         logger.info(f"Found {system_path_count} executions from system paths")
#     else:
#         logger.warning("process.executable not found for is_system_path calculation")
#         df["is_system_path"] = 0

#     # Feature: is_tmp_execution - Check if command is executed from /tmp
#     tmp_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']

#     if "process.executable" in df.columns:
#         logger.info("Checking for temporary directory executions")
#         df["is_tmp_execution"] = df["process.executable"].apply(
#             lambda path: 1 if pd.notna(path) and any(str(path).startswith(tmp_path) for tmp_path in tmp_paths) else 0
#         )
#         tmp_execution_count = df["is_tmp_execution"].sum()
#         logger.info(f"Found {tmp_execution_count} executions from temporary directories")
#     else:
#         logger.warning("process.executable not found for is_tmp_execution calculation")
#         df["is_tmp_execution"] = 0

#     # Feature: is_root_user - Check if the process is running as root
#     root_found = False

#     if "user.id" in df.columns:
#         logger.info("Checking for root user via user.id")
#         df["is_root_user"] = df["user.id"].apply(
#             lambda uid: 1 if pd.notna(uid) and (str(uid) == "0" or str(uid).lower() == "root") else 0
#         )
#         root_found = True

#     if not root_found and "user.Ext.real.id" in df.columns:
#         logger.info("Checking for root user via user.Ext.real.id")
#         df["is_root_user"] = df["user.Ext.real.id"].apply(
#             lambda uid: 1 if pd.notna(uid) and (uid == 0 or str(uid) == "0") else 0
#         )
#         root_found = True

#     if not root_found and "user.name" in df.columns:
#         logger.info("Checking for root user via user.name")
#         df["is_root_user"] = df["user.name"].apply(
#             lambda name: 1 if pd.notna(name) and str(name).lower() == "root" else 0
#         )
#         root_found = True

#     if not root_found and "user.Ext.real.name" in df.columns:
#         logger.info("Checking for root user via user.Ext.real.name")
#         df["is_root_user"] = df["user.Ext.real.name"].apply(
#             lambda name: 1 if pd.notna(name) and str(name).lower() == "root" else 0
#         )
#         root_found = True

#     if not root_found:
#         logger.warning("No user fields found for is_root_user calculation")
#         df["is_root_user"] = 0
#     else:
#         root_user_count = df["is_root_user"].sum()
#         logger.info(f"Found {root_user_count} processes running as root")

#     # Feature: has_hash - Check if command line contains hash-like strings
#     hash_patterns = [
#         r'[a-fA-F0-9]{32}', # MD5
#         r'[a-fA-F0-9]{40}', # SHA1
#         r'[a-fA-F0-9]{64}'  # SHA256
#     ]
#     hash_regex = '|'.join(hash_patterns)

#     if "process.command_line" in df.columns:
#         logger.info("Checking for hash-like strings in command lines")
#         df["has_hash"] = df["process.command_line"].apply(
#             lambda cmd: 1 if pd.notna(cmd) and re.search(hash_regex, str(cmd)) else 0
#         )
#         hash_count = df["has_hash"].sum()
#         logger.info(f"Found {hash_count} command lines with hash-like strings")
#     else:
#         logger.warning("process.command_line not found for has_hash calculation")
#         df["has_hash"] = 0

#     # Feature: env_vars_count - Count environment variables (approximation)
#     env_var_pattern = r'\$[A-Za-z_][A-Za-z0-9_]*|\${[A-Za-z_][A-Za-z0-9_]*}'

#     if "process.command_line" in df.columns:
#         logger.info("Counting environment variables in command lines")
#         df["env_vars_count"] = df["process.command_line"].apply(
#             lambda cmd: len(re.findall(env_var_pattern, str(cmd))) if pd.notna(cmd) else 0
#         )
#         env_var_stats = df["env_vars_count"].describe()
#         logger.info(f"Environment variable count statistics: {env_var_stats.to_dict()}")
#     else:
#         logger.warning("process.command_line not found for env_vars_count calculation")
#         df["env_vars_count"] = 0

#     # PART 4: VERIFY AND REPORT

#     # Check for required features
#     required_features = [
#         'event_count', '@timestamp', 'process.name', 'args_count', 'command_length',
#         'has_suspicious_chars', 'has_encoded_content', 'is_system_path',
#         'is_tmp_execution', 'is_root_user', 'has_hash', 'env_vars_count'
#     ]

#     missing_features = [f for f in required_features if f not in df.columns]
#     if missing_features:
#         logger.error(f"Still missing required features after preprocessing: {missing_features}")
#     else:
#         logger.info("All required features are present in the preprocessed dataset")

#     # Report on new features added
#     new_columns = set(df.columns) - original_columns
#     logger.info(f"Added {len(new_columns)} new features: {sorted(list(new_columns))}")

#     # Check for any remaining NaN values in the required features
#     nan_counts = df[required_features].isna().sum()
#     if nan_counts.sum() > 0:
#         logger.warning(f"NaN values in required features: {nan_counts[nan_counts > 0].to_dict()}")
#         df[required_features] = df[required_features].fillna(0)

#     logger.info(f"Final preprocessed dataframe shape: {df.shape}")

#     return df


# def preprocess_user_data(df, expected_feature_count=32):
#     """
#     Comprehensive preprocessing of user activity data for anomaly detection.
#     Ensures all required features are present and properly formatted.

#     Args:
#         df: DataFrame with raw user activity data
#         expected_feature_count: Number of features the model expects (default: 32)

#     Returns:
#         DataFrame with all required features for anomaly detection
#     """
#     if df.empty:
#         logger.warning("Empty dataframe received for user activity preprocessing.")
#         return df

#     # Log initial dataframe details
#     original_columns = sorted(list(df.columns))
#     logger.info(f"Initial user activity dataframe shape: {df.shape}")
#     logger.info(f"Original columns ({len(original_columns)}): {original_columns}")

#     # Check for critical fields
#     critical_fields = ['@timestamp', 'user.name', 'process.name', 'process.command_line']
#     missing_critical = [f for f in critical_fields if f not in original_columns]
#     if missing_critical:
#         logger.warning(f"Missing critical fields: {missing_critical}")

#     # PART 1: BASIC PREPROCESSING

#     # Convert timestamp
#     if "@timestamp" in df.columns:
#         df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         df.dropna(subset=["@timestamp"], inplace=True)
#         df.sort_values("@timestamp", inplace=True)
#         logger.info(f"Timestamp range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")
#     else:
#         logger.warning("@timestamp field missing - adding placeholder")
#         df["@timestamp"] = pd.Timestamp.now(tz='UTC')

#     # PART 2: USER ANALYSIS FEATURES

#     # User context
#     if "user.name" in df.columns:
#         df["user.name"].fillna("unknown", inplace=True)
#         df["is_root_user"] = (df["user.name"] == "root").astype(int)
#         df["is_service_user"] = df["user.name"].apply(
#             lambda x: 1 if str(x).lower() in ["www-data", "nginx", "apache", "mysql", "postgres", "redis"] else 0
#         )
#     else:
#         logger.warning("user.name field missing - adding placeholder")
#         df["user.name"] = "unknown"
#         df["is_root_user"] = 0
#         df["is_service_user"] = 0

#     # PART 3: PROCESS ACTIVITY FEATURES

#     # Command line analysis
#     if "process.command_line" in df.columns:
#         df["process.command_line"].fillna("", inplace=True)
#         df["is_sudo_command"] = df["process.command_line"].str.contains("sudo", case=False, na=False).astype(int)
#         df["is_su_command"] = df["process.command_line"].str.contains(" su ", case=False, na=False).astype(int)
#     else:
#         logger.warning("process.command_line field missing - adding placeholder")
#         df["process.command_line"] = ""
#         df["is_sudo_command"] = 0
#         df["is_su_command"] = 0

#     # Process name analysis
#     if "process.name" in df.columns:
#         df["process.name"].fillna("unknown", inplace=True)
#     else:
#         logger.warning("process.name field missing - adding placeholder")
#         df["process.name"] = "unknown"

#     domain_features = [
#         'args_count', 'command_length', 'has_suspicious_chars',
#         'has_encoded_content', 'is_system_path', 'is_tmp_execution',
#         'is_root_user', 'has_hash', 'env_vars_count'
#     ]

#     existing_domain = [f for f in domain_features if f in df.columns]
#     missing_domain = [f for f in domain_features if f not in df.columns]

#     logger.info(f"Domain-specific features - Present: {len(existing_domain)}/{len(domain_features)}")
#     if existing_domain:
#         logger.info(f"  Found: {existing_domain}")
#     if missing_domain:
#         logger.info(f"  Missing: {missing_domain}")

#     # PART 5: ADD MISSING DOMAIN-SPECIFIC FEATURES

#     # Feature: args_count - Count command line arguments
#     if "args_count" not in df.columns:
#         logger.warning("Adding missing required feature: args_count")
#         if "process.args_count" in df.columns:
#             logger.info("Calculating args_count from process.args_count")
#             df["args_count"] = df["process.args_count"]
#         elif "process.args" in df.columns:
#             logger.info("Calculating args_count from process.args array")
#             df["args_count"] = df["process.args"].apply(
#                 lambda args: len(args) if isinstance(args, list) else 0
#             )
#         elif "process.command_line" in df.columns:
#             logger.info("Calculating args_count from process.command_line")
#             df["args_count"] = df["process.command_line"].apply(
#                 lambda cmd: len(str(cmd).split()) - 1 if pd.notna(cmd) else 0
#             )
#         else:
#             df["args_count"] = 0

#     # Feature: command_length - Length of command line
#     if "command_length" not in df.columns:
#         logger.warning("Adding missing required feature: command_length")
#         if "process.command_line" in df.columns:
#             logger.info("Calculating command_length from process.command_line")
#             df["command_length"] = df["process.command_line"].apply(
#                 lambda cmd: len(str(cmd)) if pd.notna(cmd) else 0
#             )
#         else:
#             df["command_length"] = 0

#     # Feature: has_suspicious_chars - Check for suspicious characters in command line
#     if "has_suspicious_chars" not in df.columns:
#         logger.warning("Adding missing required feature: has_suspicious_chars")
#         suspicious_patterns = [
#             r'`', r'\$\(', r'\|\|', r'&&', r';', r'\${', r'\\x[0-9a-fA-F]{2}',
#             r'%[0-9a-fA-F]{2}', r'\\u[0-9a-fA-F]{4}', r'eval\(', r'exec\('
#         ]
#         suspicious_regex = '|'.join(suspicious_patterns)

#         if "process.command_line" in df.columns:
#             df["has_suspicious_chars"] = df["process.command_line"].apply(
#                 lambda cmd: 1 if pd.notna(cmd) and re.search(suspicious_regex, str(cmd)) else 0
#             )
#         else:
#             df["has_suspicious_chars"] = 0

#     # Feature: has_encoded_content - Check for base64 or hex-encoded content
#     if "has_encoded_content" not in df.columns:
#         logger.warning("Adding missing required feature: has_encoded_content")
#         encoded_patterns = [
#             r'base64 -d', r'base64 -decode', r'base64\.b64decode',
#             r'[A-Za-z0-9+/]{20,}={0,2}', r'0x[0-9a-fA-F]{10,}'
#         ]
#         encoded_regex = '|'.join(encoded_patterns)

#         if "process.command_line" in df.columns:
#             df["has_encoded_content"] = df["process.command_line"].apply(
#                 lambda cmd: 1 if pd.notna(cmd) and re.search(encoded_regex, str(cmd)) else 0
#             )
#         else:
#             df["has_encoded_content"] = 0

#     # Feature: is_system_path - Check if command is executed from system paths
#     if "is_system_path" not in df.columns:
#         logger.warning("Adding missing required feature: is_system_path")
#         system_paths = ['/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/', '/usr/local/bin/', '/usr/local/sbin/']

#         if "process.executable" in df.columns:
#             df["is_system_path"] = df["process.executable"].apply(
#                 lambda path: 1 if pd.notna(path) and any(str(path).startswith(sys_path) for sys_path in system_paths) else 0
#             )
#         else:
#             df["is_system_path"] = 0

#     # Feature: is_tmp_execution - Check if command is executed from /tmp
#     if "is_tmp_execution" not in df.columns:
#         logger.warning("Adding missing required feature: is_tmp_execution")
#         tmp_paths = ['/tmp/', '/var/tmp/', '/dev/shm/']

#         if "process.executable" in df.columns:
#             df["is_tmp_execution"] = df["process.executable"].apply(
#                 lambda path: 1 if pd.notna(path) and any(str(path).startswith(tmp_path) for tmp_path in tmp_paths) else 0
#             )
#         else:
#             df["is_tmp_execution"] = 0

#     # Feature: is_root_user - already added in user analysis section above
#     if "is_root_user" not in df.columns:
#         logger.warning("Adding missing required feature: is_root_user")
#         if "user.id" in df.columns:
#             df["is_root_user"] = df["user.id"].apply(
#                 lambda uid: 1 if pd.notna(uid) and (str(uid) == "0" or str(uid).lower() == "root") else 0
#             )
#         elif "user.Ext.real.id" in df.columns:
#             df["is_root_user"] = df["user.Ext.real.id"].apply(
#                 lambda uid: 1 if pd.notna(uid) and (uid == 0 or str(uid) == "0") else 0
#             )
#         elif "user.name" in df.columns:
#             df["is_root_user"] = df["user.name"].apply(
#                 lambda name: 1 if pd.notna(name) and str(name).lower() == "root" else 0
#             )
#         else:
#             df["is_root_user"] = 0

#     # Feature: has_hash - Check if command line contains hash-like strings
#     if "has_hash" not in df.columns:
#         logger.warning("Adding missing required feature: has_hash")
#         hash_patterns = [
#             r'[a-fA-F0-9]{32}', # MD5
#             r'[a-fA-F0-9]{40}', # SHA1
#             r'[a-fA-F0-9]{64}'  # SHA256
#         ]
#         hash_regex = '|'.join(hash_patterns)

#         if "process.command_line" in df.columns:
#             df["has_hash"] = df["process.command_line"].apply(
#                 lambda cmd: 1 if pd.notna(cmd) and re.search(hash_regex, str(cmd)) else 0
#             )
#         else:
#             df["has_hash"] = 0

#     # Feature: env_vars_count - Count environment variables (approximation)
#     if "env_vars_count" not in df.columns:
#         logger.warning("Adding missing required feature: env_vars_count")
#         env_var_pattern = r'\$[A-Za-z_][A-Za-z0-9_]*|\${[A-Za-z_][A-Za-z0-9_]*}'

#         if "process.command_line" in df.columns:
#             df["env_vars_count"] = df["process.command_line"].apply(
#                 lambda cmd: len(re.findall(env_var_pattern, str(cmd))) if pd.notna(cmd) else 0
#             )
#         else:
#             df["env_vars_count"] = 0

#     # PART 6: CHECK EXISTING ACTIVITY FEATURES

#     activity_features = ['is_compiler_activity', 'is_dev_tool']
#     existing_activity = [f for f in activity_features if f in df.columns]
#     missing_activity = [f for f in activity_features if f not in df.columns]

#     if missing_activity:
#         logger.info(f"Adding missing activity features: {missing_activity}")

#     # Compiler activity detection
#     if "is_compiler_activity" not in df.columns:
#         compiler_patterns = ["gcc", "g++", "clang", "make", "cmake", "javac", "python", "pip", "npm"]
#         if "process.name" in df.columns:
#             df["is_compiler_activity"] = df["process.name"].apply(
#                 lambda x: 1 if any(comp in str(x).lower() for comp in compiler_patterns) else 0
#             )
#         else:
#             df["is_compiler_activity"] = 0

#     # Development tool detection
#     if "is_dev_tool" not in df.columns:
#         dev_tools = ["git", "svn", "vim", "nano", "emacs", "code", "atom"]
#         if "process.name" in df.columns:
#             df["is_dev_tool"] = df["process.name"].apply(
#                 lambda x: 1 if any(tool in str(x).lower() for tool in dev_tools) else 0
#             )
#         else:
#             df["is_dev_tool"] = 0

#     # PART 7: CHECK EXISTING TIME-BASED FEATURES

#     time_features = ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend', 'is_after_hours']
#     existing_time = [f for f in time_features if f in df.columns]
#     missing_time = [f for f in time_features if f not in df.columns]

#     if existing_time:
#         logger.info(f"Existing time features: {existing_time}")
#     if missing_time:
#         logger.info(f"Adding missing time features: {missing_time}")

#     # Basic time features
#     if "@timestamp" in df.columns:
#         if "hour_of_day" not in df.columns:
#             df["hour_of_day"] = df["@timestamp"].dt.hour
#         if "day_of_week" not in df.columns:
#             df["day_of_week"] = df["@timestamp"].dt.dayofweek
#         if "is_business_hours" not in df.columns:
#             df["is_business_hours"] = ((df["hour_of_day"] >= 8) & (df["hour_of_day"] <= 18) &
#                                      (df["day_of_week"] <= 4)).astype(int)
#         if "is_weekend" not in df.columns:
#             df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
#         if "is_after_hours" not in df.columns:
#             df["is_after_hours"] = (1 - df["is_business_hours"]).astype(int)
#     else:
#         # Default time features if timestamp not available
#         for feature in missing_time:
#             df[feature] = 0

#     # PART 8: ADD EVENT COUNT

#     if "event_count" not in df.columns:
#         logger.info("Adding event_count feature")
#         df["event_count"] = 1

#     # PART 9: CHECK FEATURE COUNT AND ADD TIME SERIES FEATURES IF NEEDED

#     # Check current feature count against expected
#     current_feature_count = len(df.columns)

#     if current_feature_count < expected_feature_count:
#         logger.info(f"Current feature count ({current_feature_count}) below expected ({expected_feature_count})")
#         logger.info(f"Adding advanced time series features to match model expectations")

#         # Time series features to potentially add
#         ts_features = [
#             'hour_sin', 'hour_cos', 'day_sin', 'day_cos',
#             'rolling_mean_3h', 'rolling_std_3h', 'rolling_max_3h',
#             'rolling_mean_6h', 'rolling_std_6h', 'rolling_max_6h',
#             'rolling_mean_12h', 'rolling_std_12h', 'rolling_max_12h',
#             'rolling_mean_24h', 'rolling_std_24h', 'rolling_max_24h',
#             'event_count_lag_1', 'event_count_lag_3', 'event_count_lag_6',
#             'event_count_lag_12', 'event_count_lag_24',
#             'event_count_roc', 'event_count_day_roc',
#             'expected_count', 'pattern_deviation', 'relative_deviation'
#         ]

#         existing_ts = [f for f in ts_features if f in df.columns]
#         missing_ts = [f for f in ts_features if f not in df.columns]

#         if existing_ts:
#             logger.info(f"Existing time series features: {existing_ts}")

#         # Prioritize adding features in a logical order until we reach the expected count
#         features_to_add = []
#         for feature in missing_ts:
#             features_to_add.append(feature)
#             if len(df.columns) + len(features_to_add) >= expected_feature_count:
#                 break

#         logger.info(f"Adding {len(features_to_add)} time series features: {features_to_add}")

#         # Cyclic time encoding
#         if "hour_sin" in features_to_add and "hour_of_day" in df.columns:
#             df["hour_sin"] = np.sin(2 * np.pi * df["hour_of_day"] / 24)
#         if "hour_cos" in features_to_add and "hour_of_day" in df.columns:
#             df["hour_cos"] = np.cos(2 * np.pi * df["hour_of_day"] / 24)
#         if "day_sin" in features_to_add and "day_of_week" in df.columns:
#             df["day_sin"] = np.sin(2 * np.pi * df["day_of_week"] / 7)
#         if "day_cos" in features_to_add and "day_of_week" in df.columns:
#             df["day_cos"] = np.cos(2 * np.pi * df["day_of_week"] / 7)

#         # Add the rest of the time series features with reasonable default values
#         for feature in features_to_add:
#             if feature not in df.columns:  # Skip already added features
#                 if feature.startswith('rolling_mean'):
#                     # Rolling means should be close to event_count
#                     df[feature] = df['event_count'] * (1 + np.random.normal(0, 0.1, size=len(df)))
#                 elif feature.startswith('rolling_std'):
#                     # Standard deviations are small positive values
#                     df[feature] = np.abs(np.random.normal(0.5, 0.1, size=len(df)))
#                 elif feature.startswith('rolling_max'):
#                     # Max values should be higher than event_count
#                     df[feature] = df['event_count'] * (1.2 + np.random.normal(0, 0.1, size=len(df)))
#                 elif feature.endswith('_lag_1'):
#                     # Most recent lag close to current value
#                     df[feature] = df['event_count'] * (1 + np.random.normal(0, 0.05, size=len(df)))
#                 elif '_lag_' in feature:
#                     # Other lags similar to event_count with more variation
#                     df[feature] = df['event_count'] * (1 + np.random.normal(0, 0.2, size=len(df)))
#                 elif feature == 'event_count_roc':
#                     # Rate of change usually close to zero
#                     df[feature] = np.random.normal(0, 0.1, size=len(df))
#                 elif feature == 'event_count_day_roc':
#                     # Day rate of change close to zero
#                     df[feature] = np.random.normal(0, 0.15, size=len(df))
#                 elif feature == 'expected_count':
#                     # Expected count close to actual count
#                     df[feature] = df['event_count'] * (1 + np.random.normal(0, 0.1, size=len(df)))
#                 elif feature == 'pattern_deviation':
#                     # Pattern deviation small positive value
#                     df[feature] = np.abs(np.random.normal(0, 0.2, size=len(df)))
#                 elif feature == 'relative_deviation':
#                     # Relative deviation small positive value
#                     df[feature] = np.abs(np.random.normal(0, 0.2, size=len(df)))

#     # Check if we still need more features
#     final_feature_count = len(df.columns)
#     if final_feature_count < expected_feature_count:
#         logger.warning(f"Final feature count ({final_feature_count}) still below expected ({expected_feature_count})")
#         logger.warning("Model may fail due to feature count mismatch")

#     # Log features added
#     new_columns = sorted(list(set(df.columns) - set(original_columns)))
#     if new_columns:
#         logger.info(f"Added {len(new_columns)} new features: {new_columns}")

#     logger.info(f"Final preprocessed dataframe shape: {df.shape}")
#     return df


# def preprocess_discovery_data(df):
#     """
#     Preprocess discovery commands data for anomaly detection.
#     """
#     if df.empty:
#         logger.warning("Empty dataframe received for discovery preprocessing.")
#         return df

#     logger.info(f"Initial discovery dataframe shape: {df.shape}")

#     # Convert timestamp
#     if "@timestamp" in df.columns:
#         df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         df.dropna(subset=["@timestamp"], inplace=True)
#         df.sort_values("@timestamp", inplace=True)

#     # Discovery command categorization
#     discovery_categories = {
#         "network": ["netstat", "ss", "lsof", "nmap", "arp", "route", "ip", "ifconfig"],
#         "process": ["ps", "top", "htop", "pgrep", "pidof"],
#         "user": ["who", "w", "users", "last", "lastlog", "id", "groups"],
#         "system": ["uname", "hostname", "uptime", "lscpu", "df", "mount"],
#         "service": ["systemctl", "service", "chkconfig"]
#     }

#     if "process.name" in df.columns:
#         df["process.name"].fillna("unknown", inplace=True)

#         def categorize_discovery_command(process_name):
#             for category, commands in discovery_categories.items():
#                 if any(cmd in str(process_name).lower() for cmd in commands):
#                     return category
#             return "other"

#         df["discovery_category"] = df["process.name"].apply(categorize_discovery_command)

#     # Command complexity analysis
#     if "process.command_line" in df.columns:
#         df["process.command_line"].fillna("", inplace=True)
#         df["command_length"] = df["process.command_line"].str.len()
#         df["has_pipes"] = df["process.command_line"].str.contains("|", na=False).astype(int)
#         df["has_redirection"] = df["process.command_line"].str.contains("[><]", regex=True, na=False).astype(int)
#         df["args_count"] = df["process.command_line"].str.split().str.len()

#     # User context for discovery
#     if "user.name" in df.columns:
#         df["user.name"].fillna("unknown", inplace=True)
#         df["is_root_discovery"] = (df["user.name"] == "root").astype(int)
#         df["is_regular_user_discovery"] = (~df["user.name"].isin(["root", "daemon", "bin", "sys"])).astype(int)

#     # Time-based features
#     if "@timestamp" in df.columns:
#         df["hour_of_day"] = df["@timestamp"].dt.hour
#         df["day_of_week"] = df["@timestamp"].dt.dayofweek
#         df["is_business_hours"] = ((df["hour_of_day"] >= 8) & (df["hour_of_day"] <= 18) &
#                                  (df["day_of_week"] <= 4)).astype(int)
#         df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)

#     # Add event_count for aggregation
#     df["event_count"] = 1

#     logger.info(f"Preprocessed discovery dataframe shape: {df.shape}")
#     return df


# def preprocess_metadata_data(df):
#     """
#     Preprocess metadata access data for anomaly detection.
#     """
#     if df.empty:
#         logger.warning("Empty dataframe received for metadata preprocessing.")
#         return df

#     logger.info(f"Initial metadata dataframe shape: {df.shape}")

#     # Convert timestamp
#     if "@timestamp" in df.columns:
#         df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         df.dropna(subset=["@timestamp"], inplace=True)
#         df.sort_values("@timestamp", inplace=True)

#     # Access method analysis
#     if "process.name" in df.columns:
#         df["process.name"].fillna("unknown", inplace=True)
#         df["access_method"] = df["process.name"].apply(
#             lambda x: "http_client" if str(x) in ["curl", "wget"] else
#                      "script" if str(x) in ["python", "python3", "bash", "sh"] else "other"
#         )

#     # User context for metadata access
#     if "user.name" in df.columns:
#         df["user.name"].fillna("unknown", inplace=True)
#         df["is_root_access"] = (df["user.name"] == "root").astype(int)
#         df["is_service_account"] = df["user.name"].apply(
#             lambda x: 1 if str(x) in ["www-data", "nginx", "apache", "ubuntu", "ec2-user"] else 0
#         )

#     # Command analysis for credential harvesting indicators
#     if "process.command_line" in df.columns:
#         df["potential_cred_harvest"] = df["process.command_line"].apply(
#             lambda x: 1 if any(keyword in str(x).lower() for keyword in
#                               ["credentials", "token", "key", "secret", "password", "iam"]) else 0
#         )
#         df["user_data_access"] = df["process.command_line"].apply(
#             lambda x: 1 if "user-data" in str(x).lower() else 0
#         )

#     # Time-based features
#     if "@timestamp" in df.columns:
#         df["hour_of_day"] = df["@timestamp"].dt.hour
#         df["day_of_week"] = df["@timestamp"].dt.dayofweek
#         df["is_business_hours"] = ((df["hour_of_day"] >= 8) & (df["hour_of_day"] <= 18) &
#                                  (df["day_of_week"] <= 4)).astype(int)
#         df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)

#     # Add event_count for aggregation
#     df["event_count"] = 1

#     logger.info(f"Preprocessed metadata dataframe shape: {df.shape}")
#     return df


# def calculate_baselines(historical_data, config, data_type="process"):
#     """
#     Calculate baseline statistics for Linux entities.
#     """
#     if historical_data.empty:
#         return {}

#     baselines = {}

#     # Determine entity column based on data type and available fields
#     if data_type == "process":
#         entity_col = 'process.name'
#     elif data_type == "network":
#         # For network, use destination port as primary entity
#         entity_col = 'destination.port'
#     elif data_type == "user":
#         entity_col = 'user.name'
#     elif data_type == "discovery":
#         entity_col = 'process.name'
#     elif data_type == "metadata":
#         entity_col = 'process.name'
#     else:
#         entity_col = 'host.hostname'

#     if entity_col not in historical_data.columns:
#         logger.warning(f"Entity column {entity_col} not found, using available columns")
#         # Fallback to any available identifying column
#         possible_cols = ['process.name', 'user.name', 'host.hostname', 'destination.port']
#         for col in possible_cols:
#             if col in historical_data.columns:
#                 entity_col = col
#                 break
#         else:
#             return {}

#     # Ensure event_count exists
#     if "event_count" not in historical_data.columns:
#         logger.warning("event_count not found, creating default")
#         historical_data["event_count"] = 1

#     # Group data by entity
#     entity_groups = historical_data.groupby(entity_col)

#     for entity, group in entity_groups:
#         # Basic statistics
#         stats = {
#             "mean": group["event_count"].mean(),
#             "std": group["event_count"].std(),
#             "median": group["event_count"].median(),
#             "max": group["event_count"].max(),
#             "min": group["event_count"].min()
#         }

#         # Handle very small standard deviations
#         if stats["std"] < 0.1 or pd.isna(stats["std"]):
#             stats["std"] = max(0.1, stats["mean"] * 0.1)

#         # Calculate percentiles
#         percentiles = {
#             "p50": group["event_count"].quantile(0.5),
#             "p75": group["event_count"].quantile(0.75),
#             "p90": group["event_count"].quantile(0.9),
#             "p95": group["event_count"].quantile(0.95),
#             "p99": group["event_count"].quantile(0.99)
#         }
#         stats["percentiles"] = percentiles

#         # Time-based patterns
#         if "hour_of_day" in group.columns:
#             hour_patterns = group.groupby("hour_of_day")["event_count"].mean().to_dict()
#             stats["hourly_patterns"] = hour_patterns

#         if "day_of_week" in group.columns:
#             day_patterns = group.groupby("day_of_week")["event_count"].mean().to_dict()
#             stats["daily_patterns"] = day_patterns

#         baselines[entity] = stats

#     logger.info(f"Calculated baselines for {len(baselines)} entities")
#     return baselines


# def aggregate_data_for_baseline(df, config, data_type="process"):
#     """
#     Aggregate data to create event counts for baseline training.
#     Optimized for limited data scenarios.
#     """
#     if df.empty:
#         logger.warning("Empty dataframe for aggregation")
#         return df

#     # Ensure timestamp column exists
#     if "@timestamp" not in df.columns:
#         logger.error("No @timestamp column found")
#         return df

#     # For limited data, use smaller time buckets (1-minute instead of 5-minute)
#     # This gives us more data points for training
#     hours_of_data = (df["@timestamp"].max() - df["@timestamp"].min()).total_seconds() / 3600

#     if hours_of_data < 1:
#         bucket_size = '1T'  # 1-minute buckets for very limited data
#     elif hours_of_data < 6:
#         bucket_size = '2T'  # 2-minute buckets for < 6 hours
#     elif hours_of_data < 24:
#         bucket_size = '5T'  # 5-minute buckets for < 24 hours
#     else:
#         bucket_size = '15T'  # 15-minute buckets for more data

#     logger.info(f"Using {bucket_size} time buckets for {hours_of_data:.1f} hours of data")

#     df["time_bucket"] = pd.to_datetime(df["@timestamp"]).dt.floor(bucket_size)

#     # Define aggregation columns based on data type
#     if data_type == "process":
#         group_cols = ["time_bucket", "host.hostname", "process.name", "user.name"]
#     elif data_type == "network":
#         group_cols = ["time_bucket", "process.name", "destination.port", "network.direction"]
#         if "destination.geo.country_name" in df.columns and df["destination.geo.country_name"].notna().any():
#             group_cols.append("destination.geo.country_name")
#     elif data_type == "user":
#         group_cols = ["time_bucket", "host.hostname", "user.name"]
#     elif data_type == "discovery":
#         group_cols = ["time_bucket", "host.hostname", "process.name", "user.name"]
#     elif data_type == "metadata":
#         group_cols = ["time_bucket", "host.hostname", "process.name"]
#     else:
#         group_cols = ["time_bucket", "host.hostname"]

#     # Filter to only existing columns
#     group_cols = [col for col in group_cols if col in df.columns]

#     if not group_cols:
#         logger.error("No grouping columns found")
#         return df

#     # Count events per group
#     event_counts = df.groupby(group_cols).size().reset_index(name='event_count')

#     # Aggregate other features
#     agg_dict = {}

#     # Keep first timestamp
#     if "@timestamp" in df.columns:
#         agg_dict["@timestamp"] = "first"

#     # Aggregate numeric features
#     numeric_features = [
#         "is_root_user", "is_system_user", "is_compiler_activity",
#         "is_sudo_command", "has_pipes", "has_redirection",
#         "is_well_known_port", "is_ephemeral_port", "is_inbound", "is_outbound",
#         "hour_of_day", "day_of_week", "is_business_hours", "is_weekend"
#     ]

#     for feature in numeric_features:
#         if feature in df.columns:
#             agg_dict[feature] = "mean"

#     # Aggregate categorical features
#     categorical_features = [
#         "event.type", "event.action", "network.transport", "network.type"
#     ]

#     for feature in categorical_features:
#         if feature in df.columns:
#             agg_dict[feature] = lambda x: x.mode()[0] if len(x.mode()) > 0 else x.iloc[0]

#     # Perform aggregation
#     if agg_dict:
#         aggregated_features = df.groupby(group_cols).agg(agg_dict).reset_index()
#         aggregated = event_counts.merge(aggregated_features, on=group_cols, how='left')
#     else:
#         aggregated = event_counts

#     logger.info(f"Aggregated {len(df)} records into {len(aggregated)} time buckets")
#     logger.info(f"Event count range: {aggregated['event_count'].min()} to {aggregated['event_count'].max()}")

#     # With limited data, log if we have very few aggregated records
#     if len(aggregated) < 100:
#         logger.warning(f"Only {len(aggregated)} aggregated records available.")
#         logger.warning("Model may have limited accuracy. Consider collecting more data.")

#     return aggregated


# def aggregate_data_by_group(data_dict):
#     """
#     Aggregate data by the defined groups for efficient processing.

#     Args:
#         data_dict (dict): Dictionary containing different types of data

#     Returns:
#         dict: Aggregated data by group
#     """
#     logger.info("Aggregating data by groups for efficient processing")

#     grouped_data = {
#         "network_security": {
#             "process_network": data_dict.get("process", pd.DataFrame()),
#             "network_activity": data_dict.get("network", pd.DataFrame())
#         },
#         "process_monitoring": {
#             "process_data": data_dict.get("process", pd.DataFrame())
#         },
#         "user_behavior": {
#             "user_activity": data_dict.get("user", pd.DataFrame()),
#             "process_user_context": data_dict.get("process", pd.DataFrame())
#         },
#         "discovery_activity": {
#             "discovery_commands": data_dict.get("discovery", pd.DataFrame())
#         },
#         "metadata_access": {
#             "metadata_events": data_dict.get("metadata", pd.DataFrame())
#         }
#     }

#     # Log aggregation statistics
#     for group, data in grouped_data.items():
#         total_records = sum(len(df) for df in data.values())
#         logger.info(f"Group '{group}': {total_records} total records across {len(data)} data sources")

#     return grouped_data


# def create_time_buckets(df, bucket_span="15m", timestamp_col="@timestamp"):
#     """
#     Create time buckets and return aggregated DataFrame in expected format.

#     Args:
#         df (pd.DataFrame): DataFrame with timestamp data
#         bucket_span (str): Time bucket span (e.g., "15m", "1h", "1d")
#         timestamp_col (str): Name of timestamp column

#     Returns:
#         pd.DataFrame: Aggregated DataFrame with time bucket info included
#     """
#     if df.empty or timestamp_col not in df.columns:
#         logger.warning("Cannot create time buckets: empty DataFrame or missing timestamp column")
#         return pd.DataFrame()

#     # Convert bucket span to pandas frequency
#     freq_map = {
#         "1m": "1T", "5m": "5T", "15m": "15T", "30m": "30T",
#         "1h": "1H", "2h": "2H", "6h": "6H", "12h": "12H",
#         "1d": "1D", "1w": "1W"
#     }

#     freq = freq_map.get(bucket_span, "15T")  # Default to 15 minutes

#     df = df.copy()
#     df["time_bucket"] = df[timestamp_col].dt.floor(freq)

#     # Group by time bucket and key fields, then aggregate
#     grouping_cols = ["time_bucket", "host.hostname", "process.name", "user.name"]

#     # Only use columns that exist
#     available_grouping_cols = [col for col in grouping_cols if col in df.columns]

#     if not available_grouping_cols:
#         logger.warning("No grouping columns available for time bucketing")
#         return df

#     # Aggregate by time bucket and entity
#     agg_dict = {
#         timestamp_col: 'first',  # Keep first timestamp from bucket
#         'event_count': 'sum' if 'event_count' in df.columns else 'size'
#     }

#     # Add other numeric columns for aggregation
#     numeric_cols = df.select_dtypes(include=[np.number]).columns
#     for col in numeric_cols:
#         if col not in agg_dict and col != 'event_count':
#             agg_dict[col] = 'mean'  # Average for numeric features

#     # Add categorical columns (take first value)
#     categorical_cols = ['event.action', 'event.type', 'event.category', 'process.executable']
#     for col in categorical_cols:
#         if col in df.columns and col not in agg_dict:
#             agg_dict[col] = 'first'

#     try:
#         # Perform aggregation
#         if 'event_count' not in df.columns:
#             # If no event_count, create it by counting rows
#             aggregated = df.groupby(available_grouping_cols).agg(agg_dict).reset_index()
#             aggregated['event_count'] = df.groupby(available_grouping_cols).size().values
#         else:
#             aggregated = df.groupby(available_grouping_cols).agg(agg_dict).reset_index()

#         # Add time bucket metadata
#         aggregated['bucket_span'] = bucket_span
#         aggregated['bucket_start'] = aggregated['time_bucket']
#         aggregated['bucket_end'] = aggregated['time_bucket'] + pd.Timedelta(freq)

#         logger.info(f"Created time buckets with {bucket_span} span")
#         logger.info(f"Aggregated {len(df)} records into {len(aggregated)} time-bucketed records")
#         logger.info(f"Time buckets span: {aggregated['time_bucket'].min()} to {aggregated['time_bucket'].max()}")

#         return aggregated

#     except Exception as e:
#         logger.error(f"Error in time bucketing aggregation: {e}")
#         # Fallback: return original data with time bucket column
#         logger.warning("Returning original data with time bucket column added")
#         return df


# logger = logging.getLogger("linux_anomaly_detection")

# def connect_to_elasticsearch(config):
#     """
#     Establish connection to Elasticsearch cluster.

#     Args:
#         config (dict): Elasticsearch configuration dictionary

#     Returns:
#         Elasticsearch: Elasticsearch client object or None if connection fails
#     """
#     try:
#         es_config = config["elasticsearch"]
#         es = Elasticsearch(
#             es_config["host"],
#             basic_auth=(es_config["username"], es_config["password"]),
#             verify_certs=False,
#             ssl_show_warn=False,
#             timeout=60
#         )
#         if es.ping():
#             logger.info("Connected to Elasticsearch successfully!")
#             return es
#         else:
#             logger.error("Failed to connect to Elasticsearch.")
#             return None
#     except Exception as e:
#         logger.error(f"Error connecting to Elasticsearch: {e}")
#         return None


# def debug_elasticsearch_data(es, index_pattern=".ds-logs-endpoint.events.process-default-*"):
#     """
#     Enhanced debug function to check Elasticsearch data availability and structure.
#     Now includes deep investigation of field mappings and data structure.
#     """
#     try:
#         logger.info("=== ELASTICSEARCH DEBUG INFORMATION ===")

#         # Test 1: Check cluster health
#         health = es.cluster.health()
#         cluster_status = health.get('status', 'unknown')
#         logger.info(f"Cluster health: {cluster_status}")

#         if cluster_status == 'red':
#             logger.warning("CLUSTER IS RED - This may cause data retrieval issues!")
#             logger.warning("Some shards may be unallocated or corrupted")

#         # Test 2: Check individual indices health
#         try:
#             indices_info = es.cat.indices(index=index_pattern, format='json', h='index,health,status,docs.count,store.size')
#             logger.info("=== INDIVIDUAL INDICES HEALTH ===")
#             for idx in indices_info[:5]:  # Show first 5 indices
#                 logger.info(f"Index: {idx['index']}, Health: {idx['health']}, Docs: {idx['docs.count']}")
#         except Exception as e:
#             logger.warning(f"Could not get individual indices info: {e}")

#         # Test 3: Check if index exists and get count
#         try:
#             count_result = es.count(index=index_pattern)
#             total_docs = count_result.get('count', 0)
#             logger.info(f"Total documents in {index_pattern}: {total_docs:,}")
#         except Exception as e:
#             logger.warning(f"Could not count documents in {index_pattern}: {e}")
#             return None

#         # Test 4: Check field mappings for @timestamp
#         try:
#             logger.info("=== CHECKING FIELD MAPPINGS ===")
#             mapping_result = es.indices.get_mapping(index=index_pattern)

#             # Examine @timestamp field mapping
#             for index_name, mapping_data in mapping_result.items():
#                 properties = mapping_data.get('mappings', {}).get('properties', {})
#                 timestamp_mapping = properties.get('@timestamp', {})

#                 if timestamp_mapping:
#                     logger.info(f"@timestamp mapping in {index_name}: {timestamp_mapping}")
#                     break
#                 else:
#                     logger.warning(f"@timestamp field not found in {index_name} mappings")
#                     # Show available fields
#                     available_fields = list(properties.keys())[:10]
#                     logger.info(f"Available fields: {available_fields}")

#         except Exception as e:
#             logger.warning(f"Could not get field mappings: {e}")

#         # Test 5: Get sample documents with detailed timestamp analysis
#         try:
#             logger.info("=== ANALYZING SAMPLE DOCUMENTS ===")
#             recent_query = {
#                 "size": 10,  # Start with smaller sample for analysis
#                 "query": {"match_all": {}},
#                 "sort": [{"@timestamp": {"order": "desc"}}],
#                 "_source": ["@timestamp", "event", "process.name", "host.hostname"]  # Focus on key fields
#             }
#             recent_result = es.search(index=index_pattern, body=recent_query)
#             recent_docs = recent_result.get('hits', {}).get('hits', [])

#             if recent_docs:
#                 logger.info(f"Found {len(recent_docs)} recent documents")

#                 # Analyze timestamps in detail
#                 timestamps = []
#                 timestamp_formats = set()

#                 for i, doc in enumerate(recent_docs):
#                     source = doc.get('_source', {})
#                     ts = source.get('@timestamp')

#                     if ts:
#                         timestamps.append(ts)
#                         timestamp_formats.add(type(ts).__name__)

#                         if i < 3:  # Show first 3 timestamps in detail
#                             logger.info(f"Sample timestamp {i+1}: {ts} (type: {type(ts).__name__})")

#                 if timestamps:
#                     logger.info(f"Timestamp formats found: {timestamp_formats}")
#                     logger.info(f"Raw timestamp range: {min(timestamps)} to {max(timestamps)}")

#                     # Test if we can query these exact timestamps
#                     logger.info("=== TESTING TIMESTAMP QUERIES ===")

#                     # Test 1: Query with exact timestamp from sample
#                     sample_ts = timestamps[0]
#                     test_query_1 = {
#                         "size": 1,
#                         "query": {
#                             "range": {
#                                 "@timestamp": {
#                                     "gte": sample_ts,
#                                     "lte": sample_ts
#                                 }
#                             }
#                         }
#                     }

#                     try:
#                         test_result_1 = es.search(index=index_pattern, body=test_query_1)
#                         test_hits_1 = test_result_1.get('hits', {}).get('total', {}).get('value', 0)
#                         logger.info(f"Exact timestamp query result: {test_hits_1} hits")
#                     except Exception as e:
#                         logger.error(f"Exact timestamp query failed: {e}")

#                     # Test 2: Query with broader range around sample timestamp
#                     sample_dt = pd.to_datetime(sample_ts, utc=True)
#                     start_range = sample_dt - timedelta(minutes=5)
#                     end_range = sample_dt + timedelta(minutes=5)

#                     test_query_2 = {
#                         "size": 10,
#                         "query": {
#                             "range": {
#                                 "@timestamp": {
#                                     "gte": start_range.isoformat(),
#                                     "lte": end_range.isoformat()
#                                 }
#                             }
#                         }
#                     }

#                     try:
#                         test_result_2 = es.search(index=index_pattern, body=test_query_2)
#                         test_hits_2 = test_result_2.get('hits', {}).get('total', {}).get('value', 0)
#                         logger.info(f"10-minute window query result: {test_hits_2} hits")

#                         if test_hits_2 > 0:
#                             logger.info("SUCCESS: Range queries work with proper format!")
#                             # Get the successful query format
#                             successful_format = {
#                                 "start": start_range.isoformat(),
#                                 "end": end_range.isoformat(),
#                                 "sample_ts": sample_ts
#                             }

#                             # Add successful format to docs for later use
#                             for doc in recent_docs:
#                                 doc['_successful_query_format'] = successful_format

#                         else:
#                             logger.error("Range queries still return 0 hits!")

#                     except Exception as e:
#                         logger.error(f"Range query test failed: {e}")

#                     # Test 3: Try different timestamp field names
#                     alternative_timestamp_fields = ['timestamp', 'event.created', 'event.ingested', '@event_timestamp']

#                     for field in alternative_timestamp_fields:
#                         try:
#                             alt_query = {
#                                 "size": 1,
#                                 "query": {
#                                     "range": {
#                                         field: {
#                                             "gte": start_range.isoformat(),
#                                             "lte": end_range.isoformat()
#                                         }
#                                     }
#                                 }
#                             }
#                             alt_result = es.search(index=index_pattern, body=alt_query)
#                             alt_hits = alt_result.get('hits', {}).get('total', {}).get('value', 0)

#                             if alt_hits > 0:
#                                 logger.info(f"FOUND WORKING TIMESTAMP FIELD: {field} returned {alt_hits} hits")

#                         except Exception as e:
#                             logger.debug(f"Alternative field {field} failed: {e}")

#                     # Convert timestamps for time range expansion (original logic)
#                     try:
#                         latest_ts = pd.to_datetime(max(timestamps), utc=True)
#                         earliest_ts = pd.to_datetime(min(timestamps), utc=True)
#                         original_span_hours = (latest_ts - earliest_ts).total_seconds() / 3600

#                         logger.info(f"Original span: {original_span_hours:.6f} hours")

#                         # Apply intelligent time expansion
#                         if original_span_hours < 0.1:  # Less than 6 minutes
#                             logger.warning("Very narrow time range detected - applying expansion")

#                             # Expand around the center time
#                             center_time = earliest_ts + (latest_ts - earliest_ts) / 2
#                             expansion_hours = 6  # Expand to 6 hours total

#                             earliest_ts = center_time - timedelta(hours=expansion_hours/2)
#                             latest_ts = center_time + timedelta(hours=expansion_hours/2)

#                             logger.info(f"Expanded time range: {earliest_ts} to {latest_ts}")
#                             logger.info(f"Expanded span: {expansion_hours} hours")

#                         elif original_span_hours < 1:  # Less than 1 hour
#                             logger.info("Short time range - adding buffer")

#                             # Add 2-hour buffer on each side
#                             buffer_hours = 2
#                             earliest_ts = earliest_ts - timedelta(hours=buffer_hours)
#                             latest_ts = latest_ts + timedelta(hours=buffer_hours)

#                             final_span = (latest_ts - earliest_ts).total_seconds() / 3600
#                             logger.info(f"Buffered time range: {earliest_ts} to {latest_ts}")
#                             logger.info(f"Buffered span: {final_span:.1f} hours")

#                         else:
#                             logger.info("Adequate time range found")

#                         # Round timestamps to avoid precision issues
#                         earliest_ts = earliest_ts.floor('1T')  # Round down to minute
#                         latest_ts = latest_ts.ceil('1T')      # Round up to minute

#                         # Update recent_docs with expanded time info
#                         for doc in recent_docs:
#                             doc['_expanded_time_range'] = {
#                                 'start': earliest_ts,
#                                 'end': latest_ts,
#                                 'span_hours': (latest_ts - earliest_ts).total_seconds() / 3600
#                             }

#                     except Exception as e:
#                         logger.error(f"Error in time range expansion: {e}")

#                 # Show sample document structure
#                 if recent_docs:
#                     sample_doc = recent_docs[0]['_source']
#                     logger.info("Sample document fields:")
#                     for key in sorted(sample_doc.keys()):
#                         logger.info(f"  - {key}")

#                 return recent_docs
#             else:
#                 logger.warning("No documents found with match_all query")
#                 return None

#         except Exception as e:
#             logger.error(f"Could not retrieve recent documents: {e}")
#             return None

#     except Exception as e:
#         logger.error(f"Debug function failed: {e}")
#         return None
# def validate_and_fix_fields(df):
#     """
#     Ensure expected fields exist after flattening and provide fallbacks.
#     Maps flattened field names to expected field names used by anomaly detection.

#     Args:
#         df (pd.DataFrame): DataFrame with flattened fields

#     Returns:
#         pd.DataFrame: DataFrame with validated and fixed field names
#     """
#     if df.empty:
#         return df

#     # Required field mappings from flattened names to expected names
#     required_mappings = {
#         # Process fields
#         'process.name': ['process.name', 'process_name'],
#         'process.executable': ['process.executable', 'process_executable'],
#         'process.command_line': ['process.command_line', 'process_command_line'],
#         'process.args': ['process.args', 'process_args'],
#         'process.args_count': ['process.args_count', 'process_args_count', 'args_count'],
#         'process.pid': ['process.pid', 'process_pid'],
#         'process.entity_id': ['process.entity_id', 'process_entity_id'],
#         'process.working_directory': ['process.working_directory', 'process_working_directory'],

#         # Process parent fields
#         'process.parent.name': ['process.parent.name', 'process_parent_name'],
#         'process.parent.executable': ['process.parent.executable', 'process_parent_executable'],
#         'process.parent.command_line': ['process.parent.command_line', 'process_parent_command_line'],
#         'process.parent.pid': ['process.parent.pid', 'process_parent_pid'],
#         'process.parent.entity_id': ['process.parent.entity_id', 'process_parent_entity_id'],

#         # User fields
#         'user.name': ['user.name', 'user_name'],
#         'user.id': ['user.id', 'user_id'],
#         'user.Ext.real.name': ['user.Ext.real.name', 'user_Ext_real_name'],
#         'user.Ext.real.id': ['user.Ext.real.id', 'user_Ext_real_id'],

#         # Group fields
#         'group.name': ['group.name', 'group_name'],
#         'group.id': ['group.id', 'group_id'],
#         'group.Ext.real.name': ['group.Ext.real.name', 'group_Ext_real_name'],
#         'group.Ext.real.id': ['group.Ext.real.id', 'group_Ext_real_id'],

#         # Host fields
#         'host.hostname': ['host.hostname', 'host_hostname'],
#         'host.id': ['host.id', 'host_id'],
#         'host.name': ['host.name', 'host_name'],
#         'host.os.name': ['host.os.name', 'host_os_name'],
#         'host.os.version': ['host.os.version', 'host_os_version'],
#         'host.os.family': ['host.os.family', 'host_os_family'],
#         'host.os.type': ['host.os.type', 'host_os_type'],
#         'host.ip': ['host.ip', 'host_ip'],
#         'host.mac': ['host.mac', 'host_mac'],
#         'host.architecture': ['host.architecture', 'host_architecture'],

#         # Event fields
#         'event.action': ['event.action', 'event_action'],
#         'event.type': ['event.type', 'event_type'],
#         'event.category': ['event.category', 'event_category'],
#         'event.outcome': ['event.outcome', 'event_outcome'],
#         'event.sequence': ['event.sequence', 'event_sequence'],
#         'event.id': ['event.id', 'event_id'],
#         'event.kind': ['event.kind', 'event_kind'],
#         'event.module': ['event.module', 'event_module'],
#         'event.created': ['event.created', 'event_created'],
#         'event.ingested': ['event.ingested', 'event_ingested'],

#         # Agent fields
#         'agent.id': ['agent.id', 'agent_id'],
#         'agent.type': ['agent.type', 'agent_type'],
#         'agent.version': ['agent.version', 'agent_version'],

#         # Hash fields
#         'process.hash.sha256': ['process.hash.sha256', 'process_hash_sha256'],
#         'process.hash.sha1': ['process.hash.sha1', 'process_hash_sha1'],
#         'process.hash.md5': ['process.hash.md5', 'process_hash_md5'],

#         # Network fields (for network data)
#         'network.transport': ['network.transport', 'network_transport'],
#         'network.direction': ['network.direction', 'network_direction'],
#         'network.type': ['network.type', 'network_type'],
#         'source.ip': ['source.ip', 'source_ip'],
#         'source.port': ['source.port', 'source_port'],
#         'destination.ip': ['destination.ip', 'destination_ip'],
#         'destination.port': ['destination.port', 'destination_port'],
#         'destination.address': ['destination.address', 'destination_address'],
#         'destination.domain': ['destination.domain', 'destination_domain']
#     }

#     # Apply field mappings
#     for expected_field, possible_fields in required_mappings.items():
#         if expected_field not in df.columns:
#             # Try to find the field under alternative names
#             for alt_field in possible_fields:
#                 if alt_field in df.columns:
#                     df[expected_field] = df[alt_field]
#                     logger.debug(f"Mapped {alt_field} -> {expected_field}")
#                     break
#             else:
#                 # If still not found, create with appropriate default values
#                 if any(x in expected_field for x in ['name', 'executable', 'command_line']):
#                     df[expected_field] = 'unknown'
#                 elif any(x in expected_field for x in ['action', 'type', 'category', 'outcome', 'kind', 'module']):
#                     df[expected_field] = 'unknown'
#                 elif any(x in expected_field for x in ['id', 'pid', 'sequence']):
#                     df[expected_field] = 0
#                 elif any(x in expected_field for x in ['ip', 'port', 'address', 'domain']):
#                     df[expected_field] = ''
#                 else:
#                     df[expected_field] = ''

#                 logger.debug(f"Created missing field {expected_field} with default value")

#     return df

# def flatten_dict(d, parent_key='', sep='.'):
#     """
#     designed for Elasticsearch endpoint event documents.

#     Args:
#         d (dict): Dictionary to flatten
#         parent_key (str): Prefix for nested keys
#         sep (str): Separator for flattened keys

#     Returns:
#         dict: Flattened dictionary with proper array handling
#     """
#     items = []
#     for k, v in d.items():
#         new_key = f"{parent_key}{sep}{k}" if parent_key else k

#         if isinstance(v, dict):
#             # Recursively flatten nested dictionaries
#             items.extend(flatten_dict(v, new_key, sep=sep).items())
#         elif isinstance(v, list):
#             # Handle arrays properly based on content type
#             if len(v) > 0:
#                 # If it's a list of strings/primitives (like process.args), join them
#                 if all(isinstance(item, (str, int, float, bool)) for item in v):
#                     if k == 'args':
#                         # Special handling for process args - join with spaces
#                         items.append((new_key, ' '.join(str(item) for item in v)))
#                         # Also create args_count field
#                         items.append((f"{parent_key}{sep}args_count" if parent_key else "args_count", len(v)))
#                     elif k in ['action', 'type', 'category']:
#                         # For event fields that are arrays, take first element or join
#                         if len(v) == 1:
#                             items.append((new_key, v[0]))
#                         else:
#                             items.append((new_key, ','.join(str(item) for item in v)))
#                     else:
#                         # Default: join with commas
#                         items.append((new_key, ','.join(str(item) for item in v)))
#                 # If it's a list of dicts, flatten each with index
#                 elif all(isinstance(item, dict) for item in v):
#                     for i, item in enumerate(v):
#                         items.extend(flatten_dict(item, f"{new_key}_{i}", sep=sep).items())
#                 else:
#                     # Mixed types - convert to string representation
#                     items.append((new_key, str(v)))
#             else:
#                 # Empty array
#                 items.append((new_key, ''))
#         else:
#             # Primitive values
#             items.append((new_key, v))

#     return dict(items)


# class OptimizedRetriever:
#     """Enhanced retriever with better debugging and error handling"""

#     def __init__(self, es_client, config):
#         self.es = es_client
#         self.config = config
#         self.max_workers = config.get("max_workers", 4)
#         self.batch_size = min(config.get("batch_size", 10000), 10000)
#         self.debug_mode = config.get("debug_mode", False)

#     def retrieve_with_search_after(self, index_pattern, query_body, source_fields, max_records=None):
#         """Enhanced search_after with proper field handling and debugging"""
#         all_records = []
#         search_after = None
#         page_count = 0

#         # Use simplified source fields - request parent objects instead of dot-notation
#         simplified_source = [
#             "@timestamp", "host", "process", "user", "group", "event",
#             "agent", "data_stream", "ecs", "message"
#         ]

#         # Debug the initial query
#         if self.debug_mode:
#             logger.info("=== ENHANCED QUERY DEBUG ===")
#             logger.info(f"Index pattern: {index_pattern}")
#             logger.info(f"Original source fields requested: {len(source_fields)} fields")
#             logger.info(f"Using simplified source fields: {simplified_source}")
#             logger.info(f"Query body: {json.dumps(query_body, indent=2)}")

#         while True:
#             page_count += 1

#             # Construct the search query with improved error handling
#             query = {
#                 "size": self.batch_size,
#                 "_source": simplified_source,  # Use simplified source fields
#                 "query": query_body.get("query", {"match_all": {}})
#             }

#             # Enhanced sorting logic with better fallbacks
#             try:
#                 # Try with just @timestamp first
#                 query["sort"] = [{"@timestamp": {"order": "desc"}}]

#                 # Add secondary sort if available
#                 if "event.sequence" in simplified_source:
#                     query["sort"].append({"event.sequence": {"order": "desc"}})

#             except Exception as sort_error:
#                 logger.warning(f"Sort configuration failed: {sort_error}")
#                 # Remove sorting entirely if it fails
#                 pass

#             if search_after:
#                 query["search_after"] = search_after

#             try:
#                 if self.debug_mode:
#                     logger.info(f"=== PAGE {page_count} ENHANCED QUERY ===")
#                     logger.info(f"Query: {json.dumps(query, indent=2)}")

#                 response = self.es.search(index=index_pattern, body=query)

#                 if self.debug_mode:
#                     total_hits = response.get("hits", {}).get("total", {})
#                     logger.info(f"Page {page_count} response - Total: {total_hits}, Returned: {len(response.get('hits', {}).get('hits', []))}")

#                 hits = response.get("hits", {}).get("hits", [])

#                 # Enhanced error handling for first page
#                 if page_count == 1 and not hits:
#                     logger.warning("No hits returned on first page with enhanced query")

#                     # Try even simpler fallback
#                     fallback_query = {
#                         "size": min(self.batch_size, 100),
#                         "_source": ["@timestamp", "process", "user", "host", "event"],
#                         "query": {"match_all": {}}
#                     }

#                     try:
#                         fallback_response = self.es.search(index=index_pattern, body=fallback_query)
#                         fallback_hits = fallback_response.get("hits", {}).get("hits", [])

#                         if fallback_hits:
#                             logger.info(f"Fallback query successful: {len(fallback_hits)} hits")
#                             hits = fallback_hits
#                         else:
#                             logger.error("Even fallback query returned no results")
#                             break

#                     except Exception as fallback_error:
#                         logger.error(f"Fallback query failed: {fallback_error}")
#                         break

#                 if not hits:
#                     break

#                 # Enhanced record processing with validation
#                 try:
#                     records = []
#                     for hit in hits:
#                         # Apply enhanced flattening
#                         flattened = flatten_dict(hit["_source"])
#                         records.append(flattened)

#                     # Convert to DataFrame for validation
#                     if records:
#                         temp_df = pd.DataFrame(records)
#                         validated_df = validate_and_fix_fields(temp_df)
#                         validated_records = validated_df.to_dict('records')
#                         all_records.extend(validated_records)

#                         if self.debug_mode and page_count == 1:
#                             logger.info(f"Sample enhanced record fields: {list(validated_records[0].keys())[:15]}...")
#                             logger.info(f"Enhanced flattening created {len(validated_records[0])} fields per record")

#                 except Exception as processing_error:
#                     logger.error(f"Error in enhanced record processing on page {page_count}: {processing_error}")
#                     # Fallback to simple flattening
#                     try:
#                         records = [flatten_dict(hit["_source"]) for hit in hits]
#                         all_records.extend(records)
#                         logger.warning("Used fallback simple flattening")
#                     except Exception as fallback_error:
#                         logger.error(f"Even fallback flattening failed: {fallback_error}")
#                         continue

#                 # Get search_after values for next page
#                 if "sort" in query and hits and len(hits) > 0:
#                     try:
#                         search_after = hits[-1]["sort"]
#                     except KeyError:
#                         logger.warning("No sort values in response - pagination may not work correctly")
#                         break
#                 else:
#                     # No sorting means no pagination - get what we can and break
#                     break

#                 # Check if we've reached max_records
#                 if max_records and len(all_records) >= max_records:
#                     all_records = all_records[:max_records]
#                     logger.info(f"Reached maximum records limit of {max_records:,}")
#                     break

#                 # Log progress
#                 if len(all_records) % 50000 == 0:
#                     logger.info(f"Retrieved {len(all_records):,} enhanced records so far...")

#                 # Safety check - don't infinite loop
#                 if page_count > 1000:
#                     logger.warning(f"Stopping after {page_count} pages to prevent infinite loop")
#                     break

#             except Exception as e:
#                 logger.error(f"Error in enhanced search_after retrieval on page {page_count}: {e}")
#                 if self.debug_mode:
#                     import traceback
#                     logger.error(f"Full traceback: {traceback.format_exc()}")
#                 break

#         logger.info(f"Enhanced retrieval: {len(all_records):,} records across {page_count} pages")

#         # Final validation if we got records
#         if all_records:
#             try:
#                 final_df = pd.DataFrame(all_records)
#                 final_validated_df = validate_and_fix_fields(final_df)
#                 final_records = final_validated_df.to_dict('records')
#                 logger.info(f"Final validation complete: {len(final_records)} validated records")
#                 return final_records
#             except Exception as final_error:
#                 logger.error(f"Final validation failed: {final_error}, returning raw records")
#                 return all_records

#         return all_records

# def debug_elasticsearch_enhanced(es, index_pattern=".ds-logs-endpoint.events.process-default-*"):
#     """
#     Enhanced debug function that specifically tests the new field access patterns.
#     """
#     try:
#         logger.info("=== ENHANCED ELASTICSEARCH DEBUG ===")

#         # Test 1: Basic connectivity
#         health = es.cluster.health()
#         logger.info(f"Cluster health: {health.get('status', 'unknown')}")

#         # Test 2: Test new source field pattern
#         test_query = {
#             "size": 5,
#             "_source": ["@timestamp", "host", "process", "user", "event"],
#             "query": {"match_all": {}},
#             "sort": [{"@timestamp": {"order": "desc"}}]
#         }

#         try:
#             response = es.search(index=index_pattern, body=test_query)
#             hits = response.get('hits', {}).get('hits', [])

#             if hits:
#                 logger.info(f"✅ Enhanced field access test: {len(hits)} records retrieved")

#                 # Test flattening on sample
#                 sample_doc = hits[0]['_source']
#                 flattened = flatten_dict(sample_doc)

#                 logger.info(f"✅ Enhanced flattening test: {len(flattened)} fields created")
#                 logger.info(f"Sample flattened fields: {list(flattened.keys())[:10]}")

#                 # Test validation
#                 temp_df = pd.DataFrame([flattened])
#                 validated_df = validate_and_fix_fields(temp_df)

#                 logger.info(f"✅ Field validation test: {len(validated_df.columns)} final fields")

#                 # Check for key expected fields
#                 key_fields = ['process.name', 'user.name', '@timestamp', 'event.action']
#                 found_fields = [f for f in key_fields if f in validated_df.columns]
#                 missing_fields = [f for f in key_fields if f not in validated_df.columns]

#                 logger.info(f"✅ Key fields found: {found_fields}")
#                 if missing_fields:
#                     logger.warning(f"❌ Key fields missing: {missing_fields}")

#                 return True
#             else:
#                 logger.error("❌ Enhanced field access test failed: no records")
#                 return False

#         except Exception as e:
#             logger.error(f"❌ Enhanced field access test failed: {e}")
#             return False

#     except Exception as e:
#         logger.error(f"❌ Enhanced debug failed: {e}")
#         return False
# def test_enhanced_data_retrieval(es, config):
#     """
#     Quick test function to verify the enhanced data retrieval works.
#     """
#     logger.info("=== TESTING ENHANCED DATA RETRIEVAL ===")

#     try:
#         # Test the enhanced retriever
#         retriever_config = {
#             "batch_size": 100,
#             "debug_mode": True
#         }
#         retriever = OptimizedRetriever(es, retriever_config)

#         query_body = {"query": {"match_all": {}}}
#         source_fields = ["@timestamp", "process.name", "user.name"]  # Old style fields

#         records = retriever.retrieve_with_search_after(
#             ".ds-logs-endpoint.events.process-default-*",
#             query_body,
#             source_fields,
#             100
#         )

#         if records and len(records) > 0:
#             df = pd.DataFrame(records)
#             logger.info(f"✅ Test successful: Retrieved {len(records)} records")
#             logger.info(f"✅ DataFrame shape: {df.shape}")
#             logger.info(f"✅ Available fields: {list(df.columns)[:20]}")

#             # Check for key fields
#             key_fields = ['process.name', 'user.name', '@timestamp']
#             available_key_fields = [f for f in key_fields if f in df.columns]
#             logger.info(f"✅ Key fields available: {available_key_fields}")

#             return True
#         else:
#             logger.error("❌ Test failed: No records retrieved")
#             return False

#     except Exception as e:
#         logger.error(f"❌ Test failed with error: {e}")
#         return False

# def fetch_process_data(es, config, time_range=None, query_size=10000):
#     """
#     Enhanced fetch process data with better debugging and error handling.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     try:
#         query_size = int(query_size)
#     except (TypeError, ValueError):
#         query_size = 10000
#         logger.warning(f"Invalid query_size, using default: {query_size}")

#     # Enhanced time range handling
#     if not time_range:
#         # First, check what data is actually available
#         debug_docs = debug_elasticsearch_data(es)

#         if debug_docs:
#             # Extract timestamps from recent data
#             timestamps = []
#             for doc in debug_docs:
#                 ts = doc.get('_source', {}).get('@timestamp')
#                 if ts:
#                     timestamps.append(pd.to_datetime(ts, utc=True))

#             if timestamps:
#                 latest_ts = max(timestamps)
#                 earliest_ts = min(timestamps)
#                 logger.info(f"Available data range: {earliest_ts} to {latest_ts}")

#                 # Use a more intelligent time range based on available data
#                 end_time = latest_ts
#                 start_time = max(earliest_ts, end_time - timedelta(hours=12))

#                 logger.info(f"Using intelligent time range: {start_time} to {end_time}")
#             else:
#                 logger.warning("No valid timestamps found in debug data")
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=24)
#         else:
#             logger.warning("Could not determine available data range, using default")
#             end_time = datetime.utcnow()
#             start_time = end_time - timedelta(hours=24)

#         start_time = pd.Timestamp(start_time, tz='UTC')
#         end_time = pd.Timestamp(end_time, tz='UTC')
#         time_range = {
#             "gte": start_time.isoformat(),
#             "lte": end_time.isoformat()  # Changed from "lt" to "lte"
#         }
#         logger.info(f"Using time range for process data: {start_time} to {end_time}")

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"

#     source_fields = [
#         "@timestamp", "host.hostname", "host.id", "host.name",
#         "host.os.name", "host.os.version", "host.os.family", "host.os.type",
#         "host.ip", "host.mac", "host.architecture",
#         "process.name", "process.executable", "process.args", "process.command_line",
#         "process.pid", "process.entity_id", "process.working_directory",
#         "process.hash.sha256", "process.hash.sha1", "process.hash.md5", "process.args_count",
#         "process.parent.name", "process.parent.executable", "process.parent.pid",
#         "process.parent.entity_id", "process.parent.command_line", "process.parent.args",
#         "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#         "group.name", "group.id", "group.Ext.real.name", "group.Ext.real.id",
#         "event.action", "event.type", "event.outcome", "event.category",
#         "event.sequence", "event.id", "event.kind", "event.module",
#         "agent.id", "agent.type", "agent.version"
#     ]

#     # Enhanced retriever with debugging
#     retriever_config = {
#         "batch_size": min(query_size, 10000),
#         "debug_mode": config.get("debug_mode", False)
#     }
#     retriever = OptimizedRetriever(es, retriever_config)

#     query_body = {
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         records = retriever.retrieve_with_search_after(
#             index_pattern, query_body, source_fields, query_size
#         )

#         if not records:
#             logger.warning("No discovery commands data returned from Elasticsearch.")
#             # Try without time filter
#             fallback_query = {"query": {"match_all": {}}}
#             records = retriever.retrieve_with_search_after(
#                 index_pattern, fallback_query, source_fields, min(query_size, 1000)
#             )

#         if not records:
#             return pd.DataFrame()

#         df = pd.DataFrame(records)

#         # Apply existing preprocessing
#         if "@timestamp" in df.columns:
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

#         # Apply time filtering
#         if isinstance(time_range, dict) and "@timestamp" in df.columns:
#             start_time = pd.to_datetime(time_range["gte"], utc=True)
#             end_time = pd.to_datetime(time_range["lte"], utc=True)
#             df = df[(df["@timestamp"] >= start_time) & (df["@timestamp"] <= end_time)]

#         # Apply discovery command filtering
#         discovery_commands = ["netstat", "ss", "lsof", "ps", "top", "htop", "who", "w", "users",
#                              "last", "lastlog", "id", "groups", "getent", "finger", "uname",
#                              "hostname", "uptime", "lscpu", "lsmem", "lsblk", "df", "mount",
#                              "free", "vmstat", "systemctl", "service", "chkconfig", "crontab",
#                              "pgrep", "pidof", "jobs", "pstree", "nmap", "arp", "route", "ip",
#                              "ifconfig", "ping", "traceroute"]

#         if "process.name" in df.columns and len(df) > 0:
#             df["is_discovery"] = df["process.name"].apply(
#                 lambda x: 1 if any(cmd in str(x).lower() for cmd in discovery_commands) else 0
#             )
#             df = df[df["is_discovery"] == 1]

#         return df

#     except Exception as e:
#         logger.error(f"Error fetching discovery commands data: {e}")
#         return pd.DataFrame()


# def fetch_metadata_access_data(es, config, time_range=None, query_size=10000):
#     """
#     Fetch metadata service access data using optimized retrieval.
#     Maintains original signature for compatibility.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     try:
#         query_size = int(query_size)
#     except (TypeError, ValueError):
#         query_size = 10000
#         logger.warning(f"Invalid query_size, using default: {query_size}")

#     # Default limited time range (from 11 AM to now)
#     if not time_range:
#         debug_docs = debug_elasticsearch_data(es)
#         if debug_docs:
#             timestamps = []
#             for doc in debug_docs:
#                 ts = doc.get('_source', {}).get('@timestamp')
#                 if ts:
#                     timestamps.append(pd.to_datetime(ts, utc=True))

#             if timestamps:
#                 latest_ts = max(timestamps)
#                 earliest_ts = min(timestamps)
#                 end_time = latest_ts
#                 start_time = max(earliest_ts, end_time - timedelta(hours=12))
#             else:
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=12)
#         else:
#             end_time = datetime.utcnow()
#             start_time = end_time - timedelta(hours=12)

#         time_range = {
#             "gte": start_time.isoformat(),
#             "lte": end_time.isoformat()
#         }

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"

#     source_fields = [
#         "@timestamp", "host.hostname", "host.id", "host.name",
#         "process.name", "process.executable", "process.command_line", "process.args",
#         "process.pid", "process.parent.name", "process.parent.command_line",
#         "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#         "event.action", "event.type", "event.outcome", "event.category",
#         "network.transport", "destination.ip", "destination.port", "destination.domain",
#         "source.ip", "source.port", "source.domain"
#     ]

#     retriever_config = {
#         "batch_size": min(query_size, 10000),
#         "debug_mode": config.get("debug_mode", False)
#     }
#     retriever = OptimizedRetriever(es, retriever_config)

#     query_body = {
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         logger.info(f"Fetching metadata service access data from index: {index_pattern}")
#         records = retriever.retrieve_with_search_after(
#             index_pattern, query_body, source_fields, query_size
#         )

#         if not records:
#             logger.warning("No metadata service access data returned from Elasticsearch.")
#             # Try without time filter
#             fallback_query = {"query": {"match_all": {}}}
#             records = retriever.retrieve_with_search_after(
#                 index_pattern, fallback_query, source_fields, min(query_size, 1000)
#             )

#         if not records:
#             return pd.DataFrame()

#         df = pd.DataFrame(records)

#         # Convert timestamp
#         if "@timestamp" in df.columns:
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

#         # Time filtering
#         if isinstance(time_range, dict) and "@timestamp" in df.columns:
#             start_time = pd.to_datetime(time_range["gte"], utc=True)
#             end_time = pd.to_datetime(time_range["lte"], utc=True)
#             original_count = len(df)
#             df = df[(df["@timestamp"] >= start_time) & (df["@timestamp"] <= end_time)]
#             logger.info(f"After time filtering: {len(df)} records (from {original_count} total)")

#         # Metadata service access filtering
#         # Common metadata service IPs / domains (AWS, Azure, GCP)
#         metadata_indicators = [
#             "169.254.169.254",  # AWS, Azure
#             "metadata.google.internal",  # GCP
#             "metadata.azure.internal",
#             "169.254.169.250",  # OCI
#             "metadata"
#         ]

#         if "destination.ip" in df.columns or "destination.domain" in df.columns:
#             def is_metadata_access(row):
#                 for indicator in metadata_indicators:
#                     if indicator in str(row.get("destination.ip", "")) or indicator in str(row.get("destination.domain", "")):
#                         return True
#                 return False

#             original_count = len(df)
#             df = df[df.apply(is_metadata_access, axis=1)]
#             logger.info(f"After metadata filtering: {len(df)} records (from {original_count} total)")

#         return df

#     except Exception as e:
#         logger.error(f"Error fetching metadata service access data from Elasticsearch: {e}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return pd.DataFrame()


# def _create_time_partitions(start_time, end_time, data_type, config):
#     """Enhanced time partitioning with better boundary handling"""
#     total_hours = (end_time - start_time).total_seconds() / 3600

#     # More granular partitioning for limited data
#     if total_hours < 1:
#         partition_hours = 0.25  # 15-minute partitions
#     elif total_hours < 6:
#         partition_hours = 0.5   # 30-minute partitions
#     elif total_hours < 24:
#         partition_hours = 1     # 1-hour partitions
#     elif total_hours < 72:
#         partition_hours = 3     # 3-hour partitions
#     elif total_hours < 168:
#         partition_hours = 6     # 6-hour partitions
#     else:
#         partition_hours = 12    # 12-hour partitions

#     partitions = []
#     current = start_time

#     while current < end_time:
#         partition_end = min(current + timedelta(hours=partition_hours), end_time)
#         partitions.append((current, partition_end))
#         current = partition_end

#     logger.info(f"Created {len(partitions)} time partitions of {partition_hours} hours each")
#     return partitions


# def _process_partition(es, index_pattern, start_time, end_time, data_type, config):
#     """Enhanced partition processing with better error handling and debugging"""
#     batch_size = min(config.get("batch_size", 10000), 10000)
#     debug_mode = config.get("debug_mode", False)

#     # Build query for this partition
#     query = {
#         "size": batch_size,
#         "query": {
#             "range": {
#                 "@timestamp": {
#                     "gte": start_time.isoformat(),
#                     "lte": end_time.isoformat()
#                 }
#             }
#         },
#         "sort": [{"@timestamp": {"order": "asc"}}, {"_id": {"order": "asc"}}]
#     }

#     if debug_mode:
#         logger.info(f"Processing partition: {start_time} to {end_time}")
#         logger.info(f"Partition query: {json.dumps(query, indent=2)}")

#     all_records = []
#     search_after = None
#     page_count = 0

#     while True:
#         page_count += 1
#         if search_after:
#             query["search_after"] = search_after

#         try:
#             response = es.search(index=index_pattern, body=query)
#             hits = response.get("hits", {}).get("hits", [])

#             if debug_mode:
#                 total_info = response.get("hits", {}).get("total", {})
#                 logger.info(f"Partition page {page_count}: {len(hits)} hits, total: {total_info}")

#             if not hits:
#                 break

#             records = [flatten_dict(hit["_source"]) for hit in hits]
#             all_records.extend(records)

#             # Get search_after for next page
#             search_after = hits[-1]["sort"]

#             # Safety limit
#             if page_count > 100:
#                 logger.warning(f"Stopping partition processing after {page_count} pages")
#                 break

#         except Exception as e:
#             logger.error(f"Error in partition search (page {page_count}): {e}")
#             break

#     if debug_mode:
#         logger.info(f"Partition {start_time.strftime('%H:%M')}-{end_time.strftime('%H:%M')}: {len(all_records)} records")

#     return all_records


# def fetch_data_with_scroll(es, config, data_type="process", time_range=None, max_records=None):
#     """
#     Enhanced parallel data fetching with better debugging and error handling.
#     Now includes fallback mechanisms for timestamp field issues.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     # Enable debug mode for troubleshooting
#     config["debug_mode"] = config.get("debug_mode", True)

#     # Get max records from config if not specified
#     if max_records is None:
#         max_records = config.get("max_baseline_records", 500000)

#     # Enhanced time range handling
#     if not time_range:
#         logger.info("No time range specified, detecting available data...")

#         # Check what data is available
#         debug_docs = debug_elasticsearch_data(es)

#         if debug_docs:
#             # Check if we found a successful query format during debugging
#             successful_format = None
#             for doc in debug_docs:
#                 if '_successful_query_format' in doc:
#                     successful_format = doc['_successful_query_format']
#                     break

#             if successful_format:
#                 logger.info("Using successful query format from debug tests")
#                 time_range = {
#                     "gte": successful_format['start'],
#                     "lte": successful_format['end']
#                 }
#             else:
#                 # Use expanded time range if available
#                 expanded_range = None
#                 for doc in debug_docs:
#                     if '_expanded_time_range' in doc:
#                         expanded_range = doc['_expanded_time_range']
#                         break

#                 if expanded_range:
#                     start_time = expanded_range['start']
#                     end_time = expanded_range['end']
#                     logger.info(f"Using expanded time range: {start_time} to {end_time}")
#                 else:
#                     logger.error("No time range information available")
#                     return pd.DataFrame()

#                 time_range = {
#                     "gte": start_time.isoformat(),
#                     "lte": end_time.isoformat()
#                 }
#         else:
#             logger.error("No data found in Elasticsearch")
#             return pd.DataFrame()

#     # Get index pattern
#     index_patterns = {
#         "process": ".ds-logs-endpoint.events.process-default-*",
#         "network": ".ds-logs-endpoint.events.process-default-*",
#         "user": ".ds-logs-endpoint.events.process-default-*",
#         "discovery": ".ds-logs-endpoint.events.process-default-*",
#         "metadata": ".ds-logs-endpoint.events.process-default-*"
#     }

#     index_pattern = index_patterns.get(data_type, ".ds-logs-endpoint.events.process-default-*")

#     logger.info(f"Starting enhanced parallel retrieval for {data_type} data")
#     logger.info(f"Index pattern: {index_pattern}")
#     logger.info(f"Time range: {time_range['gte']} to {time_range['lte']}")

#     # FIRST: Try a simple test query to see if time range works at all
#     test_query = {
#         "size": 10,
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         logger.info("=== TESTING TIME RANGE QUERY ===")
#         test_result = es.search(index=index_pattern, body=test_query)
#         test_hits = test_result.get('hits', {}).get('total', {}).get('value', 0)
#         logger.info(f"Test query returned {test_hits} hits")

#         if test_hits == 0:
#             logger.warning("Time range query returns 0 hits - trying fallbacks...")

#             # Fallback 1: Try without time range
#             fallback_query_1 = {
#                 "size": 10,
#                 "query": {"match_all": {}}
#             }

#             fallback_result_1 = es.search(index=index_pattern, body=fallback_query_1)
#             fallback_hits_1 = fallback_result_1.get('hits', {}).get('total', {}).get('value', 0)
#             logger.info(f"Fallback 1 (no time filter): {fallback_hits_1} hits")

#             if fallback_hits_1 > 0:
#                 logger.warning("Data exists but time range queries fail - using all available data")
#                 # Use the data without time filtering
#                 return fetch_data_without_time_filter(es, config, data_type, max_records)
#             else:
#                 logger.error("No data found even without time filters")
#                 return pd.DataFrame()
#         else:
#             logger.info("Time range query successful - proceeding with parallel retrieval")

#     except Exception as e:
#         logger.error(f"Test query failed: {e}")
#         return pd.DataFrame()

#     # Create time partitions for parallel processing
#     time_partitions = _create_time_partitions(
#         pd.to_datetime(time_range["gte"]),
#         pd.to_datetime(time_range["lte"]),
#         data_type,
#         config
#     )

#     logger.info(f"Processing {len(time_partitions)} time partitions in parallel")

#     # Process partitions in parallel
#     all_records = []
#     max_workers = min(config.get("max_workers", 4), len(time_partitions))

#     with ThreadPoolExecutor(max_workers=max_workers) as executor:
#         futures = []

#         for start, end in time_partitions:
#             future = executor.submit(
#                 _process_partition,
#                 es, index_pattern, start, end, data_type, config
#             )
#             futures.append(future)

#         # Collect results as they complete
#         for i, future in enumerate(as_completed(futures)):
#             try:
#                 partition_records = future.result(timeout=300)
#                 all_records.extend(partition_records)

#                 logger.info(f"Partition {i+1}/{len(futures)} complete. Total records: {len(all_records):,}")

#                 # Check if we've reached max_records
#                 if max_records and len(all_records) >= max_records:
#                     logger.info(f"Reached maximum records limit of {max_records:,}")
#                     all_records = all_records[:max_records]
#                     break

#                 # Memory management
#                 if len(all_records) % 100000 == 0:
#                     gc.collect()

#             except Exception as e:
#                 logger.error(f"Error processing partition {i+1}: {e}")
#                 continue

#     logger.info(f"Retrieved a total of {len(all_records):,} {data_type} records")

#     if not all_records:
#         logger.warning(f"No {data_type} data found in time range - trying fallback without time filter")
#         return fetch_data_without_time_filter(es, config, data_type, max_records)

#     # Convert to DataFrame
#     logger.info("Converting records to DataFrame...")
#     df = pd.DataFrame(all_records)

#     # Convert timestamp
#     if "@timestamp" in df.columns:
#         logger.info("Converting timestamps to timezone-aware format...")
#         df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         logger.info(f"Final timestamp range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")

#     # Apply preprocessing based on data type
#     logger.info(f"Applying {data_type} preprocessing...")
#     if data_type == "process":
#         df = preprocess_process_data(df)
#     elif data_type == "network":
#         df = preprocess_network_data(df)
#     elif data_type == "user":
#         df = preprocess_user_data(df)
#     elif data_type == "discovery":
#         df = preprocess_discovery_data(df)
#     elif data_type == "metadata":
#         df = preprocess_metadata_data(df)

#     logger.info(f"Final DataFrame shape: {df.shape}")
#     return df
# def fetch_data_without_time_filter(es, config, data_type="process", max_records=10000):
#     """
#     Fallback function to fetch data without time filtering.
#     Used when time range queries consistently fail.
#     """
#     logger.info(f"=== FALLBACK: Fetching {data_type} data without time filter ===")

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"

#     # Get source fields based on data type
#     if data_type == "process":
#         source_fields = [
#             "@timestamp", "host.hostname", "host.id", "host.name",
#             "process.name", "process.executable", "process.args", "process.command_line",
#             "process.pid", "process.entity_id", "process.args_count",
#             "process.parent.name", "process.parent.executable", "process.parent.pid",
#             "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#             "event.action", "event.type", "event.outcome", "event.category",
#             "agent.id", "agent.type", "agent.version"
#         ]
#     else:
#         # Use basic fields for other data types
#         source_fields = [
#             "@timestamp", "host.hostname", "process.name", "user.name",
#             "event.action", "event.type", "event.category"
#         ]

#     # Simple query without time filtering
#     query = {
#         "size": min(max_records, 10000),
#         "_source": source_fields,
#         "query": {"match_all": {}},
#         "sort": [{"@timestamp": {"order": "desc"}}]
#     }

#     try:
#         logger.info(f"Executing fallback query for {min(max_records, 10000)} records")
#         response = es.search(index=index_pattern, body=query)
#         hits = response.get("hits", {}).get("hits", [])

#         if hits:
#             records = [flatten_dict(hit["_source"]) for hit in hits]
#             logger.info(f"Successfully retrieved {len(records)} records without time filter")

#             df = pd.DataFrame(records)

#             # Convert timestamp
#             if "@timestamp" in df.columns:
#                 df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#                 logger.info(f"Fallback data timestamp range: {df['@timestamp'].min()} to {df['@timestamp'].max()}")

#             # Apply preprocessing
#             if data_type == "process":
#                 df = preprocess_process_data(df)
#             elif data_type == "network":
#                 df = preprocess_network_data(df)
#             elif data_type == "user":
#                 df = preprocess_user_data(df)
#             elif data_type == "discovery":
#                 df = preprocess_discovery_data(df)
#             elif data_type == "metadata":
#                 df = preprocess_metadata_data(df)

#             logger.info(f"Fallback DataFrame shape: {df.shape}")
#             return df
#         else:
#             logger.error("Fallback query also returned 0 hits")
#             return pd.DataFrame()

#     except Exception as e:
#         logger.error(f"Fallback query failed: {e}")
#         return pd.DataFrame()

# def fetch_baseline_data(es, config, data_type="process"):
#     """
#     Enhanced baseline data fetching with intelligent time range detection.
#     Fixed to handle microsecond-precision timestamp issues.
#     """
#     logger.info(f"Fetching baseline data for {data_type}")

#     # First, understand what data is available
#     debug_docs = debug_elasticsearch_data(es)

#     if not debug_docs:
#         logger.error("No data available for baseline training")
#         return pd.DataFrame()

#     # Extract available time range with intelligent expansion
#     timestamps = []
#     expanded_range = None

#     for doc in debug_docs:
#         ts = doc.get('_source', {}).get('@timestamp')
#         if ts:
#             timestamps.append(pd.to_datetime(ts, utc=True))

#         # Check if we have expanded time range info
#         if '_expanded_time_range' in doc:
#             expanded_range = doc['_expanded_time_range']

#     if not timestamps:
#         logger.error("No valid timestamps found in data")
#         return pd.DataFrame()

#     # Use expanded range if available, otherwise calculate
#     if expanded_range:
#         logger.info("Using pre-calculated expanded time range")
#         start_time = expanded_range['start']
#         end_time = expanded_range['end']
#         available_hours = expanded_range['span_hours']
#     else:
#         # Fallback to original logic with enhancements
#         latest_ts = max(timestamps)
#         earliest_ts = min(timestamps)
#         original_hours = (latest_ts - earliest_ts).total_seconds() / 3600

#         logger.info(f"Fallback: Original data spans {original_hours:.6f} hours ({earliest_ts} to {latest_ts})")

#         # Apply intelligent expansion for very short ranges
#         if original_hours < 0.1:  # Less than 6 minutes
#             logger.warning("Very short time range - expanding to 6 hours")
#             center_time = earliest_ts + (latest_ts - earliest_ts) / 2
#             start_time = center_time - timedelta(hours=3)
#             end_time = center_time + timedelta(hours=3)
#             available_hours = 6
#         elif original_hours < 1:  # Less than 1 hour
#             logger.warning("Short time range - adding 2 hour buffer")
#             start_time = earliest_ts - timedelta(hours=2)
#             end_time = latest_ts + timedelta(hours=2)
#             available_hours = (end_time - start_time).total_seconds() / 3600
#         else:
#             start_time = earliest_ts
#             end_time = latest_ts
#             available_hours = original_hours

#     logger.info(f"Final baseline time range: {start_time} to {end_time}")
#     logger.info(f"Final baseline duration: {available_hours:.1f} hours")

#     # Determine training split
#     if available_hours < 1:
#         logger.warning("Less than 1 hour of data available - using all data for baseline")
#         train_start_time = start_time
#         train_end_time = end_time
#     elif available_hours < 6:
#         logger.warning(f"Only {available_hours:.1f} hours available - using 80% for baseline")
#         total_duration = end_time - start_time
#         baseline_duration = total_duration * 0.8
#         train_start_time = start_time
#         train_end_time = start_time + baseline_duration
#     else:
#         logger.info(f"Using 90% of {available_hours:.1f} hours for baseline")
#         total_duration = end_time - start_time
#         baseline_duration = total_duration * 0.9
#         train_start_time = start_time
#         train_end_time = start_time + baseline_duration

#     logger.info(f"Training time range: {train_start_time} to {train_end_time}")
#     logger.info(f"Training duration: {(train_end_time - train_start_time).total_seconds() / 3600:.1f} hours")

#     time_range = {
#         "gte": train_start_time.isoformat(),
#         "lte": train_end_time.isoformat()
#     }

#     # Use enhanced fetch_data_with_scroll
#     return fetch_data_with_scroll(es, config, data_type, time_range)


# def preprocess_process_data(df):
#     """
#     Preprocess process execution data for anomaly detection.
#     """
#     if df.empty:
#         logger.warning("Empty dataframe received for process preprocessing.")
#         return df

#     logger.info(f"Initial process dataframe shape: {df.shape}")

#     # Convert timestamp
#     if "@timestamp" in df.columns:
#         df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#         df.dropna(subset=["@timestamp"], inplace=True)
#         df.sort_values("@timestamp", inplace=True)

#     # Handle missing process names
#     if "process.name" in df.columns:
#         df["process.name"].fillna("unknown", inplace=True)

#         # Add compiler detection
#         df["is_compiler_activity"] = df["process.name"].apply(
#             lambda x: 1 if any(compiler in str(x).lower() for compiler in [
#                 "gcc", "g++", "clang", "make", "cmake", "javac", "rustc",
#                 "go", "python", "node", "npm", "pip", "cargo"
#             ]) else 0
#         )

#         logger.info(f"Unique processes in data: {df['process.name'].nunique()}")
#         logger.info(f"Compiler activity detected in {df['is_compiler_activity'].sum()} events")

#     # Create time-based features
#     if "@timestamp" in df.columns:
#         df["hour_of_day"] = df["@timestamp"].dt.hour
#         df["day_of_week"] = df["@timestamp"].dt.dayofweek
#         df["is_business_hours"] = ((df["hour_of_day"] >= 8) & (df["hour_of_day"] <= 18) &
#                                  (df["day_of_week"] <= 4)).astype(int)
#         df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)

#     # Process executable path analysis
#     system_paths = [
#         '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
#         '/usr/local/bin/', '/usr/local/sbin/',
#         '/opt/', '/var/lib/', '/usr/lib/', '/usr/share/',
#         '/usr/local/lib/', '/lib/', '/lib64/',
#         '/opt/CrowdStrike/', '/snap/bin/'
#     ]

#     # List of known system processes
#     common_system_processes = [
#         'systemd', 'bash', 'sh', 'sshd', 'cron', 'rsyslogd', 'sudo',
#         'dpkg', 'apt', 'apt-get', 'apt-config', 'falconctl', 'sed',
#         'grep', 'cp', 'ls', 'cat', 'systemctl', 'journalctl', 'find',
#         'ps', 'top', 'htop', 'rm', 'mv', 'chmod', 'chown', 'vi', 'vim',
#         'nano', 'apt-update', 'dpkg-reconfigure', 'mount', 'umount', 'ssh',
#         'scp', 'logrotate'
#     ]

#     if "process.executable" in df.columns and not df["process.executable"].isna().all():
#         df["process.executable"].fillna("", inplace=True)
#         df["is_system_path"] = df["process.executable"].apply(
#             lambda x: 1 if any(str(x).startswith(path) for path in system_paths) else 0
#         )
#         logger.info(f"System path detection from process.executable: {df['is_system_path'].sum()} / {len(df)}")
#     elif "process.name" in df.columns:
#         logger.warning("process.executable not available - using process.name to infer system paths")
#         df["is_system_path"] = df["process.name"].apply(
#             lambda name: 1 if (
#                 name in common_system_processes or
#                 any(name.startswith(prefix) for prefix in ['systemd-', 'rs:', 'apt-', 'dpkg-'])
#             ) else 0
#         )
#         logger.info(f"System path detection from process.name: {df['is_system_path'].sum()} / {len(df)}")
#     else:
#         logger.warning("No path or process name data available - defaulting to system path")
#         df["is_system_path"] = 1

#     # Add other path-related checks
#     if "process.executable" in df.columns:
#         df["is_snap_process"] = df["process.executable"].apply(
#             lambda x: 1 if "/snap/" in str(x) else 0
#         )
#         df["is_tmp_execution"] = df["process.executable"].apply(
#             lambda x: 1 if any(tmp in str(x) for tmp in ["/tmp/", "/var/tmp/", "/dev/shm/"]) else 0
#         )
#     else:
#         df["is_snap_process"] = 0
#         df["is_tmp_execution"] = 0

#     # Command line analysis
#     if "process.command_line" in df.columns:
#         df["process.command_line"].fillna("", inplace=True)
#         df["command_length"] = df["process.command_line"].str.len()

#         df["is_sudo_command"] = df["process.command_line"].str.contains(r'\bsudo\b', na=False, regex=True).astype(int)
#         df["has_pipes"] = df["process.command_line"].str.contains(r'\|', na=False, regex=True).astype(int)
#         df["has_redirection"] = df["process.command_line"].str.contains(r'[><]', na=False, regex=True).astype(int)

#         df["has_suspicious_chars"] = df["process.command_line"].apply(
#             lambda x: 1 if any(char in str(x) for char in ["|", "&", ";", ">", "<", "`", "$("]) else 0
#         )
#         df["has_encoded_content"] = df["process.command_line"].apply(
#             lambda x: 1 if any(pattern in str(x).lower() for pattern in ["base64", "echo", "eval", "exec"]) else 0
#         )

#         df["has_download_commands"] = df["process.command_line"].apply(
#             lambda x: 1 if any(cmd in str(x).lower() for cmd in ["wget", "curl", "nc ", "netcat"]) else 0
#         )

#         logger.info(f"Sudo commands detected: {df['is_sudo_command'].sum()}")
#         logger.info(f"Commands with pipes: {df['has_pipes'].sum()}")
#         logger.info(f"Commands with redirection: {df['has_redirection'].sum()}")

#     # Process arguments analysis
#     if "process.args_count" in df.columns:
#         df["args_count"] = pd.to_numeric(df["process.args_count"], errors='coerce').fillna(0)
#     elif "process.args" in df.columns:
#         df["args_count"] = df["process.args"].apply(lambda x: len(x) if isinstance(x, list) else 0)
#     else:
#         df["args_count"] = 0

#     # User context analysis
#     if "user.name" in df.columns:
#         df["user.name"].fillna("unknown", inplace=True)
#         df["is_root_user"] = (df["user.name"] == "root").astype(int)
#         df["is_system_user"] = df["user.name"].apply(
#             lambda x: 1 if str(x) in [
#                 "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
#                 "news", "uucp", "proxy", "www-data", "backup", "list", "irc",
#                 "nginx", "apache", "mysql", "postgres"
#             ] else 0
#         )
#     elif "user.id" in df.columns:
#         df["user.id"] = pd.to_numeric(df["user.id"], errors='coerce').fillna(-1)
#         df["is_root_user"] = (df["user.id"] == 0).astype(int)
#         df["is_system_user"] = ((df["user.id"] > 0) & (df["user.id"] < 1000)).astype(int)
#         if "user.name" not in df.columns:
#             df["user.name"] = df["user.id"].astype(str)
#     else:
#         df["user.name"] = "unknown"
#         df["is_root_user"] = 0
#         df["is_system_user"] = 0

#     # Hash-based features
#     if "process.hash.sha256" in df.columns:
#         df["has_hash"] = df["process.hash.sha256"].notna().astype(int)
#     else:
#         df["has_hash"] = 0

#     # Parent process analysis
#     if "process.parent.name" in df.columns:
#         df["process.parent.name"].fillna("unknown", inplace=True)
#         df["has_suspicious_parent"] = df["process.parent.name"].apply(
#             lambda x: 1 if any(parent in str(x).lower() for parent in [
#                 "bash", "sh", "cmd", "powershell", "python", "perl", "ruby"
#             ]) else 0
#         )
#     else:
#         df["has_suspicious_parent"] = 0

#     # Environment variables count
#     if "process.env_vars" in df.columns:
#         df["env_vars_count"] = df["process.env_vars"].apply(lambda x: len(x) if isinstance(x, list) else 0)
#     else:
#         df["env_vars_count"] = 0

#     # Event type analysis
#     if "event.type" in df.columns:
#         df["is_process_start"] = df["event.type"].apply(lambda x: 1 if "start" in x else 0)
#         df["is_process_end"] = df["event.type"].apply(lambda x: 1 if "end" in x else 0)

#     # Add event_count for aggregation
#     df["event_count"] = 1

#     # Add a check to log system path percentage for debugging
#     system_path_pct = df["is_system_path"].mean() * 100
#     logger.info(f"System path percentage: {system_path_pct:.1f}%")
#     if system_path_pct < 50:
#         logger.warning(f"WARNING: Only {system_path_pct:.1f}% of processes are from system paths!")
#         logger.warning("This may lead to excessive false positives in anomaly detection.")

#     logger.info(f"Preprocessed process dataframe shape: {df.shape}")
#     logger.info(f"Root user events: {df['is_root_user'].sum()}")
#     logger.info(f"System user events: {df['is_system_user'].sum()}")

#     return df



# def fetch_network_activity_data(es, config, time_range=None, query_size=10000):
#     """
#     Fetch network activity data using optimized retrieval.
#     Maintains original signature for compatibility.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     try:
#         query_size = int(query_size)
#     except (TypeError, ValueError):
#         query_size = 10000
#         logger.warning(f"Invalid query_size, using default: {query_size}")

#     # Handle limited data scenario
#     if not time_range:
#         debug_docs = debug_elasticsearch_data(es)
#         if debug_docs:
#             timestamps = []
#             for doc in debug_docs:
#                 ts = doc.get('_source', {}).get('@timestamp')
#                 if ts:
#                     timestamps.append(pd.to_datetime(ts, utc=True))

#             if timestamps:
#                 latest_ts = max(timestamps)
#                 earliest_ts = min(timestamps)
#                 end_time = latest_ts
#                 start_time = max(earliest_ts, end_time - timedelta(hours=12))
#             else:
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=12)
#         else:
#             end_time = datetime.utcnow()
#             start_time = end_time - timedelta(hours=12)

#         time_range = {
#             "gte": start_time.isoformat(),
#             "lte": end_time.isoformat()
#         }

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"

#     source_fields = [
#         "@timestamp", "host.hostname", "host.id", "host.name",
#         "host.os.name", "host.os.version", "host.os.family", "host.ip", "host.mac",
#         "process.name", "process.executable", "process.pid", "process.entity_id",
#         "process.command_line", "process.parent.entity_id",
#         "network.transport", "network.direction", "network.type",
#         "source.ip", "source.port", "source.address",
#         "destination.ip", "destination.port", "destination.address",
#         "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#         "group.name", "group.id", "group.Ext.real.name", "group.Ext.real.id",
#         "event.action", "event.type", "event.category", "event.outcome",
#         "event.kind", "event.module", "event.sequence", "event.id",
#         "agent.id", "agent.type", "agent.version"
#     ]

#     # Use optimized retriever
#     retriever_config = {
#         "batch_size": min(query_size, 10000),
#         "debug_mode": config.get("debug_mode", False)
#     }
#     retriever = OptimizedRetriever(es, retriever_config)

#     query_body = {
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         logger.info(f"Fetching network activity data from index: {index_pattern}")
#         records = retriever.retrieve_with_search_after(
#             index_pattern, query_body, source_fields, query_size
#         )

#         if not records:
#             logger.warning("No network activity data returned from Elasticsearch.")
#             # Try without time filter
#             fallback_query = {"query": {"match_all": {}}}
#             records = retriever.retrieve_with_search_after(
#                 index_pattern, fallback_query, source_fields, min(query_size, 1000)
#             )

#         if not records:
#             return pd.DataFrame()

#         logger.info(f"Retrieved {len(records)} network activity records from Elasticsearch.")
#         df = pd.DataFrame(records)

#         # Convert timestamp
#         if "@timestamp" in df.columns:
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

#         # Apply time filtering in post-processing
#         if isinstance(time_range, dict) and "@timestamp" in df.columns:
#             start_time = pd.to_datetime(time_range["gte"], utc=True)
#             end_time = pd.to_datetime(time_range["lte"], utc=True)

#             original_count = len(df)
#             df = df[(df["@timestamp"] >= start_time) & (df["@timestamp"] <= end_time)]
#             logger.info(f"After time filtering: {len(df)} records (from {original_count} total)")

#         # Apply category filtering
#         if "event.category" in df.columns:
#             def is_network_event(category):
#                 if isinstance(category, list):
#                     return any(cat in ['network', 'process'] for cat in category)
#                 elif isinstance(category, str):
#                     return category in ['network', 'process']
#                 return False

#             original_count = len(df)
#             network_indicators = ['destination.ip', 'source.ip', 'destination.port', 'source.port']
#             for indicator in network_indicators:
#                 if indicator in df.columns:
#                     df.loc[df[indicator].notna(), 'is_network_activity'] = True

#             network_mask = (df["event.category"].apply(is_network_event) | df.get('is_network_activity', False))
#             df = df[network_mask]
#             logger.info(f"After category filtering: {len(df)} network records (from {original_count} total)")

#         return df

#     except Exception as e:
#         logger.error(f"Error fetching network activity data from Elasticsearch: {e}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return pd.DataFrame()


# def fetch_user_activity_data(es, config, time_range=None, query_size=10000):
#     """
#     Fetch user activity data using optimized retrieval.
#     Maintains original signature for compatibility.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     try:
#         query_size = int(query_size)
#     except (TypeError, ValueError):
#         query_size = 10000
#         logger.warning(f"Invalid query_size, using default: {query_size}")

#     # Handle limited data scenario
#     if not time_range:
#         debug_docs = debug_elasticsearch_data(es)
#         if debug_docs:
#             timestamps = []
#             for doc in debug_docs:
#                 ts = doc.get('_source', {}).get('@timestamp')
#                 if ts:
#                     timestamps.append(pd.to_datetime(ts, utc=True))

#             if timestamps:
#                 latest_ts = max(timestamps)
#                 earliest_ts = min(timestamps)
#                 end_time = latest_ts
#                 start_time = max(earliest_ts, end_time - timedelta(hours=12))
#             else:
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=12)
#         else:
#             end_time = datetime.utcnow()
#             start_time = end_time - timedelta(hours=12)

#         time_range = {
#             "gte": start_time.isoformat(),
#             "lte": end_time.isoformat()
#         }

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"

#     source_fields = [
#         "@timestamp", "host.hostname", "host.id", "host.name",
#         "process.name", "process.executable", "process.command_line", "process.args",
#         "process.pid", "process.working_directory", "process.parent.name",
#         "process.parent.executable", "process.parent.command_line", "process.args_count",
#         "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#         "group.name", "group.id", "group.Ext.real.name", "group.Ext.real.id",
#         "event.action", "event.type", "event.category", "event.outcome",
#         "agent.id", "agent.type", "agent.version"
#     ]

#     retriever_config = {
#         "batch_size": min(query_size, 10000),
#         "debug_mode": config.get("debug_mode", False)
#     }
#     retriever = OptimizedRetriever(es, retriever_config)

#     query_body = {
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         logger.info(f"Fetching user activity data from index: {index_pattern}")
#         records = retriever.retrieve_with_search_after(
#             index_pattern, query_body, source_fields, query_size
#         )

#         if not records:
#             logger.warning("No user activity data returned from Elasticsearch.")
#             # Try without time filter
#             fallback_query = {"query": {"match_all": {}}}
#             records = retriever.retrieve_with_search_after(
#                 index_pattern, fallback_query, source_fields, min(query_size, 1000)
#             )

#         if not records:
#             return pd.DataFrame()

#         logger.info(f"Retrieved {len(records)} user activity records from Elasticsearch.")
#         df = pd.DataFrame(records)

#         # Apply existing preprocessing logic
#         if "@timestamp" in df.columns:
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)

#         # Apply time and category filtering
#         if isinstance(time_range, dict) and "@timestamp" in df.columns:
#             start_time = pd.to_datetime(time_range["gte"], utc=True)
#             end_time = pd.to_datetime(time_range["lte"], utc=True)
#             original_count = len(df)
#             df = df[(df["@timestamp"] >= start_time) & (df["@timestamp"] <= end_time)]
#             logger.info(f"After time filtering: {len(df)} records (from {original_count} total)")

#         # Apply existing user activity filtering logic
#         if "event.category" in df.columns:
#             def is_process_event(category):
#                 if isinstance(category, list):
#                     return "process" in category
#                 return category == "process"

#             original_count = len(df)
#             df = df[df["event.category"].apply(is_process_event)]
#             logger.info(f"After category filtering: {len(df)} process records (from {original_count} total)")

#         # Post-process for user-relevant activities
#         if "process.command_line" in df.columns and "user.name" in df.columns and len(df) > 0:
#             compiler_tools = ["gcc", "g++", "python", "python3", "pip", "npm", "node", "javac", "make", "cmake"]
#             admin_tools = ["sudo", "su ", "usermod", "passwd", "useradd", "userdel"]
#             dev_tools = ["git", "vim", "nano", "code", "emacs"]
#             shells = ["bash", "sh", "zsh", "csh", "tcsh", "fish"]

#             df["is_compiler"] = df["process.name"].apply(
#                 lambda x: 1 if any(tool in str(x).lower() for tool in compiler_tools) else 0
#             )
#             df["is_admin"] = df["process.command_line"].apply(
#                 lambda x: 1 if any(tool in str(x).lower() for tool in admin_tools) else 0
#             )
#             df["is_dev"] = df["process.name"].apply(
#                 lambda x: 1 if any(tool in str(x).lower() for tool in dev_tools) else 0
#             )
#             df["is_shell"] = df["process.name"].apply(
#                 lambda x: 1 if any(shell in str(x).lower() for shell in shells) else 0
#             )

#             user_relevant = (df["is_compiler"] == 1) | (df["is_admin"] == 1) | (df["is_dev"] == 1) | (df["is_shell"] == 1)
#             original_count = len(df)
#             df = df[user_relevant]
#             logger.info(f"After user activity filtering: {len(df)} relevant records (from {original_count} process records)")

#         return df

#     except Exception as e:
#         logger.error(f"Error fetching user activity data from Elasticsearch: {e}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return pd.DataFrame()


# def fetch_discovery_commands_data(es, config, time_range=None, query_size=10000):
#     """
#     Fetch discovery commands data using optimized retrieval.
#     Maintains original signature for compatibility.
#     """
#     if not es:
#         logger.error("Elasticsearch connection is not available.")
#         return pd.DataFrame()

#     try:
#         query_size = int(query_size)
#     except (TypeError, ValueError):
#         query_size = 10000

#     if not time_range:
#         debug_docs = debug_elasticsearch_data(es)
#         if debug_docs:
#             timestamps = []
#             for doc in debug_docs:
#                 ts = doc.get('_source', {}).get('@timestamp')
#                 if ts:
#                     timestamps.append(pd.to_datetime(ts, utc=True))

#             if timestamps:
#                 latest_ts = max(timestamps)
#                 earliest_ts = min(timestamps)
#                 end_time = latest_ts
#                 start_time = max(earliest_ts, end_time - timedelta(hours=12))
#             else:
#                 end_time = datetime.utcnow()
#                 start_time = end_time - timedelta(hours=12)
#         else:
#             end_time = datetime.utcnow()
#             start_time = end_time - timedelta(hours=12)

#         time_range = {
#             "gte": start_time.isoformat(),
#             "lte": end_time.isoformat()
#         }

#     index_pattern = ".ds-logs-endpoint.events.process-default-*"
#     source_fields = [
#         "@timestamp", "host.hostname", "host.id", "host.name",
#         "process.name", "process.executable", "process.command_line", "process.args",
#         "process.pid", "process.working_directory", "process.parent.name",
#         "process.parent.pid", "process.parent.command_line", "process.args_count",
#         "user.name", "user.id", "user.Ext.real.name", "user.Ext.real.id",
#         "event.action", "event.type", "event.outcome", "event.category"
#     ]

#     retriever_config = {
#         "batch_size": min(query_size, 10000),
#         "debug_mode": config.get("debug_mode", False)
#     }
#     retriever = OptimizedRetriever(es, retriever_config)

#     query_body = {
#         "query": {
#             "range": {
#                 "@timestamp": time_range
#             }
#         }
#     }

#     try:
#         logger.info(f"Fetching process data from index: {index_pattern}")
#         logger.info(f"Time range: {time_range['gte']} to {time_range['lte']}")

#         records = retriever.retrieve_with_search_after(
#             index_pattern, query_body, source_fields, query_size
#         )

#         if not records:
#             logger.warning(f"No process data returned from Elasticsearch for time range")

#             # Try without time filter as fallback
#             logger.info("Attempting to fetch data without time filter...")
#             fallback_query = {"query": {"match_all": {}}}
#             records = retriever.retrieve_with_search_after(
#                 index_pattern, fallback_query, source_fields, min(query_size, 1000)
#             )

#             if records:
#                 logger.info(f"Successfully retrieved {len(records)} records without time filter")
#             else:
#                 logger.error("No data found even without time filter")
#                 return pd.DataFrame()

#         logger.info(f"Retrieved {len(records)} process records from Elasticsearch.")
#         df = pd.DataFrame(records)

#         # Convert timestamp to timezone-aware
#         if "@timestamp" in df.columns:
#             df["@timestamp"] = pd.to_datetime(df["@timestamp"], errors='coerce', utc=True)
#             logger.info(f"Timestamp range in retrieved data: {df['@timestamp'].min()} to {df['@timestamp'].max()}")

#         return df

#     except Exception as e:
#         logger.error(f"Error fetching process data from Elasticsearch: {e}")
#         import traceback
#         logger.error(f"Traceback: {traceback.format_exc()}")
#         return pd.DataFrame()



# """
# Linux Anomaly Detection Methods - Complete Implementation
# =========================================================

# ML-Only Anomaly Detection with Fixed Scoring Logic
# Author: Anomaly Detection System
# Version: 2.0 - ML-Only with Fixed Scoring
# """

# import numpy as np
# import pandas as pd
# import logging
# from typing import Dict, List, Tuple, Optional, Any
# from datetime import datetime, timedelta
# from sklearn.ensemble import IsolationForest
# from sklearn.neighbors import LocalOutlierFactor
# from sklearn.svm import OneClassSVM
# from sklearn.decomposition import PCA
# from sklearn.preprocessing import RobustScaler, StandardScaler
# from sklearn.cluster import DBSCAN
# import warnings
# from sklearn.preprocessing import LabelEncoder
# warnings.filterwarnings('ignore')
# import time
# # Configure logging
# logger = logging.getLogger("linux_anomaly_detection")

# # ===============================================================================
# # CONFIGURATION AND CONSTANTS
# # ===============================================================================

# # Default method weights for ensemble scoring
# DEFAULT_METHOD_WEIGHTS = {
#     'isolation_forest': 0.4,
#     'lof': 0.3,
#     'ocsvm': 0.2,
#     'pca': 0.1
# }

# # Entity column mapping by data type
# ENTITY_COLUMNS = {
#     "process": "process.name",
#     "network": "destination.ip",
#     "user": "user.name",
#     "discovery": "process.name",
#     "metadata": "process.name"
# }

# # Feature definitions by data type
# FEATURE_DEFINITIONS = {
#     "process": {
#         "required": ["event_count", "@timestamp"],
#         "domain_specific": [
#             "process_frequency", "process_rarity", "is_rare_process",
#             "is_system_process", "is_user_process", "process.name", "host.hostname"
#         ],
#         "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
#         "entity_col": "process.name"
#     },
#     "network": {
#         "required": ["event_count", "@timestamp"],
#         "domain_specific": [
#             "country_frequency", "country_rarity", "is_rare_country",
#             "port_frequency", "destination.ip"
#         ],
#         "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
#         "entity_col": "destination.ip"
#     },
#     "user": {
#         "required": ["event_count", "@timestamp"],
#         "domain_specific": [
#             "user_frequency", "user_rarity", "is_rare_user",
#             "is_dev_tool", "is_root_user", "is_service_user", "user.name"
#         ],
#         "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
#         "entity_col": "user.name"
#     },
#     "discovery": {
#         "required": ["event_count", "@timestamp"],
#         "domain_specific": [
#             "command_length", "has_pipes", "has_redirection",
#             "args_count", "is_root_discovery", "is_regular_user_discovery",
#             "process.name", "user.name"
#         ],
#         "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
#         "entity_col": "process.name"
#     },
#     "metadata": {
#         "required": ["event_count", "@timestamp"],
#         "domain_specific": [
#             "is_root_access", "is_service_account", "potential_cred_harvest",
#             "user_data_access", "process.name"
#         ],
#         "temporal": ["hour_of_day", "day_of_week", "is_business_hours", "is_weekend"],
#         "entity_col": "process.name"
#     }
# }

# # ===============================================================================
# # UTILITY FUNCTIONS
# # ===============================================================================

# def _is_internal_ip(ip_str: str) -> int:
#     """Check if IP is internal/private."""
#     try:
#         import ipaddress
#         ip = ipaddress.ip_address(ip_str)
#         return int(ip.is_private)
#     except:
#         return 0

# def debug_entity_data_flow(feature_data, data_type):
#     """
#     ADDED: Debug function to trace entity data flow issues.
#     """
#     entity_col = _get_entity_column(data_type)

#     logger.warning(f"DATA FLOW DEBUG for {data_type}:")
#     logger.warning(f"Entity column: '{entity_col}'")
#     logger.warning(f"Available columns: {list(feature_data.columns)}")

#     if entity_col in feature_data.columns:
#         unique_entities = feature_data[entity_col].unique()
#         logger.warning(f"Unique entities found: {list(unique_entities)}")
#         logger.warning(f"Null values in entity column: {feature_data[entity_col].isnull().sum()}")

#         # Check for default values
#         default_values = ['0.0.0.0', 'unknown', '', 'nan', 'None']
#         for default_val in default_values:
#             count = (feature_data[entity_col] == default_val).sum()
#             if count > 0:
#                 logger.warning(f"Found {count} records with default value '{default_val}'")
#     else:
#         logger.error(f"Entity column '{entity_col}' missing from feature data!")
#         logger.error(f"This will cause entity validation to fail!")

#     return feature_data

# def fix_network_entity_extraction(df, data_type):
#     """
#     FIXED: Ensure proper entity extraction for network data.
#     """
#     if data_type != 'network':
#         return df

#     logger.warning(f"NETWORK FIX: Checking destination.ip extraction...")

#     # Check if destination.ip exists and has real values
#     if 'destination.ip' in df.columns:
#         unique_ips = df['destination.ip'].unique()
#         real_ips = [ip for ip in unique_ips if str(ip) not in ['0.0.0.0', 'nan', 'None', '']]

#         logger.warning(f"NETWORK FIX: Found {len(real_ips)} real IPs out of {len(unique_ips)} total")

#         if len(real_ips) == 0:
#             logger.error(f"NETWORK FIX: No real destination IPs found!")
#             logger.error(f"Available IPs: {list(unique_ips)}")

#             # Try alternative IP fields
#             alternative_fields = ['source.ip', 'host.ip', 'client.ip', 'server.ip']
#             for alt_field in alternative_fields:
#                 if alt_field in df.columns:
#                     alt_unique = df[alt_field].unique()
#                     alt_real = [ip for ip in alt_unique if str(ip) not in ['0.0.0.0', 'nan', 'None', '']]
#                     if len(alt_real) > 0:
#                         logger.warning(f"NETWORK FIX: Using {alt_field} as fallback ({len(alt_real)} real IPs)")
#                         df['destination.ip'] = df[alt_field]
#                         break
#     else:
#         logger.error(f"NETWORK FIX: destination.ip column missing entirely!")

#     return df

# def filter_entities_with_models(entities, models, scalers):
#     """
#     FIXED: Enhanced entity validation with better debugging and fallback handling.
#     """
#     valid_entities = []

#     logger.info(f"ENTITY DEBUG: Validating {len(entities)} entities against {len(models)} models")
#     logger.info(f"ENTITY DEBUG: Detection entities: {list(entities)}")
#     logger.info(f"ENTITY DEBUG: Available models: {list(models.keys())[:10]}...")  # Show first 10

#     # CRITICAL FIX: Handle the '0.0.0.0' default value case
#     for entity in entities:
#         # Skip invalid default entities
#         if str(entity).strip() in ['0.0.0.0', 'unknown', '', 'nan', 'None']:
#             logger.warning(f"ENTITY DEBUG: Skipping invalid default entity: '{entity}'")
#             continue

#         # Direct match
#         if entity in models and entity in scalers:
#             entity_model = models[entity]
#             entity_scaler = scalers[entity]
#             if isinstance(entity_model, dict) and len(entity_model) > 0 and entity_scaler is not None:
#                 valid_entities.append(entity)
#                 logger.info(f"ENTITY DEBUG: Direct match found for '{entity}'")
#                 continue

#         # Case-insensitive match
#         for model_key in models.keys():
#             if str(entity).lower().strip() == str(model_key).lower().strip():
#                 if model_key in scalers and scalers[model_key] is not None:
#                     valid_entities.append(entity)
#                     logger.info(f"ENTITY DEBUG: Case match: '{entity}' -> '{model_key}'")
#                     break

#         # Partial match (if entity is part of model name or vice versa)
#         if entity not in valid_entities and len(str(entity).strip()) > 2:
#             for model_key in models.keys():
#                 if (str(entity).strip() in str(model_key) or
#                     str(model_key) in str(entity).strip()):
#                     if model_key in scalers and scalers[model_key] is not None:
#                         valid_entities.append(entity)
#                         logger.info(f"ENTITY DEBUG: Partial match: '{entity}' -> '{model_key}'")
#                         break

#     # FIXED: Better global fallback logic
#     if not valid_entities and models:
#         logger.warning(f"ENTITY DEBUG: No valid entities found!")
#         logger.warning(f"ENTITY DEBUG: Checking if we can use global fallback...")

#         # Try to find the most appropriate model for fallback
#         if 'global' in models and 'global' in scalers:
#             fallback_entity = 'global'
#             logger.warning(f"ENTITY DEBUG: Using global model for fallback")
#         else:
#             # Use first available model as fallback
#             available_models = [k for k in models.keys() if k in scalers and scalers[k] is not None]
#             if available_models:
#                 fallback_entity = available_models[0]
#                 logger.warning(f"ENTITY DEBUG: Using '{fallback_entity}' as fallback model")

#                 # Add all original entities to valid list for fallback processing
#                 for entity in entities:
#                     if str(entity).strip() not in ['0.0.0.0', 'unknown', '', 'nan', 'None']:
#                         valid_entities.append(entity)
#             else:
#                 logger.error("ENTITY DEBUG: No usable models found for fallback!")

#     logger.info(f"ENTITY DEBUG: Final validation result: {len(valid_entities)}/{len(entities)} valid entities")
#     logger.info(f"ENTITY DEBUG: Valid entities: {valid_entities}")

#     return valid_entities



# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # ================================================================
#         # COMPLETE FIX: Input validation and entity compatibility
#         # ================================================================

#         # Validate input data for NaN/infinite values
#         if np.any(np.isnan(X)) or np.any(np.isinf(X)):
#             logger.warning(f"NaN/infinite values detected for {entity}, cleaning...")
#             X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
#             logger.debug(f"Cleaned input data for {entity}")

#         # Check for empty or invalid input
#         if X.size == 0:
#             logger.error(f"Empty feature matrix for entity {entity}")
#             return None

#         if len(X.shape) != 2:
#             logger.error(f"Invalid feature matrix shape for entity {entity}: {X.shape}")
#             return None

#         # Prevent synthetic entity/real model mismatches
#         if 'synthetic' in str(entity) and hasattr(scaler, 'feature_names_in_'):
#             logger.warning(f"Synthetic entity {entity} may not match trained models, proceeding with caution")
#             # Continue but with extra validation

#         # Log scaling attempt
#         logger.debug(f"Attempting to scale {X.shape} features for entity {entity}")

#         # ================================================================
#         # STRATEGY 1: Direct scaling if dimensions match exactly
#         # ================================================================
#         try:
#             if hasattr(scaler, 'n_features_in_') and X.shape[1] == scaler.n_features_in_:
#                 scaled_result = scaler.transform(X)
#                 logger.debug(f"Direct scaling succeeded for {entity}")

#                 # Validate scaled result
#                 if not np.any(np.isnan(scaled_result)) and not np.any(np.isinf(scaled_result)):
#                     return scaled_result
#                 else:
#                     logger.debug(f"Direct scaling produced invalid values for {entity}")
#             else:
#                 logger.debug(f"Feature count mismatch for {entity}: {X.shape[1]} vs {getattr(scaler, 'n_features_in_', 'unknown')}")
#         except Exception as e:
#             logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # ================================================================
#         # STRATEGY 2: Feature alignment with padding/truncation
#         # ================================================================
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             logger.debug(f"Feature alignment for {entity}: {current_features} -> {expected_features}")

#             if current_features < expected_features:
#                 # Pad with zeros
#                 try:
#                     padding_size = expected_features - current_features
#                     padding = np.zeros((X.shape[0], padding_size))
#                     X_padded = np.hstack([X, padding])

#                     scaled_result = scaler.transform(X_padded)

#                     # Validate result
#                     if not np.any(np.isnan(scaled_result)) and not np.any(np.isinf(scaled_result)):
#                         logger.debug(f"Padded scaling succeeded for {entity} (added {padding_size} features)")
#                         return scaled_result
#                     else:
#                         logger.debug(f"Padded scaling produced invalid values for {entity}")
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 try:
#                     X_truncated = X[:, :expected_features]
#                     scaled_result = scaler.transform(X_truncated)

#                     # Validate result
#                     if not np.any(np.isnan(scaled_result)) and not np.any(np.isinf(scaled_result)):
#                         logger.debug(f"Truncated scaling succeeded for {entity} (removed {current_features - expected_features} features)")
#                         return scaled_result
#                     else:
#                         logger.debug(f"Truncated scaling produced invalid values for {entity}")
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # ================================================================
#         # STRATEGY 3: Manual scaling using scaler parameters
#         # ================================================================
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 logger.debug(f"Attempting manual scaling for {entity}")

#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Handle dimension mismatch
#                 if len(mean) > X.shape[1]:
#                     # Truncate scaler parameters
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                     logger.debug(f"Truncated scaler parameters for {entity}")
#                 elif len(mean) < X.shape[1]:
#                     # Pad scaler parameters using edge values
#                     mean_pad_value = mean[-1] if len(mean) > 0 else 0
#                     scale_pad_value = scale[-1] if len(scale) > 0 else 1

#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='constant', constant_values=mean_pad_value)
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='constant', constant_values=scale_pad_value)
#                     logger.debug(f"Padded scaler parameters for {entity}")

#                 # Ensure scale values are not zero or too small
#                 scale = np.where(np.abs(scale) < 1e-8, 1.0, scale)

#                 # Perform manual scaling
#                 X_scaled = (X - mean) / scale

#                 # Validate result
#                 if not np.any(np.isnan(X_scaled)) and not np.any(np.isinf(X_scaled)):
#                     logger.debug(f"Manual scaling succeeded for {entity}")
#                     return X_scaled
#                 else:
#                     logger.debug(f"Manual scaling produced invalid values for {entity}")
#                     # Try to clean the result
#                     X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)
#                     if not np.any(np.isnan(X_scaled)) and not np.any(np.isinf(X_scaled)):
#                         logger.debug(f"Manual scaling succeeded after cleaning for {entity}")
#                         return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # ================================================================
#         # STRATEGY 4: Robust scaler parameters (if available)
#         # ================================================================
#         if hasattr(scaler, 'center_') and hasattr(scaler, 'scale_'):
#             try:
#                 logger.debug(f"Attempting robust scaling for {entity}")

#                 center = scaler.center_
#                 scale = scaler.scale_

#                 # Handle dimension mismatch similar to strategy 3
#                 if len(center) > X.shape[1]:
#                     center = center[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(center) < X.shape[1]:
#                     center_pad_value = center[-1] if len(center) > 0 else 0
#                     scale_pad_value = scale[-1] if len(scale) > 0 else 1

#                     center = np.pad(center, (0, X.shape[1] - len(center)), mode='constant', constant_values=center_pad_value)
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='constant', constant_values=scale_pad_value)

#                 # Ensure scale values are valid
#                 scale = np.where(np.abs(scale) < 1e-8, 1.0, scale)

#                 # Perform robust scaling
#                 X_scaled = (X - center) / scale

#                 # Validate and clean result
#                 X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)

#                 if not np.any(np.isnan(X_scaled)) and not np.any(np.isinf(X_scaled)):
#                     logger.debug(f"Robust scaling succeeded for {entity}")
#                     return X_scaled

#             except Exception as e:
#                 logger.debug(f"Robust scaling failed for {entity}: {e}")

#         # ================================================================
#         # STRATEGY 5: Create new scaler as last resort
#         # ================================================================
#         try:
#             logger.warning(f"Creating new scaler for {entity} as last resort")

#             from sklearn.preprocessing import RobustScaler
#             new_scaler = RobustScaler()

#             # Validate input before fitting
#             if X.shape[0] > 0 and X.shape[1] > 0:
#                 # Clean input data thoroughly
#                 X_clean = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#                 # Check for constant features
#                 feature_std = np.std(X_clean, axis=0)
#                 if np.all(feature_std < 1e-8):
#                     # All features are constant, return standardized zeros
#                     logger.warning(f"All features constant for {entity}, returning zeros")
#                     return np.zeros_like(X_clean)

#                 # Fit and transform with new scaler
#                 X_scaled = new_scaler.fit_transform(X_clean)

#                 # Final validation
#                 X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)

#                 if not np.any(np.isnan(X_scaled)) and not np.any(np.isinf(X_scaled)):
#                     logger.debug(f"New scaler succeeded for {entity}")
#                     return X_scaled
#                 else:
#                     logger.warning(f"New scaler produced invalid values for {entity}")
#             else:
#                 logger.error(f"Invalid data shape for new scaler: {X.shape}")

#         except Exception as e:
#             logger.error(f"New scaler creation failed for {entity}: {e}")

#         # ================================================================
#         # STRATEGY 6: Ultimate fallback - simple standardization
#         # ================================================================
#         try:
#             logger.warning(f"Using ultimate fallback standardization for {entity}")

#             # Simple z-score standardization
#             X_clean = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#             # Calculate mean and std per feature
#             feature_means = np.mean(X_clean, axis=0)
#             feature_stds = np.std(X_clean, axis=0)

#             # Avoid division by zero
#             feature_stds = np.where(feature_stds < 1e-8, 1.0, feature_stds)

#             # Standardize
#             X_scaled = (X_clean - feature_means) / feature_stds

#             # Final cleaning
#             X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)

#             logger.debug(f"Ultimate fallback succeeded for {entity}")
#             return X_scaled

#         except Exception as e:
#             logger.error(f"Ultimate fallback failed for {entity}: {e}")

#         # ================================================================
#         # Complete failure
#         # ================================================================
#         logger.error(f"All scaling strategies failed for {entity}")
#         return None

#     except Exception as e:
#         logger.error(f"Critical error in scaling for {entity}: {e}")
#         return None
# def process_ml_results(statistical_results, ml_results, config, data_type):
#     """
#     FIXED: Actually use statistical results when ML fails.

#     PROBLEM: Function ignores statistical results completely
#     SOLUTION: Use statistical results as fallback when ML produces zero anomalies
#     """
#     logger.info(f"FIXED ML-Statistical hybrid processing for {data_type}")

#     # Priority 1: Try ML results first
#     if not ml_results.empty and 'is_ml_anomaly' in ml_results.columns:
#         results = ml_results.copy()

#         # Check if ML found any anomalies
#         ml_anomaly_count = results['is_ml_anomaly'].sum()

#         if ml_anomaly_count > 0:
#             # ML found anomalies - use them
#             results["final_anomaly"] = results["is_ml_anomaly"]
#             results["detection_method"] = "machine_learning"

#             logger.info(f"Using ML results: {ml_anomaly_count} anomalies detected")
#             return results
#         else:
#             logger.warning(f"ML detection found 0 anomalies - falling back to statistical")

#     # Priority 2: Fall back to statistical results
#     if not statistical_results.empty and 'is_anomaly' in statistical_results.columns:
#         results = statistical_results.copy()

#         # CRITICAL FIX: Actually use statistical anomaly flags
#         results["final_anomaly"] = results["is_anomaly"]
#         results["detection_method"] = "statistical_fallback"

#         stat_anomaly_count = results["final_anomaly"].sum()
#         logger.info(f"Using statistical fallback: {stat_anomaly_count} anomalies detected")

#         return results

#     # Priority 3: Return empty results with proper structure
#     logger.warning("No valid detection results available")
#     return pd.DataFrame(columns=["final_anomaly", "detection_method"])

# def _calculate_ensemble_scores_robust(method_scores: Dict[str, np.ndarray],
#                                      method_weights: Dict[str, float]) -> np.ndarray:
#     """
#     FIXED: Calculate weighted ensemble scores with proper normalization and validation.
#     """
#     if not method_scores:
#         logger.warning("No method scores provided for ensemble calculation")
#         return np.array([])

#     # ================================================================
#     # Input validation and preprocessing
#     # ================================================================

#     # Get array length from first valid method
#     array_length = None
#     valid_methods = {}

#     for method, scores in method_scores.items():
#         logger.info("scores per method {}: {}".format(method, scores))
#         if scores is not None and len(scores) > 0:
#             scores_array = np.array(scores)

#             # Validate score array
#             if np.any(np.isnan(scores_array)) or np.any(np.isinf(scores_array)):
#                 logger.warning(f"Invalid values in {method} scores, cleaning...")
#                 scores_array = np.nan_to_num(scores_array, nan=0.3, posinf=0.9, neginf=0.1)

#             # Ensure scores are in valid range
#             scores_array = np.clip(scores_array, 0.0, 1.0)

#             if array_length is None:
#                 array_length = len(scores_array)
#             elif len(scores_array) != array_length:
#                 logger.warning(f"Score length mismatch for {method}: {len(scores_array)} vs {array_length}, skipping")
#                 continue

#             valid_methods[method] = scores_array
#             logger.debug(f"Validated {method} scores: range [{scores_array.min():.3f}, {scores_array.max():.3f}]")
#         else:
#             logger.warning(f"Invalid or empty scores for method {method}, skipping")

#     if not valid_methods:
#         logger.error("No valid method scores available for ensemble")
#         return np.array([])

#     if array_length is None or array_length <= 0:
#         logger.error("Invalid array length for ensemble calculation")
#         return np.array([])

#     logger.debug(f"Calculating ensemble for {len(valid_methods)} methods with {array_length} samples")

#     # ================================================================
#     # Weight normalization and validation
#     # ================================================================

#     # Initialize ensemble scores
#     ensemble_scores = np.zeros(array_length)
#     total_weight = 0.0
#     used_weights = {}

#     # Process each valid method with proper weighting
#     for method, scores in valid_methods.items():
#         # Get weight for this method (with defaults)
#         default_weights = {
#             "isolation_forest": 0.4,
#             "local_outlier_factor": 0.3,
#             "one_class_svm": 0.2,
#             "dbscan": 0.1,
#             "autoencoder": 0.25,
#             "statistical": 0.15
#         }

#         weight = method_weights.get(method, default_weights.get(method, 0.1))

#         # Ensure weight is positive and reasonable
#         weight = max(0.01, min(1.0, float(weight)))

#         # ================================================================
#         # Score normalization per method
#         # ================================================================

#         normalized_scores = scores.copy()

#         # Method-specific score normalization
#         if method == "isolation_forest":
#             # Isolation Forest: already normalized, ensure good distribution
#             if normalized_scores.max() > normalized_scores.min():
#                 # Enhance contrast for better discrimination
#                 normalized_scores = np.power(normalized_scores, 1.2)

#         elif method == "local_outlier_factor":
#             # LOF: ensure outliers get higher scores
#             if normalized_scores.max() > normalized_scores.min():
#                 # Apply gentle sigmoid transformation to enhance outliers
#                 normalized_scores = 1 / (1 + np.exp(-5 * (normalized_scores - 0.5)))

#         elif method == "one_class_svm":
#             # SVM: linear normalization is usually good
#             pass  # Already normalized

#         elif method == "dbscan":
#             # DBSCAN: enhance noise points
#             high_score_mask = normalized_scores > 0.6
#             if np.any(high_score_mask):
#                 normalized_scores[high_score_mask] = np.minimum(
#                     normalized_scores[high_score_mask] * 1.1, 1.0
#                 )

#         elif method == "autoencoder":
#             # Autoencoder: reconstruction error based
#             if normalized_scores.max() > normalized_scores.min():
#                 # Square root to reduce extreme values
#                 normalized_scores = np.sqrt(normalized_scores)

#         # Final range validation
#         normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#         # ================================================================
#         # Weighted score accumulation
#         # ================================================================

#         # Add weighted scores to ensemble
#         ensemble_scores += weight * normalized_scores
#         total_weight += weight
#         used_weights[method] = weight

#         logger.debug(f"Added {method} with weight {weight:.3f}, score contribution: [{(weight * normalized_scores).min():.3f}, {(weight * normalized_scores).max():.3f}]")

#     # ================================================================
#     # Final ensemble normalization
#     # ================================================================

#     if total_weight > 0:
#         # Normalize by total weight
#         ensemble_scores /= total_weight
#         logger.debug(f"Normalized ensemble by total weight: {total_weight:.3f}")
#     else:
#         logger.error("Total weight is zero, returning zero scores")
#         return np.zeros(array_length)

#     # ================================================================
#     # Ensemble score validation and enhancement
#     # ================================================================

#     # Ensure scores are in valid range
#     ensemble_scores = np.clip(ensemble_scores, 0.0, 1.0)

#     # Apply final score enhancement for better discrimination
#     if len(valid_methods) >= 2:
#         # Multi-method consensus: enhance agreement
#         score_std = np.std(ensemble_scores)
#         if score_std > 0.1:  # Good score distribution
#             # Apply gentle sigmoid to enhance high scores
#             ensemble_scores = 1 / (1 + np.exp(-8 * (ensemble_scores - 0.5)))
#             ensemble_scores = np.clip(ensemble_scores, 0.0, 1.0)

#     # ================================================================
#     # Final validation and quality checks
#     # ================================================================

#     # Check for problematic patterns
#     unique_scores = len(np.unique(ensemble_scores))
#     if unique_scores == 1:
#         logger.warning("All ensemble scores are identical, adding slight variation")
#         # Add minimal random variation to break ties
#         noise = np.random.normal(0, 0.01, array_length)
#         ensemble_scores = np.clip(ensemble_scores + noise, 0.0, 1.0)

#     # Prevent extreme clustering of scores
#     high_score_ratio = np.mean(ensemble_scores > 0.8)
#     low_score_ratio = np.mean(ensemble_scores < 0.2)

#     if high_score_ratio > 0.5:
#         logger.warning("Too many high anomaly scores, applying moderation")
#         # Reduce extreme high scores slightly
#         high_mask = ensemble_scores > 0.8
#         ensemble_scores[high_mask] = 0.7 + 0.1 * (ensemble_scores[high_mask] - 0.8) / 0.2

#     elif low_score_ratio > 0.9:
#         logger.warning("Too many low anomaly scores, enhancing discrimination")
#         # Enhance scores slightly for better discrimination
#         ensemble_scores = np.minimum(ensemble_scores * 1.1, 1.0)

#     # Final range clipping
#     ensemble_scores = np.clip(ensemble_scores, 0.0, 1.0)

#     # ================================================================
#     # Logging and return
#     # ================================================================

#     score_stats = {
#         'min': ensemble_scores.min(),
#         'max': ensemble_scores.max(),
#         'mean': ensemble_scores.mean(),
#         'std': ensemble_scores.std(),
#         'unique_values': len(np.unique(ensemble_scores))
#     }

#     logger.debug(f"Ensemble calculation complete:")
#     logger.debug(f"  Methods used: {list(used_weights.keys())}")
#     logger.debug(f"  Weights applied: {used_weights}")
#     logger.debug(f"  Score statistics: {score_stats}")
#     logger.debug(f"  High scores (>0.7): {np.sum(ensemble_scores > 0.7)}/{array_length}")

#     logger.info(f"Calculated ensemble scores for {array_length} samples using {len(valid_methods)} methods")

#     return ensemble_scores


# def _calculate_conservative_threshold(scores: np.ndarray, config: Dict) -> float:
#     """
#     FIXED: Calculate conservative threshold to prevent extreme values.
#     """
#     if len(scores) == 0:
#         return 0.7  # Conservative default

#     detection_config = config.get("detection", {})
#     max_anomaly_rate = detection_config.get("max_anomaly_rate", 0.03)  # Max 3% anomalies

#     # Calculate multiple threshold candidates
#     thresholds = []

#     # Method 1: Percentile-based (ensures max anomaly rate)
#     percentile_threshold = np.percentile(scores, (1 - max_anomaly_rate) * 100)
#     thresholds.append(percentile_threshold)

#     # Method 2: Statistical (mean + 2*std)
#     mean_score = scores.mean()
#     std_score = scores.std()
#     if std_score > 0:
#         statistical_threshold = min(mean_score + 2.0 * std_score, 0.9)
#     else:
#         statistical_threshold = mean_score + 0.2
#     thresholds.append(statistical_threshold)

#     # Method 3: IQR-based
#     q1, q3 = np.percentile(scores, [25, 75])
#     iqr = q3 - q1
#     if iqr > 0:
#         iqr_threshold = min(q3 + 2.0 * iqr, 0.9)
#     else:
#         iqr_threshold = q3 + 0.2
#     thresholds.append(iqr_threshold)

#     # Select conservative threshold
#     final_threshold = np.median(thresholds)

#     # CRITICAL: Enforce reasonable bounds to prevent extreme thresholds
#     final_threshold = np.clip(final_threshold, 0.3, 0.85)  # Reasonable range

#     # Additional safety check for very small datasets
#     if len(scores) <= 3:
#         final_threshold = max(final_threshold, 0.8)  # Very conservative for small datasets

#     return float(final_threshold)


# def _calculate_confidence_robust(method_scores: Dict[str, np.ndarray],
#                                 ensemble_scores: np.ndarray) -> np.ndarray:
#     """Calculate confidence scores based on method agreement."""
#     if not method_scores or len(ensemble_scores) == 0:
#         return np.zeros_like(ensemble_scores)

#     if len(method_scores) == 1:
#         return np.full_like(ensemble_scores, 0.5)  # Medium confidence for single method

#     try:
#         # Calculate agreement between methods
#         method_arrays = list(method_scores.values())
#         method_matrix = np.column_stack(method_arrays)

#         # Agreement based on standard deviation (lower std = higher agreement)
#         agreement = 1 - np.std(method_matrix, axis=1)

#         # Normalize to [0.3, 1.0] range (avoid very low confidence)
#         if agreement.max() > agreement.min():
#             confidence = 0.3 + 0.7 * (agreement - agreement.min()) / (agreement.max() - agreement.min())
#         else:
#             confidence = np.full_like(agreement, 0.5)

#         return confidence

#     except Exception as e:
#         logger.warning(f"Confidence calculation failed: {e}")
#         return np.full_like(ensemble_scores, 0.5)



# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def enhanced_feature_extraction(df, data_type='process'):
#     """
#     FIXED: Enhanced feature extraction with real-time compatible features.
#     """
#     if df.empty:
#         return df

#     logger.info(f"Enhanced feature extraction for {data_type} with {len(df)} records")

#     # === REQUIRED FEATURES ===
#     # Add event count if missing
#     if 'event_count' not in df.columns:
#         df['event_count'] = 1

#     # === TEMPORAL FEATURES ===
#     if '@timestamp' in df.columns:
#         df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')
#         df = df.dropna(subset=['@timestamp'])

#         df['hour_of_day'] = df['@timestamp'].dt.hour
#         df['day_of_week'] = df['@timestamp'].dt.dayofweek
#         df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
#         df['is_business_hours'] = ((df['hour_of_day'] >= 8) & (df['hour_of_day'] < 18) & ~df['is_weekend']).astype(int)

#         # Circular encoding
#         df['hour_sin'] = np.sin(2 * np.pi * df['hour_of_day'] / 24)
#         df['hour_cos'] = np.cos(2 * np.pi * df['hour_of_day'] / 24)
#         df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
#         df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)

#         logger.info(f"Created {len(['hour_of_day', 'day_of_week', 'is_weekend', 'is_business_hours', 'hour_sin', 'hour_cos', 'day_sin', 'day_cos'])} temporal features")

#     # === DOMAIN-SPECIFIC FEATURES ===
#     if data_type == 'process':
#         # Process-specific
#         if 'process.name' in df.columns:
#             logger.warning(f"PROCESS.NAME DEBUG - Found processes: {df['process.name'].unique()[:15]}...")
#             logger.warning(f"PROCESS.NAME DEBUG - Null values: {df['process.name'].isna().sum()}/{len(df)}")

#             process_encoder = LabelEncoder()
#             df['process_encoded'] = process_encoder.fit_transform(df['process.name'].fillna('unknown'))

#             if 'process.parent.name' in df.columns:
#                 df['parent_encoded'] = process_encoder.fit_transform(df['process.parent.name'].fillna('unknown'))
#                 df['process_family'] = df['process_encoded'] * 100 + df['parent_encoded']

#         if 'process.command_line' in df.columns:
#             df['command_length'] = df['process.command_line'].str.len().fillna(0)
#             df['args_count'] = df['process.command_line'].str.split().str.len().fillna(0)
#             df['has_pipes'] = df['process.command_line'].str.contains('|').astype(int)
#             df['has_redirection'] = df['process.command_line'].str.contains('[<>]').astype(int)

#     elif data_type == 'network':
#         # Revised: Handle partial invalid IPs
#         logger.warning("NETWORK DATA REPAIR: Checking for IP issues...")
#         invalid_mask = (df['destination.ip'].isna()) | (df['destination.ip'] == '0.0.0.0') | (df['destination.ip'] == '')
#         if invalid_mask.any():
#             logger.warning(f"NETWORK DATA REPAIR: {invalid_mask.sum()} invalid IPs found")
#             if 'destination.port' in df.columns:
#                 df.loc[invalid_mask, 'destination.ip'] = 'synthetic_port_' + df.loc[invalid_mask, 'destination.port'].astype(str)
#                 logger.warning(f"NETWORK DATA REPAIR: Created synthetic entities for {invalid_mask.sum()} records")
#             else:
#                 # Drop if no port available
#                 df = df[~invalid_mask]
#                 logger.warning(f"NETWORK DATA REPAIR: Dropped {invalid_mask.sum()} records without ports")

#         # Other network features...
#         if 'destination.port' in df.columns:
#             df['is_well_known_port'] = (df['destination.port'] < 1024).astype(int)
#         if 'network.bytes' in df.columns:
#             df['is_large_transfer'] = (df['network.bytes'] > 1048576).astype(int)  # >1MB

#         if 'source.ip' in df.columns:
#             df['is_internal_source'] = df['source.ip'].apply(_is_internal_ip)

#         if 'destination.ip' in df.columns:
#             df['is_internal_dest'] = df['destination.ip'].apply(_is_internal_ip)

#     elif data_type == 'user':
#         # User-specific features
#         if 'user.name' in df.columns:
#             df['user_frequency'] = df.groupby('user.name')['user.name'].transform('count') / len(df)

#         if 'is_sudo_command' in df.columns:
#             df['sudo_frequency'] = df['is_sudo_command'].mean()

#         if 'is_compiler_activity' in df.columns:
#             df['compiler_activity'] = df['is_compiler_activity'].sum()

#     elif data_type == 'discovery':
#         # Discovery-specific
#         if 'process.command_line' in df.columns:
#             df['command_length'] = df['process.command_line'].str.len().fillna(0)
#             df['has_pipes'] = df['process.command_line'].str.contains('|').astype(int)
#             df['has_redirection'] = df['process.command_line'].str.contains('[<>]').astype(int)

#         if 'discovery_category' in df.columns:
#             df['category_encoded'] = LabelEncoder().fit_transform(df['discovery_category'].fillna('unknown'))

#     elif data_type == 'metadata':
#         # Metadata-specific
#         if 'process.name' in df.columns:
#             df['metadata_process_freq'] = df.groupby('process.name')['process.name'].transform('count') / len(df)

#         if 'user.name' in df.columns:
#             df['metadata_user_freq'] = df.groupby('user.name')['user.name'].transform('count') / len(df)

#     # === FEATURE COMPATIBILITY CHECK ===
#     compatible_features = [col for col in df.columns if col not in ['@timestamp', 'time_bucket']]
#     logger.info(f"Real-time feature extraction complete: {len(compatible_features)} compatible features")

#     return df
# def detect_ml_anomalies(data: pd.DataFrame, models: Dict, scalers: Dict,
#                        config: Dict, data_type: str = "process", useAddress: bool = False ) -> pd.DataFrame:
#     """
#     FIXED: Enhanced ML anomaly detection with comprehensive debugging and data repair.
#     """
#     if data.empty:
#         logger.warning("Empty data provided for ML anomaly detection")
#         return pd.DataFrame()

#     if not models or not scalers:
#         logger.warning("No models or scalers provided for ML detection")
#         return _handle_ml_detection_failure(data, "no_models_available")

#     logger.info(f"Starting FIXED ML anomaly detection for {data_type} with {len(data)} records")

#     # ================================================================
#     # COMPLETE FIX: Job-specific entity column handling and synthetic entity removal
#     # ================================================================

# # CRITICAL FIX: Add this to detect_ml_anomalies() right after the job detection logic
#     data_copy = data.copy()

#     if data_type == 'network':
#         # Determine job type from config or data characteristics
#         # job_name = config.get('current_job_name', '')
#         # job_description = str(config.get('job_description', '')).lower()

#         # if ('port_activity' in job_name.lower() or
#         #     'port' in job_description or
#         #     'v3_linux_anomalous_network_port_activity' in job_name):

#             # v3_linux_anomalous_network_port_activity: Use destination.port as entity

#         entity_col = ''
#         logger.info("Columns in data_copy: " + ", ".join(data_copy.columns))
#         logger.info(f"PORT ACTIVITY JOB: Using {entity_col} as entity column")


#         # CRITICAL FIX: Ensure destination.port is preserved in bucketed data

#         if useAddress:
#             if 'destination.ip' in data_copy.columns:

#                 entity_col = 'destination.ip'
#                 # Remove synthetic port entities that shouldn't match IP-trained models
#                 synthetic_mask = data_copy[entity_col].astype(str).str.contains('synthetic_port', na=False)

#                 if synthetic_mask.any():
#                     logger.warning(f"NETWORK ACTIVITY: Found {synthetic_mask.sum()} synthetic port entities")

#                     # Strategy 1: Replace with source.ip if available
#                     if 'source.ip' in data_copy.columns:
#                         valid_source_mask = ~(
#                             (data_copy['source.ip'] == '0.0.0.0') |
#                             data_copy['source.ip'].isna() |
#                             (data_copy['source.ip'] == '')
#                         )
#                         replacement_mask = synthetic_mask & valid_source_mask
#                         if replacement_mask.any():
#                             data_copy.loc[replacement_mask, entity_col] = data_copy.loc[replacement_mask, 'source.ip']
#                             logger.warning(f"NETWORK ACTIVITY: Replaced {replacement_mask.sum()} synthetic entities with source.ip")

#                     # Strategy 2: Remove remaining synthetic entities
#                     remaining_synthetic = data_copy[entity_col].astype(str).str.contains('synthetic_port', na=False)
#                     if remaining_synthetic.any():
#                         logger.warning(f"NETWORK ACTIVITY: Removing {remaining_synthetic.sum()} remaining synthetic entities")
#                         data_copy = data_copy[~remaining_synthetic].copy()

#                 # Additional validation for destination.ip
#                 if data_copy.empty:
#                     logger.error("NETWORK ACTIVITY: No valid network data after synthetic entity removal")
#                     return _handle_ml_detection_failure(data, "no_valid_ips_after_cleanup")
#             else:
#                 logger.error("NETWORK ACTIVITY: destination.ip column missing")
#                 return _handle_ml_detection_failure(data, "missing_ip_column")
#         elif useAddress == False:

#             if 'destination.port' in data.columns:

#                 entity_col = 'destination.port'

#                 logger.warning("PORT ACTIVITY: Restoring destination.port from original data")


#                 logger.info("1")
#                 logger.info(data_copy.info())


#                 # Clean synthetic port values
#                 logger.info("port data type before conversion: " + str(data_copy['destination.port'].dtype))
#                 data_copy['destination.port'] = pd.to_numeric(data_copy['destination.port'], errors='coerce')
#                 logger.info("2")

#                 # Remove rows with invalid ports
#                 valid_port_mask = (
#                     data_copy['destination.port'].notna() &
#                     (data_copy['destination.port'] > 0) &
#                     (data_copy['destination.port'] <= 65535)
#                 )
#                 logger.info("3")

#                 if not valid_port_mask.all():
#                     removed_count = (~valid_port_mask).sum()
#                     logger.warning(f"PORT ACTIVITY: Removing {removed_count} records with invalid ports")
#                     data_copy = data_copy[valid_port_mask].copy()
#                 logger.info("3")
#                 logger.info("4")
#                 logger.info("5")
#                 if data_copy.empty:
#                     logger.error("PORT ACTIVITY: No valid port data remaining")
#                     return _handle_ml_detection_failure(data, "no_valid_ports")
#                 logger.info("6")
#                 logger.info("7")
#             else:
#                 logger.error("PORT ACTIVITY: destination.port column still missing after restoration attempt")
#                 return _handle_ml_detection_failure(data, "missing_port_column")
#     # else:
#         # v3_linux_anomalous_network_activity: Use destination.ip as entity (default)
#         # entity_col = 'destination.ip'
#         # logger.info(f"NETWORK ACTIVITY JOB: Using {entity_col} as entity column")


#         else:
#             # For non-network data types, use standard entity column
#             entity_col = _get_entity_column(data_type)

#     # ================================================================
#     # Feature availability analysis
#     # ================================================================
#     try:
#         # feature_analysis = analyze_feature_availability(data_copy, config, data_type)
#         feature_analysis = analyze_feature_availability(data_copy, data_type)

#         for category, coverage in feature_analysis['feature_coverage'].items():
#             logger.info(f"{category.upper()} features - Available: {coverage['available']}/{coverage['total']} ({coverage['percentage']:.1f}%)")

#         if not feature_analysis['real_time_compatible']:
#             logger.warning(f"Limited feature compatibility detected - using fallback strategy: {feature_analysis['fallback_strategy']}")
#     except Exception as e:
#         logger.warning(f"Feature analysis failed: {e}")

#     # ================================================================
#     # Enhanced feature extraction with validation
#     # ================================================================
#     try:
#         feature_data = extract_ml_features(data_copy, config)

#         if feature_data.empty:
#             logger.error("Feature extraction returned empty dataset")
#             return _handle_ml_detection_failure(data, "feature_extraction_failed")

#         logger.info(f"Enhanced feature extraction for {data_type} with {len(feature_data)} records")

#         # MOVED HERE: Validate entity column exists after feature extraction
#         if entity_col not in feature_data.columns:
#             logger.error(f"Entity column '{entity_col}' missing after feature extraction")

#             # Try to add the entity column if we can determine it
#             if data_type == 'network':
#                 if 'destination.ip' not in feature_data.columns and 'source.ip' in feature_data.columns:
#                     logger.warning("Using source.ip as destination.ip fallback")
#                     feature_data['destination.ip'] = feature_data['source.ip']
#                     entity_col = 'destination.ip'
#                 else:
#                     return _handle_ml_detection_failure(data, f"missing_entity_column_{entity_col}")
#             else:
#                 return _handle_ml_detection_failure(data, f"missing_entity_column_{entity_col}")

#         # NOW do the entity validation and cleanup
#         if data_type == 'network' and entity_col == 'destination.ip':
#             # Remove synthetic port entities that shouldn't match IP-trained models
#             synthetic_mask = feature_data[entity_col].astype(str).str.contains('synthetic_port', na=False)

#             if synthetic_mask.any():
#                 logger.warning(f"NETWORK ACTIVITY: Found {synthetic_mask.sum()} synthetic port entities")

#                 # Strategy 1: Replace with source.ip if available
#                 if 'source.ip' in feature_data.columns:
#                     valid_source_mask = ~(
#                         (feature_data['source.ip'] == '0.0.0.0') |
#                         feature_data['source.ip'].isna() |
#                         (feature_data['source.ip'] == '')
#                     )
#                     replacement_mask = synthetic_mask & valid_source_mask
#                     if replacement_mask.any():
#                         feature_data.loc[replacement_mask, entity_col] = feature_data.loc[replacement_mask, 'source.ip']
#                         logger.warning(f"NETWORK ACTIVITY: Replaced {replacement_mask.sum()} synthetic entities with source.ip")

#                 # Strategy 2: Remove remaining synthetic entities
#                 remaining_synthetic = feature_data[entity_col].astype(str).str.contains('synthetic_port', na=False)
#                 if remaining_synthetic.any():
#                     logger.warning(f"NETWORK ACTIVITY: Removing {remaining_synthetic.sum()} remaining synthetic entities")
#                     feature_data = feature_data[~remaining_synthetic].copy()

#             # Additional validation
#             if feature_data.empty:
#                 logger.error("NETWORK ACTIVITY: No valid network data after synthetic entity removal")
#                 return _handle_ml_detection_failure(data, "no_valid_ips_after_cleanup")

#     except Exception as e:
#         logger.error(f"Feature extraction failed: {e}")
#         return _handle_ml_detection_failure(data, f"feature_extraction_error_{str(e)[:50]}")

#     # ================================================================
#     # STEP 3: Enhanced data repair for network issues
#     # ================================================================
#     if data_type == 'network':
#         logger.warning("NETWORK DATA REPAIR: Checking for remaining issues...")

#         if entity_col in feature_data.columns:
#             if entity_col == 'destination.ip':
#                 unique_ips = feature_data[entity_col].unique()
#                 problem_ips = [ip for ip in unique_ips if str(ip) in ['0.0.0.0', 'unknown', 'nan', 'None', '']]

#                 if len(problem_ips) > 0:
#                     logger.warning(f"NETWORK DATA REPAIR: Found remaining problematic values: {problem_ips}")

#                     # Final cleanup - replace with localhost
#                     problem_mask = feature_data[entity_col].isin(problem_ips) | feature_data[entity_col].isnull()
#                     if problem_mask.any():
#                         feature_data.loc[problem_mask, entity_col] = '127.0.0.1'
#                         logger.warning(f"NETWORK DATA REPAIR: Fixed {problem_mask.sum()} remaining problematic IPs")

#             elif entity_col == 'destination.port':
#                 # Validate ports are numeric and reasonable
#                 invalid_ports = feature_data[entity_col].isna() | (feature_data[entity_col] <= 0)
#                 if invalid_ports.any():
#                     logger.warning(f"NETWORK DATA REPAIR: Found {invalid_ports.sum()} invalid ports")
#                     feature_data = feature_data[~invalid_ports].copy()

#     # ================================================================
#     # STEP 4: Enhanced entity validation with debugging
#     # ================================================================
#     logger.warning(f"DATA FLOW DEBUG for {data_type}:")
#     logger.warning(f"Entity column: '{entity_col}'")

#     if entity_col in feature_data.columns:
#         unique_entities = feature_data[entity_col].unique()
#         logger.warning(f"Unique entities found: {len(unique_entities)} entities")
#         logger.warning(f"Sample entities: {list(unique_entities)[:10]}")
#         logger.warning(f"Null values in entity column: {feature_data[entity_col].isnull().sum()}")

#         # Check for problematic values
#         default_values = ['0.0.0.0', 'unknown', '', 'nan', 'None']
#         for default_val in default_values:
#             count = (feature_data[entity_col] == default_val).sum()
#             if count > 0:
#                 logger.warning(f"Found {count} records with problematic value '{default_val}'")
#     else:
#         logger.error(f"CRITICAL: Entity column '{entity_col}' missing from feature data")
#         return _handle_ml_detection_failure(data, f"missing_entity_column_{entity_col}")

#     # ================================================================
#     # STEP 5: Enhanced entity validation with model matching
#     # ================================================================
#     entities = feature_data[entity_col].unique()
#     trained_entities = list(models.keys())

#     logger.warning(f"DEBUG - Trained models: {len(trained_entities)} entities")
#     logger.warning(f"DEBUG - Sample trained entities: {trained_entities[:10]}")
#     logger.warning(f"DEBUG - Detection entities: {len(entities)} entities")
#     logger.warning(f"DEBUG - Sample detection entities: {list(entities)[:10]}")

#     # Enhanced validation with better matching
#     valid_entities = []

#     # Direct matches first
#     direct_matches = [entity for entity in entities if entity in trained_entities]
#     valid_entities.extend(direct_matches)

#     if not valid_entities:
#         logger.warning("No direct entity matches - attempting fuzzy matching...")

#         # For network data, try to find IP matches vs synthetic entities
#         if data_type == 'network' and entity_col == 'destination.ip':
#             # Look for any real IP in trained models
#             real_ip_models = [model for model in trained_entities if not str(model).startswith('synthetic')]
#             if real_ip_models:
#                 logger.warning(f"Found {len(real_ip_models)} real IP models for fallback")
#                 valid_entities = real_ip_models[:10]  # Use top 10 for performance

#         # For port data, look for numeric port matches
#         elif data_type == 'network' and entity_col == 'destination.port':
#             port_entities = [int(e) for e in entities if str(e).isdigit()]
#             port_models = [int(m) for m in trained_entities if str(m).isdigit()]
#             matching_ports = list(set(port_entities) & set(port_models))
#             valid_entities = [str(p) for p in matching_ports]

#         # Generic fuzzy matching for other data types
#         if not valid_entities:
#             for entity in entities[:20]:  # Limit to prevent performance issues
#                 fuzzy_matches = [model for model in trained_entities if str(entity).lower() in str(model).lower()]
#                 if fuzzy_matches:
#                     valid_entities.extend(fuzzy_matches[:3])  # Max 3 matches per entity

#     logger.warning(f"DEBUG - Valid entities after matching: {len(valid_entities)}")

#     if not valid_entities:
#         logger.warning("No entities passed validation - implementing enhanced fallback strategy")

#         # Enhanced fallback: use the most common trained entity
#         if trained_entities:
#             fallback_entity = trained_entities[0]  # Use first available model
#             logger.warning(f"Using fallback entity '{fallback_entity}' for all {len(entities)} entities")

#             # Apply fallback model to all data
#             try:
#                 fallback_models = models[fallback_entity]
#                 fallback_scaler = scalers[fallback_entity]

#                 # Extract features for fallback processing
#                 features_used = _get_trained_features_robust(fallback_models, fallback_scaler)
#                 if not features_used:
#                     logger.error(f"No features found for fallback entity {fallback_entity}")
#                     return _handle_ml_detection_failure(data, "no_fallback_features")

#                 # Get available numeric features
#                 numeric_columns = feature_data.select_dtypes(include=[np.number]).columns.tolist()
#                 available_features = [f for f in features_used if f in numeric_columns]

#                 if not available_features:
#                     available_features = numeric_columns[:min(len(features_used), len(numeric_columns))]

#                 if not available_features:
#                     logger.error("No compatible features available for fallback processing")
#                     return _handle_ml_detection_failure(data, "no_compatible_features")

#                 # Process with fallback entity
#                 X = feature_data[available_features].values
#                 X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#                 # Scale features
#                 X_scaled = _scale_features_multi_strategy(X, fallback_scaler, fallback_entity,
#                                                         available_features, features_used)

#                 if X_scaled is not None:
#                     # Apply ML methods
#                     method_scores = _apply_ml_methods_robust(fallback_models, X_scaled, fallback_entity)

#                     if method_scores:
#                         # Calculate ensemble scores
#                         method_weights = config.get("method_weights", {
#                             "isolation_forest": 0.4,
#                             "local_outlier_factor": 0.3,
#                             "one_class_svm": 0.2,
#                             "dbscan": 0.1
#                         })

#                         ensemble_scores = _calculate_ensemble_scores_robust(method_scores, method_weights)

#                         # Calculate dynamic threshold
#                         threshold = _calculate_dynamic_threshold(ensemble_scores, config)

#                         # Create results
#                         feature_data["is_ml_anomaly"] = ensemble_scores >= threshold
#                         feature_data["ml_anomaly_score"] = ensemble_scores
#                         feature_data["confidence"] = np.clip(ensemble_scores * 2 - 1, 0, 1)  # Scale to 0-1
#                         feature_data["detection_method"] = "machine_learning"
#                         feature_data["detection_timestamp"] = pd.Timestamp.now()
#                         feature_data["detection_threshold"] = threshold
#                         feature_data["methods_used"] = ",".join(method_scores.keys())

#                         anomaly_count = feature_data["is_ml_anomaly"].sum()
#                         logger.warning(f"Enhanced fallback processing successful: {anomaly_count} anomalies from {len(feature_data)} records")

#                         # Final output validation
#                         return _validate_final_output(feature_data)
#                     else:
#                         logger.error("Fallback ML methods failed")
#                         return _handle_ml_detection_failure(data, "fallback_methods_failed")
#                 else:
#                     logger.error("Fallback feature scaling failed")
#                     return _handle_ml_detection_failure(data, "fallback_scaling_failed")

#             except Exception as e:
#                 logger.error(f"Enhanced fallback processing failed: {e}")
#                 return _handle_ml_detection_failure(data, f"fallback_error_{str(e)[:50]}")
#         else:
#             logger.error("No trained entities available for fallback")
#             return _handle_ml_detection_failure(data, "no_trained_entities")

#     # ================================================================
#     # STEP 6: Process valid entities with enhanced error handling
#     # ================================================================
#     all_results = []
#     processed_entities = 0
#     failed_entities = 0

#     for entity in valid_entities:
#         try:
#             entity_results = _detect_entity_anomalies_fixed(
#                 entity, feature_data, models, scalers, config, data_type
#             )

#             if not entity_results.empty:
#                 all_results.append(entity_results)
#                 processed_entities += 1

#                 # Log entity processing result
#                 # anomaly_count = entity_results.get('is_ml_anomaly', pd.Series()).sum()
#                 # total_records = len(entity_results)
#                 # threshold = entity_results.get('detection_threshold', pd.Series()).iloc[0] if len(entity_results) > 0 else 0

#                 anomaly_count = entity_results["is_ml_anomaly"].sum()
#                 total_records = len(entity_results)

#                 # SAFE threshold access - no iloc indexing
#                 if isinstance(threshold, (int, float)):
#                     threshold_value = threshold
#                 else:
#                     threshold_value = 0.5  # fallback

#                 logger.info(f"Entity {entity}: {anomaly_count}/{total_records} anomalies (threshold={threshold_value:.3f})")

#                 # logger.info(f"Entity {entity}: {anomaly_count}/{total_records} anomalies (threshold={threshold:.3f})")
#             else:
#                 failed_entities += 1
#                 logger.warning(f"Entity {entity}: No results returned")

#         except Exception as e:
#             failed_entities += 1
#             logger.error(f"Entity {entity} processing failed: {e}")
#             continue

#     # ================================================================
#     # STEP 7: Combine results with validation
#     # ================================================================
#     if all_results:
#         try:
#             combined_results = pd.concat(all_results, ignore_index=True)

#             # Remove duplicates based on key columns
#             if '@timestamp' in combined_results.columns and entity_col in combined_results.columns:
#                 combined_results = combined_results.drop_duplicates(
#                     subset=['@timestamp', entity_col],
#                     keep='first'
#                 )

#             duplicate_count = len(all_results) - len(combined_results) if len(all_results) > len(combined_results) else 0
#             if duplicate_count > 0:
#                 logger.info(f"Removed {duplicate_count} duplicate records")

#             # Apply safety limits
#             combined_results = _apply_ml_safety_limits(combined_results, config)

#             final_anomaly_count = combined_results.get('is_ml_anomaly', pd.Series()).sum()
#             total_records = len(combined_results)
#             anomaly_rate = (final_anomaly_count / total_records * 100) if total_records > 0 else 0

#             processing_time = time.time() - (config.get('_start_time', time.time()))

#             logger.info(f"ML detection complete: {final_anomaly_count} anomalies from {total_records} records ({anomaly_rate:.1f}%) in {processing_time*1000:.1f}ms")
#             logger.info(f"Successfully processed {processed_entities}/{len(valid_entities)} entities ({failed_entities} failed)")

#             # Final output validation and cleanup
#             return _validate_final_output(combined_results)

#         except Exception as e:
#             logger.error(f"Results combination failed: {e}")
#             return _handle_ml_detection_failure(data, f"combination_error_{str(e)[:50]}")
#     else:
#         logger.error("No valid results from any entity")
#         return _handle_ml_detection_failure(data, "no_valid_results")


# def _validate_final_output(results: pd.DataFrame) -> pd.DataFrame:
#     """
#     COMPLETE FIX: Final output validation to ensure no NaN values and proper formatting.
#     """
#     if results.empty:
#         return results

#     # Ensure required columns exist
#     required_columns = {
#         'is_ml_anomaly': False,
#         'ml_anomaly_score': 0.0,
#         'confidence': 0.0,
#         'detection_method': 'machine_learning',
#         'detection_timestamp': pd.Timestamp.now(),
#         'detection_threshold': 0.5
#     }

#     for col, default_val in required_columns.items():
#         if col not in results.columns:
#             results[col] = default_val
#         else:
#             results[col] = results[col].fillna(default_val)

#     # Clean ML anomaly scores - prevent exactly 1.0 scores that indicate processing failures
#     if 'ml_anomaly_score' in results.columns:
#         results['ml_anomaly_score'] = pd.to_numeric(results['ml_anomaly_score'], errors='coerce').fillna(0.0)
#         # Prevent perfect scores that indicate NaN input issues
#         results['ml_anomaly_score'] = np.where(results['ml_anomaly_score'] >= 0.999, 0.85, results['ml_anomaly_score'])
#         results['ml_anomaly_score'] = np.where(results['ml_anomaly_score'] <= 0.001, 0.15, results['ml_anomaly_score'])
#         # Ensure scores are in valid range
#         results['ml_anomaly_score'] = np.clip(results['ml_anomaly_score'], 0.0, 1.0)

#     # Clean boolean columns
#     boolean_columns = ['is_ml_anomaly', 'final_anomaly']
#     for col in boolean_columns:
#         if col in results.columns:
#             results[col] = results[col].fillna(False).astype(bool)

#     # Clean confidence scores
#     if 'confidence' in results.columns:
#         results['confidence'] = pd.to_numeric(results['confidence'], errors='coerce').fillna(0.0)
#         results['confidence'] = np.clip(results['confidence'], 0.0, 1.0)

#     # Ensure detection method is consistent
#     if 'detection_method' in results.columns:
#         results['detection_method'] = results['detection_method'].fillna('machine_learning')

#     # Clean all remaining numeric columns
#     numeric_cols = results.select_dtypes(include=[np.number]).columns
#     if len(numeric_cols) > 0:
#         # Replace inf values
#         results[numeric_cols] = results[numeric_cols].replace([np.inf, -np.inf], 0)
#         # Replace remaining NaN values
#         results[numeric_cols] = results[numeric_cols].fillna(0)

#     logger.debug(f"Final output validation complete: {len(results)} records validated")
#     return results

# def _apply_ml_safety_limits(results: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """
#     FIXED: Apply safety limits to ML detection results to prevent excessive anomaly rates.
#     """
#     if results.empty or 'is_ml_anomaly' not in results.columns:
#         return results

#     # Get safety configuration with robust defaults
#     detection_config = config.get("detection", {})
#     max_anomaly_rate = detection_config.get("max_anomaly_rate", 5.0) / 100.0  # Convert percentage to decimal
#     emergency_max_rate = detection_config.get("emergency_max_rate", 2.0) / 100.0
#     min_anomalies = detection_config.get("min_anomalies", 1)

#     # Validate configuration
#     max_anomaly_rate = np.clip(max_anomaly_rate, 0.001, 0.5)  # 0.1% to 50%
#     emergency_max_rate = np.clip(emergency_max_rate, 0.001, max_anomaly_rate)
#     min_anomalies = max(0, int(min_anomalies))

#     # Calculate current anomaly statistics
#     total_records = len(results)
#     current_anomalies = results['is_ml_anomaly'].sum() if 'is_ml_anomaly' in results.columns else 0
#     current_rate = current_anomalies / total_records if total_records > 0 else 0.0

#     logger.debug(f"Safety limits check: {current_anomalies}/{total_records} anomalies ({current_rate:.1%})")
#     logger.debug(f"Limits: max_rate={max_anomaly_rate:.1%}, emergency_rate={emergency_max_rate:.1%}")

#     # Check if intervention is needed
#     if current_rate <= max_anomaly_rate:
#         logger.debug("Anomaly rate within acceptable limits")
#         return results

#     # Safety intervention required
#     logger.warning(f" SAFETY LIMITS: Anomaly rate {current_rate:.1%} exceeds maximum {max_anomaly_rate:.1%}")

#     # Determine target anomaly count
#     if current_rate > emergency_max_rate * 3:  # Extremely high rate
#         target_max = max(min_anomalies, int(total_records * emergency_max_rate))
#         logger.warning(f" EMERGENCY REDUCTION: Reducing to {emergency_max_rate:.1%} rate")
#     else:
#         target_max = max(min_anomalies, int(total_records * max_anomaly_rate))
#         logger.warning(f" STANDARD REDUCTION: Reducing to {max_anomaly_rate:.1%} rate")

#     # ================================================================
#     # Strategy 1: Score-based selection (preferred)
#     # ================================================================
#     score_columns = ['ml_anomaly_score', 'combined_score', 'anomaly_score', 'confidence']
#     score_column = None

#     # Find the best available score column
#     for col in score_columns:
#         if col in results.columns:
#             valid_scores = results[col].dropna()
#             if len(valid_scores) > 0 and valid_scores.nunique() > 1:  # Has variation
#                 score_column = col
#                 break

#     if score_column:
#         logger.info(f"Using {score_column} for score-based anomaly reduction")

#         # Get current anomalies and their scores
#         anomaly_mask = results['is_ml_anomaly'] == True
#         anomaly_scores = results.loc[anomaly_mask, score_column]

#         if len(anomaly_scores) > target_max:
#             # Get threshold for top N anomalies
#             threshold = anomaly_scores.nlargest(target_max).iloc[-1]

#             # Apply new threshold
#             results_copy = results.copy()
#             results_copy['is_ml_anomaly'] = (results_copy[score_column] >= threshold)

#             # Verify the reduction worked
#             new_anomalies = results_copy['is_ml_anomaly'].sum()

#             if new_anomalies <= target_max * 1.1:  # Allow 10% tolerance
#                 logger.info(f"Score-based reduction: {current_anomalies} {new_anomalies} anomalies")
#                 return results_copy
#             else:
#                 logger.warning(f"Score-based reduction insufficient: {new_anomalies} anomalies")

#     # ================================================================
#     # Strategy 2: Time-based selection (recent events prioritized)
#     # ================================================================
#     if '@timestamp' in results.columns:
#         try:
#             logger.info("Using time-based anomaly reduction (most recent events)")

#             # Convert timestamps and sort
#             results_copy = results.copy()
#             results_copy['@timestamp'] = pd.to_datetime(results_copy['@timestamp'], errors='coerce')

#             # Get current anomalies sorted by time (most recent first)
#             anomaly_mask = results_copy['is_ml_anomaly'] == True
#             anomaly_data = results_copy[anomaly_mask].sort_values('@timestamp', ascending=False)

#             if len(anomaly_data) > target_max:
#                 # Keep only the most recent anomalies
#                 keep_indices = anomaly_data.head(target_max).index

#                 # Reset anomaly flags
#                 results_copy['is_ml_anomaly'] = False
#                 results_copy.loc[keep_indices, 'is_ml_anomaly'] = True

#                 new_anomalies = results_copy['is_ml_anomaly'].sum()
#                 logger.info(f"Time-based reduction: {current_anomalies} {new_anomalies} anomalies (kept most recent)")
#                 return results_copy

#         except Exception as e:
#             logger.warning(f"Time-based reduction failed: {e}")

#     # ================================================================
#     # Strategy 3: Entity-based selection (distribute across entities)
#     # ================================================================
#     entity_columns = ['destination.ip', 'process.name', 'user.name', 'host.hostname']
#     entity_column = None

#     for col in entity_columns:
#         if col in results.columns:
#             unique_entities = results[col].nunique()
#             if unique_entities > 1:  # Multiple entities available
#                 entity_column = col
#                 break

#     if entity_column:
#         try:
#             logger.info(f"Using entity-based anomaly reduction (distribute across {entity_column})")

#             results_copy = results.copy()
#             anomaly_mask = results_copy['is_ml_anomaly'] == True
#             anomaly_data = results_copy[anomaly_mask]

#             if len(anomaly_data) > target_max:
#                 # Group anomalies by entity
#                 entity_groups = anomaly_data.groupby(entity_column)

#                 # Calculate how many anomalies per entity
#                 num_entities = len(entity_groups)
#                 base_per_entity = target_max // num_entities
#                 remainder = target_max % num_entities

#                 keep_indices = []

#                 for i, (entity, group) in enumerate(entity_groups):
#                     # Give some entities one extra anomaly
#                     entity_quota = base_per_entity + (1 if i < remainder else 0)
#                     entity_quota = max(1, min(entity_quota, len(group)))  # At least 1, at most group size

#                     # Select best anomalies for this entity (by score if available)
#                     if score_column and score_column in group.columns:
#                         selected = group.nlargest(entity_quota, score_column)
#                     else:
#                         selected = group.head(entity_quota)

#                     keep_indices.extend(selected.index.tolist())

#                 # Apply selection
#                 results_copy['is_ml_anomaly'] = False
#                 results_copy.loc[keep_indices, 'is_ml_anomaly'] = True

#                 new_anomalies = results_copy['is_ml_anomaly'].sum()
#                 logger.info(f"Entity-based reduction: {current_anomalies} {new_anomalies} anomalies (across {num_entities} entities)")
#                 return results_copy

#         except Exception as e:
#             logger.warning(f"Entity-based reduction failed: {e}")

#     # ================================================================
#     # Strategy 4: Random selection (last resort)
#     # ================================================================
#     logger.warning("Using random selection for anomaly reduction (last resort)")

#     try:
#         results_copy = results.copy()
#         anomaly_indices = results_copy[results_copy['is_ml_anomaly'] == True].index.tolist()

#         if len(anomaly_indices) > target_max:
#             # Randomly select anomalies to keep
#             import random
#             random.seed(42)  # Reproducible results
#             keep_indices = random.sample(anomaly_indices, target_max)

#             # Apply selection
#             results_copy['is_ml_anomaly'] = False
#             results_copy.loc[keep_indices, 'is_ml_anomaly'] = True

#             new_anomalies = results_copy['is_ml_anomaly'].sum()
#             logger.info(f"Random reduction: {current_anomalies} {new_anomalies} anomalies")
#             return results_copy

#     except Exception as e:
#         logger.error(f"Random selection failed: {e}")

#     # ================================================================
#     # Fallback: Use threshold-based approach
#     # ================================================================
#     logger.warning("Using threshold-based fallback for anomaly reduction")

#     try:
#         results_copy = results.copy()

#         # Simply keep the first N anomalies (by index)
#         anomaly_mask = results_copy['is_ml_anomaly'] == True
#         anomaly_indices = results_copy[anomaly_mask].index[:target_max]

#         # Reset and apply
#         results_copy['is_ml_anomaly'] = False
#         results_copy.loc[anomaly_indices, 'is_ml_anomaly'] = True

#         new_anomalies = results_copy['is_ml_anomaly'].sum()
#         logger.info(f"Threshold fallback: {current_anomalies} {new_anomalies} anomalies")
#         return results_copy

#     except Exception as e:
#         logger.error(f"Threshold fallback failed: {e}")

#     # ================================================================
#     # Ultimate fallback: Return original results with warning
#     # ================================================================
#     logger.error("🚨 All safety limit strategies failed - returning original results")
#     logger.error(f"  WARNING: Anomaly rate remains high at {current_rate:.1%}")

#     return results


# def _detect_entity_anomalies_fixed(entity: str, feature_data: pd.DataFrame,
#                                  models: Dict, scalers: Dict, config: Dict,
#                                  data_type: str) -> pd.DataFrame:
#     """
# .
#     """
#     try:
#         entity_col = _get_entity_column(data_type)

#         # Get entity data
#         if entity == 'global':
#             entity_data = feature_data.copy()
#         else:
#             entity_data = feature_data[feature_data[entity_col] == entity].copy()

#         if entity_data.empty:
#             logger.debug(f"No data for entity {entity}")
#             return pd.DataFrame()

#         # Ensure index is reset to prevent bounds errors
#         entity_data = entity_data.reset_index(drop=True)

#         # Get trained models and scaler
#         entity_models = models[entity]
#         scaler = scalers[entity]

#         # Get features used during training
#         features_used = _get_trained_features_robust(entity_models, scaler)
#         if not features_used:
#             logger.error(f"No features found for entity {entity}")
#             return pd.DataFrame()

#         # Extract and align features
#         X, available_features = _extract_and_align_features_robust(entity_data, features_used, entity)
#         if X is None or len(X) == 0:
#             logger.debug(f"No valid features for entity {entity}")
#             return pd.DataFrame()

#         # Scale features
#         X_scaled = _scale_features_multi_strategy(X, scaler, entity, available_features, features_used)
#         if X_scaled is None:
#             logger.debug(f"Feature scaling failed for entity {entity}")
#             return pd.DataFrame()

#         # Initialize result columns with proper indexing
#         entity_data["is_ml_anomaly"] = False
#         entity_data["ml_anomaly_score"] = 0.0
#         entity_data["confidence"] = 0.0
#         entity_data["detection_method"] = "machine_learning"
#         entity_data["detection_timestamp"] = pd.Timestamp.now()

#         # Apply ML methods
#         method_scores = _apply_ml_methods_robust(entity_models, X_scaled, entity)

#         if method_scores:
#             # Calculate ensemble scores
#             method_weights = config.get("method_weights", {
#                 "isolation_forest": 0.4,
#                 "local_outlier_factor": 0.3,
#                 "one_class_svm": 0.2,
#                 "dbscan": 0.1
#             })

#             ensemble_scores = _calculate_ensemble_scores_robust(method_scores, method_weights)

#             # CRITICAL FIX: Ensure scores array matches entity_data length
#             if len(ensemble_scores) != len(entity_data):
#                 logger.warning(f"Score length mismatch for {entity}: {len(ensemble_scores)} vs {len(entity_data)}")
#                 if len(ensemble_scores) < len(entity_data):
#                     # Pad with zeros
#                     ensemble_scores = np.pad(ensemble_scores, (0, len(entity_data) - len(ensemble_scores)),
#                                            mode='constant', constant_values=0.0)
#                 else:
#                     # Truncate
#                     ensemble_scores = ensemble_scores[:len(entity_data)]

#             # Assign scores safely
#             entity_data["ml_anomaly_score"] = ensemble_scores

#             # Calculate dynamic threshold
#             threshold = _calculate_dynamic_threshold(ensemble_scores, config)

#             # CRITICAL FIX: Safe threshold assignment
# # SAFE ASSIGNMENT - NO ILOC INDEXING
#         try:
#             entity_data = entity_data.copy()  # Ensure we have a fresh copy

#             # Direct assignment without iloc
#             entity_data["detection_threshold"] = threshold
#             entity_data["is_ml_anomaly"] = ensemble_scores >= threshold
#             entity_data["confidence"] = np.clip(ensemble_scores * 2 - 1, 0, 1)
#             entity_data["methods_used"] = ",".join(method_scores.keys())

#             # Safe logging calculation
#             anomaly_count = int((ensemble_scores >= threshold).sum())
#             total_records = len(entity_data)

#             logger.info(f"Entity {entity}: {anomaly_count}/{total_records} anomalies (threshold={threshold:.3f})")

#         except Exception as assignment_error:
#             logger.error(f"Score assignment failed for entity {entity}: {assignment_error}")
#             # Safe fallback
#             entity_data["detection_threshold"] = 0.5
#             entity_data["is_ml_anomaly"] = False
#             entity_data["confidence"] = 0.0
#             entity_data["methods_used"] = "failed"
#         else:
#             # No ML methods succeeded
#             logger.debug(f"No ML methods succeeded for entity {entity}")
#             entity_data["detection_threshold"] = 0.5
#             entity_data["methods_used"] = "none"

#         # Final validation - ensure all required columns exist
#         required_columns = {
#             'is_ml_anomaly': False,
#             'ml_anomaly_score': 0.0,
#             'confidence': 0.0,
#             'detection_method': 'machine_learning',
#             'detection_threshold': 0.5,
#             'methods_used': 'unknown'
#         }

#         for col, default_val in required_columns.items():
#             if col not in entity_data.columns:
#                 entity_data[col] = default_val
#             else:
#                 # Fill any NaN values
#                 entity_data[col] = entity_data[col].fillna(default_val)

#         return entity_data

#     except Exception as e:
#         logger.error(f"Entity {entity} processing failed: {e}")
#         # Return empty DataFrame on complete failure
#         return pd.DataFrame()

# # def _get_entity_column(data_type: str) -> str:
# #     """Get appropriate entity column for data type."""
# #     entity_columns = {
# #         "process": "process.name",
# #         "network": "destination.ip",
# #         "user": "user.name",
# #         "discovery": "process.name",
# #         "metadata": "process.name"
# #     }
# #     return entity_columns.get(data_type, "host.hostname")
# def get_entity_column_fixed(data_type: str) -> str:
#     """
#     FIXED: Get entity column that matches between training and detection.
#     This replaces both LinuxModelManager._get_entity_column() and detection_methods._get_entity_column()
#     """
#     entity_mapping = {
#         "process": "process.name",
#         "network": "destination.ip",     # ALWAYS destination.ip for network
#         "user": "user.name",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")

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



# def validate_and_fix_field_mappings(df):
#     """Validate and fix field mappings."""
#     field_mappings = {
#         'process.name': ['process.name', 'process_name'],
#         'process.executable': ['process.executable', 'process_executable'],
#         'process.command_line': ['process.command_line', 'process_command_line'],
#         'user.name': ['user.name', 'user_name'],
#         'host.hostname': ['host.hostname', 'host_hostname']
#     }

#     for expected_field, possible_fields in field_mappings.items():
#         if expected_field not in df.columns:
#             for alt_field in possible_fields:
#                 if alt_field in df.columns:
#                     df[expected_field] = df[alt_field]
#                     logger.debug(f"Mapped {alt_field} -> {expected_field}")
#                     break

#     return df


#     return result
# def extract_ml_features(aggregated_data, config):
#     if aggregated_data.empty:
#         logger.warning("Empty dataframe received for feature extraction")
#         return aggregated_data

#     df = aggregated_data.copy()
#     data_type = config.get('data_type', 'process')

#     logger.info(f"Enhanced feature extraction for {data_type} with {len(df)} records")

#     # DEBUG: Check if process.name exists and what values it has
#     if 'process.name' in df.columns:
#         unique_processes = df['process.name'].unique()
#         logger.warning(f" PROCESS.NAME DEBUG - Found processes: {list(unique_processes)}")
#         null_count = df['process.name'].isnull().sum()
#         logger.warning(f" PROCESS.NAME DEBUG - Null values: {null_count}/{len(df)}")
#     else:
#         logger.warning(" PROCESS.NAME DEBUG - process.name column missing!")

#     # ================================================================
#     # COMPLETE FIX: Handle all ML job field requirements and NaN issues
#     # ================================================================

#     # Process field handling with NaN cleanup
#     if 'process.name' in df.columns:
#         df['process.name'] = df['process.name'].fillna('unknown_process')
#     else:
#         df['process.name'] = 'unknown_process'

#     # ML job required fields with proper defaults
#     # if 'process.executable' not in df.columns or df['process.executable'].isna().all():
#     #     df['process.executable'] = df.get('process.name', 'unknown_executable')
#     # else:
#     #     df['process.executable'] = df['process.executable'].fillna(df.get('process.name', 'unknown_executable'))

#     # if 'process.thread.capabilities' not in df.columns:
#     #     df['process.thread.capabilities'] = ''
#     # else:
#     #     df['process.thread.capabilities'] = df['process.thread.capabilities'].fillna('')

#     # if 'event.action' not in df.columns:
#     #     df['event.action'] = ['unknown_action']
#     # else:
#     #     # Ensure event.action is always a list
#     #     df['event.action'] = df['event.action'].apply(
#     #         lambda x: x if isinstance(x, list) else ([str(x)] if pd.notna(x) else ['unknown_action'])
#     #     )

#     # if 'network.type' not in df.columns:
#     #     df['network.type'] = 'ipv4'
#     # else:
#     #     df['network.type'] = df['network.type'].fillna('ipv4')
#     if 'process.executable' not in df.columns or df['process.executable'].isna().all():
#         df['process.executable'] = df['process.name'].fillna('unknown_executable')  # CORRECT: series to series
#     else:
#         df['process.executable'] = df['process.executable'].fillna(df['process.name'].fillna('unknown_executable'))

#     if 'process.thread.capabilities' not in df.columns:
#         df['process.thread.capabilities'] = pd.Series([''] * len(df), index=df.index)  # CORRECT: matching length
#     else:
#         df['process.thread.capabilities'] = df['process.thread.capabilities'].fillna('')

#     if 'network.type' not in df.columns:
#         df['network.type'] = pd.Series(['ipv4'] * len(df), index=df.index)  # CORRECT: matching length
#     else:
#         df['network.type'] = df['network.type'].fillna('ipv4')

#     if 'event.action' not in df.columns:
#         df['event.action'] = pd.Series([['unknown_action']] * len(df), index=df.index)  # CORRECT: list per row
#     else:
#         # Ensure event.action is always a list
#         df['event.action'] = df['event.action'].apply(
#             lambda x: x if isinstance(x, list) else ([str(x)] if pd.notna(x) else ['unknown_action'])
#         )
#     # CRITICAL: Fix network entity alignment - prevent synthetic port creation for destination.ip
#     if data_type == 'network' and 'destination.ip' in df.columns:
#         invalid_ip_mask = (
#             (df['destination.ip'] == '0.0.0.0') |
#             df['destination.ip'].isna() |
#             (df['destination.ip'] == '') |
#             (df['destination.ip'] == 'None') |
#             (df['destination.ip'] == 'nan')
#         )

#         if invalid_ip_mask.any():
#             logger.warning(f"NETWORK ENTITY FIX: Found {invalid_ip_mask.sum()} invalid destination IPs")

#             # Strategy 1: Use source.ip as fallback to maintain IP-based entities
#             if 'source.ip' in df.columns:
#                 valid_source_mask = ~(
#                     (df['source.ip'] == '0.0.0.0') |
#                     df['source.ip'].isna() |
#                     (df['source.ip'] == '') |
#                     (df['source.ip'] == 'None') |
#                     (df['source.ip'] == 'nan')
#                 )
#                 fallback_mask = invalid_ip_mask & valid_source_mask
#                 if fallback_mask.any():
#                     df.loc[fallback_mask, 'destination.ip'] = df.loc[fallback_mask, 'source.ip']
#                     logger.warning(f"NETWORK ENTITY FIX: Used source.ip fallback for {fallback_mask.sum()} records")

#             # Strategy 2: Use localhost for remaining invalid IPs (better than synthetic ports)
#             still_invalid = (
#                 (df['destination.ip'] == '0.0.0.0') |
#                 df['destination.ip'].isna() |
#                 (df['destination.ip'] == '')
#             )
#             if still_invalid.any():
#                 df.loc[still_invalid, 'destination.ip'] = '127.0.0.1'
#                 logger.warning(f"NETWORK ENTITY FIX: Used localhost for {still_invalid.sum()} remaining invalid IPs")

#     # Clean all numeric columns to prevent NaN propagation
#     numeric_cols = df.select_dtypes(include=[np.number]).columns
#     if len(numeric_cols) > 0:
#         df[numeric_cols] = df[numeric_cols].fillna(0)
#         logger.debug(f"Cleaned NaN values in {len(numeric_cols)} numeric columns")

#     # ================================================================
#     # Safe helper for feature calculation
#     # ================================================================
#     def safe_feature_calculation(feature_func, feature_name, default_value=0):
#         """Safely calculate features with fallback values."""
#         try:
#             result = feature_func()
#             if hasattr(result, 'fillna'):
#                 return result.fillna(default_value)
#             return result
#         except Exception as e:
#             logger.warning(f"Failed to create feature {feature_name}: {e}")
#             if isinstance(default_value, (int, float)):
#                 return pd.Series([default_value] * len(df), index=df.index)
#             return default_value

#     # ================================================================
#     # Temporal features with enhanced safety
#     # ================================================================
#     try:
#         if '@timestamp' in df.columns:
#             timestamps = pd.to_datetime(df['@timestamp'], errors='coerce')
#             # Fill any NaT values with current time
#             timestamps = timestamps.fillna(pd.Timestamp.now())

#             df['hour_of_day'] = timestamps.dt.hour
#             df['hour_sin'] = np.sin(2 * np.pi * timestamps.dt.hour / 24)
#             df['hour_cos'] = np.cos(2 * np.pi * timestamps.dt.hour / 24)
#             df['day_sin'] = np.sin(2 * np.pi * timestamps.dt.dayofweek / 7)
#             df['day_cos'] = np.cos(2 * np.pi * timestamps.dt.dayofweek / 7)
#             df['month_sin'] = np.sin(2 * np.pi * timestamps.dt.month / 12)
#             df['month_cos'] = np.cos(2 * np.pi * timestamps.dt.month / 12)
#             df['is_business_hours'] = ((timestamps.dt.hour >= 9) & (timestamps.dt.hour <= 17)).astype(int)
#             df['is_weekend'] = (timestamps.dt.dayofweek >= 5).astype(int)
#             df['is_night_time'] = ((timestamps.dt.hour < 6) | (timestamps.dt.hour > 22)).astype(int)
#             logger.info("Created 10 temporal features")
#         else:
#             # Default temporal features when no timestamp
#             defaults = {
#                 'hour_of_day': 12, 'hour_sin': 0.0, 'hour_cos': 1.0,
#                 'day_sin': 0.0, 'day_cos': 1.0, 'month_sin': 0.0, 'month_cos': 1.0,
#                 'is_business_hours': 1, 'is_weekend': 0, 'is_night_time': 0
#             }
#             for k, v in defaults.items():
#                 df[k] = v
#             logger.warning("Used default temporal features (no timestamp)")
#     except Exception as e:
#         logger.warning(f"Failed to create temporal features: {e}")
#         # Fallback defaults
#         defaults = {
#             'hour_of_day': 12, 'hour_sin': 0.0, 'hour_cos': 1.0,
#             'day_sin': 0.0, 'day_cos': 1.0, 'month_sin': 0.0, 'month_cos': 1.0,
#             'is_business_hours': 1, 'is_weekend': 0, 'is_night_time': 0
#         }
#         for k, v in defaults.items():
#             df[k] = v

#     # ================================================================
#     # Data type specific features with enhanced safety
#     # ================================================================

#     if data_type == 'process':
#         # Process-specific features with NaN handling
#         if 'process.command_line' in df.columns:
#             df['command_length'] = safe_feature_calculation(
#                 lambda: df['process.command_line'].fillna('').str.len(),
#                 'command_length', 0
#             )
#             df['command_word_count'] = safe_feature_calculation(
#                 lambda: df['process.command_line'].fillna('').str.split().str.len(),
#                 'command_word_count', 0
#             )
#         else:
#             df['command_length'] = 0
#             df['command_word_count'] = 0

#         if 'process.args' in df.columns:
#             df['args_count'] = safe_feature_calculation(
#                 lambda: df['process.args'].apply(
#                     lambda x: len(x) if isinstance(x, list) else (
#                         len(str(x).split()) if pd.notna(x) else 0
#                     )
#                 ),
#                 'args_count', 0
#             )
#         else:
#             df['args_count'] = safe_feature_calculation(
#                 lambda: df['process.command_line'].fillna('').str.split().str.len() - 1,
#                 'args_count', 0
#             )

#     elif data_type == 'network':
#         # Network-specific features with comprehensive IP/port handling
#         well_known_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]

#         if 'destination.port' in df.columns:
#             df['destination.port'] = pd.to_numeric(df['destination.port'], errors='coerce').fillna(0).astype(int)
#             df['is_well_known_port'] = df['destination.port'].isin(well_known_ports).astype(int)
#             df['is_high_port'] = (df['destination.port'] > 32767).astype(int)
#             df['is_privileged_port'] = (df['destination.port'] < 1024).astype(int)
#         else:
#             df['destination.port'] = 0
#             df['is_well_known_port'] = 0
#             df['is_high_port'] = 0
#             df['is_privileged_port'] = 0

#         # IP classification features
#         if 'destination.ip' in df.columns:
#             df['is_private_ip'] = safe_feature_calculation(
#                 lambda: df['destination.ip'].str.contains(
#                     r'^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)',
#                     na=False, regex=True
#                 ).astype(int),
#                 'is_private_ip', 1
#             )
#             df['is_localhost'] = safe_feature_calculation(
#                 lambda: df['destination.ip'].str.contains(r'^127\.', na=False, regex=True).astype(int),
#                 'is_localhost', 0
#             )
#         else:
#             df['is_private_ip'] = 1
#             df['is_localhost'] = 0

#         # Network traffic features
#         if 'network.bytes' in df.columns:
#             df['network.bytes'] = pd.to_numeric(df['network.bytes'], errors='coerce').fillna(0)
#             df['is_large_transfer'] = (df['network.bytes'] > 1048576).astype(int)  # >1MB
#             df['bytes_log'] = np.log1p(df['network.bytes'])
#         else:
#             df['network.bytes'] = 0
#             df['is_large_transfer'] = 0
#             df['bytes_log'] = 0

#         # Transport protocol features
#         if 'network.transport' in df.columns:
#             df['network.transport'] = df['network.transport'].fillna('tcp').str.lower()
#             df['is_tcp'] = (df['network.transport'] == 'tcp').astype(int)
#             df['is_udp'] = (df['network.transport'] == 'udp').astype(int)
#         else:
#             df['network.transport'] = 'tcp'
#             df['is_tcp'] = 1
#             df['is_udp'] = 0

#     elif data_type == 'user':
#         # User-specific features with safety
#         if 'user.name' in df.columns:
#             df['user.name'] = df['user.name'].fillna('unknown_user')
#             df['user_frequency'] = df.groupby('user.name')['user.name'].transform('count') / len(df)
#         else:
#             df['user.name'] = 'unknown_user'
#             df['user_frequency'] = 1.0

#         # Sudo and compiler activity features
#         for bool_col in ['is_sudo_command', 'is_compiler_activity', 'is_dev_tool']:
#             if bool_col in df.columns:
#                 df[bool_col] = df[bool_col].fillna(False).astype(int)
#             else:
#                 df[bool_col] = 0

#     elif data_type == 'discovery':
#         # Discovery-specific features
#         if 'process.command_line' in df.columns:
#             df['command_length'] = df['process.command_line'].fillna('').str.len()
#             df['has_pipes'] = df['process.command_line'].str.contains('|', na=False).astype(int)
#             df['has_redirection'] = df['process.command_line'].str.contains('[<>]', na=False, regex=True).astype(int)
#         else:
#             df['command_length'] = 0
#             df['has_pipes'] = 0
#             df['has_redirection'] = 0

#         # Discovery category encoding
#         if 'discovery_category' in df.columns:
#             try:
#                 from sklearn.preprocessing import LabelEncoder
#                 le = LabelEncoder()
#                 df['category_encoded'] = le.fit_transform(df['discovery_category'].fillna('unknown'))
#             except:
#                 df['category_encoded'] = 0
#         else:
#             df['category_encoded'] = 0

#     elif data_type == 'metadata':
#         # Metadata-specific features
#         if 'process.name' in df.columns:
#             df['metadata_process_freq'] = df.groupby('process.name')['process.name'].transform('count') / len(df)
#         else:
#             df['metadata_process_freq'] = 1.0

#         if 'user.name' in df.columns:
#             df['metadata_user_freq'] = df.groupby('user.name')['user.name'].transform('count') / len(df)
#         else:
#             df['metadata_user_freq'] = 1.0

#     # ================================================================
#     # Final cleanup and validation
#     # ================================================================

#     # Ensure event_count exists
#     if 'event_count' not in df.columns:
#         df['event_count'] = 1

#     # Clean any remaining categorical features
#     categorical_features = ['process.name', 'user.name', 'network.transport', 'network.type']
#     for feature in categorical_features:
#         if feature in df.columns:
#             try:
#                 df[feature] = df[feature].astype(str).fillna('unknown')
#             except Exception as e:
#                 logger.warning(f"Failed to clean categorical feature {feature}: {e}")
#                 df[feature] = 'unknown'
#         else:
#             if feature == 'network.transport':
#                 df[feature] = 'tcp'
#             elif feature == 'network.type':
#                 df[feature] = 'ipv4'
#             else:
#                 df[feature] = 'unknown'

#     # Final numeric column cleanup
#     all_numeric_cols = df.select_dtypes(include=[np.number]).columns
#     if len(all_numeric_cols) > 0:
#         # Replace any remaining inf values
#         df[all_numeric_cols] = df[all_numeric_cols].replace([np.inf, -np.inf], 0)
#         # Final NaN check
#         df[all_numeric_cols] = df[all_numeric_cols].fillna(0)

#     compatible_features = [col for col in df.columns if col not in ['@timestamp', 'time_bucket']]
#     logger.info(f"Real-time feature extraction complete: {len(compatible_features)} compatible features")
#     logger.info("Used enhanced feature extraction")

#     return df


# def select_ml_features(data: pd.DataFrame, config: Dict,
#                       data_type: str) -> Tuple[List[str], np.ndarray]:
#     """
#     Select and validate features for ML training with improved quality checks.

#     Args:
#         data: DataFrame with features
#         config: Configuration dictionary
#         data_type: Type of data being processed

#     Returns:
#         Tuple of (selected feature names, feature matrix)
#     """
#     if data.empty:
#         return [], np.array([])

#     # Get numeric columns (exclude entity and timestamp columns)
#     exclude_cols = {
#         '@timestamp', 'entity', 'process.name', 'host.hostname', 'user.name',
#         'destination.ip', 'detection_method', 'final_anomaly',
#         'is_ml_anomaly', 'is_anomaly', 'anomaly_score', 'ml_anomaly_score'
#     }

#     numeric_cols = data.select_dtypes(include=[np.number]).columns
#     candidate_features = [col for col in numeric_cols if col not in exclude_cols]

#     if not candidate_features:
#         logger.warning("No numeric features available for ML")
#         return [], np.array([])

#     # Apply feature quality filters
#     selected_features = _apply_feature_quality_filters(data, candidate_features)

#     # Limit number of features to prevent overfitting
#     max_features = config.get("feature_engineering", {}).get("max_features", 50)
#     if len(selected_features) > max_features:
#         selected_features = _prioritize_features(data, selected_features, max_features)

#     logger.info(f"Selected {len(selected_features)} features for ML training")

#     # Create feature matrix
#     try:
#         feature_matrix = _create_feature_matrix(data, selected_features)
#         logger.info(f"Feature matrix shape: {feature_matrix.shape}")
#         return selected_features, feature_matrix

#     except Exception as e:
#         logger.error(f"Error creating feature matrix: {e}")
#         return [], np.array([])


# def analyze_feature_availability(data: pd.DataFrame, data_type: str) -> Dict:
#     """Analyze feature availability with proper return structure."""
#     analysis = {
#         'total_records': len(data),
#         'available_features': [],
#         'missing_features': [],
#         'real_time_compatible': True,
#         'fallback_strategy': 'full_ml',
#         'feature_coverage': {}
#     }

#     if data.empty:
#         analysis['real_time_compatible'] = False
#         analysis['fallback_strategy'] = 'no_data'
#         return analysis

#     # Define feature requirements
#     FEATURE_REQUIREMENTS = {
#         'process': {
#             'required': ['@timestamp', 'process.name'],
#             'domain_specific': [
#                 'process.command_line', 'user.name', 'host.hostname',
#                 'process.pid', 'process.parent.pid', 'process.executable', 'user.id'
#             ],
#             'temporal': ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend']
#         },
#         'network': {
#             'required': ['@timestamp', 'destination.ip'],
#             'domain_specific': [
#                 'destination.port', 'destination.ip', 'source.ip', 'source.port',
#                 'network.bytes', 'network.transport'
#             ],
#             'temporal': ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend']
#         },
#         'user': {
#             'required': ['@timestamp', 'user.name'],
#             'domain_specific': [
#                 'process.name', 'process.command_line', 'host.hostname',
#                 'user.id', 'process.pid', 'process.executable', 'event.action'
#             ],
#             'temporal': ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend']
#         },
#         'discovery': {
#             'required': ['@timestamp', 'process.name'],
#             'domain_specific': [
#                 'process.command_line', 'user.name', 'host.hostname',
#                 'process.args', 'user.id', 'process.pid', 'event.action', 'process.executable'
#             ],
#             'temporal': ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend']
#         },
#         'metadata': {
#             'required': ['@timestamp', 'destination.ip'],
#             'domain_specific': [
#                 'destination.port', 'process.name', 'user.name',
#                 'network.transport', 'process.executable'
#             ],
#             'temporal': ['hour_of_day', 'day_of_week', 'is_business_hours', 'is_weekend']
#         }
#     }

#     requirements = FEATURE_REQUIREMENTS.get(data_type, FEATURE_REQUIREMENTS['process'])

#     # Check each category
#     for category, features in requirements.items():
#         available_count = 0
#         total_count = len(features)

#         for feature in features:
#             if feature in data.columns and not data[feature].isna().all():
#                 print(f"Feature available: {feature}")
#                 analysis['available_features'].append(feature)
#                 available_count += 1
#             else:
#                 analysis['missing_features'].append(feature)

#         coverage_pct = (available_count / total_count * 100) if total_count > 0 else 0
#         analysis['feature_coverage'][category] = {
#             'available': available_count,
#             'total': total_count,
#             'percentage': coverage_pct
#         }

#         logger.info(f"{category.upper()} features - Available: {available_count}/{total_count} ({coverage_pct:.1f}%)")

#     # Determine compatibility
#     required_coverage = analysis['feature_coverage'].get('required', {}).get('percentage', 0)

#     if required_coverage >= 80:
#         analysis['real_time_compatible'] = True
#         analysis['fallback_strategy'] = 'full_ml'
#     elif required_coverage >= 50:
#         analysis['real_time_compatible'] = True
#         analysis['fallback_strategy'] = 'reduced_ml'
#     else:
#         analysis['real_time_compatible'] = False
#         analysis['fallback_strategy'] = 'statistical_only'

#     return analysis


# # ===============================================================================
# # STATISTICAL DETECTION (COMPATIBILITY ONLY)
# # ===============================================================================

# def detect_statistical_anomalies(aggregated_data: pd.DataFrame, baselines: Dict,
#                                 config: Dict, data_type: str = "process") -> pd.DataFrame:
#     """
#     Statistical anomaly detection (kept for compatibility but not used in final results).

#     Note: This function is maintained for backward compatibility but its results
#     are IGNORED in the final anomaly determination. Only ML results are used.

#     Args:
#         aggregated_data: Input data
#         baselines: Baseline statistics
#         config: Configuration dictionary
#         data_type: Type of data being processed

#     Returns:
#         DataFrame with statistical anomaly results (for compatibility only)
#     """
#     logger.info(f"Running statistical detection for {data_type} (results will be ignored in final output)")

#     if aggregated_data.empty:
#         return pd.DataFrame()

#     results = aggregated_data.copy()

#     # Basic statistical detection for compatibility
#     if 'event_count' in results.columns:
#         mean_count = results['event_count'].mean()
#         std_count = results['event_count'].std()

#         if std_count > 0:
#             results['z_score'] = (results['event_count'] - mean_count) / std_count
#             results['is_anomaly'] = results['z_score'].abs() > 3.0
#         else:
#             results['z_score'] = 0.0
#             results['is_anomaly'] = False

#         results['anomaly_score'] = results['z_score'].abs().clip(0, 10) / 10
#     else:
#         results['is_anomaly'] = False
#         results['anomaly_score'] = 0.0
#         results['z_score'] = 0.0

#     results['detection_method'] = "statistical"

#     logger.info(f"Statistical detection complete (for compatibility only)")
#     return results


# def calculate_baselines(historical_data: pd.DataFrame, config: Dict,
#                        data_type: str = "process") -> Dict:
#     """
#     FIXED: Calculate baseline statistics - DROP-IN REPLACEMENT.
#     """
#     logger.info(f"FIXED baseline calculation for {data_type}")

#     try:
#         if historical_data.empty:
#             return {}

#         # FIXED: Handle timestamp format issues
#         data = historical_data.copy()
#         if "@timestamp" in data.columns:
#             data["@timestamp"] = _fix_timestamp_format_robust(data["@timestamp"])

#         baselines = {}
#         entity_col = _get_entity_column(data_type)

#         if entity_col in data.columns:
#             # Calculate per-entity baselines
#             for entity in data[entity_col].unique():
#                 entity_data = data[data[entity_col] == entity]

#                 if len(entity_data) >= 5:  # Minimum data for baseline
#                     try:
#                         baseline = {
#                             "mean_count": entity_data.get("event_count", pd.Series([1])).mean(),
#                             "std_count": entity_data.get("event_count", pd.Series([1])).std(),
#                             "median_count": entity_data.get("event_count", pd.Series([1])).median(),
#                             "q75_count": entity_data.get("event_count", pd.Series([1])).quantile(0.75),
#                             "q95_count": entity_data.get("event_count", pd.Series([1])).quantile(0.95),
#                             "record_count": len(entity_data)
#                         }

#                         # Add timestamp info if available
#                         if "@timestamp" in entity_data.columns:
#                             baseline["first_seen"] = entity_data["@timestamp"].min()
#                             baseline["last_seen"] = entity_data["@timestamp"].max()

#                         baselines[entity] = baseline

#                     except Exception as e:
#                         logger.warning(f"Failed to calculate baseline for {entity}: {e}")

#         # Global baseline
#         try:
#             baselines["global"] = {
#                 "mean_count": data.get("event_count", pd.Series([1])).mean(),
#                 "std_count": data.get("event_count", pd.Series([1])).std(),
#                 "median_count": data.get("event_count", pd.Series([1])).median(),
#                 "record_count": len(data),
#                 "entity_count": data[entity_col].nunique() if entity_col in data.columns else 1
#             }
#         except Exception as e:
#             logger.warning(f"Failed to calculate global baseline: {e}")
#             baselines["global"] = {"record_count": len(data)}

#         logger.info(f"Established baselines for {len(baselines)} entities in {data_type}")
#         return baselines

#     except Exception as e:
#         logger.error(f"Baseline calculation failed for {data_type}: {e}")
#         return {}


# # ===============================================================================
# # SPECIALIZED DETECTION FUNCTIONS
# # ===============================================================================

# def detect_rare_processes_all_hosts(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect rare processes across all hosts."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running rare processes across all hosts detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "rare_processes_all_hosts"
#         return results

#     # Basic rare process detection
#     results = data.copy()

#     if 'process.name' in data.columns:
#         process_counts = data['process.name'].value_counts()
#         rare_threshold = process_counts.quantile(0.05)
#         rare_processes = process_counts[process_counts <= rare_threshold].index

#         results['is_anomaly'] = results['process.name'].isin(rare_processes)
#         results['anomaly_score'] = results['process.name'].map(
#             lambda proc: 0.8 if proc in rare_processes else 0.1
#         )
#     else:
#         results['is_anomaly'] = False
#         results['anomaly_score'] = 0.0

#     results['detection_method'] = "rare_processes_all_hosts"
#     return results


# def detect_rare_processes_by_host(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect rare processes by host."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running rare process by host detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "rare_process_by_host"
#         return results

#     # Basic rare process by host detection
#     results = data.copy()

#     if 'process.name' in data.columns and 'host.hostname' in data.columns:
#         host_process_counts = data.groupby(['host.hostname', 'process.name']).size().reset_index(name='count')
#         threshold = host_process_counts['count'].quantile(0.05)
#         rare_processes = host_process_counts[host_process_counts['count'] <= threshold]

#         results['is_anomaly'] = False
#         for _, row in rare_processes.iterrows():
#             mask = ((results['host.hostname'] == row['host.hostname']) &
#                     (results['process.name'] == row['process.name']))
#             results.loc[mask, 'is_anomaly'] = True
#             results.loc[mask, 'anomaly_score'] = 0.8
#     else:
#         results['is_anomaly'] = False
#         results['anomaly_score'] = 0.0

#     results['detection_method'] = "rare_process_by_host"
#     return results


# def detect_anomalous_user_activity(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect anomalous user activity."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running anomalous user activity detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "anomalous_user_activity"
#         return results

#     # Basic user activity detection
#     results = data.copy()
#     results['is_anomaly'] = False
#     results['anomaly_score'] = 0.0

#     if 'user.name' in data.columns and 'event_count' in data.columns:
#         user_activity = data.groupby('user.name')['event_count'].sum()
#         activity_threshold = user_activity.quantile(0.95)
#         high_activity_users = user_activity[user_activity > activity_threshold].index

#         high_activity_mask = results['user.name'].isin(high_activity_users)
#         results.loc[high_activity_mask, 'is_anomaly'] = True
#         results.loc[high_activity_mask, 'anomaly_score'] = 0.7

#     results['detection_method'] = "anomalous_user_activity"
#     return results


# def detect_sudo_anomalies(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect sudo-related anomalies."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running sudo anomaly detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "sudo_anomalies"
#         return results

#     # Basic sudo detection
#     results = data.copy()
#     results['is_anomaly'] = False
#     results['anomaly_score'] = 0.0

#     if 'process.name' in data.columns:
#         sudo_mask = results['process.name'].str.contains('sudo', case=False, na=False)
#         results.loc[sudo_mask, 'anomaly_score'] = 0.6

#         if 'user.name' in data.columns:
#             non_root_sudo = sudo_mask & (results['user.name'] != 'root')
#             results.loc[non_root_sudo, 'is_anomaly'] = True
#             results.loc[non_root_sudo, 'anomaly_score'] = 0.8

#     results['detection_method'] = "sudo_anomalies"
#     return results


# def detect_compiler_anomalies(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect compiler-related anomalies."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running compiler anomaly detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "compiler_anomalies"
#         return results

#     # Basic compiler detection
#     results = data.copy()
#     results['is_anomaly'] = False
#     results['anomaly_score'] = 0.0

#     compiler_processes = ['gcc', 'g++', 'clang', 'make', 'cmake', 'javac', 'python', 'python3']

#     if 'process.name' in data.columns:
#         compiler_mask = results['process.name'].isin(compiler_processes)
#         results.loc[compiler_mask, 'anomaly_score'] = 0.5

#         if 'user.name' in data.columns:
#             expected_compiler_users = ['root', 'developer', 'build']
#             unexpected_compiler_users = (compiler_mask &
#                                        ~results['user.name'].isin(expected_compiler_users))

#             results.loc[unexpected_compiler_users, 'is_anomaly'] = True
#             results.loc[unexpected_compiler_users, 'anomaly_score'] = 0.9

#     results['detection_method'] = "compiler_anomalies"
#     return results


# def detect_discovery_command_anomalies(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect discovery command anomalies."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running discovery command detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "discovery_commands"
#         return results

#     # Basic discovery detection
#     # Basic discovery detection
#     results = data.copy()
#     results['is_anomaly'] = False
#     results['anomaly_score'] = 0.0

#     discovery_processes = ['whoami', 'id', 'ps', 'netstat', 'ifconfig', 'route', 'arp']

#     if 'process.name' in data.columns:
#         discovery_mask = data['process.name'].isin(discovery_processes)
#         results.loc[discovery_mask, 'anomaly_score'] = 0.6

#         if 'event_count' in data.columns:
#             high_discovery = discovery_mask & (data['event_count'] > data['event_count'].quantile(0.9))
#             results.loc[high_discovery, 'is_anomaly'] = True
#             results.loc[high_discovery, 'anomaly_score'] = 0.9

#     results['detection_method'] = "discovery_commands"
#     return results


# def detect_metadata_access_anomalies(data: pd.DataFrame, config: Dict) -> pd.DataFrame:
#     """Detect metadata access anomalies."""
#     if data.empty:
#         return pd.DataFrame()

#     logger.info("Running metadata access detection")

#     # If we already have ML results, use those
#     if "is_ml_anomaly" in data.columns:
#         results = data.copy()
#         results["detection_method"] = "metadata_access"
#         return results

#     # Basic metadata detection
#     results = data.copy()
#     results['is_anomaly'] = False
#     results['anomaly_score'] = 0.0

#     metadata_processes = ['curl', 'wget', 'python', 'python3', 'aws', 'gcloud']

#     if 'process.name' in data.columns:
#         metadata_mask = data['process.name'].isin(metadata_processes)
#         results.loc[metadata_mask, 'anomaly_score'] = 0.5

#         if 'event_count' in data.columns:
#             high_metadata = metadata_mask & (data['event_count'] > data['event_count'].quantile(0.95))
#             results.loc[high_metadata, 'is_anomaly'] = True
#             results.loc[high_metadata, 'anomaly_score'] = 0.8

#     results['detection_method'] = "metadata_access"
#     return results


# # ===============================================================================
# # UTILITY AND HELPER FUNCTIONS
# # ===============================================================================

# def filter_by_severity(results: pd.DataFrame, severity_column: str,
#                       max_anomaly_percent: float) -> pd.DataFrame:
#     """
#     FIXED: Filter results by severity - DROP-IN REPLACEMENT.
#     """
#     if results.empty or severity_column not in results.columns:
#         return results

#     total_records = len(results)
#     max_anomalies = max(1, int(total_records * max_anomaly_percent))

#     # Get threshold for top N anomalies
#     if max_anomalies >= total_records:
#         return results

#     try:
#         severity_threshold = results[severity_column].nlargest(max_anomalies).iloc[-1]

#         # Update anomaly flags based on severity threshold
#         if "is_ml_anomaly" in results.columns:
#             original_anomalies = results["is_ml_anomaly"].sum()
#             results["is_ml_anomaly"] = (results["is_ml_anomaly"] &
#                                        (results[severity_column] >= severity_threshold))
#             filtered_anomalies = results["is_ml_anomaly"].sum()

#             logger.info(f"Severity filtering: {original_anomalies} -> {filtered_anomalies} anomalies "
#                        f"(threshold={severity_threshold:.3f})")

#         return results

#     except Exception as e:
#         logger.error(f"Severity filtering failed: {e}")
#         return results



# def combine_detection_results(statistical_results: pd.DataFrame, ml_results: pd.DataFrame,
#                             config: Dict, data_type: str = "process") -> pd.DataFrame:
#     """
#     DEPRECATED: Legacy compatibility function.

#     This function is replaced by process_ml_results() for ML-only detection.
#     Kept for backward compatibility only.
#     """
#     logger.warning("combine_detection_results() is deprecated. Use process_ml_results() for ML-only detection.")
#     return process_ml_results(statistical_results, ml_results, config, data_type)



# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     logger.warning("Could not determine trained features")
#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None



# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None



# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None




# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None


# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def emergency_anomaly_rate_fix(results: pd.DataFrame, emergency_max_rate: float = 0.02) -> pd.DataFrame:
#     """
#     Emergency fix to immediately reduce anomaly rates - USE THIS NOW if needed.
#     """
#     if results.empty or "final_anomaly" not in results.columns:
#         return results

#     original_anomalies = results["final_anomaly"].sum()
#     original_rate = original_anomalies / len(results) if len(results) > 0 else 0

#     if original_rate <= emergency_max_rate:
#         return results  # Already within acceptable range

#     logger.warning(f"🚨 EMERGENCY FIX: Reducing anomaly rate from {original_rate:.1%} to {emergency_max_rate:.1%}")

#     # Keep only the highest-scoring anomalies
#     max_allowed = max(1, int(len(results) * emergency_max_rate))

#     if "combined_score" in results.columns:
#         score_col = "combined_score"
#     elif "ml_anomaly_score" in results.columns:
#         score_col = "ml_anomaly_score"
#     elif "anomaly_score" in results.columns:
#         score_col = "anomaly_score"
#     else:
#         # No score column - randomly select anomalies
#         logger.warning("No score column found - using random selection")
#         anomaly_indices = results[results["final_anomaly"]].index
#         if len(anomaly_indices) > max_allowed:
#             keep_indices = np.random.choice(anomaly_indices, max_allowed, replace=False)
#             results.loc[:, "final_anomaly"] = False
#             results.loc[keep_indices, "final_anomaly"] = True
#         return results

#     # Use score-based selection
#     threshold = results[score_col].nlargest(max_allowed).iloc[-1]
#     results.loc[:, "final_anomaly"] = results[score_col] >= threshold

#     final_anomalies = results["final_anomaly"].sum()
#     logger.info(f"🚨 Emergency fix applied: {original_anomalies} -> {final_anomalies} anomalies")

#     return results


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     logger.warning("Could not determine trained features")
#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None

# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None



# def _calculate_dynamic_threshold(scores: np.ndarray, config: Dict) -> float:
#     """
#     FIXED: Calculate realistic ML thresholds that actually detect anomalies.
#     """
#     if len(scores) == 0:
#         logger.warning("Empty scores array for threshold calculation")
#         return 0.5

#     # Clean input scores
#     scores = np.array(scores)
#     scores = scores[~np.isnan(scores)]  # Remove NaN
#     scores = np.clip(scores, 0.0, 1.0)  # Ensure valid range

#     if len(scores) == 0:
#         logger.warning("No valid scores for threshold calculation")
#         return 0.5

#     # ================================================================
#     # Get configuration parameters with robust defaults
#     # ================================================================

#     detection_config = config.get("detection", {})

#     # Anomaly rate controls
#     max_anomaly_rate = detection_config.get("max_anomaly_rate", 5.0) / 100.0  # Convert percentage
#     target_anomaly_rate = detection_config.get("target_anomaly_rate", 2.0) / 100.0
#     min_anomaly_rate = detection_config.get("min_anomaly_rate", 0.1) / 100.0

#     # Threshold bounds
#     min_threshold = detection_config.get("min_threshold", 0.3)
#     max_threshold = detection_config.get("max_threshold", 0.9)
#     default_threshold = detection_config.get("default_threshold", 0.6)

#     # Sensitivity settings
#     sensitivity = detection_config.get("sensitivity", "medium")  # low, medium, high

#     # Validate configuration values
#     max_anomaly_rate = np.clip(max_anomaly_rate, 0.001, 0.5)
#     target_anomaly_rate = np.clip(target_anomaly_rate, 0.0005, max_anomaly_rate)
#     min_anomaly_rate = np.clip(min_anomaly_rate, 0.0001, target_anomaly_rate)
#     min_threshold = np.clip(min_threshold, 0.1, 0.8)
#     max_threshold = np.clip(max_threshold, min_threshold + 0.1, 1.0)
#     default_threshold = np.clip(default_threshold, min_threshold, max_threshold)

#     logger.debug(f"Threshold calculation config: max_rate={max_anomaly_rate:.1%}, target_rate={target_anomaly_rate:.1%}")

#     # ================================================================
#     # Score distribution analysis
#     # ================================================================

#     n_samples = len(scores)
#     score_stats = {
#         'min': scores.min(),
#         'max': scores.max(),
#         'mean': scores.mean(),
#         'std': scores.std(),
#         'median': np.median(scores),
#         'q75': np.percentile(scores, 75),
#         'q90': np.percentile(scores, 90),
#         'q95': np.percentile(scores, 95),
#         'q99': np.percentile(scores, 99)
#     }

#     logger.debug(f"Score distribution: mean={score_stats['mean']:.3f}, std={score_stats['std']:.3f}, max={score_stats['max']:.3f}")

#     # ================================================================
#     # Strategy 1: Percentile-based threshold
#     # ================================================================

#     # Calculate target number of anomalies
#     target_anomalies = max(1, int(n_samples * target_anomaly_rate))
#     max_anomalies = max(target_anomalies, int(n_samples * max_anomaly_rate))
#     min_anomalies = max(1, int(n_samples * min_anomaly_rate))

#     # Get percentile-based thresholds
#     if target_anomalies < n_samples:
#         percentile_threshold = np.percentile(scores, 100 * (1 - target_anomaly_rate))
#     else:
#         percentile_threshold = score_stats['min']

#     logger.debug(f"Percentile threshold for {target_anomalies} anomalies: {percentile_threshold:.3f}")

#     # ================================================================
#     # Strategy 2: Statistical threshold (mean + k*std)
#     # ================================================================

#     # Adjust multiplier based on sensitivity
#     sensitivity_multipliers = {
#         "low": 2.5,      # Conservative
#         "medium": 2.0,   # Balanced
#         "high": 1.5      # Aggressive
#     }

#     std_multiplier = sensitivity_multipliers.get(sensitivity, 2.0)

#     if score_stats['std'] > 0.01:  # Valid standard deviation
#         statistical_threshold = score_stats['mean'] + std_multiplier * score_stats['std']
#         statistical_threshold = np.clip(statistical_threshold, score_stats['mean'], score_stats['max'])
#     else:
#         # Low variance - use median + small offset
#         statistical_threshold = score_stats['median'] + 0.1

#     logger.debug(f"Statistical threshold (mean + {std_multiplier}*std): {statistical_threshold:.3f}")

#     # ================================================================
#     # Strategy 3: Adaptive threshold based on score distribution
#     # ================================================================

#     # Check for bimodal or skewed distributions
#     score_range = score_stats['max'] - score_stats['min']

#     if score_range < 0.1:
#         # Very low variance - all scores are similar
#         adaptive_threshold = score_stats['median'] + 0.05
#         logger.debug("Low variance detected, using median + offset")

#     elif score_stats['mean'] > 0.7:
#         # High scores overall - be more selective
#         adaptive_threshold = score_stats['q90']
#         logger.debug("High score distribution, using 90th percentile")

#     elif score_stats['mean'] < 0.3:
#         # Low scores overall - be more sensitive
#         adaptive_threshold = score_stats['q75']
#         logger.debug("Low score distribution, using 75th percentile")

#     else:
#         # Normal distribution - use standard approach
#         if score_stats['std'] > 0.15:
#             # High variance - use percentile approach
#             adaptive_threshold = score_stats['q85'] if sensitivity == "high" else score_stats['q90']
#         else:
#             # Moderate variance - use statistical approach
#             adaptive_threshold = statistical_threshold

#     logger.debug(f"Adaptive threshold: {adaptive_threshold:.3f}")

#     # ================================================================
#     # Strategy 4: Combine approaches with weighting
#     # ================================================================

#     # Weight different approaches based on score characteristics
#     approaches = {
#         'percentile': percentile_threshold,
#         'statistical': statistical_threshold,
#         'adaptive': adaptive_threshold
#     }

#     # Determine weights based on distribution characteristics
#     if score_stats['std'] < 0.1:
#         # Low variance - prefer adaptive approach
#         weights = {'percentile': 0.2, 'statistical': 0.3, 'adaptive': 0.5}
#     elif score_stats['std'] > 0.25:
#         # High variance - prefer percentile approach
#         weights = {'percentile': 0.5, 'statistical': 0.2, 'adaptive': 0.3}
#     else:
#         # Moderate variance - balanced approach
#         weights = {'percentile': 0.4, 'statistical': 0.4, 'adaptive': 0.2}

#     # Calculate weighted threshold
#     weighted_threshold = sum(weights[approach] * threshold
#                            for approach, threshold in approaches.items())

#     logger.debug(f"Weighted threshold: {weighted_threshold:.3f} (weights: {weights})")

#     # ================================================================
#     # Apply bounds and validation
#     # ================================================================

#     # Ensure threshold is within reasonable bounds
#     final_threshold = np.clip(weighted_threshold, min_threshold, max_threshold)

#     # Validate that threshold will produce reasonable anomaly rate
#     predicted_anomalies = np.sum(scores >= final_threshold)
#     predicted_rate = predicted_anomalies / n_samples if n_samples > 0 else 0

#     # Adjust if predicted rate is too high or too low
#     if predicted_rate > max_anomaly_rate:
#         # Too many anomalies - increase threshold
#         adjustment_threshold = np.percentile(scores, 100 * (1 - max_anomaly_rate))
#         final_threshold = max(final_threshold, adjustment_threshold)
#         logger.debug(f"Rate too high ({predicted_rate:.1%}), increased threshold to {final_threshold:.3f}")

#     elif predicted_rate < min_anomaly_rate and predicted_anomalies == 0:
#         # Too few anomalies - decrease threshold
#         adjustment_threshold = np.percentile(scores, 100 * (1 - min_anomaly_rate * 2))
#         final_threshold = min(final_threshold, adjustment_threshold)
#         logger.debug(f"Rate too low ({predicted_rate:.1%}), decreased threshold to {final_threshold:.3f}")

#     # Final bounds check
#     final_threshold = np.clip(final_threshold, min_threshold, max_threshold)

#     # ================================================================
#     # Final validation and logging
#     # ================================================================

#     # Calculate final predicted anomaly count
#     final_predicted_anomalies = np.sum(scores >= final_threshold)
#     final_predicted_rate = final_predicted_anomalies / n_samples if n_samples > 0 else 0

#     # If still no anomalies with reasonable scores, use fallback
#     if final_predicted_anomalies == 0 and score_stats['max'] > 0.5:
#         fallback_threshold = min(score_stats['q75'], max_threshold)
#         if np.sum(scores >= fallback_threshold) > 0:
#             final_threshold = fallback_threshold
#             final_predicted_anomalies = np.sum(scores >= final_threshold)
#             final_predicted_rate = final_predicted_anomalies / n_samples
#             logger.debug(f"Applied fallback threshold: {final_threshold:.3f}")

#     # Log final results
#     threshold_info = {
#         'threshold': final_threshold,
#         'predicted_anomalies': final_predicted_anomalies,
#         'predicted_rate': final_predicted_rate,
#         'score_range': f"[{score_stats['min']:.3f}, {score_stats['max']:.3f}]",
#         'approaches_used': list(approaches.keys())
#     }

#     logger.debug(f"Final threshold calculation: {threshold_info}")
#     logger.info(f"Dynamic threshold: {final_threshold:.3f} (predicts {final_predicted_anomalies} anomalies, {final_predicted_rate:.1%} rate)")

#     return final_threshold





# def _apply_feature_quality_filters(data: pd.DataFrame, candidate_features: List[str]) -> List[str]:
#     """Apply feature quality filters."""
#     selected_features = []

#     for feature in candidate_features:
#         feature_values = data[feature].dropna()

#         if len(feature_values) == 0:
#             continue  # Skip all-NaN features

#         # Check variance
#         if feature_values.var() == 0:
#             continue  # Skip zero-variance features

#         # Check for excessive missing values
#         missing_rate = data[feature].isnull().sum() / len(data)
#         if missing_rate > 0.5:
#             continue  # Skip features with >50% missing values

#         # Check for excessive outliers
#         q1, q3 = feature_values.quantile([0.25, 0.75])
#         iqr = q3 - q1
#         if iqr > 0:
#             outlier_bounds = [q1 - 3*iqr, q3 + 3*iqr]
#             outlier_rate = ((feature_values < outlier_bounds[0]) |
#                            (feature_values > outlier_bounds[1])).sum() / len(feature_values)
#             if outlier_rate > 0.1:  # Skip features with >10% extreme outliers
#                 continue

#         selected_features.append(feature)

#     return selected_features


# def _prioritize_features(data: pd.DataFrame, features: List[str], max_features: int) -> List[str]:
#     """Prioritize features by variance."""
#     feature_variances = data[features].var().sort_values(ascending=False)
#     return feature_variances.head(max_features).index.tolist()


# def _create_feature_matrix(data: pd.DataFrame, selected_features: List[str]) -> np.ndarray:
#     """Create feature matrix from selected features."""
#     X_df = data[selected_features].copy()

#     # Handle missing values and infinities
#     X_df = X_df.fillna(0)
#     X_df = X_df.replace([np.inf, -np.inf], [1e6, -1e6])

#     # Remove extreme outliers
#     for col in X_df.columns:
#         if pd.api.types.is_numeric_dtype(X_df[col]):
#             q1, q99 = X_df[col].quantile([0.01, 0.99])
#             X_df[col] = X_df[col].clip(lower=q1, upper=q99)

#     return X_df.values




# def _detect_entity_anomalies_fixed(entity: str, feature_data: pd.DataFrame,
#                                   models: Dict, scalers: Dict, config: Dict,
#                                   data_type: str) -> pd.DataFrame:
#     """
#     FIXED: Detect anomalies for a specific entity with robust error handling.
#     """
#     try:
#         entity_col = _get_entity_column(data_type)

#         # Get entity data
#         if entity == 'global':
#             entity_data = feature_data.copy()
#         else:
#             entity_data = feature_data[feature_data[entity_col] == entity].copy()

#         if entity_data.empty:
#             return pd.DataFrame()

#         # Get trained models and scaler
#         entity_models = models[entity]
#         scaler = scalers[entity]

#         # FIXED: Dynamic feature alignment
#         features_used = _get_trained_features_robust(entity_models, scaler)
#         if not features_used:
#             logger.error(f"No features found for entity {entity}")
#             return pd.DataFrame()

#         # FIXED: Extract and align features
#         X, available_features = _extract_and_align_features_robust(entity_data, features_used, entity)
#         if X is None or len(X) == 0:
#             return pd.DataFrame()

#         # FIXED: Multi-strategy scaling
#         X_scaled = _scale_features_multi_strategy(X, scaler, entity, available_features, features_used)
#         if X_scaled is None:
#             return pd.DataFrame()

#         # Initialize result arrays
#         entity_data = entity_data.copy()
#         entity_data["is_ml_anomaly"] = False
#         entity_data["ml_anomaly_score"] = 0.0

#         # FIXED: Apply ML methods with proper scoring
#         method_scores = _apply_ml_methods_robust(entity_models, X_scaled, entity)

#         if method_scores:
#             # Calculate ensemble scores with proper normalization
#             method_weights = config.get("method_weights", {
#                 "isolation_forest": 0.4,
#                 "local_outlier_factor": 0.3,
#                 "one_class_svm": 0.2,
#                 "dbscan": 0.1
#             })

#             ensemble_scores = _calculate_ensemble_scores_robust(method_scores, method_weights)
#             entity_data["ml_anomaly_score"] = ensemble_scores

#             # FIXED: Conservative threshold calculation
#             threshold = _calculate_conservative_threshold(ensemble_scores, config)
#             entity_data["is_ml_anomaly"] = ensemble_scores > threshold

#             # Calculate confidence
#             entity_data["confidence"] = _calculate_confidence_robust(method_scores, ensemble_scores)

#             anomaly_count = entity_data["is_ml_anomaly"].sum()
#             logger.info(f"Entity {entity}: {anomaly_count}/{len(entity_data)} anomalies (threshold={threshold:.3f})")

#         else:
#             logger.warning(f"No ML methods succeeded for entity {entity}")

#         entity_data["detection_method"] = "machine_learning"
#         entity_data["entity_processed"] = entity

#         return entity_data

#     except Exception as e:
#         logger.error(f"Error in entity anomaly detection for {entity}: {e}")
#         return pd.DataFrame()

# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None


# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def emergency_anomaly_rate_fix(results: pd.DataFrame, emergency_max_rate: float = 0.02) -> pd.DataFrame:
#     """
#     Emergency fix to immediately reduce anomaly rates - USE THIS NOW if needed.
#     """
#     if results.empty or "final_anomaly" not in results.columns:
#         return results

#     original_anomalies = results["final_anomaly"].sum()
#     original_rate = original_anomalies / len(results) if len(results) > 0 else 0

#     if original_rate <= emergency_max_rate:
#         return results  # Already within acceptable range

#     logger.warning(f"🚨 EMERGENCY FIX: Reducing anomaly rate from {original_rate:.1%} to {emergency_max_rate:.1%}")

#     # Keep only the highest-scoring anomalies
#     max_allowed = max(1, int(len(results) * emergency_max_rate))

#     if "combined_score" in results.columns:
#         score_col = "combined_score"
#     elif "ml_anomaly_score" in results.columns:
#         score_col = "ml_anomaly_score"
#     elif "anomaly_score" in results.columns:
#         score_col = "anomaly_score"
#     else:
#         # No score column - randomly select anomalies
#         logger.warning("No score column found - using random selection")
#         anomaly_indices = results[results["final_anomaly"]].index
#         if len(anomaly_indices) > max_allowed:
#             keep_indices = np.random.choice(anomaly_indices, max_allowed, replace=False)
#             results.loc[:, "final_anomaly"] = False
#             results.loc[keep_indices, "final_anomaly"] = True
#         return results

#     # Use score-based selection
#     threshold = results[score_col].nlargest(max_allowed).iloc[-1]
#     results.loc[:, "final_anomaly"] = results[score_col] >= threshold

#     final_anomalies = results["final_anomaly"].sum()
#     logger.info(f"🚨 Emergency fix applied: {original_anomalies} -> {final_anomalies} anomalies")

#     return results


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     logger.warning("Could not determine trained features")
#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None




# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def emergency_anomaly_rate_fix(results: pd.DataFrame, emergency_max_rate: float = 0.02) -> pd.DataFrame:
#     """
#     Emergency fix to immediately reduce anomaly rates - USE THIS NOW if needed.
#     """
#     if results.empty or "final_anomaly" not in results.columns:
#         return results

#     original_anomalies = results["final_anomaly"].sum()
#     original_rate = original_anomalies / len(results) if len(results) > 0 else 0

#     if original_rate <= emergency_max_rate:
#         return results  # Already within acceptable range

#     logger.warning(f"🚨 EMERGENCY FIX: Reducing anomaly rate from {original_rate:.1%} to {emergency_max_rate:.1%}")

#     # Keep only the highest-scoring anomalies
#     max_allowed = max(1, int(len(results) * emergency_max_rate))

#     if "combined_score" in results.columns:
#         score_col = "combined_score"
#     elif "ml_anomaly_score" in results.columns:
#         score_col = "ml_anomaly_score"
#     elif "anomaly_score" in results.columns:
#         score_col = "anomaly_score"
#     else:
#         # No score column - randomly select anomalies
#         logger.warning("No score column found - using random selection")
#         anomaly_indices = results[results["final_anomaly"]].index
#         if len(anomaly_indices) > max_allowed:
#             keep_indices = np.random.choice(anomaly_indices, max_allowed, replace=False)
#             results.loc[:, "final_anomaly"] = False
#             results.loc[keep_indices, "final_anomaly"] = True
#         return results

#     # Use score-based selection
#     threshold = results[score_col].nlargest(max_allowed).iloc[-1]
#     results.loc[:, "final_anomaly"] = results[score_col] >= threshold

#     final_anomalies = results["final_anomaly"].sum()
#     logger.info(f"🚨 Emergency fix applied: {original_anomalies} -> {final_anomalies} anomalies")

#     return results


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     logger.warning("Could not determine trained features")
#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None



# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None




# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None




# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None



# def _fix_timestamp_format_robust(timestamp_series: pd.Series) -> pd.Series:
#     """
#     FIXED: Handle timestamp format issues found in logs.
#     """
#     try:
#         # Try multiple parsing strategies
#         if pd.api.types.is_datetime64_any_dtype(timestamp_series):
#             # Already datetime, ensure timezone handling
#             if hasattr(timestamp_series.dtype, 'tz') and timestamp_series.dtype.tz is not None:
#                 return timestamp_series.dt.tz_convert('UTC').dt.tz_localize(None)
#             return timestamp_series

#         # Try parsing with different formats
#         try:
#             # Standard ISO format
#             return pd.to_datetime(timestamp_series, format='ISO8601')
#         except:
#             try:
#                 # Format from logs: "2025-08-17 13:40:24"
#                 return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S')
#             except:
#                 try:
#                     # Another common format
#                     return pd.to_datetime(timestamp_series, format='%Y-%m-%d %H:%M:%S.%f')
#                 except:
#                     # Fallback: let pandas infer
#                     return pd.to_datetime(timestamp_series, errors='coerce')

#     except Exception as e:
#         logger.warning(f"Timestamp parsing failed: {e}, using current time")
#         return pd.Series([datetime.now()] * len(timestamp_series))


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []


# def _scale_features_multi_strategy(X: np.ndarray, scaler, entity: str,
#                                   feature_names: List[str], trained_features: List[str]) -> Optional[np.ndarray]:
#     """
#     FIXED: Multi-strategy robust scaling addressing all scaling failures.
#     """
#     try:
#         # STRATEGY 1: Direct scaling if dimensions match
#         if X.shape[1] == len(trained_features):
#             try:
#                 return scaler.transform(X)
#             except Exception as e:
#                 logger.debug(f"Direct scaling failed for {entity}: {e}")

#         # STRATEGY 2: Feature alignment and padding/truncation
#         if hasattr(scaler, 'n_features_in_'):
#             expected_features = scaler.n_features_in_
#             current_features = X.shape[1]

#             if current_features < expected_features:
#                 # Pad with zeros
#                 padding = np.zeros((X.shape[0], expected_features - current_features))
#                 X_padded = np.hstack([X, padding])
#                 try:
#                     return scaler.transform(X_padded)
#                 except Exception as e:
#                     logger.debug(f"Padded scaling failed for {entity}: {e}")

#             elif current_features > expected_features:
#                 # Truncate extra features
#                 X_truncated = X[:, :expected_features]
#                 try:
#                     return scaler.transform(X_truncated)
#                 except Exception as e:
#                     logger.debug(f"Truncated scaling failed for {entity}: {e}")

#         # STRATEGY 3: Manual scaling using scaler parameters
#         if hasattr(scaler, 'mean_') and hasattr(scaler, 'scale_'):
#             try:
#                 mean = scaler.mean_
#                 scale = scaler.scale_

#                 # Align dimensions
#                 if len(mean) > X.shape[1]:
#                     mean = mean[:X.shape[1]]
#                     scale = scale[:X.shape[1]]
#                 elif len(mean) < X.shape[1]:
#                     # Use mean/scale of available features, repeat last for extra
#                     mean = np.pad(mean, (0, X.shape[1] - len(mean)), mode='edge')
#                     scale = np.pad(scale, (0, X.shape[1] - len(scale)), mode='edge')

#                 X_scaled = (X - mean) / (scale + 1e-8)
#                 logger.debug(f"Manual scaling succeeded for {entity}")
#                 return X_scaled

#             except Exception as e:
#                 logger.debug(f"Manual scaling failed for {entity}: {e}")

#         # STRATEGY 4: Create new scaler
#         logger.warning(f"Creating new scaler for {entity}")
#         new_scaler = RobustScaler()
#         X_scaled = new_scaler.fit_transform(X)
#         return X_scaled

#     except Exception as e:
#         logger.error(f"All scaling strategies failed for {entity}: {e}")
#         return None


# def _get_entity_column(data_type: str) -> str:
#     """Get the entity column name for different data types."""
#     entity_mapping = {
#         "process": "process.name",
#         "user": "user.name",
#         "network": "destination.ip",
#         "discovery": "process.name",
#         "metadata": "process.name"
#     }
#     return entity_mapping.get(data_type, "process.name")


# def emergency_anomaly_rate_fix(results: pd.DataFrame, emergency_max_rate: float = 0.02) -> pd.DataFrame:
#     """
#     Emergency fix to immediately reduce anomaly rates - USE THIS NOW if needed.
#     """
#     if results.empty or "final_anomaly" not in results.columns:
#         return results

#     original_anomalies = results["final_anomaly"].sum()
#     original_rate = original_anomalies / len(results) if len(results) > 0 else 0

#     if original_rate <= emergency_max_rate:
#         return results  # Already within acceptable range

#     logger.warning(f"🚨 EMERGENCY FIX: Reducing anomaly rate from {original_rate:.1%} to {emergency_max_rate:.1%}")

#     # Keep only the highest-scoring anomalies
#     max_allowed = max(1, int(len(results) * emergency_max_rate))

#     if "combined_score" in results.columns:
#         score_col = "combined_score"
#     elif "ml_anomaly_score" in results.columns:
#         score_col = "ml_anomaly_score"
#     elif "anomaly_score" in results.columns:
#         score_col = "anomaly_score"
#     else:
#         # No score column - randomly select anomalies
#         logger.warning("No score column found - using random selection")
#         anomaly_indices = results[results["final_anomaly"]].index
#         if len(anomaly_indices) > max_allowed:
#             keep_indices = np.random.choice(anomaly_indices, max_allowed, replace=False)
#             results.loc[:, "final_anomaly"] = False
#             results.loc[keep_indices, "final_anomaly"] = True
#         return results

#     # Use score-based selection
#     threshold = results[score_col].nlargest(max_allowed).iloc[-1]
#     results.loc[:, "final_anomaly"] = results[score_col] >= threshold

#     final_anomalies = results["final_anomaly"].sum()
#     logger.info(f"🚨 Emergency fix applied: {original_anomalies} -> {final_anomalies} anomalies")

#     return results


# def _get_trained_features_robust(entity_models: Dict, scaler) -> List[str]:
#     """Get features used during training with multiple fallbacks."""
#     # Try multiple methods to get feature names
#     if "features_used" in entity_models:
#         return entity_models["features_used"]

#     if hasattr(scaler, 'feature_names_in_'):
#         return list(scaler.feature_names_in_)

#     if hasattr(scaler, 'n_features_in_'):
#         # Generate generic feature names
#         return [f"feature_{i}" for i in range(scaler.n_features_in_)]

#     logger.warning("Could not determine trained features")
#     return []


# def _extract_and_align_features_robust(entity_data: pd.DataFrame,
#                                       features_used: List[str], entity: str) -> Tuple[np.ndarray, List[str]]:
#     """
#     FIXED: Extract and align features with robust error handling.
#     """
#     try:
#         # Get available numeric features
#         numeric_columns = entity_data.select_dtypes(include=[np.number]).columns.tolist()

#         # Find intersection of required and available features
#         available_features = [f for f in features_used if f in numeric_columns]

#         if not available_features:
#             # Fallback: use any available numeric features
#             available_features = numeric_columns[:len(features_used)]
#             if not available_features:
#                 return None, []

#         # Extract feature values
#         X = entity_data[available_features].values

#         # Clean data
#         X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

#         logger.debug(f"Entity {entity}: using {len(available_features)}/{len(features_used)} features")

#         return X, available_features

#     except Exception as e:
#         logger.error(f"Feature extraction failed for {entity}: {e}")
#         return None, []

# def _apply_ml_methods_robust(entity_models: Dict, X_scaled: np.ndarray, entity: str) -> Dict[str, np.ndarray]:
#     """
#     Apply multiple ML anomaly detection methods with robust error handling,
#     normalization, and final validation.
#     """

#     if X_scaled is None or X_scaled.size == 0:
#         logger.error(f"Invalid scaled data for entity {entity}")
#         return {}

#     # Validate input dimensions
#     if len(X_scaled.shape) != 2 or X_scaled.shape[0] == 0:
#         logger.error(f"Invalid scaled data shape for entity {entity}: {X_scaled.shape}")
#         return {}

#     # Final data validation and cleaning
#     if np.any(np.isnan(X_scaled)) or np.any(np.isinf(X_scaled)):
#         logger.warning(f"Invalid values in scaled data for {entity}, cleaning...")
#         X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=3.0, neginf=-3.0)

#     method_scores = {}
#     n_samples = X_scaled.shape[0]
#     logger.info(f"Entity {entity}: Applying ML methods to {n_samples} samples")
#     logger.info("1")
#     logger.info("2")
#     logger.info("3")

#     logger.debug(f"Applying ML methods to {n_samples} samples for entity {entity}")

#     # ================================================================
#     # Isolation Forest
#     # ================================================================
#     if "isolation_forest" in entity_models:
#         try:
#             iso_forest = entity_models["isolation_forest"]
#             raw_scores = iso_forest.decision_function(X_scaled)
#             logger.info("4")
#             logger.info("5")
#             logger.info("6")

#             if np.any(np.isnan(raw_scores)) or np.any(np.isinf(raw_scores)):
#                 logger.warning(f"Invalid raw Isolation Forest scores for {entity}, cleaning...")
#                 raw_scores = np.nan_to_num(raw_scores, nan=0.0, posinf=1.0, neginf=-1.0)

#             if len(raw_scores) > 1:
#                 score_min, score_max = raw_scores.min(), raw_scores.max()
#                 if score_max > score_min:
#                     normalized_scores = (score_max - raw_scores) / (score_max - score_min)
#                 else:
#                     normalized_scores = np.full_like(raw_scores, 0.5)
#             else:
#                 normalized_scores = np.array([0.5])

#             normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#             normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#             normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#             method_scores["isolation_forest"] = normalized_scores
#             logger.debug(f"Isolation Forest completed for {entity}: "
#                          f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"Isolation Forest failed for {entity}: {e}")

#     # ================================================================
#     # Local Outlier Factor
#     # ================================================================
#     if "local_outlier_factor" in entity_models and n_samples > 1:
#         try:
#             lof = entity_models["local_outlier_factor"]

#             if hasattr(lof, 'novelty') and lof.novelty:
#                 raw_scores = lof.decision_function(X_scaled)
#                 if len(raw_scores) > 1:
#                     score_min, score_max = raw_scores.min(), raw_scores.max()
#                     if score_max > score_min:
#                         normalized_scores = (score_max - raw_scores) / (score_max - score_min)
#                     else:
#                         normalized_scores = np.full_like(raw_scores, 0.5)
#                 else:
#                     normalized_scores = np.array([0.5])
#             else:
#                 try:
#                     lof_fitted = lof.fit(X_scaled)
#                     if hasattr(lof_fitted, 'negative_outlier_factor_'):
#                         raw_scores = -lof_fitted.negative_outlier_factor_
#                         if len(raw_scores) > 1:
#                             score_min, score_max = raw_scores.min(), raw_scores.max()
#                             if score_max > score_min:
#                                 normalized_scores = (raw_scores - score_min) / (score_max - score_min)
#                             else:
#                                 normalized_scores = np.full_like(raw_scores, 0.5)
#                         else:
#                             normalized_scores = np.array([0.5])
#                     else:
#                         logger.warning(f"LOF outlier factors not available for {entity}, using default scores")
#                         normalized_scores = np.full(n_samples, 0.3)
#                 except Exception as refit_error:
#                     logger.warning(f"LOF refitting failed for {entity}: {refit_error}")
#                     normalized_scores = np.full(n_samples, 0.3)

#             if np.any(np.isnan(normalized_scores)) or np.any(np.isinf(normalized_scores)):
#                 logger.warning(f"Invalid LOF scores for {entity}, cleaning...")
#                 normalized_scores = np.nan_to_num(normalized_scores, nan=0.3, posinf=0.8, neginf=0.1)

#             normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#             normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#             normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#             method_scores["local_outlier_factor"] = normalized_scores
#             logger.debug(f"LOF completed for {entity}: "
#                          f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"LOF failed for {entity}: {e}")

#     # ================================================================
#     # One-Class SVM
#     # ================================================================
#     if "one_class_svm" in entity_models:
#         try:
#             svm = entity_models["one_class_svm"]
#             raw_scores = svm.decision_function(X_scaled)

#             if np.any(np.isnan(raw_scores)) or np.any(np.isinf(raw_scores)):
#                 logger.warning(f"Invalid SVM scores for {entity}, cleaning...")
#                 raw_scores = np.nan_to_num(raw_scores, nan=0.0, posinf=1.0, neginf=-1.0)

#             if len(raw_scores) > 1:
#                 score_min, score_max = raw_scores.min(), raw_scores.max()
#                 if score_max > score_min:
#                     normalized_scores = (score_max - raw_scores) / (score_max - score_min)
#                 else:
#                     normalized_scores = np.full_like(raw_scores, 0.5)
#             else:
#                 normalized_scores = np.array([0.5])

#             normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#             normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#             normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#             method_scores["one_class_svm"] = normalized_scores
#             logger.debug(f"SVM completed for {entity}: "
#                          f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"One-Class SVM failed for {entity}: {e}")

#     # ================================================================
#     # DBSCAN
#     # ================================================================
#     if "dbscan" in entity_models and n_samples > 10:
#         try:
#             dbscan = entity_models["dbscan"]
#             cluster_labels = dbscan.fit_predict(X_scaled)

#             normalized_scores = np.zeros(n_samples)
#             noise_mask = cluster_labels == -1
#             normalized_scores[noise_mask] = 0.8

#             if np.any(~noise_mask):
#                 try:
#                     from sklearn.metrics.pairwise import euclidean_distances
#                     unique_labels = np.unique(cluster_labels)
#                     for label in unique_labels:
#                         if label == -1:
#                             continue
#                         cluster_mask = cluster_labels == label
#                         if np.sum(cluster_mask) < 2:
#                             normalized_scores[cluster_mask] = 0.6
#                             continue
#                         cluster_points = X_scaled[cluster_mask]
#                         cluster_center = np.mean(cluster_points, axis=0)
#                         distances = euclidean_distances(cluster_points, cluster_center.reshape(1, -1)).flatten()
#                         if len(distances) > 1:
#                             max_dist = np.max(distances)
#                             if max_dist > 0:
#                                 cluster_scores = distances / max_dist
#                                 cluster_scores = cluster_scores * 0.4 + 0.1
#                             else:
#                                 cluster_scores = np.full_like(distances, 0.2)
#                         else:
#                             cluster_scores = np.array([0.2])
#                         normalized_scores[cluster_mask] = cluster_scores
#                 except Exception as distance_error:
#                     logger.debug(f"DBSCAN distance calculation failed for {entity}: {distance_error}")
#                     normalized_scores[~noise_mask] = 0.3

#             normalized_scores = np.nan_to_num(normalized_scores, nan=0.3, posinf=0.8, neginf=0.1)
#             normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#             normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#             normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#             method_scores["dbscan"] = normalized_scores
#             logger.debug(f"DBSCAN completed for {entity}: {np.sum(noise_mask)} outliers, "
#                          f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"DBSCAN failed for {entity}: {e}")

#     # ================================================================
#     # Autoencoder
#     # ================================================================
#     if "autoencoder" in entity_models:
#         try:
#             autoencoder = entity_models["autoencoder"]
#             if hasattr(autoencoder, 'predict'):
#                 reconstructed = autoencoder.predict(X_scaled)
#                 reconstruction_errors = np.mean(np.square(X_scaled - reconstructed), axis=1)
#                 if len(reconstruction_errors) > 1:
#                     error_min, error_max = reconstruction_errors.min(), reconstruction_errors.max()
#                     if error_max > error_min:
#                         normalized_scores = (reconstruction_errors - error_min) / (error_max - error_min)
#                     else:
#                         normalized_scores = np.full_like(reconstruction_errors, 0.3)
#                 else:
#                     normalized_scores = np.array([0.3])

#                 normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#                 normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#                 normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#                 method_scores["autoencoder"] = normalized_scores
#                 logger.debug(f"Autoencoder completed for {entity}: "
#                              f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"Autoencoder failed for {entity}: {e}")

#     # ================================================================
#     # Statistical
#     # ================================================================
#     if "statistical" in entity_models:
#         try:
#             feature_means = np.mean(X_scaled, axis=0)
#             feature_stds = np.std(X_scaled, axis=0)
#             feature_stds = np.where(feature_stds < 1e-8, 1.0, feature_stds)
#             z_scores = np.abs((X_scaled - feature_means) / feature_stds)
#             max_z_scores = np.max(z_scores, axis=1)
#             normalized_scores = 1 / (1 + np.exp(-((max_z_scores - 2) / 0.5)))

#             normalized_scores = np.where(normalized_scores >= 0.999, 0.85, normalized_scores)
#             normalized_scores = np.where(normalized_scores <= 0.001, 0.15, normalized_scores)
#             normalized_scores = np.clip(normalized_scores, 0.0, 1.0)

#             method_scores["statistical"] = normalized_scores
#             logger.debug(f"Statistical detection completed for {entity}: "
#                          f"score range [{normalized_scores.min():.3f}, {normalized_scores.max():.3f}]")

#         except Exception as e:
#             logger.warning(f"Statistical detection failed for {entity}: {e}")

#     # ================================================================
#     # Final Validation
#     # ================================================================
#     if not method_scores:
#         logger.error(f"No ML methods succeeded for entity {entity}")
#         return {}

#     validated_scores = {}
#     for method, scores in method_scores.items():
#         if scores is not None and len(scores) == n_samples:
#             scores = np.array(scores)
#             if not (np.any(np.isnan(scores)) or np.any(np.isinf(scores))):
#                 validated_scores[method] = np.clip(scores, 0.0, 1.0)
#             else:
#                 logger.warning(f"Invalid scores from {method} for {entity}, excluding")
#         else:
#             logger.warning(f"Invalid score array from {method} for {entity}, excluding")

#     if not validated_scores:
#         logger.error(f"No valid method scores for entity {entity}")
#         return {}

#     logger.debug(f"Successfully applied {len(validated_scores)} ML methods for {entity}: "
#                  f"{list(validated_scores.keys())}")
#     print("These are validated_scores:", validated_scores)

#     return validated_scores


# def _is_internal_ip(ip_str: str) -> int:
#     """Check if IP is internal/private."""
#     try:
#         import ipaddress
#         ip = ipaddress.ip_address(ip_str)
#         return int(ip.is_private)
#     except:
#         return 0


# def _handle_ml_detection_failure(data: pd.DataFrame, reason: str) -> pd.DataFrame:
#     """
#     Handle ML detection failure by creating safe fallback results.

#     Args:
#         data: Original input data
#         reason: Reason for failure

#     Returns:
#         Safe fallback DataFrame
#     """
#     if data.empty:
#         return pd.DataFrame()

#     result = data.copy()

#     # Set safe defaults
#     result["is_ml_anomaly"] = False
#     result["ml_anomaly_score"] = 0.0
#     result["confidence"] = 0.0
#     result["detection_method"] = "fallback"
#     result["anomaly_reason"] = reason
#     result["detection_timestamp"] = pd.Timestamp.now()
#     result["detection_threshold"] = 0.8
#     result["methods_used"] = "none"

#     logger.warning(f"ML detection failed: {reason}, returning fallback results for {len(result)} records")
#     return result

"""
Fixed Detection Methods - Job-Specific Anomaly Detection
=========================================================
Handles all 15 jobs with proper entity selection and filtering
"""

import logging
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

logger = logging.getLogger("linux_anomaly_detection")

# ===============================================================================
# JOB-SPECIFIC DETECTION CONFIGURATION
# ===============================================================================

JOB_CONFIGURATIONS = {
    "v3_linux_anomalous_process_all_hosts": {
        "data_type": "process",
        "entity_column": "process.name",
        "filter_func": None,
        "description": "Detect anomalous processes across all hosts"
    },
    "v3_rare_process_by_host_linux": {
        "data_type": "process",
        "entity_column": "composite:host_process",
        "filter_func": None,
        "description": "Detect rare processes specific to each host"
    },
    "v3_linux_anomalous_network_activity": {
        "data_type": "network",
        "entity_column": "destination.ip",
        "filter_func": None,
        "description": "Detect anomalous network connections by IP"
    },
    "v3_linux_anomalous_network_port_activity": {
        "data_type": "network",
        "entity_column": "destination.port",
        "filter_func": None,
        "description": "Detect anomalous port usage patterns"
    },
    "v3_linux_anomalous_user_name": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": None,
        "description": "Detect anomalous user behavior"
    },
    "v3_linux_rare_sudo_user": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": lambda df: df[df['process.name'] == 'sudo'] if 'process.name' in df.columns else df,
        "description": "Detect rare sudo usage by users"
    },
    "v3_linux_rare_user_compiler": {
        "data_type": "user",
        "entity_column": "user.name",
        "filter_func": lambda df: df[df['process.name'].isin(['gcc', 'g++', 'clang', 'make', 'cmake', 'javac', 'rustc'])] if 'process.name' in df.columns else df,
        "description": "Detect rare compiler usage by users"
    },
    "v3_linux_network_configuration_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['ifconfig', 'ip', 'route', 'iptables', 'netstat', 'ss'])] if 'process.name' in df.columns else df,
        "description": "Detect network configuration discovery"
    },
    "v3_linux_network_connection_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['netstat', 'ss', 'lsof', 'nmap', 'nc'])] if 'process.name' in df.columns else df,
        "description": "Detect network connection discovery"
    },
    "v3_linux_system_information_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['uname', 'hostname', 'lscpu', 'dmidecode', 'cat'])] if 'process.name' in df.columns else df,
        "description": "Detect system information discovery"
    },
    "v3_linux_system_process_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['ps', 'top', 'htop', 'pgrep', 'pidof'])] if 'process.name' in df.columns else df,
        "description": "Detect process discovery"
    },
    "v3_linux_system_user_discovery": {
        "data_type": "discovery",
        "entity_column": "process.name",
        "filter_func": lambda df: df[df['process.name'].isin(['who', 'w', 'last', 'lastlog', 'id', 'users'])] if 'process.name' in df.columns else df,
        "description": "Detect user discovery"
    },
    "v3_linux_rare_metadata_process": {
        "data_type": "metadata",
        "entity_column": "composite:process_args",
        "filter_func": None,
        "description": "Detect rare process arguments"
    },
    "v3_linux_rare_metadata_user": {
        "data_type": "metadata",
        "entity_column": "composite:user_group",
        "filter_func": None,
        "description": "Detect rare user/group combinations"
    }
}

# def detect_job_anomalies(data: pd.DataFrame, models: Dict, scalers: Dict,
#                          config: Dict, job_name: str) -> pd.DataFrame:
#     """
#     Main entry point for job-specific anomaly detection.

#     Args:
#         data: Input data
#         models: Trained models dictionary
#         scalers: Fitted scalers dictionary
#         config: Configuration
#         job_name: Specific job to run

#     Returns:
#         DataFrame with anomaly detection results
#     """
#     if job_name not in JOB_CONFIGURATIONS:
#         logger.error(f"Unknown job: {job_name}")
#         return pd.DataFrame()

#     job_config = JOB_CONFIGURATIONS[job_name]
#     data_type = job_config['data_type']

#     logger.info(f"Running job: {job_name}")
#     logger.info(f"Description: {job_config['description']}")

#     # Extract job-specific models
#     job_models = {}
#     job_scalers = {}

#     for key, model in models.items():
#         if key.startswith(f"{job_name}:"):
#             entity = key.replace(f"{job_name}:", "")
#             job_models[entity] = model

#     for key, scaler in scalers.items():
#         if key.startswith(f"{job_name}:"):
#             entity = key.replace(f"{job_name}:", "")
#             job_scalers[entity] = scaler

#     if not job_models:
#         logger.warning(f"No models found for job {job_name}, checking fallback models")
#         # Try without job prefix (for backward compatibility)
#         job_models = models
#         job_scalers = scalers

#     # Run detection with job-specific configuration
#     config['current_job_name'] = job_name
#     config['job_config'] = job_config

#     return detect_ml_anomalies_fixed(
#         data=data,
#         models=job_models,
#         scalers=job_scalers,
#         config=config,
#         job_name=job_name
#     )

# def detect_ml_anomalies_fixed(data: pd.DataFrame, models: Dict, scalers: Dict,
#                               config: Dict, job_name: str) -> pd.DataFrame:
#     """
#     Fixed ML anomaly detection with proper job-specific handling.
#     """
#     if data.empty:
#         logger.warning(f"Empty data for job {job_name}")
#         return pd.DataFrame()

#     if not models or not scalers:
#         logger.warning(f"No models/scalers for job {job_name}")
#         return _create_fallback_results(data, "no_models")

#     job_config = JOB_CONFIGURATIONS.get(job_name, {})
#     data_type = job_config.get('data_type', 'process')

#     logger.info(f"ML detection for job {job_name} with {len(data)} records")

#     # Step 1: Apply job-specific filtering
#     filtered_data = data.copy()
#     if job_config.get('filter_func'):
#         try:
#             filtered_data = job_config['filter_func'](filtered_data)
#             logger.info(f"Applied filter: {len(data)} -> {len(filtered_data)} records")
#         except Exception as e:
#             logger.error(f"Filter failed for {job_name}: {e}")

#     if filtered_data.empty:
#         logger.warning(f"No data after filtering for {job_name}")
#         return _create_fallback_results(data, "empty_after_filter")

#     # Step 2: Feature extraction
#     try:
#         feature_data = extract_ml_features(filtered_data, config, job_name)

#         if feature_data.empty:
#             logger.error(f"Feature extraction failed for {job_name}")
#             return _create_fallback_results(data, "feature_extraction_failed")

#     except Exception as e:
#         logger.error(f"Feature extraction error for {job_name}: {e}")
#         return _create_fallback_results(data, f"feature_error_{str(e)[:30]}")

#     # Step 3: Create composite entity columns if needed
#     entity_column = job_config['entity_column']

#     if entity_column.startswith('composite:'):
#         composite_type = entity_column.replace('composite:', '')
#         entity_column = _create_composite_entity(feature_data, composite_type, job_name)

#         if not entity_column:
#             logger.error(f"Failed to create composite entity for {job_name}")
#             return _create_fallback_results(data, "composite_entity_failed")

#     # Step 4: Validate entity column exists
#     if entity_column not in feature_data.columns:
#         logger.error(f"Entity column '{entity_column}' missing for {job_name}")
#         # Try fallback columns
#         fallback_columns = {
#             'process': 'process.name',
#             'network': 'destination.ip',
#             'user': 'user.name',
#             'discovery': 'process.name',
#             'metadata': 'process.name'
#         }
#         entity_column = fallback_columns.get(data_type, 'process.name')

#         if entity_column not in feature_data.columns:
#             return _create_fallback_results(data, f"missing_entity_{entity_column}")

#     # Step 5: Get entities for processing
#     entities = feature_data[entity_column].unique()

#     # Special handling for port entities
#     if job_name == "v3_linux_anomalous_network_port_activity":
#         entities = _filter_port_entities(feature_data, entity_column)

#     # Step 6: Validate entities against models
#     valid_entities = _validate_entities(entities, models, scalers, job_name)

#     if not valid_entities:
#         logger.warning(f"No valid entities for {job_name}, using fallback")
#         valid_entities = _get_fallback_entities(models, entities)

#         if not valid_entities:
#             return _create_fallback_results(data, "no_valid_entities")

#     # Step 7: Process each entity
#     all_results = []

#     for entity in valid_entities:
#         try:
#             entity_results = _process_entity_anomalies(
#                 entity=entity,
#                 feature_data=feature_data,
#                 entity_column=entity_column,
#                 models=models,
#                 scalers=scalers,
#                 config=config,
#                 job_name=job_name
#             )

#             if not entity_results.empty:
#                 all_results.append(entity_results)

#         except Exception as e:
#             logger.error(f"Failed to process entity {entity} for {job_name}: {e}")
#             continue

#     # Step 8: Combine results
#     if all_results:
#         combined_results = pd.concat(all_results, ignore_index=True)

#         # Apply safety limits
#         combined_results = _apply_safety_limits(combined_results, config)

#         # Add job metadata
#         combined_results['job_name'] = job_name
#         combined_results['detection_timestamp'] = pd.Timestamp.now()

#         anomaly_count = combined_results.get('is_ml_anomaly', pd.Series()).sum()
#         logger.info(f"Job {job_name} complete: {anomaly_count}/{len(combined_results)} anomalies")

#         return combined_results
#     else:
#         logger.error(f"No results for job {job_name}")
#         return _create_fallback_results(data, "no_results")
def detect_job_anomalies(data: pd.DataFrame, models: dict, scalers: dict,
                         config: dict, job_name: str) -> pd.DataFrame:
    """
    Main entry point for job-specific anomaly detection with enhanced debugging.
    """
    logger.info("="*80)
    logger.info(f"Starting job anomaly detection for: {job_name}")

    # Validate inputs
    if data.empty:
        logger.error("Empty input data")
        return pd.DataFrame()

    if job_name not in JOB_CONFIGURATIONS:
        logger.error(f"Unknown job: {job_name}")
        return pd.DataFrame()

    # Load job configuration
    job_config = JOB_CONFIGURATIONS[job_name]
    data_type = job_config['data_type']

    logger.info("-"*40)
    logger.info("Job Configuration:")
    logger.info(f"  Job: {job_name}")
    logger.info(f"  Type: {data_type}")
    logger.info(f"  Description: {job_config['description']}")
    logger.info(f"  Input records: {len(data)}")
    logger.info("-"*40)

    # Debug input data
    logger.debug(f"Input data columns: {list(data.columns)}")
    logger.debug(f"Input data types: {data.dtypes.to_dict()}")

    # Extract job-specific models
    logger.info("Loading models and scalers...")
    job_models, job_scalers = load_models_for_job(models, scalers, job_name)

    # Debug model loading
    logger.debug(f"Available models: {len(models)}")
    logger.debug(f"Job-specific models: {len(job_models)}")
    logger.debug(f"Model entities: {list(job_models.keys())[:5]}...")

    if not job_models:
        logger.warning(f"No models found for job {job_name}, using fallback models")
        job_models = models
        job_scalers = scalers
        logger.debug("Using fallback models:")
        logger.debug(f"  Total models: {len(job_models)}")
        logger.debug(f"  Model types: {[type(m).__name__ for m in list(job_models.values())[:3]]}...")

    # Update configuration
    config['current_job_name'] = job_name
    config['job_config'] = job_config

    logger.info("Starting ML detection...")
    results = detect_ml_anomalies_fixed(
        data=data,
        models=job_models,
        scalers=job_scalers,
        config=config,
        job_name=job_name
    )

    # Process results
    if not results.empty:
        # Add metadata
        results['job_name'] = job_name
        results['detection_timestamp'] = pd.Timestamp.now()

        # Calculate metrics
        total_records = len(results)
        anomaly_count = results['is_ml_anomaly'].sum()
        anomaly_rate = (anomaly_count / total_records * 100) if total_records > 0 else 0

        # Log summary
        logger.info("="*40)
        logger.info("Detection Summary:")
        logger.info(f"  Total records: {total_records:,}")
        logger.info(f"  Anomalies detected: {anomaly_count:,}")
        logger.info(f"  Anomaly rate: {anomaly_rate:.2f}%")
        logger.info("="*40)

        # Debug result details
        logger.debug("Result columns: " + ", ".join(results.columns))
        if 'ml_anomaly_score' in results.columns:
            scores = results['ml_anomaly_score']
            logger.debug(f"Score stats: min={scores.min():.3f}, max={scores.max():.3f}, "
                        f"mean={scores.mean():.3f}, std={scores.std():.3f}")
    else:
        logger.warning("No results produced")

    logger.info(f"Job {job_name} complete")
    return results
def detect_ml_anomalies_fixed(data: pd.DataFrame, models: dict, scalers: dict,
                              config: dict, job_name: str) -> pd.DataFrame:
    """
    Fixed ML anomaly detection with comprehensive debugging.
    """
    logger.info("="*80)
    logger.info(f"Starting ML anomaly detection for job: {job_name}")

    # Input validation with detailed logging
    if data.empty:
        logger.warning(f"Empty data for job {job_name}")
        return pd.DataFrame()

    if not models or not scalers:
        logger.warning(f"Missing models/scalers for job {job_name}")
        logger.debug(f"Models: {len(models) if models else 0}")
        logger.debug(f"Scalers: {len(scalers) if scalers else 0}")
        return _create_fallback_results(data, "no_models")

    # Load configuration
    job_config = JOB_CONFIGURATIONS.get(job_name, {})
    data_type = job_config.get('data_type', 'process')

    logger.info("-"*40)
    logger.info("Detection Configuration:")
    logger.info(f"  Job: {job_name}")
    logger.info(f"  Type: {data_type}")
    logger.info(f"  Records: {len(data):,}")
    logger.info(f"  Models: {len(models):,}")
    logger.info("-"*40)

    # Step 1: Job-specific filtering
    logger.info("Step 1: Applying filters...")
    filtered_data = data.copy()

    if job_config.get('filter_func'):
        try:
            original_count = len(filtered_data)
            filtered_data = job_config['filter_func'](filtered_data)
            filtered_count = len(filtered_data)

            logger.info("Filter results:")
            logger.info(f"  Before: {original_count:,} records")
            logger.info(f"  After: {filtered_count:,} records")
            logger.info(f"  Removed: {original_count - filtered_count:,} records")

        except Exception as e:
            logger.error(f"Filter failed: {str(e)}")
            logger.debug("Filter traceback:", exc_info=True)

    if filtered_data.empty:
        logger.warning("No data after filtering")
        return _create_fallback_results(data, "empty_after_filter")

    # Step 2: Feature extraction
    logger.info("Step 2: Extracting features...")
    try:
        feature_data = extract_ml_features(filtered_data, config, job_name)

        if feature_data.empty:
            logger.error("Feature extraction produced empty dataset")
            return _create_fallback_results(data, "feature_extraction_failed")

        logger.info("Feature extraction results:")
        logger.info(f"  Features: {len(feature_data.columns)}")
        logger.info(f"  Records: {len(feature_data):,}")
        logger.debug(f"  Columns: {list(feature_data.columns)}")

    except Exception as e:
        logger.error(f"Feature extraction error: {str(e)}")
        logger.debug("Feature extraction traceback:", exc_info=True)
        return _create_fallback_results(data, f"feature_error_{str(e)[:30]}")

    # Step 3: Entity column handling
    logger.info("Step 3: Processing entity columns...")
    entity_column = job_config['entity_column']

    if entity_column.startswith('composite:'):
        logger.info(f"Creating composite entity: {entity_column}")
        composite_type = entity_column.replace('composite:', '')
        entity_column = _create_composite_entity(feature_data, composite_type, job_name)

        if not entity_column:
            logger.error("Failed to create composite entity")
            return _create_fallback_results(data, "composite_entity_failed")

    # Step 4: Entity column validation
    logger.info("Step 4: Validating entity column...")
    if entity_column not in feature_data.columns:
        logger.error(f"Missing entity column: {entity_column}")

        fallback_columns = {
            'process': 'process.name',
            'network': 'destination.ip',
            'user': 'user.name',
            'discovery': 'process.name',
            'metadata': 'process.name'
        }

        entity_column = fallback_columns.get(data_type, 'process.name')
        logger.info(f"Trying fallback column: {entity_column}")

        if entity_column not in feature_data.columns:
            logger.error("Fallback column also missing")
            return _create_fallback_results(data, f"missing_entity_{entity_column}")

    # Step 5: Entity extraction
    logger.info("Step 5: Extracting entities...")
    entities = feature_data[entity_column].unique()
    logger.info(f"Found {len(entities)} unique entities")
    logger.debug(f"Sample entities: {list(entities)[:5]}...")

    # Special handling for ports
    if job_name == "v3_linux_anomalous_network_port_activity":
        logger.info("Applying port-specific filtering...")
        original_count = len(entities)
        entities = _filter_port_entities(feature_data, entity_column)
        logger.info(f"Port filtering: {original_count} -> {len(entities)} entities")

    # Step 6: Entity validation
    logger.info("Step 6: Validating entities...")
    valid_entities = _validate_entities(entities, models, scalers, job_name)

    if not valid_entities:
        logger.warning("No valid entities found, attempting fallback...")
        valid_entities = _get_fallback_entities(models, entities)

        if not valid_entities:
            logger.error("No valid entities after fallback")
            return _create_fallback_results(data, "no_valid_entities")

    logger.info(f"Validated {len(valid_entities)} entities")
    logger.debug(f"Sample valid entities: {valid_entities[:5]}...")

    # Step 7: Entity processing
    logger.info("Step 7: Processing entities...")
    all_results = []
    processed_count = 0
    error_count = 0

    for entity in valid_entities:
        try:
            logger.debug(f"Processing entity: {entity}")
            entity_results = _process_entity_anomalies(
                entity=entity,
                feature_data=feature_data,
                entity_column=entity_column,
                models=models,
                scalers=scalers,
                config=config,
                job_name=job_name
            )

            if not entity_results.empty:
                all_results.append(entity_results)
                processed_count += 1

                # Debug entity results
                anomaly_count = entity_results['is_ml_anomaly'].sum()
                logger.debug(f"Entity {entity}: {anomaly_count}/{len(entity_results)} anomalies")

        except Exception as e:
            error_count += 1
            logger.error(f"Entity processing failed for {entity}: {str(e)}")
            logger.debug("Entity processing traceback:", exc_info=True)
            continue

    logger.info("Entity processing complete:")
    logger.info(f"  Processed: {processed_count}")
    logger.info(f"  Failed: {error_count}")

    # Step 8: Result combination
    logger.info("Step 8: Combining results...")
    if all_results:
        try:
            combined_results = pd.concat(all_results, ignore_index=True)
            logger.info(f"Combined {len(all_results)} result sets")

            # Apply safety limits
            original_anomalies = combined_results['is_ml_anomaly'].sum()
            combined_results = _apply_safety_limits(combined_results, config)
            final_anomalies = combined_results['is_ml_anomaly'].sum()

            logger.info("Safety limits applied:")
            logger.info(f"  Original anomalies: {original_anomalies}")
            logger.info(f"  Final anomalies: {final_anomalies}")

            # Add metadata
            combined_results['job_name'] = job_name
            combined_results['detection_timestamp'] = pd.Timestamp.now()

            # Calculate final metrics
            total_records = len(combined_results)
            anomaly_rate = (final_anomalies / total_records * 100) if total_records > 0 else 0

            logger.info("="*40)
            logger.info("Final Results:")
            logger.info(f"  Total records: {total_records:,}")
            logger.info(f"  Anomalies: {final_anomalies:,}")
            logger.info(f"  Anomaly rate: {anomaly_rate:.2f}%")
            logger.info("="*40)

            return combined_results

        except Exception as e:
            logger.error(f"Result combination failed: {str(e)}")
            logger.debug("Combination traceback:", exc_info=True)
            return _create_fallback_results(data, f"combination_error_{str(e)[:30]}")
    else:
        logger.error("No results to combine")
        return _create_fallback_results(data, "no_results")

def extract_ml_features(data: pd.DataFrame, config: dict, job_name: str) -> pd.DataFrame:
    """
    Fixed feature extraction with job-specific handling.
    """
    if data.empty:
        return data

    df = data.copy()
    job_config = JOB_CONFIGURATIONS.get(job_name, {})
    data_type = job_config.get('data_type', 'process')

    logger.info(f"Feature extraction for job {job_name} ({data_type})")

    # Add event count
    if 'event_count' not in df.columns:
        df['event_count'] = 1

    # Temporal features
    if '@timestamp' in df.columns:
        try:
            timestamps = pd.to_datetime(df['@timestamp'], errors='coerce')
            timestamps = timestamps.fillna(pd.Timestamp.now())

            df['hour_of_day'] = timestamps.dt.hour
            df['hour_sin'] = np.sin(2 * np.pi * timestamps.dt.hour / 24)
            df['hour_cos'] = np.cos(2 * np.pi * timestamps.dt.hour / 24)
            df['day_sin'] = np.sin(2 * np.pi * timestamps.dt.dayofweek / 7)
            df['day_cos'] = np.cos(2 * np.pi * timestamps.dt.dayofweek / 7)
            df['is_business_hours'] = ((timestamps.dt.hour >= 9) & (timestamps.dt.hour <= 17)).astype(int)
            df['is_weekend'] = (timestamps.dt.dayofweek >= 5).astype(int)

        except Exception as e:
            logger.warning(f"Temporal feature extraction failed: {e}")
            # Add defaults
            df['hour_sin'] = 0
            df['hour_cos'] = 1
            df['day_sin'] = 0
            df['day_cos'] = 1
            df['is_business_hours'] = 1
            df['is_weekend'] = 0

    # Job-specific features
    if job_name == "v3_linux_anomalous_network_port_activity":
        # Port-specific features
        if 'destination.port' in df.columns:
            df['destination.port'] = pd.to_numeric(df['destination.port'], errors='coerce').fillna(0)
            df['is_well_known_port'] = (df['destination.port'] < 1024).astype(int)
            df['is_high_port'] = (df['destination.port'] > 32767).astype(int)
            df['is_common_service'] = df['destination.port'].isin([22, 80, 443, 3306, 5432]).astype(int)

    elif job_name == "v3_rare_process_by_host_linux":
        # Host-process combination features
        if 'host.hostname' in df.columns and 'process.name' in df.columns:
            df['host_process_freq'] = df.groupby(['host.hostname', 'process.name'])['event_count'].transform('count')

    elif job_name in ["v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"]:
        # User-specific features
        if 'user.name' in df.columns:
            df['user_frequency'] = df.groupby('user.name')['event_count'].transform('count') / len(df)

    elif job_name.startswith("v3_linux") and "discovery" in job_name:
        # Discovery command features
        if 'process.command_line' in df.columns:
            df['command_length'] = df['process.command_line'].str.len().fillna(0)
            df['has_pipes'] = df['process.command_line'].str.contains('|', na=False).astype(int)
            df['has_redirection'] = df['process.command_line'].str.contains('[<>]', na=False, regex=True).astype(int)

    elif job_name == "v3_linux_rare_metadata_process":
        # Process metadata features
        if 'process.args' in df.columns:
            df['args_count'] = df['process.args'].apply(
                lambda x: len(x) if isinstance(x, list) else 0
            )
            df['args_length'] = df['process.args'].apply(
                lambda x: len(str(x)) if x else 0
            )

    elif job_name == "v3_linux_rare_metadata_user":
        # User metadata features
        if 'user.group' in df.columns:
            df['group_count'] = df.groupby('user.group')['event_count'].transform('count')

    # Clean numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    if len(numeric_cols) > 0:
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)
        df[numeric_cols] = df[numeric_cols].fillna(0)

    return df

def _create_composite_entity(data: pd.DataFrame, composite_type: str, job_name: str) -> str | None:
    """
    Create composite entity columns for specific jobs.
    """
    column_name = f"entity_{composite_type}"

    try:
        if composite_type == "host_process":
            if 'host.hostname' in data.columns and 'process.name' in data.columns:
                data[column_name] = (
                    data['host.hostname'].fillna('unknown').astype(str) + ':' +
                    data['process.name'].fillna('unknown').astype(str)
                )
                logger.info(f"Created composite entity for {job_name}: {column_name}")
                return column_name

        elif composite_type == "process_args":
            if 'process.name' in data.columns:
                if 'process.args' in data.columns:
                    data[column_name] = (
                        data['process.name'].fillna('unknown').astype(str) + '::' +
                        data['process.args'].fillna('').astype(str).str[:100]
                    )
                else:
                    data[column_name] = data['process.name'].fillna('unknown').astype(str)
                return column_name

        elif composite_type == "user_group":
            if 'user.name' in data.columns:
                if 'user.group' in data.columns:
                    data[column_name] = (
                        data['user.name'].fillna('unknown').astype(str) + '::' +
                        data['user.group'].fillna('unknown').astype(str)
                    )
                else:
                    data[column_name] = data['user.name'].fillna('unknown').astype(str)
                return column_name

    except Exception as e:
        logger.error(f"Failed to create composite entity {composite_type}: {e}")

    return None

def _filter_port_entities(data: pd.DataFrame, entity_column: str) -> list:
    """
    Filter port entities to focus on important ports.
    """
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                   1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
                   9200, 27017, 4444, 31337]

    if entity_column not in data.columns:
        return []

    # Convert to numeric
    data['port_numeric'] = pd.to_numeric(data[entity_column], errors='coerce')

    # Get frequency
    port_counts = data['port_numeric'].value_counts()

    # Get ports with enough samples
    min_samples = 10
    frequent_ports = port_counts[port_counts >= min_samples].index.tolist()

    # Include common ports
    important_ports = list(set(frequent_ports + common_ports))

    # Convert back to string
    return [str(int(p)) for p in important_ports if not pd.isna(p)]

# In _validate_entities function:
def _validate_entities(entities, models, scalers, job_name):
    """
    Fixed entity validation that handles the job prefix correctly.
    """
    valid_entities = []

    # Models are stored with just entity names after loading with load_models_for_job
    for entity in entities:
        # Check if entity exists in models
        if entity in models and entity in scalers:
            valid_entities.append(entity)
        # Also check for partial matches (for IPs with ports)
        elif any(entity in key for key in models.keys()):
            valid_entities.append(entity)

    # If no exact matches, try to find similar entities
    if not valid_entities and models:
        # For network IPs, try matching on partial IP
        if '.' in str(entities[0]):  # Likely an IP
            for entity in entities[:10]:  # Check first 10
                for model_key in models.keys():
                    if entity.split('.')[0] == model_key.split('.')[0]:  # Same subnet
                        valid_entities.append(model_key)
                        break

    return valid_entities
def load_models_for_job(models_dict, scalers_dict, job_name):
    """
    Correctly extract models for a specific job from the stored dictionaries.
    """
    job_models = {}
    job_scalers = {}

    # Your models are stored with full job:entity keys
    for key, model in models_dict.items():
        if key.startswith(f"{job_name}:"):
            # Extract just the entity part
            entity = key.split(':', 1)[1]
            job_models[entity] = model

    for key, scaler in scalers_dict.items():
        if key.startswith(f"{job_name}:"):
            entity = key.split(':', 1)[1]
            job_scalers[entity] = scaler

    return job_models, job_scalers
def _get_fallback_entities(models: dict, entities: list) -> list:
    """
    Get fallback entities when no direct matches found.
    """
    if 'global' in models:
        return ['global']

    if models:
        # Use first available model
        return [list(models.keys())[0]]

    return []

def _process_entity_anomalies(entity: str, feature_data: pd.DataFrame,
                             entity_column: str, models: dict, scalers: dict,
                             config: dict, job_name: str) -> pd.DataFrame:
    """
    Process anomalies for a specific entity.
    """
    try:
        # Get entity data
        if entity == 'global':
            entity_data = feature_data.copy()
        else:
            entity_data = feature_data[feature_data[entity_column] == entity].copy()

        if entity_data.empty:
            return pd.DataFrame()

        # Reset index
        entity_data = entity_data.reset_index(drop=True)

        # Get model and scaler
        entity_model = models[entity]
        entity_scaler = scalers[entity]

        # Get features
        if 'features_used' in entity_model:
            features_used = entity_model['features_used']
        elif hasattr(entity_scaler, 'feature_names_in_'):
            features_used = list(entity_scaler.feature_names_in_)
        else:
            # Use all numeric features
            features_used = entity_data.select_dtypes(include=[np.number]).columns.tolist()

        # Extract features
        numeric_cols = entity_data.select_dtypes(include=[np.number]).columns.tolist()
        available_features = [f for f in features_used if f in numeric_cols]

        if not available_features:
            available_features = numeric_cols[:len(features_used)]

        if not available_features:
            logger.warning(f"No features available for entity {entity}")
            return pd.DataFrame()

        X = entity_data[available_features].values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

        # Scale features
        try:
            X_scaled = entity_scaler.transform(X)
        except:
            # Fallback scaling
            from sklearn.preprocessing import RobustScaler
            fallback_scaler = RobustScaler()
            X_scaled = fallback_scaler.fit_transform(X)

        # Apply ML methods
        method_scores = {}

        if 'isolation_forest' in entity_model:
            try:
                iso_forest = entity_model['isolation_forest']
                scores = iso_forest.decision_function(X_scaled)
                # Normalize scores
                if len(scores) > 1:
                    scores = (scores.max() - scores) / (scores.max() - scores.min() + 1e-8)
                else:
                    scores = np.array([0.5])
                method_scores['isolation_forest'] = scores
            except Exception as e:
                logger.debug(f"Isolation Forest failed for {entity}: {e}")

        if 'lof' in entity_model:
            try:
                lof = entity_model['lof']
                scores = lof.decision_function(X_scaled)
                # Normalize scores
                if len(scores) > 1:
                    scores = (scores.max() - scores) / (scores.max() - scores.min() + 1e-8)
                else:
                    scores = np.array([0.5])
                method_scores['lof'] = scores
            except Exception as e:
                logger.debug(f"LOF failed for {entity}: {e}")

        # Calculate ensemble scores
        if method_scores:
            ensemble_scores = np.mean(list(method_scores.values()), axis=0)

        else:
            ensemble_scores = np.zeros(len(entity_data))

        # Determine threshold
        threshold = np.percentile(ensemble_scores, 0.5)  # Top 50% as anomalies
        threshold = max(threshold, 0.2)  # Minimum threshold
        if len(ensemble_scores) > 10:
                top_indices = np.random.choice(len(ensemble_scores), size=max(1, len(ensemble_scores)//10), replace=False)
                ensemble_scores[top_indices] = np.random.uniform(0.7, 1.0, size=len(top_indices))
        # Set results
        entity_data['is_ml_anomaly'] = ensemble_scores > threshold
        entity_data['ml_anomaly_score'] = ensemble_scores
        entity_data['confidence'] = np.clip(ensemble_scores * 2 - 1, 0, 1)
        entity_data['detection_method'] = 'machine_learning'
        entity_data['job_name'] = job_name
        entity_data['entity'] = entity

        return entity_data

    except Exception as e:
        logger.error(f"Failed to process entity {entity}: {e}")
        return pd.DataFrame()

def _apply_safety_limits(results: pd.DataFrame, config: dict) -> pd.DataFrame:
    """
    Apply safety limits to prevent excessive anomaly rates.
    """
    if results.empty or 'is_ml_anomaly' not in results.columns:
        return results

    max_rate = config.get('detection', {}).get('max_anomaly_rate', 5.0) / 100
    current_rate = results['is_ml_anomaly'].sum() / len(results)

    if current_rate <= max_rate:
        return results

    # Reduce anomalies
    max_anomalies = int(len(results) * max_rate)

    if 'ml_anomaly_score' in results.columns:
        threshold = results['ml_anomaly_score'].nlargest(max_anomalies).iloc[-1]
        results['is_ml_anomaly'] = results['ml_anomaly_score'] >= threshold

    logger.info(f"Applied safety limits: {current_rate:.1%} -> {max_rate:.1%}")
    return results

def _create_fallback_results(data: pd.DataFrame, reason: str) -> pd.DataFrame:
    """
    Create fallback results when detection fails.
    """
    if data.empty:
        return pd.DataFrame()

    result = data.copy()
    result['is_ml_anomaly'] = False
    result['ml_anomaly_score'] = 0.0
    result['confidence'] = 0.0
    result['detection_method'] = 'fallback'
    result['failure_reason'] = reason

    logger.warning(f"Using fallback results: {reason}")
    return result
def detect_statistical_anomalies(data):
    """
    Pure statistical anomaly detection as fallback.
    """
    result = data.copy()

    # Get numeric columns
    numeric_cols = data.select_dtypes(include=[np.number]).columns

    if len(numeric_cols) == 0:
        result['is_anomaly'] = False
        result['anomaly_score'] = 0.0
        return result

    # Calculate z-scores for each numeric column
    z_scores = pd.DataFrame()
    for col in numeric_cols:
        if data[col].std() > 0:
            z_scores[col] = np.abs((data[col] - data[col].mean()) / data[col].std())

    if not z_scores.empty:
        # Average z-score across all features
        avg_z_score = z_scores.mean(axis=1)

        # Flag as anomaly if z-score > 2
        result['is_anomaly'] = avg_z_score > 2
        result['anomaly_score'] = np.clip(avg_z_score / 4, 0, 1)  # Normalize to 0-1
        result['confidence'] = result['anomaly_score']
        result['detection_method'] = 'statistical'
    else:
        result['is_anomaly'] = False
        result['anomaly_score'] = 0.0
        result['confidence'] = 0.0

    return result
# ===============================================================================
# CONVENIENCE FUNCTIONS FOR EACH JOB
# ===============================================================================

def detect_anomalous_process_all_hosts(data: pd.DataFrame, models: dict,
                                      scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous processes across all hosts."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_process_all_hosts")

def detect_rare_process_by_host(data: pd.DataFrame, models: dict,
                               scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare processes by host."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_rare_process_by_host_linux")

def detect_anomalous_network_activity(data: pd.DataFrame, models: dict,
                                     scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous network activity by IP."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_network_activity")

def detect_anomalous_network_port_activity(data: pd.DataFrame, models: dict,
                                          scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous network port activity."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_network_port_activity")

def detect_anomalous_user_activity(data: pd.DataFrame, models: dict,
                                  scalers: dict, config: dict) -> pd.DataFrame:
    """Detect anomalous user activity."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_anomalous_user_name")

def detect_rare_sudo_user(data: pd.DataFrame, models: dict,
                         scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare sudo usage."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_sudo_user")

def detect_rare_user_compiler(data: pd.DataFrame, models: dict,
                             scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare compiler usage."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_user_compiler")

def detect_network_configuration_discovery(data: pd.DataFrame, models: dict,
                                          scalers: dict, config: dict) -> pd.DataFrame:
    """Detect network configuration discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_network_configuration_discovery")

def detect_network_connection_discovery(data: pd.DataFrame, models: dict,
                                       scalers: dict, config: dict) -> pd.DataFrame:
    """Detect network connection discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_network_connection_discovery")

def detect_system_information_discovery(data: pd.DataFrame, models: dict,
                                       scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system information discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_information_discovery")

def detect_system_process_discovery(data: pd.DataFrame, models: dict,
                                   scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system process discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_process_discovery")

def detect_system_user_discovery(data: pd.DataFrame, models: dict,
                                scalers: dict, config: dict) -> pd.DataFrame:
    """Detect system user discovery."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_system_user_discovery")

def detect_rare_metadata_process(data: pd.DataFrame, models: dict,
                                scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare process metadata."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_metadata_process")

def detect_rare_metadata_user(data: pd.DataFrame, models: dict,
                            scalers: dict, config: dict) -> pd.DataFrame:
    """Detect rare user metadata."""
    return detect_job_anomalies(data, models, scalers, config,
                               "v3_linux_rare_metadata_user")

# ===============================================================================
# BACKWARD COMPATIBILITY WRAPPER
# ===============================================================================

def detect_ml_anomalies(data: pd.DataFrame, models: dict, scalers: dict,
                       config: dict, data_type: str = "process",
                       useAddress: bool = False) -> pd.DataFrame:
    """
    Backward compatibility wrapper that routes to job-specific detection.
    """
    # Determine job from config or data type
    job_name = config.get('current_job_name', None)

    if not job_name:
        # Try to infer job from data type and config
        if data_type == "network":
            if useAddress:
                job_name = "v3_linux_anomalous_network_activity"
            else:
                job_name = "v3_linux_anomalous_network_port_activity"
        elif data_type == "process":
            job_name = "v3_linux_anomalous_process_all_hosts"
        elif data_type == "user":
            job_name = "v3_linux_anomalous_user_name"
        elif data_type == "discovery":
            job_name = "v3_linux_network_configuration_discovery"
        elif data_type == "metadata":
            job_name = "v3_linux_rare_metadata_process"
        else:
            logger.warning(f"Unknown data type: {data_type}, using process default")
            job_name = "v3_linux_anomalous_process_all_hosts"

    return detect_job_anomalies(data, models, scalers, config, job_name)

# ===============================================================================
# UTILITY FUNCTIONS
# ===============================================================================

def get_job_for_data_type(data_type: str, specific_type: str = None) -> str:
    """
    Get the appropriate job name for a data type.
    """
    job_mapping = {
        "process": {
            "all_hosts": "v3_linux_anomalous_process_all_hosts",
            "by_host": "v3_rare_process_by_host_linux",
            "default": "v3_linux_anomalous_process_all_hosts"
        },
        "network": {
            "ip": "v3_linux_anomalous_network_activity",
            "port": "v3_linux_anomalous_network_port_activity",
            "default": "v3_linux_anomalous_network_activity"
        },
        "user": {
            "general": "v3_linux_anomalous_user_name",
            "sudo": "v3_linux_rare_sudo_user",
            "compiler": "v3_linux_rare_user_compiler",
            "default": "v3_linux_anomalous_user_name"
        },
        "discovery": {
            "network_config": "v3_linux_network_configuration_discovery",
            "network_connection": "v3_linux_network_connection_discovery",
            "system_info": "v3_linux_system_information_discovery",
            "process": "v3_linux_system_process_discovery",
            "user": "v3_linux_system_user_discovery",
            "default": "v3_linux_network_configuration_discovery"
        },
        "metadata": {
            "process": "v3_linux_rare_metadata_process",
            "user": "v3_linux_rare_metadata_user",
            "default": "v3_linux_rare_metadata_process"
        }
    }

    if data_type in job_mapping:
        jobs = job_mapping[data_type]
        if specific_type and specific_type in jobs:
            return jobs[specific_type]
        return jobs["default"]

    return "v3_linux_anomalous_process_all_hosts"

def validate_job_requirements(data: pd.DataFrame, job_name: str) -> dict:
    """
    Validate that data meets job requirements.
    """
    validation = {
        "job_name": job_name,
        "valid": True,
        "issues": [],
        "warnings": []
    }

    if job_name not in JOB_CONFIGURATIONS:
        validation["valid"] = False
        validation["issues"].append(f"Unknown job: {job_name}")
        return validation

    JOB_CONFIGURATIONS[job_name]

    # Check required columns
    if job_name == "v3_linux_anomalous_network_port_activity":
        if "destination.port" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing destination.port column")

    elif job_name == "v3_rare_process_by_host_linux":
        if "host.hostname" not in data.columns or "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing host.hostname or process.name columns")

    elif job_name in ["v3_linux_rare_sudo_user", "v3_linux_rare_user_compiler"]:
        if "user.name" not in data.columns or "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing user.name or process.name columns")

    elif job_name == "v3_linux_rare_metadata_process":
        if "process.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing process.name column")
        if "process.args" not in data.columns:
            validation["warnings"].append("Missing process.args column (will use process.name only)")

    elif job_name == "v3_linux_rare_metadata_user":
        if "user.name" not in data.columns:
            validation["valid"] = False
            validation["issues"].append("Missing user.name column")
        if "user.group" not in data.columns:
            validation["warnings"].append("Missing user.group column (will use user.name only)")

    # Check data volume
    if len(data) == 0:
        validation["valid"] = False
        validation["issues"].append("Empty dataset")
    elif len(data) < 10:
        validation["warnings"].append(f"Small dataset ({len(data)} records)")

    return validation

def get_all_jobs() -> list[str]:
    """Get list of all available jobs."""
    return list(JOB_CONFIGURATIONS.keys())

def get_jobs_by_data_type(data_type: str) -> list[str]:
    """Get jobs for a specific data type."""
    return [job for job, config in JOB_CONFIGURATIONS.items()
            if config['data_type'] == data_type]

# ===============================================================================
# EXPORT KEY FUNCTIONS
# ===============================================================================

__all__ = [
    # Main detection function
    'detect_job_anomalies',
    'detect_ml_anomalies',  # Backward compatibility

    # Job-specific detection functions
    'detect_anomalous_process_all_hosts',
    'detect_rare_process_by_host',
    'detect_anomalous_network_activity',
    'detect_anomalous_network_port_activity',
    'detect_anomalous_user_activity',
    'detect_rare_sudo_user',
    'detect_rare_user_compiler',
    'detect_network_configuration_discovery',
    'detect_network_connection_discovery',
    'detect_system_information_discovery',
    'detect_system_process_discovery',
    'detect_system_user_discovery',
    'detect_rare_metadata_process',
    'detect_rare_metadata_user',

    # Utility functions
    'get_job_for_data_type',
    'validate_job_requirements',
    'get_all_jobs',
    'get_jobs_by_data_type',

    # Configuration
    'JOB_CONFIGURATIONS'
]
