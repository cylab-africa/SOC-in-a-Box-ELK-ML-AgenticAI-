"""
Main script for running the Linux Anomaly Detection system with MLflow tracking.
Enhanced to support different detection modes and all 14 Linux detection jobs
across 5 data groups: process, network, user, discovery, and metadata.
"""

import argparse
import logging
import os
import sys
import traceback
from datetime import datetime
from logging.handlers import RotatingFileHandler

try:
    import mlflow
    import mlflow.exceptions
    _MLFLOW_AVAILABLE = True
except ImportError:
    _MLFLOW_AVAILABLE = False
    mlflow = None
from dotenv import load_dotenv

load_dotenv()
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)
from anomaly_detector import LinuxAnomalyDetector
from fixedLDS import apply_all_fixes

logger = logging.getLogger("Linux_anomaly_detection")

def setup_logging(log_level='INFO', log_file=None):
    """
    Set up logging configuration.

    Args:
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str, optional): Path to log file
    """
    # Create log directory if needed
    if log_file:
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

    # Set up handlers
    handlers = []

    # Always log to console
    handlers.append(logging.StreamHandler())

    # Add file handler if specified (size-based rotation to bound disk usage)
    if log_file:
        handlers.append(
            RotatingFileHandler(log_file, maxBytes=20 * 1024 * 1024, backupCount=5)
        )

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

    # Return logger for main module
    return logging.getLogger("linux_anomaly_detection")

def setup_mlflow(logger):
    """
    Set up MLflow tracking with DAGsHub.

    Args:
        logger: Logger instance

    Returns:
        bool: True if setup successful, False otherwise
    """
    try:
        # DAGsHub setup - prefer environment variables, fall back to defaults
        dagshub_username = os.getenv("DAGSHUB_USERNAME", "DAGSHUB_USERNAME")
        dagshub_repo_name = os.getenv("DAGSHUB_REPO_NAME", "DAGSHUB_REPO_NAME")
        dagshub_token = os.getenv("DAGSHUB_TOKEN", "DAGSHUB_TOKEN")
        logger.info(f"Using DAGsHub repo: {dagshub_username}/{dagshub_repo_name}")

        # Use a timestamp-based experiment name to avoid collision with deleted experiments
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_experiment_name = f"LINUX_ANOMALY_DETECTION_{timestamp}"
        experiment_name = os.getenv("MLFLOW_EXPERIMENT_NAME", default_experiment_name)

        # Construct tracking URI
        dagshub_mlflow_uri = f"https://dagshub.com/{dagshub_username}/{dagshub_repo_name}.mlflow"

        # Set MLflow credentials
        os.environ["MLFLOW_TRACKING_USERNAME"] = dagshub_username
        os.environ["MLFLOW_TRACKING_PASSWORD"] = dagshub_token

        logger.info(f"Setting MLflow tracking URI: {dagshub_mlflow_uri}")
        mlflow.set_tracking_uri(dagshub_mlflow_uri)

        # Check if the experiment exists and is active
        existing_experiment = mlflow.get_experiment_by_name(experiment_name)

        if existing_experiment:
            # Check if experiment is deleted
            if existing_experiment.lifecycle_stage == "deleted":
                logger.warning(f"Experiment '{experiment_name}' exists but is deleted")
                # Use a new name with timestamp to avoid collision
                new_experiment_name = f"{experiment_name}_{timestamp}"
                logger.info(f"Creating new experiment with name: {new_experiment_name}")
                experiment_name = new_experiment_name
                mlflow.create_experiment(experiment_name)
            else:
                logger.info(f"Using existing active experiment: {experiment_name}")
        else:
            # Create a new experiment
            logger.info(f"Creating new experiment: {experiment_name}")
            mlflow.create_experiment(experiment_name)

        # Set the experiment - THIS IS CRUCIAL
        logger.info(f"Setting MLflow experiment: {experiment_name}")
        mlflow.set_experiment(experiment_name)

        # Verify connection
        experiment = mlflow.get_experiment_by_name(experiment_name)
        if experiment:
            logger.info(f"Successfully connected to MLflow experiment: {experiment_name} (ID: {experiment.experiment_id})")
            return True, experiment.experiment_id
        else:
            logger.error(f"Failed to create or connect to experiment: {experiment_name}")
            return False, None

    except Exception as e:
        logger.error(f"MLflow setup error: {e}")
        logger.debug(f"MLflow setup error details: {traceback.format_exc()}")
        return False, None

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Linux Anomaly Detection System')

    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to configuration file'
    )
    parser.add_argument(
        '--log-level', '-l',
        type=str,
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='Set the logging level'
    )
    parser.add_argument(
        '--log-file', '-f',
        type=str,
        default="logs/linux_anomaly_detection.log",
        help='Path to log file'
    )

    parser.add_argument(
        '--no-baseline', '-n',
        action='store_true',
        default=False,
        help='Skip baseline data collection phase'
    )
    parser.add_argument(
        '--ignore-existing-models', '-i',
        action='store_true',
        default=False,
        help='Ignore existing models and train new ones'
    )
    parser.add_argument(
        '--mlflow-run-name', '-m',
        type=str,
        default=f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help='Custom name for the MLflow run'
    )
    parser.add_argument(
        '--disable-mlflow', '-d',
        action='store_true',
        help='Disable MLflow tracking',
        default=True
    )
    parser.add_argument(
        '--separate-model-runs', '-s',
        action='store_true',
        default=True,
        help='Log each model in a separate MLflow run (default: True)'
    )

    parser.add_argument(
        '--detection-mode',
        type=str,
        choices=['single', 'group', 'comprehensive'],
        default='comprehensive',
        help='Detection mode: single (one job), group (one data group), comprehensive (all groups)'
    )

    parser.add_argument(
        '--job',
        type=str,
        help='Specific detection job to run (for single mode)'
    )

    parser.add_argument(
        '--data-group',
        type=str,
        choices=['process', 'network', 'user', 'discovery', 'metadata', 'auth', 'host'],
        help='Data group to process (for group mode)'
    )

    parser.add_argument(
        '--data-groups',
        type=str,
        nargs='+',
        choices=['process', 'network', 'user', 'discovery', 'metadata', 'auth', 'host'],
        help='Multiple data groups to process (for comprehensive mode)'
    )

    parser.add_argument(
        '--jobs',
        type=str,
        nargs='+',
        help='Specific jobs to run within a data group'
    )

    parser.add_argument(
        '--train-models',
        action='store_true',
        default=False,
        help='Train ML models before detection'
    )

    parser.add_argument(
        '--evaluate-performance',
        action='store_true',
        help='Evaluate detection performance'
    )

    parser.add_argument(
        '--list-jobs',
        action='store_true',
        help='List all supported detection jobs'
    )

    parser.add_argument(
        '--save-visualizations',
        action='store_true',
        default=False,
        help='Generate and save visualizations of results'
    )

    parser.add_argument(
        '--generate-report',
        action='store_true',
        default=True,
        help='Generate comprehensive report of results'
    )

    return parser.parse_args()

def log_detection_results(logger, results, detection_mode, job_name=None, data_group=None):
    """
    Log Linux anomaly detection results to MLflow.

    Args:
        logger: Logger instance
        results: Detection results (DataFrame or dict of DataFrames)
        detection_mode (str): Detection mode used
        job_name (str, optional): Specific job name for single mode
        data_group (str, optional): Data group for group mode
    """
    try:
        mlflow.log_param("detection_mode", detection_mode)

        if detection_mode == 'single' and job_name:
            # Single job results
            mlflow.log_param("job_name", job_name)

            if results is not None and not results.empty:
                anomalies = results[results.get("final_anomaly", False)]
                mlflow.log_metric("total_events", len(results))
                mlflow.log_metric("total_anomalies", len(anomalies))
                mlflow.log_metric("anomaly_rate", len(anomalies) / len(results) if len(results) > 0 else 0.0)

                # Log job-specific metrics
                if 'combined_score' in results.columns:
                    mlflow.log_metric("max_anomaly_score", results['combined_score'].max())
                    mlflow.log_metric("mean_anomaly_score", results['combined_score'].mean())

                logger.info(f"Single job {job_name}: {len(anomalies)} anomalies from {len(results)} events")
            else:
                mlflow.log_metric("total_events", 0)
                mlflow.log_metric("total_anomalies", 0)
                logger.info(f"Single job {job_name}: No results")

        elif detection_mode == 'group' and data_group:
            # Group results
            mlflow.log_param("data_group", data_group)

            total_events = 0
            total_anomalies = 0
            job_count = 0

            for job_name, job_results in results.items():
                if job_results is not None and not job_results.empty:
                    job_events = len(job_results)
                    job_anomalies = len(job_results[job_results.get("final_anomaly", False)])

                    total_events += job_events
                    total_anomalies += job_anomalies
                    job_count += 1

                    # Log individual job metrics
                    mlflow.log_metric(f"{job_name}_events", job_events)
                    mlflow.log_metric(f"{job_name}_anomalies", job_anomalies)
                    mlflow.log_metric(f"{job_name}_rate", job_anomalies / job_events if job_events > 0 else 0.0)

            mlflow.log_metric("total_events", total_events)
            mlflow.log_metric("total_anomalies", total_anomalies)
            mlflow.log_metric("overall_anomaly_rate", total_anomalies / total_events if total_events > 0 else 0.0)
            mlflow.log_metric("jobs_processed", job_count)

            logger.info(f"Group {data_group}: {total_anomalies} anomalies from {total_events} events across {job_count} jobs")

        elif detection_mode == 'comprehensive':
            # Comprehensive results
            total_events = 0
            total_anomalies = 0
            total_jobs = 0
            group_count = 0

            group_summaries = {}

            for group_name, group_results in results.items():
                group_events = 0
                group_anomalies = 0
                group_jobs = 0

                for job_name, job_results in group_results.items():
                    if job_results is not None and not job_results.empty:
                        job_events = len(job_results)
                        job_anomalies = len(job_results[job_results.get("final_anomaly", False)])

                        group_events += job_events
                        group_anomalies += job_anomalies
                        group_jobs += 1

                        # Log individual job metrics
                        mlflow.log_metric(f"{group_name}_{job_name}_events", job_events)
                        mlflow.log_metric(f"{group_name}_{job_name}_anomalies", job_anomalies)

                if group_events > 0:
                    # Log group-level metrics
                    mlflow.log_metric(f"{group_name}_total_events", group_events)
                    mlflow.log_metric(f"{group_name}_total_anomalies", group_anomalies)
                    mlflow.log_metric(f"{group_name}_anomaly_rate", group_anomalies / group_events)
                    mlflow.log_metric(f"{group_name}_jobs_processed", group_jobs)

                    group_summaries[group_name] = {
                        "events": group_events,
                        "anomalies": group_anomalies,
                        "rate": group_anomalies / group_events,
                        "jobs": group_jobs
                    }

                    total_events += group_events
                    total_anomalies += group_anomalies
                    total_jobs += group_jobs
                    group_count += 1

            # Log overall metrics
            mlflow.log_metric("total_events", total_events)
            mlflow.log_metric("total_anomalies", total_anomalies)
            mlflow.log_metric("overall_anomaly_rate", total_anomalies / total_events if total_events > 0 else 0.0)
            mlflow.log_metric("total_jobs_processed", total_jobs)
            mlflow.log_metric("groups_processed", group_count)

            # Log group participation
            mlflow.log_param("groups_processed", list(group_summaries.keys()))

            logger.info(f"Comprehensive detection: {total_anomalies} anomalies from {total_events} events "
                       f"across {total_jobs} jobs in {group_count} groups")

            # Log detailed group summaries
            for group_name, summary in group_summaries.items():
                logger.info(f"  {group_name}: {summary['anomalies']}/{summary['events']} "
                           f"({summary['rate']:.2%}) across {summary['jobs']} jobs")

    except Exception as e:
        logger.warning(f"Error logging detection results: {e}")
        logger.debug(traceback.format_exc())

def monkey_patch_model_training(logger, use_separate_runs=True, parent_run_id=None):
    """
    Monkey patch the model training functions to add MLflow logging.
    This allows us to track models without modifying the original code.

    Args:
        logger: Logger instance
        use_separate_runs: Whether to log each model in a separate MLflow run
        parent_run_id: ID of the parent run for nested runs
    """
    try:
        # Import the model manager from the Linux detector
        import functools

        from model_manager import LinuxModelManager

        # Get the original train_models method
        original_train_models = LinuxModelManager.train_models

        @functools.wraps(original_train_models)
        def train_models_with_mlflow(self, data, data_type):
            # Call the original method
            models, scalers, baselines = original_train_models(self, data, data_type)

            # Log training information
            if models:
                model_count = len(models) if isinstance(models, dict) else 1
                logger.info(f"Training completed for {data_type}: {model_count} models")

                if use_separate_runs:
                    mlflow.log_param(f"{data_type}_model_count", model_count)
                    mlflow.log_param(f"{data_type}_training_data_size", len(data))

                    # Log model names
                    if isinstance(models, dict):
                        mlflow.log_param(f"{data_type}_model_names", list(models.keys()))

            return models, scalers, baselines

        # Replace the original method
        LinuxModelManager.train_models = train_models_with_mlflow
        logger.info("Successfully monkey-patched Linux model training function for MLflow tracking")

    except Exception as e:
        logger.error(f"Failed to monkey patch model training: {e}")
        logger.debug(f"Monkey patch error details: {traceback.format_exc()}")

def generate_visualizations_and_reports(detector, results, args, logger):
    """
    Generate visualizations and reports for detection results.

    Args:
        detector: LinuxAnomalyDetector instance
        results: Detection results
        args: Command line arguments
        logger: Logger instance

    Returns:
        tuple: Paths to generated visualizations and reports
    """
    try:
        # Import visualization functions
        from visualizer import create_linux_visualizations, generate_linux_report

        viz_paths = []
        report_paths = []

        if args.detection_mode == 'single':
            # Single job visualization
            if not results.empty and args.save_visualizations:
                logger.info(f"Generating visualizations for job: {args.job}")
                results, _ = apply_all_fixes(results, detector.config, args.data_group or "process")
                job_viz_paths = create_linux_visualizations(results, detector.config,
                                                           data_type=args.data_group or "process")
                viz_paths.extend(job_viz_paths)

            # Single job report
            if not results.empty and args.generate_report:
                logger.info(f"Generating report for job: {args.job}")
                report_file, data_file = generate_linux_report(results, detector.config,
                                                             data_type=args.data_group or "process")
                if report_file:
                    report_paths.append(report_file)

        elif args.detection_mode == 'group':
            # Group visualizations
            if args.save_visualizations:
                logger.info(f"Generating visualizations for group: {args.data_group}")
                results, _ = apply_all_fixes(results, detector.config, args.data_group)
                group_viz_paths = create_linux_visualizations(results, detector.config, data_type=args.data_group)
                viz_paths.extend(group_viz_paths)

            # Group report
            if args.generate_report:
                logger.info(f"Generating report for group: {args.data_group}")
                report_file, data_file = generate_linux_report(results, detector.config, data_type=args.data_group)
                if report_file:
                    report_paths.append(report_file)

        elif args.detection_mode == 'comprehensive':
            # Comprehensive visualizations and reports for each group
            for group_name, group_results in results.items():
                if args.save_visualizations:
                    logger.info(f"Generating visualizations for group: {group_name}")
                    group_results, _ = apply_all_fixes(group_results, detector.config, group_name)
                    group_viz_paths = create_linux_visualizations(group_results, detector.config, data_type=group_name)
                    viz_paths.extend(group_viz_paths)

                if args.generate_report:
                    logger.info(f"Generating report for group: {group_name}")
                    report_file, data_file = generate_linux_report(group_results, detector.config, data_type=group_name)
                    if report_file:
                        report_paths.append(report_file)

        # Log summary
        if viz_paths:
            logger.info(f"Generated {len(viz_paths)} visualizations")
        if report_paths:
            logger.info(f"Generated {len(report_paths)} reports")

        return viz_paths, report_paths

    except Exception as e:
        logger.error(f"Error generating visualizations and reports: {e}")
        # logger.debug(f"Visualization error details: {traceback.format_exc()}")
        return [], []

def run_detection_process(args, logger, parent_run_id=None):
    """
    Run the actual Linux detection process.

    Args:
        args: Command line arguments
        logger: Logger instance
        parent_run_id: ID of the parent run for nested runs

    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    try:
        # Initialize Linux anomaly detector
        logger.info("Initializing LinuxAnomalyDetector")
        detector = LinuxAnomalyDetector(config_path=args.config)
        # fixed_data, fixed_config = apply_all_fixes(data, config, data_type='process')
        from fixedLDS import ConfigManager
        detector.config = ConfigManager.fix_config(detector.config)

        anomalies_file = None

        # Handle list jobs request
        if args.list_jobs:
            jobs = detector.list_supported_jobs()
            logger.info("Supported Linux Anomaly Detection Jobs:")
            for group, job_list in jobs.items():
                logger.info(f"\n{group.upper()} Group:")
                for job in job_list:
                    description = detector.get_job_description(job)
                    logger.info(f"  - {job}: {description}")
            return 0

        # Train models if requested
        if args.train_models:
            logger.info("Training models before detection")
            if args.data_group:
                success = detector.train_models_for_group(args.data_group, retrain=True)
                if not success:
                    logger.error(f"Failed to train models for {args.data_group}")
                    return 1
            else:
                # Train all groups
                for group in detector.detection_jobs.keys():
                    success = detector.train_models_for_group(group, retrain=True)
                    if not success:
                        logger.warning(f"Failed to train models for {group}")

        # Log detection configuration
        if not args.disable_mlflow:
            mlflow.log_param("use_baseline", not args.no_baseline)
            mlflow.log_param("load_existing_models", not args.ignore_existing_models)
            mlflow.log_param("config_path", args.config if args.config else "default")

        # Run detection based on mode
        results = None
        use_baseline = not args.no_baseline
        load_existing_models = not args.ignore_existing_models

        if args.detection_mode == 'single':
            if not args.job:
                logger.error("Job name required for single detection mode")
                return 1

            logger.info(f"Running single detection job: {args.job}")
            results = detector.run_single_detection_job(
                args.job,
                data_type=args.data_group,
                use_baseline=use_baseline,
                load_existing_models=load_existing_models
            )

            if not args.disable_mlflow:
                log_detection_results(logger, results, args.detection_mode, job_name=args.job)

            if results is not None and not results.empty:
                data_type = args.data_group or "unknown"
                anomalies_file = detector.extract_and_save_anomalies({
                    data_type: {args.job: results}
                })
                logger.info(f"Saved anomalies to: {anomalies_file}")

        elif args.detection_mode == 'group':
            if not args.data_group:
                logger.error("Data group required for group detection mode")
                return 1

            logger.info(f"Running group detection for: {args.data_group}")
            results = detector.run_data_group_detection(
                args.data_group,
                jobs=args.jobs,
                use_baseline=use_baseline,
                load_existing_models=load_existing_models
            )

            total_anomalies = getattr(detector, "last_anomaly_count", 0)
            logger.info(f"Total anomalies detected in group {args.data_group}: {total_anomalies}")

            if not args.disable_mlflow:
                log_detection_results(logger, results, args.detection_mode, data_group=args.data_group)
                mlflow.log_metric("total_anomalies", total_anomalies)

            if results:
                anomalies_file = detector.extract_and_save_anomalies({
                    args.data_group: results
                })
                logger.info(f"Saved anomalies to: {anomalies_file}")

        elif args.detection_mode == 'comprehensive':
            logger.info("Running comprehensive Linux anomaly detection")
            results = detector.run_comprehensive_detection(
                data_groups=args.data_groups,
                use_baseline=use_baseline,
                train_models=args.train_models,
                force_retrain=args.ignore_existing_models
            )

            if not args.disable_mlflow:
                log_detection_results(logger, results, args.detection_mode)

            if results:
                anomalies_file = detector.extract_and_save_anomalies(results)
                logger.info(f"Saved anomalies to: {anomalies_file}")

        # Generate visualizations and reports if requested
        if (args.save_visualizations or args.generate_report) and results is not None:
            try:
                viz_paths, report_paths = generate_visualizations_and_reports(
                    detector, results, args, logger
                )

                if not args.disable_mlflow:
                    for viz_path in viz_paths:
                        if os.path.exists(viz_path):
                            mlflow.log_artifact(viz_path, "visualizations")

                    for report_path in report_paths:
                        if os.path.exists(report_path):
                            mlflow.log_artifact(report_path, "reports")
            except Exception as viz_error:
                logger.error(f"Error generating visualizations and reports: {viz_error}")

        # Evaluate performance if requested
        if args.evaluate_performance:
            logger.info("Evaluating detection performance")
            evaluation = detector.evaluate_detection_performance(args.data_group)

            if not args.disable_mlflow:
                overall_metrics = evaluation.get("overall_metrics", {})
                for metric, value in overall_metrics.items():
                    mlflow.log_metric(f"eval_{metric}", value)

            logger.info(f"Performance evaluation completed: "
                        f"{overall_metrics.get('overall_detection_rate', 0):.2%} detection rate")

        # Save detection results to MLflow artifacts
        if not args.disable_mlflow and results is not None:
            import json
            import tempfile

            try:
                with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as tmp:
                    result_path = tmp.name

                    if isinstance(results, dict):
                        serializable_results = {}
                        for key, value in results.items():
                            if isinstance(value, dict):
                                serializable_results[key] = {
                                    k: v.to_dict('records') if hasattr(v, 'to_dict') else str(v)
                                    for k, v in value.items()
                                }
                            else:
                                serializable_results[key] = value.to_dict('records') if hasattr(value, 'to_dict') else str(value)
                    else:
                        serializable_results = results.to_dict('records') if hasattr(results, 'to_dict') else str(results)

                    json.dump(serializable_results, tmp, indent=2, default=str)

                mlflow.log_artifact(result_path, "detection_results")
                logger.info("Saved detection results to MLflow artifacts")

                os.unlink(result_path)

            except Exception as e:
                logger.warning(f"Failed to log results as artifact: {e}")

        logger.info("Linux anomaly detection completed successfully")
        return 0

    except Exception as e:
        logger.error(f"Error in detection process: {e}")
        logger.debug(f"Detection process error details: {traceback.format_exc()}")

        if not args.disable_mlflow:
            try:
                mlflow.log_param("error", str(e))
            except Exception:
                pass

        return 1

def main():
    """Main function with error handling."""
    try:
        # Parse command-line arguments
        args = parse_arguments()

        # Set up logging
        logger = setup_logging(args.log_level, args.log_file)

        logger.info("Starting Linux Anomaly Detection System")
        logger.info(f"Detection mode: {args.detection_mode}")

        # Force disable mlflow if not installed
        if not _MLFLOW_AVAILABLE:
            args.disable_mlflow = True

        # Setup MLflow if not disabledF
        if not args.disable_mlflow:
            # Try to restore the deleted experiment first (if that's the issue)
            try:
                # Check if we can find the deleted experiment
                client = mlflow.tracking.MlflowClient()
                deleted_experiments = [exp for exp in client.search_experiments()
                                     if exp.name == "LINUX_ANOMALY_DETECTION" and
                                        exp.lifecycle_stage == "deleted"]

                if deleted_experiments:
                    exp_id = deleted_experiments[0].experiment_id
                    logger.info(f"Found deleted experiment 'LINUX_ANOMALY_DETECTION' with ID {exp_id}. Attempting to restore...")
                    try:
                        # Try to restore the deleted experiment
                        client.restore_experiment(exp_id)
                        logger.info("Successfully restored experiment 'LINUX_ANOMALY_DETECTION'")
                    except Exception as restore_err:
                        logger.warning(f"Failed to restore experiment: {restore_err}")
            except Exception as search_err:
                logger.debug(f"Error searching for deleted experiments: {search_err}")

            # Continue with regular setup
            mlflow_setup_success, experiment_id = setup_mlflow(logger)

            if mlflow_setup_success:
                try:
                    # Start MLflow run with error handling
                    logger.info(f"Starting MLflow parent run: {args.mlflow_run_name}")
                    with mlflow.start_run(run_name=args.mlflow_run_name) as parent_run:
                        # Get parent run ID for nested runs
                        parent_run_id = parent_run.info.run_id

                        # Set parent run tags
                        mlflow.set_tag("run_type", "parent")
                        mlflow.set_tag("detection_mode", args.detection_mode)
                        mlflow.set_tag("system_type", "linux")

                        # Log run parameters
                        mlflow.log_param("baseline_used", not args.no_baseline)
                        mlflow.log_param("existing_models_used", not args.ignore_existing_models)
                        mlflow.log_param("separate_model_runs", args.separate_model_runs)
                        mlflow.log_param("train_models", args.train_models)
                        mlflow.log_param("evaluate_performance", args.evaluate_performance)
                        mlflow.log_param("save_visualizations", args.save_visualizations)
                        mlflow.log_param("generate_report", args.generate_report)

                        # Setup model training with MLflow tracking
                        monkey_patch_model_training(
                            logger,
                            use_separate_runs=args.separate_model_runs,
                            parent_run_id=parent_run_id
                        )

                        # Run the main detection process and track it
                        result = run_detection_process(args, logger, parent_run_id)

                    return result

                except mlflow.exceptions.RestException as e:
                    logger.error(f"MLflow REST error: {e}")
                    logger.info("Continuing without MLflow tracking...")
                    args.disable_mlflow = True

                except Exception as e:
                    logger.error(f"MLflow error: {e}")
                    logger.debug(f"MLflow error details: {traceback.format_exc()}")
                    logger.info("Continuing without MLflow tracking...")
                    args.disable_mlflow = True
            else:
                logger.warning("MLflow setup failed, continuing without tracking")
                args.disable_mlflow = True

        # Run without MLflow tracking if disabled or setup failed
        return run_detection_process(args, logger)

    except Exception as e:
        print(f"Critical error: {e}")
        print(traceback.format_exc())
        return 1

    finally:
        try:
            # Clean up MLflow resources if needed
            if not args.disable_mlflow:
                pass
        except:
            pass

if __name__ == "__main__":
    sys.exit(main())
