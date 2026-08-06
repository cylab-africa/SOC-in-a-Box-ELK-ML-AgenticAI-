#!/usr/bin/env python3
"""Train models in the background with checkpoint-based resume.

Usage examples:
  # Train all groups with automatic resume on failure
  nohup python3 -u train_models_background.py --all --restart-on-fail > logs/trainer.log 2>&1 &

  # Train specific groups
  python3 train_models_background.py --groups process network --restart-on-fail

  # Resume from a previous interrupted run
  python3 train_models_background.py --all --skip-existing --restart-on-fail

This script wraps the anomaly_detector training pipeline with:
  - JSON checkpoint per group (resume from last completed group on crash)
  - SIGINT/SIGTERM signal handlers for graceful stop with checkpoint save
  - --restart-on-fail: automatic retry loop on unhandled exceptions
  - Atomic model save (handled by model_manager.save_models)
"""

import os
import json
import time
import signal
import argparse
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("train_models_background")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

ALL_GROUPS = ["process", "network", "user", "discovery", "metadata", "auth", "host"]
DEFAULT_CHECKPOINT_PATH = "results/training_checkpoint.json"


def load_checkpoint(path: str) -> dict:
    """Load checkpoint state from disk."""
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Failed to load checkpoint %s: %s", path, exc)
    return {}


def save_checkpoint(path: str, state: dict) -> None:
    """Persist checkpoint state to disk."""
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)
    except Exception as exc:
        logger.warning("Failed to save checkpoint: %s", exc)


def main() -> None:
    """Entry point for background training with checkpoint resume."""
    parser = argparse.ArgumentParser(
        description="Train models in background with checkpoint resume"
    )
    parser.add_argument(
        "--groups",
        nargs="+",
        choices=ALL_GROUPS,
        help="Data groups to train (default: all)",
    )
    parser.add_argument(
        "--all", action="store_true", help="Train all data groups"
    )
    parser.add_argument(
        "--checkpoint-file",
        type=str,
        default=DEFAULT_CHECKPOINT_PATH,
        help="Path to checkpoint file",
    )
    parser.add_argument(
        "--restart-on-fail",
        action="store_true",
        help="Restart training automatically on crash (30s backoff)",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help="Skip groups already marked complete in checkpoint",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without executing",
    )
    args = parser.parse_args()

    groups = ALL_GROUPS if (args.all or not args.groups) else list(args.groups)
    checkpoint_path = args.checkpoint_file
    checkpoint = load_checkpoint(checkpoint_path)

    # If previous run completed fully, reset checkpoint
    if checkpoint.get("_status") == "all_groups_complete":
        logger.info("Previous run completed; starting fresh")
        checkpoint = {}
        save_checkpoint(checkpoint_path, checkpoint)

    stop_requested: dict = {"flag": False}

    def _handle_signal(signum: int, frame: object) -> None:
        logger.warning(
            "Received signal %d; saving checkpoint and requesting graceful stop...",
            signum,
        )
        save_checkpoint(checkpoint_path, checkpoint)
        stop_requested["flag"] = True

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    def run_training() -> None:
        # Lazy import so the heavy ML stack loads only once
        from anomaly_detector import LinuxAnomalyDetector

        detector = LinuxAnomalyDetector()

        for group in groups:
            if stop_requested["flag"]:
                logger.info("Stop requested; breaking before group %s", group)
                break

            # Skip completed groups
            group_state = checkpoint.get(group, {})
            if args.skip_existing and group_state.get("status") == "complete":
                logger.info(
                    "Skipping %s (checkpoint: completed at %s)",
                    group,
                    group_state.get("completed_at", "?"),
                )
                continue

            if group not in detector.detection_jobs:
                logger.warning(
                    "Group '%s' not recognized by detector; skipping", group
                )
                continue

            logger.info("=== Training group: %s ===", group)
            checkpoint[group] = {
                "status": "in_progress",
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            save_checkpoint(checkpoint_path, checkpoint)

            if args.dry_run:
                logger.info("DRY-RUN: would train group %s", group)
                checkpoint[group] = {"status": "complete", "completed_at": datetime.now(timezone.utc).isoformat()}
                save_checkpoint(checkpoint_path, checkpoint)
                continue

            try:
                success = detector.train_models_for_group(group, retrain=True)
            except Exception as exc:
                logger.error("Training failed for group %s: %s", group, exc)
                checkpoint[group] = {
                    "status": "failed",
                    "error": str(exc),
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                }
                save_checkpoint(checkpoint_path, checkpoint)
                continue

            if success:
                checkpoint[group] = {
                    "status": "complete",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                }
                logger.info("Group %s trained successfully", group)
            else:
                checkpoint[group] = {
                    "status": "failed",
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                }
                logger.error("Group %s training returned failure", group)

            save_checkpoint(checkpoint_path, checkpoint)

        # Mark full completion if all groups succeeded
        if not stop_requested["flag"]:
            all_ok = all(
                checkpoint.get(g, {}).get("status") == "complete" for g in groups
            )
            if all_ok:
                checkpoint["_status"] = "all_groups_complete"
                checkpoint["_completed_at"] = datetime.now(timezone.utc).isoformat()
                logger.info("All groups trained successfully")
            else:
                failed = [
                    g for g in groups
                    if checkpoint.get(g, {}).get("status") != "complete"
                ]
                logger.warning("Training incomplete; failed groups: %s", failed)
            save_checkpoint(checkpoint_path, checkpoint)
        else:
            logger.info("Training interrupted; checkpoint preserved for resume")

    # Self-restart loop
    if args.restart_on_fail:
        while True:
            try:
                run_training()
                break
            except KeyboardInterrupt:
                logger.info("KeyboardInterrupt; exiting")
                break
            except Exception as exc:
                logger.error(
                    "Training crashed: %s. Restarting in 30 seconds...", exc
                )
                time.sleep(30)
    else:
        run_training()


if __name__ == "__main__":
    main()
