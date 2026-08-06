"""
MITRE ATT&CK-aligned alert mappings and enrichment.

Provides job-to-technique mapping, investigation hints, and ES index
templates for the anomaly detection pipeline.
"""

from mappings.enrichment import (
    INVESTIGATION_HINTS,
    enrich_alert,
    get_kill_chain_phase,
    get_techniques_for_job,
)

__all__ = [
    "enrich_alert",
    "get_kill_chain_phase",
    "get_techniques_for_job",
    "INVESTIGATION_HINTS",
]
