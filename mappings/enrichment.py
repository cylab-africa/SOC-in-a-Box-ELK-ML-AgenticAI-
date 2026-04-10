"""
MITRE ATT&CK enrichment for anomaly alerts.

Adds technique IDs, tactic names, kill chain phases, and investigation
hints to each alert before push to Elasticsearch.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Load attack mapping from JSON at module level
_MAPPING_FILE: Path = Path(__file__).parent / "attack_mapping.json"
_ATTACK_MAPPING: dict[str, Any] = {}

if _MAPPING_FILE.exists():
    _ATTACK_MAPPING = json.loads(_MAPPING_FILE.read_text())


# Investigation hints keyed by technique ID
INVESTIGATION_HINTS: dict[str, str] = {
    "T1059": "Check command line for encoded payloads, unusual interpreters, or LOLBin chains.",
    "T1036": "Compare process binary hash to known-good. Check if binary was recently placed or renamed.",
    "T1071": "Inspect destination IP/domain reputation. Check for beaconing patterns or data volume spikes.",
    "T1048": "Examine destination port and protocol. Look for DNS tunneling or encrypted exfil channels.",
    "T1078": "Review login location, time, and source IP. Check for impossible travel or credential sharing.",
    "T1136": "Verify account creation was authorized. Check if account has elevated privileges.",
    "T1548": "Review sudo/su context. Check if escalation is expected for this user and time.",
    "T1016": "Correlate with other discovery commands. Single occurrence may be admin activity.",
    "T1049": "Check if user normally runs netstat/ss. Correlate with lateral movement indicators.",
    "T1082": "Verify system enumeration context. Correlate with initial access or post-exploitation.",
    "T1057": "Check if process listing is part of normal workflow or preceded by suspicious login.",
    "T1033": "Correlate user discovery with account enumeration (T1087) or privilege escalation.",
    "T1046": "Check for port scan patterns. Correlate with subsequent connection attempts.",
    "T1041": "Examine data flow volume. Compare with baseline egress for this host.",
    "T1055": "Check for unusual parent-child process relationships and memory injection indicators.",
    "T1105": "Verify download source reputation. Check downloaded file hash against threat intel.",
    "T1571": "Non-standard port usage. Verify if application normally uses this port.",
    "T1087": "Account enumeration detected. Correlate with subsequent lateral movement.",
    "T1588": "Capability building detected. Check for compiler/tool usage outside normal dev workflow.",
    "T1027": "Obfuscated execution detected. Decode and analyze the payload.",
    "T1568": "Dynamic resolution detected. Check for DGA patterns or fast-flux DNS.",
    "T1110": "Brute force detected. Check source IP reputation and lock-out policy.",
}


def enrich_alert(alert: dict[str, Any], job_name: str) -> dict[str, Any]:
    """Add MITRE ATT&CK enrichment fields to an alert document.

    Adds: mitre.techniques, mitre.tactics, mitre.kill_chain_phase,
    and investigation_hints based on the ML job that generated the alert.

    Args:
        alert: Mutable alert document dict (modified in-place).
        job_name: ML job identifier (e.g. 'v3_linux_anomalous_process_all_hosts').

    Returns:
        The enriched alert dict.
    """
    mapping = _ATTACK_MAPPING.get(job_name, {})
    techniques = mapping.get("techniques", [])
    kill_chain = mapping.get("kill_chain_phase", "unknown")

    # Build enrichment fields
    technique_ids = [t["id"] for t in techniques]
    technique_names = [f"{t['id']} - {t['name']}" for t in techniques]
    tactics = list({t["tactic"] for t in techniques})

    # Collect investigation hints for all mapped techniques
    hints = [
        INVESTIGATION_HINTS[tid]
        for tid in technique_ids
        if tid in INVESTIGATION_HINTS
    ]

    # Write to alert
    alert["mitre"] = {
        "techniques": technique_ids,
        "technique_names": technique_names,
        "tactics": tactics,
        "kill_chain_phase": kill_chain,
    }
    alert["investigation_hints"] = hints

    return alert


def get_techniques_for_job(job_name: str) -> list[dict[str, str]]:
    """Return the MITRE ATT&CK techniques mapped to a given ML job.

    Args:
        job_name: ML job identifier.

    Returns:
        List of technique dicts with 'id', 'name', 'tactic' keys.
    """
    mapping = _ATTACK_MAPPING.get(job_name, {})
    return mapping.get("techniques", [])


def get_kill_chain_phase(job_name: str) -> str:
    """Return the kill chain phase for a given ML job.

    Args:
        job_name: ML job identifier.

    Returns:
        Kill chain phase string (e.g. 'execution', 'command_and_control').
    """
    mapping = _ATTACK_MAPPING.get(job_name, {})
    return mapping.get("kill_chain_phase", "unknown")
