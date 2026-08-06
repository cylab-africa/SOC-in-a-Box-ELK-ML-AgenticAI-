#!/usr/bin/env python3
"""One-off builder for SIEM_Infrastructure_Monitor_Reproduction_Guide.docx."""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt

OUT = Path(__file__).resolve().parent / "SIEM_Infrastructure_Monitor_Reproduction_Guide.docx"


def _p(doc: Document, text: str, bold: bool = False) -> None:
    p = doc.add_paragraph()
    r = p.add_run(text)
    r.bold = bold
    r.font.size = Pt(11)


def _bullets(doc: Document, items: list[str]) -> None:
    for item in items:
        doc.add_paragraph(item, style="List Bullet")


def _numbered(doc: Document, items: list[str]) -> None:
    for item in items:
        doc.add_paragraph(item, style="List Number")


def main() -> None:
    doc = Document()

    t = doc.add_heading(
        "SIEM Infrastructure Monitor—Reproduction Guide", level=0
    )
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run(
        "Companion to the SIEM-Maintenance infrastructure monitoring specification\n"
        "Version 1.0 — April 2026"
    )
    r.italic = True
    r.font.size = Pt(11)

    doc.add_paragraph()

    doc.add_heading("1. Purpose", level=1)
    _p(
        doc,
        "This guide is written so an operator can reproduce the infrastructure "
        "monitoring subsystem described in the SIEM-Maintenance pattern document: "
        "host and Elasticsearch health, Elastic Agent status, data freshness, "
        "low-noise Google Chat alerting (transition-based bands plus per-category "
        "cooldown), optional guarded auto-remediation for seven Elasticsearch "
        "issue types, and a daily executive report. It assumes the production "
        "package is supplied as the official release tarball (not reconstructed "
        "from documentation excerpts).",
    )

    doc.add_heading("2. What you are reproducing", level=1)
    _p(doc, "Four monitoring surfaces, five independent scheduler jobs:", bold=True)
    _bullets(
        doc,
        [
            "Host OS (psutil): CPU load averages, memory, swap, disk, open file "
            "descriptors—typically every 30 seconds.",
            "Elasticsearch cluster: health, node JVM/FS/thread_pool stats, shard "
            "cat—typically every 2 hours.",
            "Elastic Agents: search of `.fleet-agents` for offline / drift "
            "conditions—typically every 30 minutes.",
            "Data freshness: latest `@timestamp` per critical data stream vs wall "
            "clock—typically every 6 hours per group.",
            "Daily executive report: cron (e.g. 08:30 local).",
        ],
    )
    _p(
        doc,
        "State survives restarts via files under `/var/lib/siem-maint/` "
        "(band transitions, cooldown timestamps, remediation audit JSONL).",
    )

    doc.add_heading("3. Prerequisites (complete before install)", level=1)
    table = doc.add_table(rows=1, cols=2)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Requirement"
    hdr[1].text = "Details"
    rows = [
        (
            "Target host",
            "Ubuntu 22.04 or 24.04 LTS; Python 3.10+. Minimum sizing example from "
            "spec: 2 vCPU, 2 GB RAM, 10 GB disk (adjust for your environment).",
        ),
        (
            "Release artifact",
            "Official `siem-maint-<version>.tar.gz` with `siem_maint/` package, "
            "`requirements.txt`, `setup.cfg`, and deployment README.",
        ),
        (
            "Elasticsearch access",
            "Service account with read access to `.fleet-agents`, endpoint data "
            "streams (e.g. `.ds-logs-endpoint.events.*`), and cluster APIs "
            "(`_cluster/health`, `_nodes/stats`, `_cat/shards`). If remediation "
            "is enabled: permissions for `_cluster/settings`, cache clear, "
            "forcemerge, ILM retry, reroute as per policy.",
        ),
        (
            "TLS",
            "Cluster CA path for `ES_CA_CERT` when using internal CA; avoid "
            "`ES_VERIFY_CERTS=false` outside labs.",
        ),
        (
            "Google Chat",
            "Incoming webhook URL for the SIEM-MAINTENANCE space (not SOC "
            "security alerting).",
        ),
        (
            "OpenAI (optional)",
            "API key only if the GPT-4 recommendation path is enabled; otherwise "
            "canned fallback applies.",
        ),
    ]
    for a, b in rows:
        row = table.add_row().cells
        row[0].text = a
        row[1].text = b

    doc.add_heading("4. Critical alignment with the installed package", level=1)
    _p(
        doc,
        "Before enabling systemd, confirm the Python module entry point matches "
        "the tree on disk:",
        bold=True,
    )
    _bullets(
        doc,
        [
            "If the application entry is `siem_maint/__main__.py` implementing "
            "`main()`, the standard invocation is "
            "`/opt/siem-maint/venv/bin/python -m siem_maint` (not "
            "`siem_maint.monitor` unless a `monitor.py` or `monitor/` package "
            "exists).",
            "Keep `ExecStart` in the systemd unit identical to whatever "
            "`python -m ...` the tarball exports and what `pip install -e` "
            "registers.",
            "Ensure the executive summary’s “nine collectors vs five jobs” "
            "wording matches the implementation (either rename for clarity or "
            "document sub-steps inside grouped jobs).",
        ],
    )

    doc.add_heading("5. Deployment procedure (reproducible sequence)", level=1)

    doc.add_heading("Step A — System packages", level=2)
    _p(doc, "As root, install Python toolchain and curl:", bold=True)
    p = doc.add_paragraph()
    p.style = "Normal"
    run = p.add_run(
        "sudo apt-get update && sudo apt-get install -y "
        "python3 python3-venv python3-pip python3-dev "
        "build-essential ca-certificates curl"
    )
    run.font.name = "Courier New"
    run.font.size = Pt(9)

    doc.add_heading("Step B — Service user and directories", level=2)
    _numbered(
        doc,
        [
            "Create system user `siem-maint` (no login shell per spec).",
            "Create `/opt/siem-maint`, `/var/lib/siem-maint`, `/etc/siem-maint`. "
            "Ownership: `siem-maint` owns opt and var; root owns `/etc/siem-maint` "
            "with group `siem-maint` and mode 750 on the env directory.",
        ],
    )

    doc.add_heading("Step C — Install the package", level=2)
    _numbered(
        doc,
            [
            "Extract tarball into `/opt/siem-maint` with ownership `siem-maint`.",
            "Create venv: `python3 -m venv /opt/siem-maint/venv`.",
            "`pip install -r requirements.txt` then `pip install -e /opt/siem-maint` "
            "(editable install is required so `python -m siem_maint` resolves).",
            "Smoke test: `python -c \"import siem_maint; print(siem_maint.__version__)\"` "
            "using the venv interpreter.",
        ],
    )

    doc.add_heading("Step D — Environment file", level=2)
    _p(doc, "Create `/etc/siem-maint/env` (mode 640, root:siem-maint) with:", bold=True)
    _bullets(
        doc,
        [
            "`ES_HOST`, `ES_USER`, `ES_PASS`, TLS variables (`ES_CA_CERT`, "
            "`ES_VERIFY_CERTS`).",
            "`CHAT_WEBHOOK` for SIEM-MAINTENANCE.",
            "Optional `OPENAI_API_KEY`.",
            "Tunables: `ES_ALERT_COOLDOWN_HOURS`, `DATA_FRESHNESS_CRITICAL_HOURS`, "
            "`HOST_CPU_CRITICAL_PERCENT` as documented in the spec.",
        ],
    )

    doc.add_heading("Step E — Pre-flight validation", level=2)
    _p(doc, "Run as `siem-maint` with env loaded:", bold=True)
    p = doc.add_paragraph()
    run = p.add_run(
        "sudo -u siem-maint env $(sudo cat /etc/siem-maint/env | xargs) "
        "/opt/siem-maint/venv/bin/python -m siem_maint --check-config\n"
        "# If your package uses a different -m target, substitute it here."
    )
    run.font.name = "Courier New"
    run.font.size = Pt(9)
    _bullets(
        doc,
        [
            "Run one-shot probes: `--once host|cluster|agents|freshness` as "
            "provided by the release.",
            "If remediation will run in production: `--dry-run-remediation` "
            "against staging or production read policy first.",
        ],
    )

    doc.add_heading("Step F — systemd unit", level=2)
    _p(doc, "Install unit with `User=siem-maint`, `EnvironmentFile=/etc/siem-maint/env`, "
            "`ExecStart` pointing to venv + correct `-m` module, "
            "`ExecReload=kill -HUP $MAINPID`, `Restart=on-failure`, "
            "`RestartSec=30`, `After=network-online.target`.", bold=True)
    _p(doc, "Then: `daemon-reload`, `enable --now`, verify `systemctl status` and "
            "`journalctl -u siem-maint.service -f`.")

    doc.add_heading("Step G — End-to-end confirmation", level=2)
    _bullets(
        doc,
        [
            "Confirm Chat test message from `--check-config` appears in "
            "SIEM-MAINTENANCE.",
            "Wait for daily report or temporarily trigger report job per "
            "vendor docs in staging.",
            "Confirm `/var/lib/siem-maint/` files appear/ update under load.",
        ],
    )

    doc.add_heading("Step H — Day-one operations", level=1)
    _bullets(
        doc,
        [
            "Install logrotate for `audit.jsonl` with `copytruncate`, weekly "
            "rotation, sufficient retention (e.g. 13 rotations ≈ quarter).",
            "Add `siem-maint.service` to host monitoring for failed units; treat "
            "missing 08:30 report as monitoring-dead signal.",
        ],
    )

    doc.add_heading("6. Behavioural contract (pattern checklist)", level=1)
    _p(doc, "After reproduction, behaviour should match the SIEM-Maintenance "
             "pattern:", bold=True)
    _bullets(
        doc,
        [
            "Alerts fire on band transitions, not on every sample in the same band.",
            "Per-category cooldown (default four hours) limits duplicate Chat noise; "
            "categories remain independent.",
            "Remediation (if enabled) only for the seven approved fix types; "
            "protected index patterns are never mutated; 24h loop guard on same "
            "fix; audit trail appended.",
            "Non auto-fix issues route to GPT recommendation (if configured) or "
            "canned guidance—commands are for human copy-paste, not auto-executed.",
            "Infrastructure alerts use SIEM-MAINTENANCE; detection pipeline alerts "
            "stay in SOC channels—do not merge rotations without intent.",
        ],
    )

    doc.add_heading("7. Freshness coverage vs detection pipeline", level=1)
    _p(
        doc,
        "If this monitor supports the Linux anomaly detection platform, align "
        "`DATA_GROUPS` (or equivalent) with every Elasticsearch stream the "
        "detection jobs require—not only process/network/file—so stale ingest "
        "is caught before models silently starve.",
    )

    doc.add_heading("8. Upgrade path", level=1)
    _p(doc, "Stop service → extract new tarball → `pip install -r` and `pip install -e` "
             "→ `--check-config` → start service. Preserve `/var/lib/siem-maint/*`.")

    doc.add_heading("9. Document history", level=1)
    _p(doc, "1.0 — April 2026: Initial reproduction guide aligned with the "
             "SIEM-Maintenance infrastructure monitoring specification.")

    doc.save(OUT)
    print(f"Wrote {OUT}")


if __name__ == "__main__":
    main()
