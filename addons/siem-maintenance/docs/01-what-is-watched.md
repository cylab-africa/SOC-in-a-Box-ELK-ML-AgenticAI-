# 1. What the Subsystem Watches

> **Runnable code in this Git repo:** see [**docs/00 — Design spec vs this repo**](00-design-spec-vs-this-repo.md) for how these *intended* probes map to `es_health_monitor.py` / `enhanced_health_monitor.py`. The snippets below reference the packaged `siem_maint` layout (`/opt/siem-maint/`).

Infrastructure failures that kill a SIEM do not look like security
incidents. They look like a noisy neighbour filling the disk, a JVM
heap slowly creeping past 85%, an Elastic Agent that stopped checking
in six hours ago, or a data pipeline that went quiet without returning
an error. The monitoring subsystem is organised around four such
surfaces, each with its own collectors and its own failure modes.

## 1.1 Host operating system

The host that runs the platform is watched first. A lightweight
`psutil` probe samples:

- CPU load averages at 1, 5, and 15 minutes
- Memory usage including swap and cache
- Disk usage across both inode count and block utilisation
- Interface errors and drops on every network interface
- Count of open file descriptors against the process limit

These metrics are cheap to collect and they fail fast — a full disk
kills Elasticsearch within minutes, so the host probe runs on the
shortest cadence of any collector.

**`siem_maint/probes/host.py`**

```python
import psutil

def collect_host_metrics():
    cpu_1m, cpu_5m, cpu_15m = psutil.getloadavg()
    mem  = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")

    # num_fds() returns ALL open file descriptors (sockets, pipes,
    # regular files, epoll, etc.) — this is what matches against the
    # process `RLIMIT_NOFILE` limit. open_files() returns only regular
    # files and undercounts significantly.
    return {
        "cpu_load_1m":   cpu_1m,
        "cpu_load_5m":   cpu_5m,
        "cpu_load_15m":  cpu_15m,
        "mem_used_pct":  mem.percent,
        "swap_used_pct": swap.percent,
        "disk_used_pct": disk.percent,
        "open_fds":      psutil.Process().num_fds(),
    }
```

## 1.2 Elasticsearch cluster

The cluster is watched through three APIs:

- **Cluster Health API** — green / yellow / red status, unassigned
  shard count, pending cluster-task count.
- **Nodes Stats API** — per-node JVM heap percentage, disk usage
  against the low / high / flood-stage watermarks, CPU percentage,
  GC pause accumulation, thread-pool rejections across search, write
  and bulk pools, and open file descriptor count.
- **Cat Shards API** — current shard distribution and the reason
  codes for any unassigned shards.

Together these give a complete picture of what the cluster is doing
and why.

**Cluster health (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  "https://es-host:9200/_cluster/health?pretty"
```

**Nodes stats — `jvm` + `fs` + `thread_pool` only (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  "https://es-host:9200/_nodes/stats/jvm,fs,thread_pool?pretty"
```

**`siem_maint/probes/cluster.py`**

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(
    hosts=[ES_HOST],
    basic_auth=(ES_USER, ES_PASS),
    request_timeout=30,
)

def probe_cluster():
    health = es.cluster.health()
    nodes  = es.nodes.stats(metric=["jvm", "fs", "thread_pool"])
    shards = es.cat.shards(
        format="json",
        h="index,shard,prirep,state,node,unassigned.reason",
    )

    issues = []
    for node_id, node in nodes["nodes"].items():
        heap_pct = node["jvm"]["mem"]["heap_used_percent"]
        if heap_pct > 85:
            issues.append(("node_pressure", node["name"], f"heap {heap_pct}%"))

    if health["status"] == "red":
        issues.append(("cluster_health", "cluster", "status=red"))

    return health, nodes, shards, issues
```

## 1.3 Elastic Agents

Endpoint agents are watched by querying the `.fleet-agents` index
directly. For each agent the subsystem tracks:

- `agent_id`
- `hostname`
- `version`
- `status` — online, offline, enrolling, unenrolling
- `last_checkin` timestamp
- assigned `policy_id`

Three failure modes get alerts:

1. An agent that was recently active goes offline.
2. No agents are reporting data for a specific data type.
3. Agent versions have drifted across the fleet.

The first is the most common and the most actionable.

**List offline agents (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -H "Content-Type: application/json" \
  -X POST "https://es-host:9200/.fleet-agents/_search" \
  -d '{
    "size": 200,
    "_source": ["agent.id", "local_metadata.host.hostname",
                "active", "last_checkin", "policy_id"],
    "query": {
      "bool": {
        "must": [
          { "term":  { "active": false } },
          { "range": { "last_checkin": { "gte": "now-24h" } } }
        ]
      }
    }
  }'
```

**`siem_maint/probes/agents.py`**

`elasticsearch-py` 8.x deprecated the `body=` kwarg on `.search()`.
Pass the query-DSL fields as top-level keyword arguments instead:

```python
def find_offline_agents():
    resp = es.search(
        index=".fleet-agents",
        size=200,
        _source=["agent.id", "local_metadata.host.hostname",
                 "active", "last_checkin", "policy_id"],
        query={
            "bool": {
                "must": [
                    {"term":  {"active": False}},
                    {"range": {"last_checkin": {"gte": "now-24h"}}},
                ]
            }
        },
    )
    return [hit["_source"] for hit in resp["hits"]["hits"]]
```

## 1.4 Data freshness

Data freshness is watched last because it is the integration point —
if the host is healthy, the cluster is healthy, and agents are online,
but data is not arriving, something between them has broken silently.
For each critical data group (process, network, file, and several
others) the subsystem queries the most recent `@timestamp` with a
one-document sorted search and computes the delta against the current
wall clock. The result is classified into a tier and alerted on
transitions only.

**Most recent `@timestamp` for the process data group (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -H "Content-Type: application/json" \
  -X POST "https://es-host:9200/.ds-logs-endpoint.events.process-default-*/_search" \
  -d '{
    "size": 1,
    "sort": [{ "@timestamp": "desc" }],
    "_source": ["@timestamp"]
  }'
```

**`siem_maint/probes/freshness.py`**

```python
from datetime import datetime, timezone

DATA_GROUPS = {
    "process": ".ds-logs-endpoint.events.process-default-*",
    "network": ".ds-logs-endpoint.events.network-default-*",
    "file":    ".ds-logs-endpoint.events.file-default-*",
}

def ingest_lag_seconds(group_name):
    index = DATA_GROUPS[group_name]
    resp = es.search(
        index=index,
        size=1,
        sort=[{"@timestamp": "desc"}],
        _source=["@timestamp"],
    )
    if not resp["hits"]["hits"]:
        return None

    raw = resp["hits"]["hits"][0]["_source"]["@timestamp"]

    # Python 3.11+ parses the trailing 'Z' directly. Default ES
    # @timestamp is millisecond precision, which parses cleanly.
    # For `date_nanos` fields (nanosecond precision), truncate the
    # fractional part to 6 digits before parsing — `fromisoformat`
    # maxes out at microseconds.
    if "." in raw:
        head, rest = raw.split(".", 1)
        digits = ""
        for ch in rest:
            if ch.isdigit():
                digits += ch
            else:
                break
        raw = f"{head}.{digits[:6]}{rest[len(digits):]}"

    latest = datetime.fromisoformat(raw)
    return (datetime.now(timezone.utc) - latest).total_seconds()
```

---

Previous: [← 0. Design spec vs this repo](00-design-spec-vs-this-repo.md)  
Next: [2. When each check runs →](02-cadence.md)
