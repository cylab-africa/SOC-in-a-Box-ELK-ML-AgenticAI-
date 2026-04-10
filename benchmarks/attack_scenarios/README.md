# Attack Scenario Benchmarks

Curated attack scenarios for benchmarking the detection pipeline.
Each scenario is a JSON file containing a mix of benign and malicious events
that simulate realistic attack patterns aligned to MITRE ATT&CK.

## Scenarios

### scenario_01_webshell_exfil.json
- **Kill chain**: execution -> discovery -> privilege_escalation -> exfiltration
- **Techniques**: T1059, T1033, T1087, T1548, T1048
- **Description**: Web shell drops to disk, enumerates users/system info,
  escalates privileges, and exfiltrates data via curl.

### scenario_02_ssh_bruteforce_lateral.json
- **Kill chain**: credential_access -> initial_access -> lateral_movement
- **Techniques**: T1110, T1078, T1021
- **Description**: SSH brute force against target host, successful auth with
  valid credentials, lateral movement to internal hosts.

### scenario_03_supply_chain_c2.json
- **Kill chain**: persistence -> command_and_control -> collection
- **Techniques**: T1053.003, T1071.001, T1568.002, T1560.001
- **Description**: Malicious cron job installed, beacons to DGA-generated
  domains for C2 communication, stages and archives local data.

### scenario_04_insider_threat.json
- **Kill chain**: initial_access -> collection -> exfiltration -> defense_evasion
- **Techniques**: T1078, T1005, T1048, T1070.004
- **Description**: Legitimate user authenticates at unusual hours, performs
  mass file access on sensitive directories, exfiltrates via rsync,
  cleans up traces.

### scenario_05_lolbin_chain.json
- **Kill chain**: execution -> command_and_control -> defense_evasion -> discovery
- **Techniques**: T1059.004, T1059.006, T1105, T1571, T1222.002, T1033
- **Description**: Living-off-the-land binary chain: bash spawns python3 for
  initial download, wget fetches second stage, chmod + execute, netcat
  reverse shell, then discovery commands.

## JSON Schema

Each scenario file follows this structure:

```json
{
  "scenario_name": "string",
  "description": "string",
  "attack_techniques": ["T####", "..."],
  "kill_chain_phases": ["phase1", "phase2"],
  "total_events": 0,
  "attack_events": 0,
  "events": [
    {
      "@timestamp": "ISO8601",
      "process.name": "string",
      "process.parent.name": "string",
      "user.name": "string",
      "host.hostname": "string",
      "process.command_line": "string",
      "event.action": "string",
      "is_attack": true,
      "attack_technique": "T####",
      "attack_phase": "string"
    }
  ]
}
```

## Expected Detection Rates

| Scenario | Min Detection Rate | Max False Negatives |
|----------|-------------------|---------------------|
| 01 Webshell Exfil | 80% | 3 |
| 02 SSH Brute Force | 85% | 2 |
| 03 Supply Chain C2 | 70% | 5 |
| 04 Insider Threat | 65% | 4 |
| 05 LOLBin Chain | 75% | 2 |
