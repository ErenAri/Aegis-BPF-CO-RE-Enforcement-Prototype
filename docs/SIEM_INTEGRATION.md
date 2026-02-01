# AegisBPF SIEM Integration Guide

This document describes how to integrate AegisBPF events with popular Security Information and Event Management (SIEM) systems.

## Event Format

AegisBPF emits events in JSON format to stdout or journald. See [event-schema.json](../config/event-schema.json) for the complete JSON Schema.

### Event Types

| Event | Description |
|-------|-------------|
| `EXEC` | Process execution observed (audit mode) |
| `BLOCK` | Process execution blocked (enforce mode) |

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `event` | string | Event type (`EXEC` or `BLOCK`) |
| `ts` | integer | Timestamp (nanoseconds since boot) |
| `pid` | integer | Process ID |
| `ppid` | integer | Parent process ID |
| `uid` | integer | User ID |
| `gid` | integer | Group ID |
| `comm` | string | Command name (max 16 chars) |
| `path` | string | Path to executable |
| `resolved_path` | string | Canonical path (if different) |
| `cgid` | integer | Cgroup ID |
| `cgroup_path` | string | Cgroup path |
| `dev` | integer | Device number |
| `ino` | integer | Inode number |

### Block-specific Fields

| Field | Type | Description |
|-------|------|-------------|
| `reason` | string | Block reason: `deny_inode`, `deny_path`, `deny_sha256` |

## Splunk Integration

### Using HTTP Event Collector (HEC)

1. Configure AegisBPF to output JSON to stdout:
   ```bash
   aegisbpf run --log=stdout --log-format=json
   ```

2. Use a log shipper (e.g., Fluentd, Vector) to forward to Splunk HEC:
   ```yaml
   # Vector config example
   [sources.aegisbpf]
   type = "journald"
   include_units = ["aegisbpf"]

   [transforms.parse_aegisbpf]
   type = "remap"
   inputs = ["aegisbpf"]
   source = '''
   . = parse_json!(.message)
   '''

   [sinks.splunk]
   type = "splunk_hec"
   inputs = ["parse_aegisbpf"]
   endpoint = "https://splunk.example.com:8088"
   token = "${SPLUNK_HEC_TOKEN}"
   index = "security"
   sourcetype = "aegisbpf"
   ```

### CEF Format (Common Event Format)

For Splunk CEF ingestion, transform AegisBPF events to CEF:

```
CEF:0|AegisBPF|AegisBPF|1.0|BLOCK|Execution Blocked|7|src=<uid> dst=<path> dproc=<comm> msg=<reason> cn1=<pid> cn1Label=pid cn2=<ppid> cn2Label=ppid cs1=<cgroup_path> cs1Label=cgroup
```

Field mapping:

| CEF Field | AegisBPF Field |
|-----------|----------------|
| `src` | `uid` |
| `dst` | `path` |
| `dproc` | `comm` |
| `msg` | `reason` |
| `cn1` | `pid` |
| `cn2` | `ppid` |
| `cs1` | `cgroup_path` |
| `deviceCustomDate1` | `ts` (converted to datetime) |

## Elastic (ELK) Integration

### Filebeat Configuration

```yaml
filebeat.inputs:
  - type: journald
    id: aegisbpf
    include_matches:
      - _SYSTEMD_UNIT=aegisbpf.service

processors:
  - decode_json_fields:
      fields: ["message"]
      target: "aegisbpf"
      overwrite_keys: true
  - timestamp:
      field: aegisbpf.ts
      layouts:
        - UNIX_NS
      target_field: "@timestamp"

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  index: "aegisbpf-%{+yyyy.MM.dd}"
```

### Index Template

```json
{
  "index_patterns": ["aegisbpf-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "event": { "type": "keyword" },
        "ts": { "type": "date", "format": "epoch_millis" },
        "pid": { "type": "integer" },
        "ppid": { "type": "integer" },
        "uid": { "type": "integer" },
        "gid": { "type": "integer" },
        "comm": { "type": "keyword" },
        "path": { "type": "keyword" },
        "resolved_path": { "type": "keyword" },
        "reason": { "type": "keyword" },
        "cgid": { "type": "long" },
        "cgroup_path": { "type": "keyword" },
        "dev": { "type": "integer" },
        "ino": { "type": "long" }
      }
    }
  }
}
```

### Kibana Detection Rules

Example detection rule for suspicious activity:

```json
{
  "name": "AegisBPF High Block Rate",
  "description": "Detects high rate of blocked executions indicating potential attack",
  "risk_score": 70,
  "severity": "high",
  "type": "threshold",
  "query": "event.type:BLOCK",
  "threshold": {
    "field": ["host.name"],
    "value": 100
  },
  "interval": "5m"
}
```

## Generic Syslog Integration

### Syslog Output

Configure rsyslog to forward AegisBPF events:

```bash
# /etc/rsyslog.d/aegisbpf.conf
if $programname == 'aegisbpf' then {
    action(type="omfwd"
           target="syslog.example.com"
           port="514"
           protocol="tcp"
           template="RSYSLOG_SyslogProtocol23Format")
    stop
}
```

### Syslog Message Format

```
<priority>1 <timestamp> <hostname> aegisbpf - - - <json_event>
```

Example:
```
<134>1 2024-01-15T10:30:00.000Z server1 aegisbpf - - - {"event":"BLOCK","ts":1234567890123456789,"pid":12345,"ppid":1000,"uid":1000,"gid":1000,"comm":"bash","path":"/usr/bin/malware","reason":"deny_path"}
```

## Prometheus/Grafana Integration

For metrics-based monitoring, use the built-in Prometheus endpoint:

```bash
aegisbpf metrics --out /var/lib/prometheus/node-exporter/aegisbpf.prom
```

See [prometheus/alerts.yml](../config/prometheus/alerts.yml) for alert rules and [grafana/dashboard.json](../config/grafana/dashboard.json) for the Grafana dashboard.

## QRadar Integration

### Log Source Configuration

1. Create a new log source with protocol type "Syslog"
2. Use the following DSM parsing:

```xml
<device_extension>
  <pattern id="aegisbpf_block"
           regex="\"event\":\"BLOCK\".*\"pid\":(\d+).*\"path\":\"([^\"]+)\".*\"reason\":\"([^\"]+)\""
           capture_groups="pid,path,reason">
    <event name="Execution Blocked" category="Security" severity="high"/>
  </pattern>
  <pattern id="aegisbpf_exec"
           regex="\"event\":\"EXEC\".*\"pid\":(\d+).*\"path\":\"([^\"]+)\""
           capture_groups="pid,path">
    <event name="Execution Observed" category="Audit" severity="low"/>
  </pattern>
</device_extension>
```

### QRadar Custom Properties

| Property Name | Expression |
|---------------|------------|
| AegisBPF PID | `\"pid\":(\d+)` |
| AegisBPF Path | `\"path\":\"([^\"]+)\"` |
| AegisBPF Reason | `\"reason\":\"([^\"]+)\"` |
| AegisBPF Cgroup | `\"cgroup_path\":\"([^\"]+)\"` |

## Security Onion Integration

### Logstash Filter

```ruby
filter {
  if [program] == "aegisbpf" {
    json {
      source => "message"
      target => "aegisbpf"
    }

    mutate {
      add_field => { "[@metadata][index]" => "so-aegisbpf" }
    }

    if [aegisbpf][event] == "BLOCK" {
      mutate {
        add_tag => ["alert", "execution_blocked"]
      }
    }
  }
}
```

## Wazuh Integration

### Custom Decoder

```xml
<!-- /var/ossec/etc/decoders/aegisbpf_decoder.xml -->
<decoder name="aegisbpf">
  <program_name>aegisbpf</program_name>
</decoder>

<decoder name="aegisbpf-block">
  <parent>aegisbpf</parent>
  <regex>"event":"BLOCK".*"pid":(\d+).*"path":"([^"]+)".*"reason":"(\w+)"</regex>
  <order>pid,path,reason</order>
</decoder>
```

### Custom Rules

```xml
<!-- /var/ossec/etc/rules/aegisbpf_rules.xml -->
<group name="aegisbpf,">
  <rule id="100001" level="10">
    <decoded_as>aegisbpf-block</decoded_as>
    <description>AegisBPF: Execution blocked - $(path)</description>
    <group>execution_blocked,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>100001</if_sid>
    <field name="reason">deny_sha256</field>
    <description>AegisBPF: Known malware blocked - $(path)</description>
    <group>malware,</group>
  </rule>
</group>
```

## Timestamp Conversion

AegisBPF timestamps are in nanoseconds since boot (kernel monotonic clock). To convert to wall-clock time:

```python
import time

def convert_ts(boot_ns):
    """Convert kernel boot timestamp to wall-clock time."""
    # Read boot time from /proc/stat
    with open('/proc/stat') as f:
        for line in f:
            if line.startswith('btime'):
                boot_time = int(line.split()[1])
                break

    # Convert nanoseconds to seconds and add to boot time
    wall_time = boot_time + (boot_ns / 1e9)
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(wall_time))
```

Alternatively, configure journald output which automatically includes wall-clock timestamps.
