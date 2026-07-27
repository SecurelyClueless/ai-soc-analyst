# SOC Detection Lab

A self-contained lab that generates real attack telemetry, ships it to a SIEM,
and feeds detected alerts into the [AI SOC Analyst](../README.md) triage
pipeline. This is the data source behind the pipeline's live (`elk`) mode.

---

## Purpose

The triage pipeline was originally built against hand-written sample alerts.
This lab replaces that fiction with real data: an attack is run against a
victim, Windows telemetry is captured by Sysmon, shipped to Elasticsearch by
Winlogbeat, queried from Python, and normalized into the same alert schema the
pipeline already consumes. The result is a genuine detection-to-triage loop.

---

## Architecture

```
┌─────────────┐        attack         ┌──────────────────┐
│  Kali Linux │ ────────────────────► │  Windows DC      │
│ (attacker)  │                       │  (victim)        │
└─────────────┘                       │  Sysmon +        │
                                      │  Winlogbeat      │
                                      └────────┬─────────┘
                                               │ ships events (TLS)
                                               ▼
                                      ┌──────────────────┐
                                      │  Ubuntu log srv  │
                                      │  Elasticsearch + │
                                      │  Kibana (ELK)    │
                                      └────────┬─────────┘
                                               │ Elasticsearch API (TLS)
                                               ▼
                                      ┌──────────────────┐
                                      │  Dev machine     │
                                      │  query → parse → │
                                      │  triage pipeline │
                                      └──────────────────┘
```

### Machines

| Host          | Role                       | OS                  | Notes                                         |
| ------------- | -------------------------- | ------------------- | --------------------------------------------- |
| DC1           | Victim / domain controller | Windows Server 2022 | Sysmon + Winlogbeat; primary telemetry source |
| Kali          | Attacker                   | Kali Linux          | Runs attack simulations                       |
| log-server    | SIEM                       | Ubuntu 24.04 LTS    | Elasticsearch 8.19 + Kibana                   |
| ubuntu-victim | Second victim              | Ubuntu              | (planned) auditd + Filebeat                   |

### Network

All lab machines sit on an isolated `192.168.100.0/24` VMware network. The log
server is dual-homed with a second NIC on the host network (`192.168.1.0/24`)
so the dev machine — which is not on the lab subnet — can query Elasticsearch.

> **Design note / tradeoff:** dual-homing the log server bridges the isolated
> attack lab and the host network. This is convenient for development but means
> the SIEM box straddles the air gap. It is acceptable while only benign attack
> _simulations_ are run. If genuinely malicious samples were ever detonated,
> this bridge should be removed and access provided another way (e.g. a jump
> host or host-only management interface).

---

## Telemetry

**Sysmon** provides the rich process telemetry the pipeline depends on. The
config is based on SwiftOnSecurity's sysmon-config. The key event is:

- **Event ID 1 (Process Create)** — supplies `process.command_line`,
  `process.hash.sha256`, `process.name`, parent process, and user. These map
  directly to the pipeline's alert schema and enrichment inputs.

Additional event types are natural extensions:

- **Event ID 3 (Network Connection)** — supplies `destination.ip`, which would
  activate the pipeline's AbuseIPDB enrichment (Event 1 has no network context).
- **Windows Security 4625/4624** — logon failures/successes for brute-force
  detection.

**Winlogbeat** ships the Sysmon channel (plus Security, System, Application) to
Elasticsearch over TLS.

---

## Setup summary

High-level steps. Sensitive values (passwords, certs) are excluded — see
placeholders.

### 1. Elasticsearch + Kibana (log server)

Installed from Elastic's 8.x APT repository (not from a zip — the repo gives
systemd services, auto-configured TLS/security, and clean upgrades).

Key `elasticsearch.yml` settings:

```yaml
network.host: 0.0.0.0
discovery.type: single-node
# cluster.initial_master_nodes: [...]   # removed — conflicts with single-node
```

JVM heap capped in `jvm.options.d/heap.options`:

```
-Xms2g
-Xmx2g
```

Kibana enrolled with a generated enrollment token and bound to `0.0.0.0:5601`.

### 2. Sysmon + Winlogbeat (Windows DC)

```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

Winlogbeat configured to output to Elasticsearch over TLS, trusting the ES CA
cert (`http_ca.crt`) copied from the log server. Sysmon channel explicitly
listed under `winlogbeat.event_logs`.

### 3. Querying from Python (dev machine)

The ES CA cert is copied to the dev box and referenced by the
`elasticsearch-py` client for proper certificate verification (no
`verify_certs=False` shortcut). Connection details live in `.env`.

---

## Issues encountered

Real problems hit during the build and how they were resolved. (This section is
the point — it is what distinguishes a working lab from a copy-pasted one.)

**Elasticsearch would not boot: `cluster.initial_master_nodes` vs
`discovery.type: single-node`.** The installer auto-added
`cluster.initial_master_nodes`, which conflicts with the single-node discovery
setting. Both answer the same question (how the node forms a cluster) and
Elasticsearch refuses to guess. Fix: comment out `cluster.initial_master_nodes`
and keep `discovery.type: single-node`.

**Python client rejected by the server: media-type version mismatch.** A fresh
`pip install elasticsearch` pulled a 9.x client, which sends
`compatible-with=9` headers that the 8.19 server refuses. Fix: pin the client
to the server's major version — `elasticsearch>=8,<9`. Lesson: match client
major version to server major version.

**Cross-subnet querying.** The dev machine (`192.168.1.0/24`) has no route into
the lab subnet (`192.168.100.0/24`). Because ES binds to `0.0.0.0`, it listens
on the log server's host-network NIC too, so the dev box connects via
`192.168.1.137:9200` — no config change or port forwarding needed, just the
right target IP.

**401 after password confusion.** The saved `elastic` password was wrong;
reset via `elasticsearch-reset-password -u elastic`. Note: rotating this
credential also breaks Winlogbeat, which authenticates with the same account —
a reminder that shared superuser credentials are fragile. A dedicated,
least-privilege Winlogbeat user would be the production approach.

**Field naming: `process.command_line` vs `.text`.** Elasticsearch multi-fields
index the same value two ways: `keyword` (exact, whole string) and `text`
(analyzed, tokenized). Full-text search inside the command line needs the
`.text` variant; the parser consumes the exact `keyword` variant.

---

## Known limitations / future work

- **No query watermark.** The pipeline re-fetches all matching events every
  run, reprocessing history. A `@timestamp` lower bound persisted between runs
  would make each run process only new events.
- **Single event type.** Only Event 1 (process creation) is detected today.
  Event 3 (network) and Security 4625 (logon) would broaden coverage and
  activate IP-based enrichment.
- **No correlation.** The richest alerts (a process that spawns _and_ connects
  out) require correlating Event 1 and Event 3 by `process.entity_id`. Not yet
  implemented.
- **Second Ubuntu victim** is planned but not yet shipping logs.
