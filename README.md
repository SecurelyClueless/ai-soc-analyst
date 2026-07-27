# AI SOC Analyst

Automated alert triage and incident report generation for security operations.

This tool takes raw SOC alerts, enriches them with live threat intelligence, uses an LLM to produce an analyst-grade triage verdict, validates every MITRE ATT&CK mapping against the official dataset, and outputs a structured incident report.

---

## Why this exists

SOC analysts spend a large share of their time on repetitive first-line triage: pulling IP reputation, checking file hashes, deciding whether an alert is worth escalating, and writing it up. This project automates that pipeline end to end while keeping a human-verifiable audit trail.

The design goal was not "let the AI decide." It was **let the AI reason, and let code verify.**

---

## Pipeline

```
Raw alert (JSON)
    ↓
Enrichment  ──  AbuseIPDB (IP reputation)
            └─  VirusTotal (file hash reputation)
    ↓
Normalize + risk flags
    ↓
LLM triage (Claude Haiku 4.5)
    ↓
MITRE ATT&CK validation  ──  official MITRE CTI dataset
    ↓
Markdown incident report
```

---

## Features

**Multi-source enrichment.** IPs are checked against AbuseIPDB for abuse confidence, geolocation, ISP, and Tor exit-node status. File hashes are checked against VirusTotal's 70+ antivirus engines. Each source is isolated in its own module and returns a normalized record, so vendor-specific field names never leak into the rest of the codebase.

**Risk flagging.** Enrichment results are scored against configurable thresholds to produce human-readable risk signals (`known_malware`, `tor_exit_node`, `suspicious_ip_reputation`). All thresholds live in a single config block rather than being buried in logic.

**LLM triage with guardrails.** The system prompt constrains the model to reason only over supplied evidence, to answer "unknown" rather than guess, and to return a fixed JSON schema. Output includes severity with justification, a plain-language summary, recommended response actions, a true/false-positive decision, and a confidence rating.

**MITRE ATT&CK validation.** The LLM *proposes* technique mappings; the code *verifies* them. Every technique ID is checked against the official MITRE CTI dataset before it reaches the report. Unverified IDs are flagged visibly rather than silently included — a hallucinated technique cannot make it into a report.

**Threat-intel caching.** Enrichment responses are cached to disk, keyed by indicator. This respects VirusTotal's free-tier rate limit (4 requests/min) and makes repeated runs near-instant during prompt tuning. Failed lookups are never cached, so a transient API error cannot poison future runs.

**Graceful degradation.** Alerts missing a hash or IP are enriched with whatever indicators are present. Any API failure returns a safe error record rather than crashing the pipeline.

---

## Sample output

```markdown
# Incident Report: Suspicious PowerShell Execution

## 1. Executive Summary

User jsmith on WIN-DESKTOP-07 executed an encoded PowerShell command that
established an outbound connection to 185.220.101.47, a Tor exit node with a
100/100 abuse score. The executable hash matches known malware detected by 64
antivirus engines.

**Severity:** HIGH — Encoded PowerShell execution with C2 connection to a Tor
exit node hosting known malware.
**Triage Decision:** true_positive
**Confidence:** high

## 4. MITRE ATT&CK Mapping

| Technique ID | Name                              | Tactic             | Status |
|--------------|-----------------------------------|--------------------|--------|
| T1059.001    | PowerShell                        | Execution          | ✅     |
| T1027        | Obfuscated Files or Information   | Defense Evasion    | ✅     |
| T1071        | Application Layer Protocol        | Command and Control| ✅     |
```

Full reports for all five test scenarios are in [`reports/`](reports/).

---

## Test scenarios

The tool was validated against five alert types spanning both true and false positives:

| Alert | Scenario | Expected | Result |
|-------|----------|----------|--------|
| A-1001 | Encoded PowerShell → Tor exit node, malicious hash | True positive | ✅ High / true_positive |
| A-1002 | 142 failed logins followed by a successful auth | True positive | ✅ Escalated |
| A-1003 | Regular-interval outbound beaconing (C2 pattern) | True positive | ✅ Flagged |
| A-1004 | Scheduled backup script, service account, internal IPs | **False positive** | ✅ **Correctly dismissed** |
| A-1005 | rclone bulk transfer of finance data, after hours | True positive | ✅ Flagged |

A-1004 is deliberately included as a control. An alert triage tool that flags
everything as high severity is worthless — the discriminating power is what
makes it credible. The tool correctly identified the benign backup script as a
false positive despite it involving PowerShell execution.

---

## Setup

Requires Python 3.9+.

```bash
git clone https://github.com/SecurelyClueless/ai-soc-analyst.git
cd ai-soc-analyst

python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate         # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
ABUSEIPDB_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ANTHROPIC_API_KEY=your_key
```

All three services offer free tiers.

## Usage

```bash
python main.py
```

Every alert in `alerts/` is processed, and a Markdown report is written to
`reports/` for each one. Drop a new JSON alert into `alerts/` and it is picked
up automatically — no code change required.

---

## Project structure

```
ai-soc-analyst/
├── alerts/                 # Input alerts (JSON)
├── enrichment/
│   ├── abuseipdb.py        # IP reputation lookup
│   ├── virustotal.py       # File hash lookup
│   ├── cache.py            # Disk cache for enrichment responses
│   └── enrich.py           # Orchestration + risk flagging
├── triage/
│   ├── triage.py           # LLM triage call
│   └── mitre.py            # ATT&CK validation against official dataset
├── report/
│   └── report.py           # Markdown report generation
├── reports/                # Generated incident reports
└── main.py                 # Pipeline entry point
```

---

## Design decisions

**Normalization at the boundary.** Each enrichment module renames vendor fields
to a common vocabulary (`abuseConfidenceScore` → `abuse_score`) at the point of
ingestion. Downstream code speaks one language regardless of source, so swapping
a threat-intel provider means changing one module rather than the whole codebase.

**LLM proposes, code validates.** An LLM generates MITRE technique IDs by
learned association, not by lookup — it can produce a plausibly-formatted ID
that does not exist, with exactly the same confidence as a real one. Validating
every ID against MITRE's published dataset closes this gap. The model supplies
judgment; the code supplies verification.

**Never cache a failure.** An early bug cached an empty result from a failed
download, and every subsequent run silently read the poisoned cache and
validated nothing. The cache now refuses to store empty or error records, so a
transient failure can never persist.

**Thresholds as configuration.** Risk-flag thresholds live in a single `CONFIG`
dict, not as magic numbers inside conditionals. Tuning sensitivity is a one-line
change in one obvious place.

---

## Limitations

This is a triage aid, not an autonomous decision-maker. It does not sandbox
files, inspect packet captures, or query endpoint telemetry — it reasons only
over the alert fields and threat-intel enrichment supplied to it.

The enrichment cache has no TTL. Threat intelligence is time-sensitive, and a
production deployment would expire cached lookups after a defined window.

LLM output is advisory. Every report is intended for analyst review, and MITRE
mappings are explicitly marked as verified or unverified so a reader can see
what has been checked.

---

## Tech stack

Python · Anthropic API (Claude Haiku 4.5) · AbuseIPDB · VirusTotal · MITRE ATT&CK (CTI dataset)
