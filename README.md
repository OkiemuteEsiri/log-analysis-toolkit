# Log Analysis Toolkit

A defensive security-engineering project for normalizing, correlating and prioritizing multi-source security telemetry. The lab demonstrates how Windows, Sysmon, identity, network, cloud and endpoint records can be converted into explainable investigation findings without relying on a commercial SIEM.

## Why this project exists
Security teams rarely suffer from a shortage of logs; the harder problem is turning heterogeneous evidence into defensible decisions. This repository demonstrates schema validation, evidence preservation, entity-based correlation, risk prioritization, ATT&CK classification, analyst-ready reporting and remediation validation.

## Architecture

```text
Synthetic JSON logs
       |
       v
Fail-closed ingestion
       |
       v
Normalized LogEvent model
       |
       v
User/host correlation engine
       |
       v
Risk + confidence + ATT&CK context
       |
       v
Prioritized Finding model
       |
       v
Markdown assessment / analyst workflow
```

## Implemented analytics
- Repeated authentication failures followed by a successful sign-in.
- Security-control impairment correlated with PowerShell or outbound network activity on the same host.
- Privileged membership/role changes requiring authorization validation.
- Deterministic evidence-linked finding IDs.
- Separate 0–100 risk and confidence values.
- Portfolio-level finding metrics.

## ATT&CK context
The current rules reference T1110 (Brute Force), T1078 (Valid Accounts), T1562.001 (Impair Defenses), T1059.001 (PowerShell), T1071 (Application Layer Protocol) and T1098 (Account Manipulation). ATT&CK mappings are classification context only and are never treated as proof of compromise.

## Repository structure

```text
src/
  models.py       normalized immutable models and validation
  io.py           fail-closed JSON ingestion
  analyzer.py     cross-source correlation and scoring
  reporting.py    Markdown executive/technical reporting
  cli.py          offline command-line workflow
data/
  synthetic_logs.json
tests/
  test_toolkit.py
docs/
  architecture-methodology.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Run locally
Requires Python 3.12+ and no third-party packages.

```bash
python -m src.cli data/synthetic_logs.json --output assessment.md
python -m unittest discover -s tests -v
```

## Engineering controls
The loader rejects malformed top-level input, missing required fields, unsupported telemetry sources, timezone-naive timestamps and duplicate event IDs. All bundled records are explicitly synthetic. Documentation IP ranges are used for sample network context.

## Investigation and remediation
Every generated finding carries evidence references, rationale, remediation guidance and revalidation criteria. Closure is therefore treated as an evidence-backed lifecycle rather than simply marking an alert resolved.

## Skills demonstrated
Detection engineering, incident-response analytics, Python security automation, log normalization, cross-source correlation, ATT&CK mapping, evidence governance, risk communication, unit testing, CI/CD and remediation validation.

## CI
GitHub Actions runs Python compilation, the unit-test suite and a CLI smoke test with read-only repository permissions.

## Limitations
This is an offline defensive lab, not a production SIEM. It does not connect to live EDR/SIEM/identity/cloud systems, execute containment, modify accounts, scan networks, capture credentials or perform exploitation. Production deployment would require source-specific parsers, baselining, allowlists, persistence, RBAC, monitoring and formal change control.

## Roadmap
- Add configurable correlation windows.
- Add CSV and JSONL adapters.
- Add baseline-aware anomaly scoring.
- Add rule metadata and ATT&CK coverage export.
- Add optional Sigma-style rule translation.
- Add evidence-quality and data-freshness dashboards.

## Safety
All examples are synthetic and intended for authorized defensive engineering, detection development and incident-response education.
