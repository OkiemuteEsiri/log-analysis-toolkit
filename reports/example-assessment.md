# Example Log Analysis Assessment

> Example output based entirely on synthetic telemetry.

## Executive summary
The sample dataset produces three analyst-review scenarios: a repeated authentication-failure sequence followed by success, endpoint security-control impairment correlated with PowerShell/outbound activity, and a privileged-access change. These findings demonstrate prioritization and evidence linkage; they are not claims of compromise.

## Priorities

### P1 — LAB-WS-01
Validate the endpoint-control state change and correlated scripting/network telemetry. Preserve relevant evidence and restore approved controls. Revalidate control health after remediation.

### P2 — lab.alex
Validate the successful authentication following repeated failures, including MFA, source and expected-user context. Escalate only if the activity remains unexplained.

### P2 — LAB-SRV-01
Validate the privileged membership change against an approved request and effective access. Remove unauthorized privilege and re-query membership before closure.

## ATT&CK context
T1110, T1078, T1562.001, T1059.001, T1071 and T1098 are used as defensive classification context.
