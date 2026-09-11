# Architecture and Methodology

## Objective
This project demonstrates a defensive, provider-neutral workflow for normalizing and correlating synthetic security telemetry. It is designed for portfolio demonstration, detection engineering practice and incident-response analytics—not production enforcement.

## Pipeline
`JSON telemetry -> schema validation -> normalized LogEvent -> entity grouping -> correlation rules -> risk/confidence -> Finding -> Markdown report`

## Data governance
Input is fail-closed: the loader requires a JSON array, required fields, timezone-aware timestamps, an approved source type and unique evidence IDs. The included dataset is synthetic and uses documentation address ranges.

## Correlation methodology
The engine deliberately favors multi-event context over isolated strings. Current analytics cover: repeated authentication failures followed by success; endpoint-control impairment followed by scripting/network behavior; and privileged-access changes requiring authorization review.

Risk and confidence are separate. Risk represents potential security impact and urgency; confidence represents strength of the observed correlation. Neither is a probability of compromise.

## ATT&CK context
Mappings currently include T1110, T1078, T1562.001, T1059.001, T1071 and T1098. ATT&CK labels are investigation context, not evidence that an adversary executed a technique.

## Analyst workflow
1. Validate evidence quality and timestamps.
2. Confirm identity, host and source context.
3. Review correlated events and expected administrative activity.
4. Escalate according to severity and confidence.
5. Apply approved remediation only after validation.
6. Re-query telemetry and document closure evidence.

## Limitations
This is an offline lab. It does not query SIEMs, EDRs, identity providers or threat-intelligence services. It does not block traffic, isolate endpoints, change accounts or perform offensive actions. Production use would require source-specific parsers, baselining, allowlists, persistence, RBAC, monitoring and change control.
