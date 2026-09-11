import hashlib
from collections import Counter, defaultdict
from .models import Finding, LogEvent


def _id(rule: str, evidence: list[LogEvent]) -> str:
    material = rule + "|" + "|".join(sorted(e.event_id for e in evidence))
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 85: return "Critical"
    if score >= 70: return "High"
    if score >= 45: return "Medium"
    return "Low"


def _finding(rule: str, title: str, entity: str, evidence: list[LogEvent], score: int,
             confidence: int, attack: tuple[str, ...], rationale: str, remediation: str,
             revalidation: str) -> Finding:
    score = max(0, min(100, score))
    return Finding(_id(rule, evidence), title, _severity(score), confidence, score, entity,
                   attack, tuple(e.event_id for e in evidence), rationale, remediation, revalidation)


def analyze(events: list[LogEvent]) -> list[Finding]:
    findings: list[Finding] = []
    by_user: dict[str, list[LogEvent]] = defaultdict(list)
    by_host: dict[str, list[LogEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x.timestamp):
        by_user[e.user].append(e); by_host[e.host].append(e)

    for user, rows in by_user.items():
        failures = [e for e in rows if e.event_type == "authentication" and e.outcome == "failure"]
        successes = [e for e in rows if e.event_type == "authentication" and e.outcome == "success"]
        if len(failures) >= 4 and successes:
            ev = failures[-4:] + [successes[-1]]
            findings.append(_finding("auth-sequence", "Repeated authentication failures followed by success", user, ev,
                78, 85, ("T1110", "T1078"), "Multiple failed authentications were followed by a successful sign-in for the same synthetic identity.",
                "Validate the sign-in, review MFA and source context, rotate credentials if compromise is confirmed.",
                "Confirm subsequent authentication is expected and no unexplained privileged activity remains."))

    for host, rows in by_host.items():
        impairment = [e for e in rows if e.event_type == "security_control" and e.action in {"disable", "stop", "tamper"}]
        script = [e for e in rows if e.event_type == "process" and "powershell" in e.process.lower()]
        outbound = [e for e in rows if e.event_type == "network" and e.action == "connect" and e.dst_ip]
        if impairment and (script or outbound):
            ev = impairment[:1] + script[:1] + outbound[:1]
            findings.append(_finding("control-chain", "Security-control impairment with follow-on activity", host, ev,
                91, 92, ("T1562.001", "T1059.001", "T1071"), "Control impairment was correlated with scripting or outbound activity on the same synthetic host.",
                "Investigate the endpoint, preserve evidence and restore security controls; isolate only under approved incident procedures.",
                "Verify controls are healthy and the correlated behavior no longer occurs after remediation."))

        privilege = [e for e in rows if e.event_type == "privilege" and e.action in {"add_admin", "role_grant"}]
        if privilege:
            findings.append(_finding("privilege-change", "Privileged access change requires validation", host, privilege,
                72, 80, ("T1098",), "A privileged membership or role change was recorded.",
                "Confirm authorization, owner, ticket and business justification; remove unauthorized access.",
                "Re-query effective privilege and confirm approved state."))

    return sorted(findings, key=lambda f: f.risk_score, reverse=True)


def metrics(findings: list[Finding]) -> dict:
    counts = Counter(f.severity for f in findings)
    return {"total_findings": len(findings), "critical_high": counts["Critical"] + counts["High"],
            "highest_risk": max((f.risk_score for f in findings), default=0),
            "affected_entities": len({f.entity for f in findings}), "severity_counts": dict(counts)}
