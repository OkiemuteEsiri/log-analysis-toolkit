from .analyzer import metrics
from .models import Finding


def markdown_report(findings: list[Finding]) -> str:
    m = metrics(findings)
    lines = ["# Log Analysis Assessment", "", "> Synthetic defensive analysis. Findings require analyst validation and are not proof of compromise.", "",
             "## Executive metrics", "", f"- Findings: **{m['total_findings']}**", f"- Critical/High: **{m['critical_high']}**",
             f"- Highest risk score: **{m['highest_risk']}**", f"- Affected entities: **{m['affected_entities']}**", "", "## Prioritized findings", ""]
    for f in findings:
        lines += [f"### {f.severity} — {f.title}", "", f"- Risk: **{f.risk_score}/100**", f"- Confidence: **{f.confidence}%**",
                  f"- Entity: `{f.entity}`", f"- ATT&CK context: {', '.join(f.attack)}", f"- Evidence: {', '.join(f.evidence_ids)}", "",
                  f"**Rationale:** {f.rationale}", "", f"**Remediation:** {f.remediation}", "", f"**Revalidation:** {f.revalidation}", ""]
    return "\n".join(lines)
