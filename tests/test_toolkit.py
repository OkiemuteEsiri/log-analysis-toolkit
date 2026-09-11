import unittest
from datetime import datetime, timezone
from src.analyzer import analyze, metrics
from src.models import LogEvent
from src.reporting import markdown_report


def ev(i, source="identity", host="H", user="U", event_type="authentication", action="login", outcome="failure", process="", dst_ip=""):
    return LogEvent(i, datetime(2026, 1, 1, tzinfo=timezone.utc), source, host, user, event_type, action, outcome, "", dst_ip, process, "")


class ToolkitTests(unittest.TestCase):
    def test_rejects_naive_timestamp(self):
        with self.assertRaises(ValueError):
            LogEvent.from_dict({"event_id":"1","timestamp":"2026-01-01T00:00:00","source":"windows","host":"H","user":"U","event_type":"x","action":"x","outcome":"x"})

    def test_auth_sequence(self):
        rows = [ev(str(i)) for i in range(4)] + [ev("5", outcome="success")]
        self.assertTrue(any("authentication failures" in f.title for f in analyze(rows)))

    def test_too_few_failures_suppressed(self):
        rows = [ev("1"), ev("2"), ev("3"), ev("4", outcome="success")]
        self.assertFalse(analyze(rows))

    def test_control_chain(self):
        rows = [ev("1", source="endpoint", event_type="security_control", action="disable", outcome="success"),
                ev("2", source="sysmon", event_type="process", action="start", outcome="success", process="powershell.exe")]
        self.assertTrue(any("impairment" in f.title for f in analyze(rows)))

    def test_privilege_change(self):
        rows = [ev("1", source="windows", event_type="privilege", action="add_admin", outcome="success")]
        self.assertEqual(analyze(rows)[0].attack, ("T1098",))

    def test_scores_bounded(self):
        self.assertTrue(all(0 <= f.risk_score <= 100 for f in analyze([ev("1", source="windows", event_type="privilege", action="add_admin", outcome="success")])))

    def test_deterministic_ids(self):
        rows = [ev("1", source="windows", event_type="privilege", action="add_admin", outcome="success")]
        self.assertEqual(analyze(rows)[0].finding_id, analyze(rows)[0].finding_id)

    def test_metrics(self):
        rows = [ev("1", source="windows", event_type="privilege", action="add_admin", outcome="success")]
        self.assertEqual(metrics(analyze(rows))["total_findings"], 1)

    def test_report_has_caveat(self):
        self.assertIn("not proof of compromise", markdown_report([]))

    def test_report_has_revalidation(self):
        rows = [ev("1", source="windows", event_type="privilege", action="add_admin", outcome="success")]
        self.assertIn("Revalidation", markdown_report(analyze(rows)))


if __name__ == "__main__": unittest.main()
