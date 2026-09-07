import io
import json
import re
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from scanner.baseline import (
    Baseline,
    BaselineError,
    apply_baseline,
    finding_identity,
    load_baseline,
    write_baseline,
)
from scanner.detector import Detector
from scanner.models import Page, Rule, ScanResult, Severity
from scanner.report import write_json_report, write_text_report
from scanner.sarif import build_sarif


def make_finding(secret="known-value", attachment_id=None):
    regex = r"password=(?P<secret>\S+)"
    rule = Rule(
        id="generic-password",
        name="Generic password",
        severity=Severity.HIGH,
        regex=regex,
        pattern=re.compile(regex),
    )
    page = Page(
        id="42",
        title="Deployment",
        space_key="ENG",
        version=7,
        content=f"password={secret}",
        web_url="https://confluence.example.test/pages/42",
        attachment_id=attachment_id,
        attachment_name="deployment.env" if attachment_id else None,
    )
    return Detector([rule]).scan(page)[0]


class BaselineTest(unittest.TestCase):
    def test_identity_ignores_revision_title_and_location_changes(self):
        finding = make_finding()
        moved = replace(
            finding,
            page_title="Renamed",
            version=99,
            location="line:500:column:1",
            matched_versions=(99, 98),
        )

        self.assertEqual(finding_identity(finding), finding_identity(moved))

    def test_identity_distinguishes_page_and_attachment_findings(self):
        page_finding = make_finding()
        attachment_finding = make_finding(attachment_id="att-1")

        self.assertNotEqual(
            finding_identity(page_finding),
            finding_identity(attachment_finding),
        )

    def test_write_and_load_round_trip_is_deterministic_and_secret_safe(self):
        findings = [make_finding("first-secret"), make_finding("second-secret")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"

            write_baseline(path, reversed(findings))
            first_output = path.read_text(encoding="utf-8")
            baseline = load_baseline(path)
            write_baseline(path, findings)
            second_output = path.read_text(encoding="utf-8")
            payload = json.loads(first_output)

            self.assertEqual(first_output, second_output)
            self.assertEqual(payload["generated_by"], "Confluleaks")
            self.assertEqual(
                baseline.finding_ids,
                frozenset(finding_identity(finding) for finding in findings),
            )
            self.assertNotIn("first-secret", first_output)
            self.assertNotIn("second-secret", first_output)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_load_rejects_invalid_version_and_identity(self):
        fixtures = (
            {"version": 2, "findings": []},
            {"version": 1, "findings": [{"id": "not-a-hash"}]},
            {"version": 1, "findings": "invalid"},
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            for payload in fixtures:
                with self.subTest(payload=payload):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(BaselineError):
                        load_baseline(path)

    def test_apply_suppresses_only_exact_known_findings(self):
        known = make_finding("known-secret")
        new = make_finding("new-secret")
        result = ScanResult(findings=[known, new])
        baseline = Baseline(finding_ids=frozenset({finding_identity(known)}))

        apply_baseline(result, baseline)

        self.assertEqual(result.findings, [new])
        self.assertEqual(result.findings_suppressed, 1)

    def test_suppression_count_is_present_in_all_report_formats(self):
        finding = make_finding("new-secret")
        result = ScanResult(findings=[finding], findings_suppressed=3)
        text_output = io.StringIO()
        json_output = io.StringIO()

        write_text_report(result, text_output)
        write_json_report(result, json_output)
        sarif = build_sarif(result)

        self.assertIn("Known findings suppressed by baseline: 3", text_output.getvalue())
        self.assertEqual(
            json.loads(json_output.getvalue())["baseline"]["suppressed_findings"],
            3,
        )
        self.assertEqual(
            sarif["runs"][0]["invocations"][0]["properties"][
                "baselineSuppressedFindings"
            ],
            3,
        )


if __name__ == "__main__":
    unittest.main()
