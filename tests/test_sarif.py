import io
import json
import re
import unittest
from dataclasses import replace

from scanner.detector import Detector
from scanner.models import Page, Rule, ScanError, ScanResult, Severity
from scanner.sarif import SARIF_SCHEMA, build_sarif, write_sarif_report


class SarifReportTest(unittest.TestCase):
    def setUp(self):
        regex = r"password=(?P<secret>\S+)"
        rule = Rule(
            id="generic-password",
            name="Generic password",
            severity=Severity.HIGH,
            regex=regex,
            pattern=re.compile(regex),
            confidence=0.8,
        )
        detector = Detector([rule])
        page = Page(
            id="42",
            title="Deployment",
            space_key="ENG",
            version=3,
            content="header\npassword=do-not-print-me",
            web_url="https://confluence.example.test/spaces/ENG/pages/42",
        )
        page_finding = detector.scan(page)[0]
        attachment_finding = detector.scan(
            replace(
                page,
                attachment_id="att/7",
                attachment_name="deployment.env",
            )
        )[0]
        self.result = ScanResult(
            spaces_discovered=1,
            spaces_scanned=1,
            pages_scanned=1,
            versions_scanned=1,
            attachments_discovered=1,
            attachments_scanned=1,
            attachment_bytes_scanned=len(page.content.encode()),
            findings=[page_finding, attachment_finding],
        )

    def test_builds_sarif_2_1_with_rules_artifacts_and_regions(self):
        payload = build_sarif(self.result)

        self.assertEqual(payload["$schema"], SARIF_SCHEMA)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(len(payload["runs"]), 1)
        run = payload["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Confluence Secret Scanner")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(len(run["artifacts"]), 2)
        self.assertEqual(len(run["results"]), 2)

        sarif_result = run["results"][0]
        self.assertEqual(sarif_result["ruleId"], "generic-password")
        self.assertEqual(sarif_result["ruleIndex"], 0)
        self.assertEqual(sarif_result["level"], "error")
        self.assertEqual(
            sarif_result["locations"][0]["physicalLocation"]["region"],
            {"startLine": 2, "startColumn": 10},
        )
        artifact_location = sarif_result["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]
        self.assertEqual(artifact_location["index"], 0)
        self.assertEqual(
            artifact_location["uri"],
            "https://confluence.example.test/spaces/ENG/pages/42",
        )

    def test_attachment_has_distinct_uri_metadata_and_fingerprint(self):
        results = build_sarif(self.result)["runs"][0]["results"]
        page_result, attachment_result = results

        self.assertEqual(attachment_result["properties"]["sourceType"], "attachment")
        self.assertEqual(attachment_result["properties"]["attachmentId"], "att/7")
        self.assertEqual(
            attachment_result["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"],
            "https://confluence.example.test/spaces/ENG/pages/42#attachment=att%2F7",
        )
        self.assertNotEqual(
            page_result["partialFingerprints"]["primaryLocationLineHash"],
            attachment_result["partialFingerprints"]["primaryLocationLineHash"],
        )

    def test_writer_is_valid_json_and_never_contains_matched_value(self):
        output = io.StringIO()

        write_sarif_report(self.result, output)
        payload = json.loads(output.getvalue())

        self.assertEqual(payload["version"], "2.1.0")
        self.assertNotIn("do-not-print-me", output.getvalue())

    def test_partial_scan_errors_are_tool_notifications(self):
        self.result.errors.append(
            ScanError(scope="space:OPS", message="synthetic request failure")
        )

        invocation = build_sarif(self.result)["runs"][0]["invocations"][0]

        self.assertFalse(invocation["executionSuccessful"])
        self.assertEqual(
            invocation["toolExecutionNotifications"][0]["message"]["text"],
            "[space:OPS] synthetic request failure",
        )

    def test_all_severities_are_mapped_to_sarif_levels(self):
        finding = self.result.findings[0]
        severities = (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        )
        findings = [
            replace(
                finding,
                rule_id=f"rule-{severity.value}",
                rule_name=f"Rule {severity.value}",
                severity=severity,
            )
            for severity in severities
        ]

        run = build_sarif(ScanResult(findings=findings))["runs"][0]

        self.assertEqual(
            [item["level"] for item in run["results"]],
            ["error", "error", "warning", "note"],
        )
        self.assertEqual(
            [
                item["defaultConfiguration"]["level"]
                for item in run["tool"]["driver"]["rules"]
            ],
            ["error", "error", "warning", "note"],
        )

    def test_fallback_confluence_uri_is_safely_encoded(self):
        finding = replace(
            self.result.findings[1],
            page_url=None,
            space_key="Team Space",
            page_id="page/42",
        )

        location = build_sarif(ScanResult(findings=[finding]))["runs"][0][
            "results"
        ][0]["locations"][0]["physicalLocation"]["artifactLocation"]

        self.assertEqual(
            location["uri"],
            "confluence://content/spaces/Team%20Space/pages/"
            "page%2F42#attachment=att%2F7",
        )

    def test_empty_clean_scan_is_representable(self):
        run = build_sarif(ScanResult())["runs"][0]

        self.assertEqual(run["tool"]["driver"]["rules"], [])
        self.assertEqual(run["results"], [])
        self.assertNotIn("artifacts", run)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])


if __name__ == "__main__":
    unittest.main()
